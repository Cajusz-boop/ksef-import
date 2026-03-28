"""
KSeF 2.0 Cloud Function — automatyczne pobieranie faktur zakupowych
Deployowane na Google Cloud Functions, triggerowane przez Cloud Scheduler

API: KSeF 2.0 (od 1 lutego 2026)
Base URL prod: https://api.ksef.mf.gov.pl/api/v2
Base URL test: https://api-test.ksef.mf.gov.pl/api/v2

Flow:
1. POST /auth/challenge -> challenge + timestamp
2. Encrypt token z certyfikatem publicznym KSeF (AES + RSA)
3. POST /auth/ksef-token -> authenticationToken + referenceNumber
4. GET /auth/{referenceNumber} - poll az status.code == 200
5. POST /auth/token/redeem (Bearer authenticationToken) -> accessToken + refreshToken
6. POST /invoices/query -> lista faktur zakupowych
7. GET /invoices/{id} -> XML faktury
8. Upload XML do Google Drive folder Inbox
"""

import os
import json
import time
import base64
import secrets
import requests
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.x509 import load_pem_x509_certificate, load_der_x509_certificate
from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.http import MediaInMemoryUpload

# === KONFIGURACJA (ustaw przez env vars lub Secret Manager) ===
KSEF_NIP = os.environ.get('KSEF_NIP', '')
KSEF_TOKEN = os.environ.get('KSEF_TOKEN', '')
KSEF_TOKEN_KEY = os.environ.get('KSEF_TOKEN_KEY', '')
KSEF_ENV = os.environ.get('KSEF_ENV', 'prod')
DRIVE_INBOX_FOLDER_ID = os.environ.get('DRIVE_INBOX_FOLDER_ID', '')
DAYS_BACK = int(os.environ.get('DAYS_BACK', '1'))

SA_KEY_FILE = os.environ.get('SA_KEY_FILE', '/tmp/sa-key.json')
SA_EMAIL_IMPERSONATE = os.environ.get('SA_EMAIL_IMPERSONATE', '')

KSEF_BASE_URL = {
    'prod': 'https://api.ksef.mf.gov.pl/api/v2',
    'test': 'https://api-test.ksef.mf.gov.pl/api/v2'
}


class KSeFClient:
    """Klient KSeF 2.0 API"""

    def __init__(self):
        self.base_url = KSEF_BASE_URL[KSEF_ENV]
        self.access_token = None
        self.refresh_token = None
        self.reference_number = None
        self.session = requests.Session()
        self.session.headers.update({
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        })

    def get_challenge(self):
        url = f"{self.base_url}/auth/challenge"
        payload = {
            "contextIdentifier": {
                "type": "onip",
                "identifier": KSEF_NIP
            }
        }
        resp = self.session.post(url, json=payload)
        resp.raise_for_status()
        data = resp.json()
        print(f"Challenge received: {data.get('challenge', 'N/A')}")
        return data

    def get_public_key_cert(self):
        url = f"{self.base_url}/security/public-key-certificates"
        resp = self.session.get(url)
        resp.raise_for_status()
        certs = resp.json()

        for cert_info in certs:
            if 'SymmetricKeyEncryption' in cert_info.get('usage', []):
                cert_data = cert_info['certificate']
                if cert_data.startswith('-----'):
                    cert = load_pem_x509_certificate(cert_data.encode('utf-8'))
                else:
                    cert_bytes = base64.b64decode(cert_data)
                    try:
                        cert = load_der_x509_certificate(cert_bytes)
                    except Exception:
                        pem = f"-----BEGIN CERTIFICATE-----\n{cert_data}\n-----END CERTIFICATE-----"
                        cert = load_pem_x509_certificate(pem.encode('utf-8'))
                return cert.public_key()

        raise Exception("Nie znaleziono certyfikatu SymmetricKeyEncryption")

    def encrypt_token_v2(self, challenge_data):
        public_key = self.get_public_key_cert()

        timestamp = challenge_data.get('timestamp', '')
        plaintext = f"{KSEF_TOKEN}|{timestamp}".encode('utf-8')

        pad_len = 16 - (len(plaintext) % 16)
        plaintext_padded = plaintext + bytes([pad_len] * pad_len)

        aes_key = secrets.token_bytes(32)
        iv = secrets.token_bytes(16)
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        encrypted_token = encryptor.update(plaintext_padded) + encryptor.finalize()

        encrypted_key = public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        return {
            'encryptedToken': base64.b64encode(iv + encrypted_token).decode('utf-8'),
            'encryptedKey': base64.b64encode(encrypted_key).decode('utf-8')
        }

    def init_session(self):
        """Pelny flow autoryzacji KSeF 2.0"""
        # 1. Challenge
        challenge = self.get_challenge()

        # 2. Encrypt token
        encrypted = self.encrypt_token_v2(challenge)

        # 3. Submit ksef-token auth
        url = f"{self.base_url}/auth/ksef-token"
        payload = {
            "contextIdentifier": {
                "type": "Nip",
                "value": KSEF_NIP
            },
            "challenge": challenge.get('challenge', ''),
            "encryptedToken": encrypted['encryptedToken'],
            "encryptedKey": encrypted['encryptedKey']
        }

        resp = self.session.post(url, json=payload)
        if resp.status_code not in (200, 201, 202):
            print(f"Auth failed: {resp.status_code} {resp.text[:500]}")
            resp.raise_for_status()

        auth_result = resp.json()
        self.reference_number = auth_result.get('referenceNumber')
        auth_token_data = auth_result.get('authenticationToken', {})
        if isinstance(auth_token_data, dict):
            temp_token = auth_token_data.get('token', '')
        else:
            temp_token = str(auth_token_data)
        print(f"Auth referenceNumber: {self.reference_number}")
        print(f"Auth temp token obtained: {temp_token[:20]}...")

        # 4. Poll auth status until ready
        for attempt in range(30):
            status_url = f"{self.base_url}/auth/{self.reference_number}"
            status_resp = self.session.get(status_url, headers={
                'Authorization': f'Bearer {temp_token}',
                'Accept': 'application/json'
            })
            if status_resp.status_code == 200:
                status_data = status_resp.json()
                status_code = status_data.get('status', {}).get('code', 0)
                if status_code == 200:
                    print(f"Auth status: ready (attempt {attempt+1})")
                    break
                elif status_code >= 400:
                    raise Exception(f"Auth failed with code {status_code}: {status_data}")
            print(f"Auth polling attempt {attempt+1}, status: {status_resp.status_code}")
            time.sleep(2)
        else:
            raise Exception("Auth polling timeout (60s)")

        # 5. Redeem authenticationToken for accessToken
        redeem_url = f"{self.base_url}/auth/token/redeem"
        resp = self.session.post(redeem_url, json={}, headers={
            'Authorization': f'Bearer {temp_token}',
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        })
        if resp.status_code not in (200, 201):
            print(f"Token redeem failed: {resp.status_code} {resp.text[:500]}")
            resp.raise_for_status()

        token_result = resp.json()
        access = token_result.get('accessToken')
        refresh = token_result.get('refreshToken')
        self.access_token = access.get('token') if isinstance(access, dict) else access
        self.refresh_token = refresh.get('token') if isinstance(refresh, dict) else refresh
        self.session.headers['Authorization'] = f'Bearer {self.access_token}'
        print("Session initialized successfully (KSeF 2.0)")
        return self.access_token

    def query_invoices(self, date_from, date_to):
        url = f"{self.base_url}/invoices/query"
        payload = {
            "queryCriteria": {
                "subjectType": "subject2",
                "type": "incremental",
                "acquisitionTimestampThresholdFrom": f"{date_from}T00:00:00",
                "acquisitionTimestampThresholdTo": f"{date_to}T23:59:59"
            },
            "pageSize": 100,
            "pageOffset": 0
        }
        resp = self.session.post(url, json=payload)
        resp.raise_for_status()
        return resp.json()

    def get_invoice_xml(self, ksef_reference_number):
        url = f"{self.base_url}/invoices/{ksef_reference_number}"
        resp = self.session.get(url)
        resp.raise_for_status()
        return resp.text

    def terminate_session(self):
        if self.access_token:
            try:
                url = f"{self.base_url}/auth/sessions/current"
                self.session.delete(url)
            except Exception:
                pass


def get_drive_service():
    if os.path.exists(SA_KEY_FILE):
        creds = service_account.Credentials.from_service_account_file(
            SA_KEY_FILE,
            scopes=['https://www.googleapis.com/auth/drive']
        )
        if SA_EMAIL_IMPERSONATE:
            creds = creds.with_subject(SA_EMAIL_IMPERSONATE)
    else:
        import google.auth
        creds, _ = google.auth.default(scopes=['https://www.googleapis.com/auth/drive'])
    return build('drive', 'v3', credentials=creds)


def upload_to_drive(drive_service, filename, content, folder_id):
    file_metadata = {'name': filename, 'parents': [folder_id]}
    media = MediaInMemoryUpload(content.encode('utf-8'), mimetype='text/xml')
    file = drive_service.files().create(
        body=file_metadata, media_body=media, fields='id, name'
    ).execute()
    print(f"Uploaded: {filename} (ID: {file.get('id')})")
    return file.get('id')


def get_existing_files(drive_service, folder_id):
    results = drive_service.files().list(
        q=f"'{folder_id}' in parents and trashed=false",
        fields="files(name)"
    ).execute()
    return set(f['name'] for f in results.get('files', []))


def main(request=None):
    print(f"=== KSeF Import Start: {datetime.now().isoformat()} ===")
    print(f"NIP: {KSEF_NIP}, ENV: {KSEF_ENV}, DAYS_BACK: {DAYS_BACK}")

    if not KSEF_NIP or not KSEF_TOKEN:
        return json.dumps({'status': 'error', 'message': 'Missing KSEF_NIP or KSEF_TOKEN env vars'}), 500, {'Content-Type': 'application/json'}

    date_to = datetime.now().strftime('%Y-%m-%d')
    date_from = (datetime.now() - timedelta(days=DAYS_BACK)).strftime('%Y-%m-%d')

    ksef = KSeFClient()
    drive_service = get_drive_service()

    try:
        ksef.init_session()
        existing = get_existing_files(drive_service, DRIVE_INBOX_FOLDER_ID)

        result = ksef.query_invoices(date_from, date_to)
        invoices = result.get('invoiceHeaderList', result.get('invoices', []))
        print(f"Found {len(invoices)} invoices from {date_from} to {date_to}")

        new_count = 0
        skip_count = 0
        errors = []

        for inv in invoices:
            ref_num = inv.get('ksefReferenceNumber', inv.get('referenceNumber', 'unknown'))
            filename = f"KSeF_{ref_num}.xml"

            if filename in existing:
                skip_count += 1
                continue

            try:
                xml_content = ksef.get_invoice_xml(ref_num)
                upload_to_drive(drive_service, filename, xml_content, DRIVE_INBOX_FOLDER_ID)
                new_count += 1
            except Exception as e:
                errors.append(f"{ref_num}: {str(e)}")
                print(f"Error processing {ref_num}: {e}")

        summary = {
            'status': 'ok',
            'date_range': f"{date_from} - {date_to}",
            'total_found': len(invoices),
            'new_uploaded': new_count,
            'skipped': skip_count,
            'errors': errors[:5]
        }

        print(f"=== Summary: {json.dumps(summary)} ===")
        return json.dumps(summary), 200, {'Content-Type': 'application/json'}

    except Exception as e:
        error_msg = f"KSeF Error: {str(e)}"
        print(error_msg)
        return json.dumps({'status': 'error', 'message': error_msg}), 500, {'Content-Type': 'application/json'}

    finally:
        ksef.terminate_session()


def ksef_import(request):
    return main(request)


if __name__ == '__main__':
    result, status, _ = main()
    print(f"\nResult ({status}): {result}")
