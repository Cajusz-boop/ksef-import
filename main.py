"""
KSeF 2.0 Cloud Function — automatyczne pobieranie faktur zakupowych
Deployowane na Google Cloud Functions, triggerowane przez Cloud Scheduler

API: KSeF 2.3.0+ (marzec 2026)
Base URL prod: https://api.ksef.mf.gov.pl/api/v2

Flow:
1. POST /auth/challenge → challenge + timestamp
2. Encrypt token RSA-OAEP SHA256
3. POST /auth/ksef-token → referenceNumber
4. Poll GET /auth/{ref} → status ready
5. POST /auth/token/redeem → accessToken
6. POST /invoices/query/metadata → lista faktur zakupowych
7. GET /invoices/ksef/{ksefNumber} → XML faktury
8. Upload XML do Google Drive + permission sharing
9. Apps Script importKsefXml() przetwarza XML do arkusza
"""

import os
import json
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
    def __init__(self):
        self.base_url = KSEF_BASE_URL[KSEF_ENV]
        self.access_token = None
        self.refresh_token = None
        self.reference_number = None
        self.session = requests.Session()
        self.session.headers.update({'Content-Type': 'application/json', 'Accept': 'application/json'})

    def get_challenge(self):
        resp = self.session.post(f"{self.base_url}/auth/challenge", json={
            "contextIdentifier": {"type": "onip", "identifier": KSEF_NIP}
        })
        resp.raise_for_status()
        data = resp.json()
        print(f"Challenge received: {data.get('challenge', 'N/A')}")
        return data

    def get_public_key_cert(self):
        resp = self.session.get(f"{self.base_url}/security/public-key-certificates")
        resp.raise_for_status()
        for cert_info in resp.json():
            if 'KsefTokenEncryption' in cert_info.get('usage', []):
                cert_data = cert_info['certificate']
                if cert_data.startswith('-----'):
                    return load_pem_x509_certificate(cert_data.encode()).public_key()
                cert_bytes = base64.b64decode(cert_data)
                try:
                    return load_der_x509_certificate(cert_bytes).public_key()
                except Exception:
                    pem = f"-----BEGIN CERTIFICATE-----\n{cert_data}\n-----END CERTIFICATE-----"
                    return load_pem_x509_certificate(pem.encode()).public_key()
        raise Exception("Nie znaleziono certyfikatu KsefTokenEncryption")

    def encrypt_token_v2(self, challenge_data):
        public_key = self.get_public_key_cert()
        timestamp_ms = challenge_data.get('timestampMs', 0)
        token_value = KSEF_TOKEN_KEY if KSEF_TOKEN_KEY else KSEF_TOKEN
        plaintext = f"{token_value}|{timestamp_ms}".encode('utf-8')
        encrypted = public_key.encrypt(plaintext, padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(), label=None
        ))
        return base64.b64encode(encrypted).decode('utf-8')

    def init_session(self):
        challenge = self.get_challenge()
        encrypted_token = self.encrypt_token_v2(challenge)

        resp = self.session.post(f"{self.base_url}/auth/ksef-token", json={
            "contextIdentifier": {"type": "Nip", "value": KSEF_NIP},
            "challenge": challenge.get('challenge', ''),
            "encryptedToken": encrypted_token
        })
        if resp.status_code not in (200, 201, 202):
            print(f"Auth failed: {resp.status_code} {resp.text[:500]}")
            resp.raise_for_status()

        auth_result = resp.json()
        self.reference_number = auth_result.get('referenceNumber')
        auth_token = auth_result.get('authenticationToken', {})
        temp_token = auth_token.get('token', '') if isinstance(auth_token, dict) else str(auth_token)
        print(f"Auth referenceNumber: {self.reference_number}")

        import time
        for attempt in range(30):
            status_resp = self.session.get(f"{self.base_url}/auth/{self.reference_number}",
                headers={'Authorization': f'Bearer {temp_token}', 'Accept': 'application/json'})
            if status_resp.status_code == 200:
                status_code = status_resp.json().get('status', {}).get('code', 0)
                if status_code == 200:
                    print(f"Auth status: ready (attempt {attempt+1})")
                    break
                elif status_code >= 400:
                    raise Exception(f"Auth failed with code {status_code}")
            time.sleep(2)
        else:
            raise Exception("Auth polling timeout (60s)")

        resp = self.session.post(f"{self.base_url}/auth/token/redeem", json={},
            headers={'Authorization': f'Bearer {temp_token}', 'Accept': 'application/json', 'Content-Type': 'application/json'})
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
        """KSeF 2.3.0+: POST /invoices/query/metadata"""
        url = f"{self.base_url}/invoices/query/metadata"
        payload = {
            "subjectType": "Subject2",
            "dateRange": {
                "dateType": "Issue",
                "from": f"{date_from}T00:00:00Z",
                "to": f"{date_to}T23:59:59Z"
            }
        }
        resp = self.session.post(url, json=payload, params={"pageSize": 100, "pageOffset": 0})
        if resp.status_code != 200:
            error_detail = resp.text[:1000]
            print(f"Query error {resp.status_code}: {error_detail}")
            raise Exception(f"Query {resp.status_code}: {error_detail}")
        return resp.json()

    def get_invoice_xml(self, ksef_number):
        """KSeF 2.3.0+: GET /invoices/ksef/{ksefNumber}"""
        resp = self.session.get(f"{self.base_url}/invoices/ksef/{ksef_number}")
        resp.raise_for_status()
        return resp.text

    def terminate_session(self):
        if self.access_token:
            try:
                self.session.delete(f"{self.base_url}/auth/sessions/current")
            except Exception:
                pass


def get_drive_service():
    if os.path.exists(SA_KEY_FILE):
        creds = service_account.Credentials.from_service_account_file(
            SA_KEY_FILE, scopes=['https://www.googleapis.com/auth/drive'])
        if SA_EMAIL_IMPERSONATE:
            creds = creds.with_subject(SA_EMAIL_IMPERSONATE)
    else:
        import google.auth
        creds, _ = google.auth.default(scopes=['https://www.googleapis.com/auth/drive'])
    return build('drive', 'v3', credentials=creds)


def upload_to_drive(drive_service, filename, content, folder_id):
    media = MediaInMemoryUpload(content.encode('utf-8'), mimetype='text/xml')
    file = drive_service.files().create(
        body={'name': filename, 'parents': [folder_id]},
        media_body=media, fields='id, name').execute()
    file_id = file.get('id')
    print(f"Uploaded: {filename} (ID: {file_id})")

    owner_email = SA_EMAIL_IMPERSONATE or 'lukasz.wojenkowski@labedzhotel.pl'
    try:
        drive_service.permissions().create(fileId=file_id,
            body={'type': 'user', 'role': 'writer', 'emailAddress': owner_email},
            sendNotificationEmail=False).execute()
    except Exception as e:
        print(f"Permission note (non-critical): {e}")
    return file_id


def get_existing_files(drive_service, folder_id):
    results = drive_service.files().list(
        q=f"'{folder_id}' in parents and trashed=false", fields="files(name)").execute()
    return set(f['name'] for f in results.get('files', []))


def main(request=None):
    print(f"=== KSeF Import Start: {datetime.now().isoformat()} ===")
    print(f"NIP: {KSEF_NIP}, ENV: {KSEF_ENV}, DAYS_BACK: {DAYS_BACK}")

    if not KSEF_NIP or not KSEF_TOKEN:
        return json.dumps({'status': 'error', 'message': 'Missing KSEF_NIP or KSEF_TOKEN'}), 500, {'Content-Type': 'application/json'}

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
        if invoices:
            print(f"First invoice keys: {list(invoices[0].keys())}")

        new_count, skip_count, errors = 0, 0, []
        for inv in invoices:
            ref_num = inv.get('ksefNumber', inv.get('ksefReferenceNumber', inv.get('referenceNumber', 'unknown')))
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

        summary = {'status': 'ok', 'date_range': f"{date_from} - {date_to}",
                   'total_found': len(invoices), 'new_uploaded': new_count,
                   'skipped': skip_count, 'errors': errors[:5]}
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
