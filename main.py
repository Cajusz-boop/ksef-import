"""
KSeF 2.0 Cloud Function — automatyczne pobieranie faktur zakupowych
Deployowane na Google Cloud Functions, triggerowane przez Cloud Scheduler

API: KSeF 2.0 (od 1 lutego 2026)
Base URL prod: https://api.ksef.mf.gov.pl/api/v2
Base URL test: https://api-test.ksef.mf.gov.pl/api/v2

Flow:
1. POST /auth/challenge → challenge + timestamp
2. Encrypt token z certyfikatem publicznym KSeF (AES + RSA)
3. POST /auth/ksef-token → referenceNumber
4. POST /auth/token/redeem → accessToken + refreshToken
5. POST /invoices/query → lista faktur zakupowych
6. GET /invoices/{id} → XML faktury
7. Upload XML do Google Drive folder Inbox
8. Apps Script w Sheets przetwarza XML automatycznie
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

# === KONFIGURACJA (ustaw przez env vars lub Secret Manager) ===
KSEF_NIP = os.environ.get('KSEF_NIP', '')
KSEF_TOKEN = os.environ.get('KSEF_TOKEN', '')
KSEF_TOKEN_KEY = os.environ.get('KSEF_TOKEN_KEY', '')
KSEF_ENV = os.environ.get('KSEF_ENV', 'prod')  # 'prod' lub 'test'
DRIVE_INBOX_FOLDER_ID = os.environ.get('DRIVE_INBOX_FOLDER_ID', '')
DAYS_BACK = int(os.environ.get('DAYS_BACK', '1'))  # ile dni wstecz szukac

# Google Service Account
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
        """Krok 1: Pobierz challenge autoryzacyjny"""
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
        """Pobierz certyfikat publiczny KSeF do szyfrowania"""
        url = f"{self.base_url}/security/public-key-certificates"
        resp = self.session.get(url)
        resp.raise_for_status()
        certs = resp.json()

        # Znajdz certyfikat do szyfrowania klucza symetrycznego
        for cert_info in certs:
            if 'KsefTokenEncryption' in cert_info.get('usage', []):
                cert_data = cert_info['certificate']
                # Sprobuj rozne formaty
                if cert_data.startswith('-----'):
                    # PEM format
                    cert = load_pem_x509_certificate(cert_data.encode('utf-8'))
                else:
                    # Base64-encoded DER
                    cert_bytes = base64.b64decode(cert_data)
                    try:
                        cert = load_der_x509_certificate(cert_bytes)
                    except Exception:
                        # Moze to PEM bez naglowkow
                        pem = f"-----BEGIN CERTIFICATE-----\n{cert_data}\n-----END CERTIFICATE-----"
                        cert = load_pem_x509_certificate(pem.encode('utf-8'))
                return cert.public_key()

        raise Exception("Nie znaleziono certyfikatu SymmetricKeyEncryption")

    def encrypt_token_v2(self, challenge_data):
        """
        KSeF 2.0: proste RSA-OAEP SHA256
        Payload: "token|timestampMs" zaszyfrowany bezposrednio RSA (bez AES!)
        """
        public_key = self.get_public_key_cert()

        # timestampMs (milisekundy!) - nie ISO timestamp
        timestamp_ms = challenge_data.get('timestampMs', 0)
        # Token KEY (hex value) gets encrypted, not the token identifier!
        token_value = KSEF_TOKEN_KEY if KSEF_TOKEN_KEY else KSEF_TOKEN
        plaintext = f"{token_value}|{timestamp_ms}".encode('utf-8')

        encrypted = public_key.encrypt(
            plaintext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        return base64.b64encode(encrypted).decode('utf-8')

    def init_session(self):
        """Krok 2-4: Autoryzacja tokenem KSeF 2.0"""
        # Krok 2: Challenge
        challenge = self.get_challenge()

        # Krok 3: Autoryzacja tokenem
        encrypted_token = self.encrypt_token_v2(challenge)

        url = f"{self.base_url}/auth/ksef-token"
        payload = {
            "contextIdentifier": {
                "type": "Nip",
                "value": KSEF_NIP
            },
            "challenge": challenge.get('challenge', ''),
            "encryptedToken": encrypted_token
        }

        resp = self.session.post(url, json=payload)
        if resp.status_code not in (200, 201, 202):
            print(f"Auth failed: {resp.status_code} {resp.text[:500]}")
            resp.raise_for_status()

        auth_result = resp.json()
        self.reference_number = auth_result.get('referenceNumber')
        auth_token = auth_result.get('authenticationToken', {})
        if isinstance(auth_token, dict):
            temp_token = auth_token.get('token', '')
        else:
            temp_token = str(auth_token)
        print(f"Auth referenceNumber: {self.reference_number}")

        # Krok 4: Poll auth status az bedzie gotowy
        import time
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
                    raise Exception(f"Auth failed with code {status_code}")
            time.sleep(2)
        else:
            raise Exception("Auth polling timeout (60s)")

        # Krok 5: Wymien authenticationToken na accessToken
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
        """Krok 5: Wyszukaj faktury zakupowe"""
        url = f"{self.base_url}/invoices/query"
        payload = {
            "queryCriteria": {
                "subjectType": "subject2",  # nabywca = my
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
        """Krok 6: Pobierz XML konkretnej faktury"""
        url = f"{self.base_url}/invoices/{ksef_reference_number}"
        resp = self.session.get(url)
        resp.raise_for_status()
        return resp.text

    def terminate_session(self):
        """Zamknij sesje (invalidate tokens)"""
        if self.access_token:
            try:
                url = f"{self.base_url}/auth/sessions/current"
                self.session.delete(url)
            except Exception:
                pass


def get_drive_service():
    """Inicjalizacja Google Drive API z Service Account"""
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
    """Upload XML do folderu Inbox na Drive + udostepnij wlascicielowi"""
    file_metadata = {
        'name': filename,
        'parents': [folder_id]
    }
    media = MediaInMemoryUpload(
        content.encode('utf-8'),
        mimetype='text/xml'
    )
    file = drive_service.files().create(
        body=file_metadata,
        media_body=media,
        fields='id, name'
    ).execute()

    file_id = file.get('id')
    print(f"Uploaded: {filename} (ID: {file_id})")

    # Udostepnij plik wlascicielowi konta (na wypadek gdyby DWD nie dzialalo)
    owner_email = SA_EMAIL_IMPERSONATE or 'lukasz.wojenkowski@labedzhotel.pl'
    try:
        drive_service.permissions().create(
            fileId=file_id,
            body={
                'type': 'user',
                'role': 'writer',
                'emailAddress': owner_email
            },
            sendNotificationEmail=False
        ).execute()
    except Exception as e:
        # Jezeli DWD dziala, to user juz jest ownerem — permission zglosi blad i to OK
        print(f"Permission note (non-critical): {e}")

    return file_id


def get_existing_files(drive_service, folder_id):
    """Pobierz liste istniejacych plikow w folderze (zeby nie duplikowac)"""
    results = drive_service.files().list(
        q=f"'{folder_id}' in parents and trashed=false",
        fields="files(name)"
    ).execute()
    return set(f['name'] for f in results.get('files', []))


def main(request=None):
    """
    Glowna funkcja - wywolywana przez Cloud Scheduler lub HTTP trigger
    """
    print(f"=== KSeF Import Start: {datetime.now().isoformat()} ===")
    print(f"NIP: {KSEF_NIP}, ENV: {KSEF_ENV}, DAYS_BACK: {DAYS_BACK}")

    if not KSEF_NIP or not KSEF_TOKEN:
        return json.dumps({'status': 'error', 'message': 'Missing KSEF_NIP or KSEF_TOKEN env vars'}), 500, {'Content-Type': 'application/json'}

    date_to = datetime.now().strftime('%Y-%m-%d')
    date_from = (datetime.now() - timedelta(days=DAYS_BACK)).strftime('%Y-%m-%d')

    ksef = KSeFClient()
    drive_service = get_drive_service()

    try:
        # Autoryzacja
        ksef.init_session()

        # Pobierz istniejace pliki (unikaj duplikatow)
        existing = get_existing_files(drive_service, DRIVE_INBOX_FOLDER_ID)

        # Query faktur
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
    """Entry point dla Google Cloud Function"""
    return main(request)


if __name__ == '__main__':
    result, status, _ = main()
    print(f"\nResult ({status}): {result}")
