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
from cryptography.x509 import load_pem_x509_certificate
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
            if 'SymmetricKeyEncryption' in cert_info.get('usage', []):
                cert_pem = cert_info['certificate']
                # Dekoduj Base64 -> PEM
                if not cert_pem.startswith('-----'):
                    cert_bytes = base64.b64decode(cert_pem)
                else:
                    cert_bytes = cert_pem.encode('utf-8')
                cert = load_pem_x509_certificate(cert_bytes)
                return cert.public_key()

        raise Exception("Nie znaleziono certyfikatu SymmetricKeyEncryption")

    def encrypt_token_v2(self, challenge_data):
        """
        Szyfrowanie tokenu w KSeF 2.0:
        1. Generuj losowy klucz AES-256 (32 bajty)
        2. Zaszyfruj token kluczem AES (AES-CBC)
        3. Zaszyfruj klucz AES certyfikatem publicznym KSeF (RSA OAEP)
        4. Zwroc oba jako Base64
        """
        public_key = self.get_public_key_cert()

        # Dane do zaszyfrowania: token|timestamp
        timestamp = challenge_data.get('timestamp', '')
        plaintext = f"{KSEF_TOKEN}|{timestamp}".encode('utf-8')

        # Pad do wielokrotnosci 16 (PKCS7)
        pad_len = 16 - (len(plaintext) % 16)
        plaintext_padded = plaintext + bytes([pad_len] * pad_len)

        # AES-256-CBC
        aes_key = secrets.token_bytes(32)
        iv = secrets.token_bytes(16)
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        encrypted_token = encryptor.update(plaintext_padded) + encryptor.finalize()

        # RSA OAEP - szyfruj klucz AES
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
        """Krok 2-4: Autoryzacja tokenem KSeF 2.0"""
        # Krok 2: Challenge
        challenge = self.get_challenge()

        # Krok 3: Autoryzacja tokenem
        encrypted = self.encrypt_token_v2(challenge)

        url = f"{self.base_url}/auth/ksef-token"
        payload = {
            "contextIdentifier": {
                "type": "onip",
                "identifier": KSEF_NIP
            },
            "encryptedToken": encrypted['encryptedToken'],
            "encryptedKey": encrypted['encryptedKey']
        }

        resp = self.session.post(url, json=payload)
        if resp.status_code not in (200, 201, 202):
            print(f"Auth failed: {resp.status_code} {resp.text[:500]}")
            resp.raise_for_status()

        auth_result = resp.json()
        self.reference_number = auth_result.get('referenceNumber')
        print(f"Auth referenceNumber: {self.reference_number}")

        # Krok 4: Wymien na accessToken
        redeem_url = f"{self.base_url}/auth/token/redeem"
        redeem_payload = {
            "referenceNumber": self.reference_number
        }

        resp = self.session.post(redeem_url, json=redeem_payload)
        if resp.status_code not in (200, 201):
            print(f"Token redeem failed: {resp.status_code} {resp.text[:500]}")
            resp.raise_for_status()

        token_result = resp.json()
        self.access_token = token_result.get('accessToken')
        self.refresh_token = token_result.get('refreshToken')
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
    """Upload XML do folderu Inbox na Drive"""
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

    print(f"Uploaded: {filename} (ID: {file.get('id')})")
    return file.get('id')


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
