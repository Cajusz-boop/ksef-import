"""
KSeF 2.0 Cloud Function — automatyczne pobieranie faktur zakupowych
Deployowane na Google Cloud Functions, triggerowane przez Cloud Scheduler

Flow:
1. Autoryzacja z KSeF API (token + RSA)
2. Query faktur zakupowych (nabywca = NIP karczmy)
3. Download XML per faktura
4. Upload do Google Drive folder Inbox
5. Apps Script w Sheets przetwarza XML automatycznie (trigger lub ręcznie)
"""

import os
import json
import base64
import hashlib
import requests
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
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
SA_EMAIL_IMPERSONATE = os.environ.get('SA_EMAIL_IMPERSONATE', '')  # email do DWD

KSEF_BASE_URL = {
    'prod': 'https://api.ksef.mf.gov.pl/api',
    'test': 'https://api-test.ksef.mf.gov.pl/api'
}

# KSeF public key URL (do szyfrowania tokena)
KSEF_PUBLIC_KEY_URL = {
    'prod': 'https://api.ksef.mf.gov.pl/api/online/Session/AuthorisationChallenge/PublicKey',
    'test': 'https://api-test.ksef.mf.gov.pl/api/online/Session/AuthorisationChallenge/PublicKey'
}


class KSeFClient:
    """Klient KSeF 2.0 API"""

    def __init__(self):
        self.base_url = KSEF_BASE_URL[KSEF_ENV]
        self.session_token = None
        self.session = requests.Session()
        self.session.headers.update({
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        })

    def get_challenge(self):
        """Krok 1: Pobierz challenge autoryzacyjny"""
        url = f"{self.base_url}/online/Session/AuthorisationChallenge"
        payload = {
            "contextIdentifier": {
                "type": "onip",
                "identifier": KSEF_NIP
            }
        }
        resp = self.session.post(url, json=payload)
        resp.raise_for_status()
        return resp.json()

    def encrypt_token(self, challenge_data):
        """Szyfruje token kluczem publicznym KSeF (RSA)"""
        # Pobierz klucz publiczny KSeF
        pub_key_url = KSEF_PUBLIC_KEY_URL[KSEF_ENV]
        resp = self.session.get(pub_key_url)
        resp.raise_for_status()
        public_key_pem = resp.content

        public_key = serialization.load_pem_public_key(public_key_pem)

        # Przygotuj dane do zaszyfrowania: token|timestamp
        timestamp = challenge_data.get('timestamp', '')
        token_to_encrypt = f"{KSEF_TOKEN}|{timestamp}"

        # Szyfruj RSA OAEP
        encrypted = public_key.encrypt(
            token_to_encrypt.encode('utf-8'),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        return base64.b64encode(encrypted).decode('utf-8')

    def init_session(self):
        """Krok 2: Inicjuj sesje z zaszyfrowanym tokenem"""
        challenge = self.get_challenge()
        print(f"Challenge received: {challenge.get('challenge', 'N/A')}")

        encrypted_token = self.encrypt_token(challenge)

        url = f"{self.base_url}/online/Session/InitToken"
        payload = {
            "context": {
                "contextIdentifier": {
                    "type": "onip",
                    "identifier": KSEF_NIP
                }
            },
            "init": {
                "identifier": {
                    "type": "onip",
                    "identifier": KSEF_NIP
                },
                "type": "token",
                "token": encrypted_token
            }
        }

        resp = self.session.post(url, json=payload)
        if resp.status_code not in (200, 201):
            print(f"InitSession failed: {resp.status_code} {resp.text[:500]}")
            resp.raise_for_status()

        result = resp.json()
        self.session_token = result['sessionToken']['token']
        self.session.headers['SessionToken'] = self.session_token
        print(f"Session initialized successfully")
        return self.session_token

    def query_invoices(self, date_from, date_to):
        """Krok 3: Wyszukaj faktury zakupowe"""
        url = f"{self.base_url}/online/Query/Invoice/Sync"
        payload = {
            "queryCriteria": {
                "subjectType": "subject2",  # nabywca = my
                "type": "incremental",
                "acquisitionTimestampThresholdFrom": f"{date_from}T00:00:00",
                "acquisitionTimestampThresholdTo": f"{date_to}T23:59:59"
            }
        }
        params = {"PageSize": 100, "PageOffset": 0}

        resp = self.session.post(url, json=payload, params=params)
        resp.raise_for_status()
        return resp.json()

    def get_invoice_xml(self, ksef_reference_number):
        """Krok 4: Pobierz XML konkretnej faktury"""
        url = f"{self.base_url}/online/Invoice/Get/{ksef_reference_number}"
        resp = self.session.get(url)
        resp.raise_for_status()
        return resp.text

    def terminate_session(self):
        """Zamknij sesje"""
        if self.session_token:
            try:
                url = f"{self.base_url}/online/Session/Terminate"
                self.session.get(url)
            except:
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
        # Fallback: default credentials (Cloud Function)
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
    """Pobierz listę istniejących plików w folderze (żeby nie duplikować)"""
    results = drive_service.files().list(
        q=f"'{folder_id}' in parents and trashed=false",
        fields="files(name)"
    ).execute()
    return set(f['name'] for f in results.get('files', []))


def main(request=None):
    """
    Główna funkcja - wywoływana przez Cloud Scheduler lub HTTP trigger
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

        # Pobierz istniejące pliki (unikaj duplikatów)
        existing = get_existing_files(drive_service, DRIVE_INBOX_FOLDER_ID)

        # Query faktur
        result = ksef.query_invoices(date_from, date_to)
        invoices = result.get('invoiceHeaderList', [])
        print(f"Found {len(invoices)} invoices from {date_from} to {date_to}")

        new_count = 0
        skip_count = 0
        errors = []

        for inv in invoices:
            ref_num = inv.get('ksefReferenceNumber', 'unknown')
            filename = f"KSeF_{ref_num}.xml"

            # Sprawdź czy już istnieje
            if filename in existing:
                skip_count += 1
                continue

            try:
                # Pobierz XML
                xml_content = ksef.get_invoice_xml(ref_num)

                # Upload do Drive Inbox
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


# Dla Cloud Functions
def ksef_import(request):
    """Entry point dla Google Cloud Function"""
    return main(request)


# Dla lokalnego testowania
if __name__ == '__main__':
    result, status, _ = main()
    print(f"\nResult ({status}): {result}")
