"""
KSeF 2.0 Cloud Function - automatyczne pobieranie faktur zakupowych

Flow:
1. POST /auth/challenge -> challenge + timestampMs
2. RSA-OAEP SHA256 encrypt "token|timestampMs" with KsefTokenEncryption cert
3. POST /auth/ksef-token -> authenticationToken + referenceNumber
4. GET /auth/{referenceNumber} - poll az status.code == 200
5. POST /auth/token/redeem (Bearer authenticationToken) -> accessToken
6. POST /invoices/query -> lista faktur
7. GET /invoices/{id} -> XML
8. Upload XML do Google Drive
"""

import os
import json
import time
import base64
import requests
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509 import load_pem_x509_certificate, load_der_x509_certificate
from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.http import MediaInMemoryUpload

KSEF_NIP = os.environ.get('KSEF_NIP', '')
KSEF_TOKEN = os.environ.get('KSEF_TOKEN', '')
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
        self.session = requests.Session()
        self.session.headers.update({
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        })

    def get_challenge(self):
        url = f"{self.base_url}/auth/challenge"
        resp = self.session.post(url, json={
            "contextIdentifier": {"type": "onip", "identifier": KSEF_NIP}
        })
        resp.raise_for_status()
        data = resp.json()
        print(f"Challenge: {data.get('challenge', 'N/A')}, timestampMs: {data.get('timestampMs')}")
        return data

    def get_public_key_cert(self):
        """Get KsefTokenEncryption certificate (NOT SymmetricKeyEncryption!)"""
        url = f"{self.base_url}/security/public-key-certificates"
        resp = self.session.get(url)
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
        raise Exception("No KsefTokenEncryption cert found")

    def encrypt_token(self, challenge_data):
        """RSA-OAEP SHA256: encrypt 'token|timestampMs' directly"""
        public_key = self.get_public_key_cert()
        timestamp_ms = challenge_data.get('timestampMs', 0)
        plaintext = f"{KSEF_TOKEN}|{timestamp_ms}".encode('utf-8')
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
        # 1. Challenge
        challenge = self.get_challenge()

        # 2. Encrypt token
        encrypted_token = self.encrypt_token(challenge)

        # 3. Submit auth
        resp = self.session.post(f"{self.base_url}/auth/ksef-token", json={
            "contextIdentifier": {"type": "Nip", "value": KSEF_NIP},
            "challenge": challenge['challenge'],
            "encryptedToken": encrypted_token
        })
        if resp.status_code not in (200, 201, 202):
            print(f"Auth failed: {resp.status_code} {resp.text[:500]}")
            resp.raise_for_status()

        auth_result = resp.json()
        ref_num = auth_result['referenceNumber']
        auth_token = auth_result.get('authenticationToken', {})
        temp_token = auth_token.get('token', '') if isinstance(auth_token, dict) else str(auth_token)
        print(f"Auth OK, ref: {ref_num}")

        # 4. Poll status
        for attempt in range(30):
            sr = self.session.get(
                f"{self.base_url}/auth/{ref_num}",
                headers={'Authorization': f'Bearer {temp_token}'}
            )
            if sr.status_code == 200:
                sd = sr.json()
                code = sd.get('status', {}).get('code', 0)
                if code == 200:
                    print(f"Auth ready (attempt {attempt+1})")
                    break
                if code >= 400:
                    raise Exception(f"Auth failed: {sd}")
            time.sleep(2)
        else:
            raise Exception("Auth timeout")

        # 5. Redeem token
        resp = self.session.post(
            f"{self.base_url}/auth/token/redeem",
            json={},
            headers={'Authorization': f'Bearer {temp_token}'}
        )
        if resp.status_code not in (200, 201):
            print(f"Redeem failed: {resp.status_code} {resp.text[:500]}")
            resp.raise_for_status()

        tr = resp.json()
        access = tr.get('accessToken')
        self.access_token = access.get('token') if isinstance(access, dict) else access
        self.session.headers['Authorization'] = f'Bearer {self.access_token}'
        print("KSeF 2.0 session OK")
        return self.access_token

    def query_invoices(self, date_from, date_to):
        resp = self.session.post(f"{self.base_url}/invoices/query", json={
            "queryCriteria": {
                "subjectType": "subject2",
                "type": "incremental",
                "acquisitionTimestampThresholdFrom": f"{date_from}T00:00:00",
                "acquisitionTimestampThresholdTo": f"{date_to}T23:59:59"
            },
            "pageSize": 100, "pageOffset": 0
        })
        resp.raise_for_status()
        return resp.json()

    def get_invoice_xml(self, ref):
        resp = self.session.get(f"{self.base_url}/invoices/{ref}")
        resp.raise_for_status()
        return resp.text

    def terminate(self):
        if self.access_token:
            try:
                self.session.delete(f"{self.base_url}/auth/sessions/current")
            except Exception:
                pass


def get_drive_service():
    if os.path.exists(SA_KEY_FILE):
        creds = service_account.Credentials.from_service_account_file(
            SA_KEY_FILE, scopes=['https://www.googleapis.com/auth/drive']
        )
        if SA_EMAIL_IMPERSONATE:
            creds = creds.with_subject(SA_EMAIL_IMPERSONATE)
    else:
        import google.auth
        creds, _ = google.auth.default(scopes=['https://www.googleapis.com/auth/drive'])
    return build('drive', 'v3', credentials=creds)


def main(request=None):
    print(f"=== KSeF Import {datetime.now().isoformat()} ===")
    if not KSEF_NIP or not KSEF_TOKEN:
        return json.dumps({'status': 'error', 'message': 'Missing env vars'}), 500, {'Content-Type': 'application/json'}

    date_to = datetime.now().strftime('%Y-%m-%d')
    date_from = (datetime.now() - timedelta(days=DAYS_BACK)).strftime('%Y-%m-%d')

    ksef = KSeFClient()
    drive = get_drive_service()

    try:
        ksef.init_session()

        existing = set()
        try:
            r = drive.files().list(
                q=f"'{DRIVE_INBOX_FOLDER_ID}' in parents and trashed=false",
                fields="files(name)"
            ).execute()
            existing = set(f['name'] for f in r.get('files', []))
        except Exception as e:
            print(f"Drive list warning: {e}")

        result = ksef.query_invoices(date_from, date_to)
        invoices = result.get('invoiceHeaderList', result.get('invoices', []))
        print(f"Found {len(invoices)} invoices")

        new_count, skip_count, errors = 0, 0, []
        for inv in invoices:
            ref = inv.get('ksefReferenceNumber', inv.get('referenceNumber', 'unknown'))
            fn = f"KSeF_{ref}.xml"
            if fn in existing:
                skip_count += 1
                continue
            try:
                xml = ksef.get_invoice_xml(ref)
                media = MediaInMemoryUpload(xml.encode(), mimetype='text/xml')
                drive.files().create(
                    body={'name': fn, 'parents': [DRIVE_INBOX_FOLDER_ID]},
                    media_body=media, fields='id'
                ).execute()
                new_count += 1
                print(f"Uploaded: {fn}")
            except Exception as e:
                errors.append(f"{ref}: {e}")

        summary = {'status': 'ok', 'range': f"{date_from} - {date_to}",
                    'found': len(invoices), 'new': new_count, 'skip': skip_count, 'errors': errors[:5]}
        print(f"Summary: {json.dumps(summary)}")
        return json.dumps(summary), 200, {'Content-Type': 'application/json'}
    except Exception as e:
        msg = f"KSeF Error: {e}"
        print(msg)
        return json.dumps({'status': 'error', 'message': msg}), 500, {'Content-Type': 'application/json'}
    finally:
        ksef.terminate()


def ksef_import(request):
    return main(request)

if __name__ == '__main__':
    r, s, _ = main()
    print(f"Result ({s}): {r}")
