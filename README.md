# KSeF Import

Cloud Function do automatycznego pobierania faktur zakupowych z KSeF (Krajowy System e-Faktur) i uploadu do Google Drive.

## Wymagane env vars

| Zmienna | Opis |
|---------|------|
| `KSEF_NIP` | NIP firmy |
| `KSEF_TOKEN` | Token autoryzacyjny KSeF |
| `KSEF_TOKEN_KEY` | Klucz tokena KSeF |
| `KSEF_ENV` | `prod` lub `test` |
| `DRIVE_INBOX_FOLDER_ID` | ID folderu Inbox na Google Drive |
| `DAYS_BACK` | Ile dni wstecz szukac faktur (default: 1) |

## Deploy

```bash
chmod +x deploy.sh
./deploy.sh
```

Tokeny KSeF ustaw przez Secret Manager (nie env vars).
