#!/bin/bash
# Deploy KSeF Cloud Function + Scheduler
# Projekt: labedz-system-pms
# Region: europe-central2 (Warszawa)

PROJECT_ID="labedz-system-pms"
REGION="europe-central2"

# 1. Deploy Cloud Function (gen2 = Cloud Run based)
gcloud functions deploy ksef-import \
  --gen2 \
  --runtime python312 \
  --region $REGION \
  --source . \
  --entry-point ksef_import \
  --trigger-http \
  --allow-unauthenticated \
  --timeout 300 \
  --memory 256MB \
  --set-env-vars "KSEF_NIP=5711640854,KSEF_ENV=prod,DAYS_BACK=1,DRIVE_INBOX_FOLDER_ID=1ro9hZ7wQtFwJZAAPCzUYntNgVqMqLBpA"
  # UWAGA: KSEF_TOKEN i KSEF_TOKEN_KEY ustaw przez Secret Manager!
  # gcloud functions deploy ... --set-secrets "KSEF_TOKEN=ksef-token:latest,KSEF_TOKEN_KEY=ksef-token-key:latest"

# 2. Cloud Scheduler - codziennie o 6:00 rano
gcloud scheduler jobs create http ksef-daily-import \
  --location $REGION \
  --schedule "0 6 * * *" \
  --uri "https://$REGION-$PROJECT_ID.cloudfunctions.net/ksef-import" \
  --http-method GET \
  --time-zone "Europe/Warsaw" \
  --description "Codzienne pobieranie faktur z KSeF"

echo "Deploy zakonczony!"
echo "Function URL: https://$REGION-$PROJECT_ID.cloudfunctions.net/ksef-import"
echo "Scheduler: codziennie o 6:00"
