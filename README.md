# Phishing-Intelligence-Automation-System
Developed and deployed a fully automated email-based phishing analysis pipeline, triggered by messages sent to phish@company.com. Engineered deep inspection of attachments using VirusTotal, Google Safe Browsing, SPF/DKIM validation, and hidden URL/image extraction, all containerized with Docker for 24/7 autonomous triage and threat scoring.

#### To Refresh with Changes
```bash
docker compose down
docker compose build --no-cache
docker compose up -d
docker logs -f growsafe-phish-analyzer
```

