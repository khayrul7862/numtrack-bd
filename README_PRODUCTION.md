# NumTrack BD — Production Setup

## 1. Environment
Copy `.env.example` to `.env` and set a strong `SECRET_KEY`, `ADMIN_PASSWORD`, and optionally `ABSTRACT_API_KEY`.

## 2. Run locally
`python -m venv .venv`
`source .venv/bin/activate`
`pip install -r requirements.txt`
`waitress-serve --host=0.0.0.0 --port=8000 app:app`

## 3. Live API
Set `ABSTRACT_API_KEY` to enable live phone validation/carrier/location/risk data. Without it, the app uses the local `phonenumbers` database and its own approved spam/scam reports.

## 4. HTTPS
Use your host's managed HTTPS or place Nginx/Caddy in front of Waitress. Never expose the development Flask server directly to the public internet.

## 5. Database
SQLite is suitable for a small deployment. For higher traffic, migrate to PostgreSQL before scaling horizontally.
