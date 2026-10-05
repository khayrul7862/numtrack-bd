# NumTrack BD - Render deployment

1. Push this folder to GitHub.
2. In Render, create a Web Service from the repository.
3. Build command: `pip install -r requirements.txt`
4. Start command: `waitress-serve --host=0.0.0.0 --port=$PORT app:app`
5. Add environment variables: `SECRET_KEY`, `ADMIN_EMAIL`, `ADMIN_PASSWORD`, `ABSTRACT_API_KEY` (optional), and `DATABASE_URL`.

## Persistent database
When `DATABASE_URL` is set, NumTrack BD uses PostgreSQL. Without it, local SQLite is used for development.

Render currently offers Free Postgres, but its free database expires after 30 days. For a longer free testing setup, use a free external PostgreSQL provider such as Neon and paste its connection string into `DATABASE_URL`.
