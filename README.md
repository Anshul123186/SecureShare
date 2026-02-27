# SecureShare – Secure File Sharing Platform

SecureShare is a Flask-based web application for securely uploading, encrypting, sharing, and auditing access to sensitive files.

## Features

- **User authentication** with hashed passwords and Flask-Login
- **AES-256 encryption at rest** for all stored files
- **Controlled sharing** with token-based links, expiry, and download limits
- **Audit logging** of logins, uploads, downloads, and admin views
- **Admin dashboard** for users and audit logs
- **CSRF protection** and **rate limiting** on sensitive endpoints

## Getting Started

### 1. Create and activate a virtual environment

```bash
cd "c:\\Users\\Anshu\\Downloads\\Python project"
python -m venv venv
venv\Scripts\activate
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Configure environment (optional but recommended)

Create a `.env` file or set environment variables:

- `SECURESHARE_SECRET_KEY` – random secret string for Flask sessions.
- `SECURESHARE_FILE_KEY` – 64‑character hex string (32 bytes) for AES‑256 file encryption.
- `SECURESHARE_DATABASE_URI` – SQLAlchemy DB URI (defaults to `sqlite:///secureshare.db`).
- `SECURESHARE_STORAGE_DIR` – directory for encrypted file storage (defaults to `storage`).

### 4. Run the app

```bash
python app.py
```

Open `http://127.0.0.1:5000` in your browser.

## Usage

- **Register** a new account and login.
- **Upload** files from the dashboard – they are encrypted before touching disk.
- **Download** files – they are decrypted on-the-fly after access checks.
- **Share** a file to create a secure token link with optional expiry and max downloads.
- **Admin**: mark a user as admin manually in the DB to access `/admin/dashboard` and view system-wide audit logs.

## Production deployment (example with Waitress)

For production, use a real WSGI server instead of `python app.py`. This project includes **waitress**, which works well on Windows and Linux.

1. Ensure your environment variables (or `.env`) are set with strong secrets and `FLASK_ENV=production`.
2. Install dependencies in your server environment:

```bash
pip install -r requirements.txt
```

3. Run the app via Waitress:

```bash
waitress-serve --call "app:create_app"
```

This will start SecureShare on port 8080 by default. You can then put it behind a reverse proxy (e.g., Nginx, Apache, or a cloud load balancer) with HTTPS enabled for a production-ready deployment.

