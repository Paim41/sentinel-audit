# Sentinel Audit

Sentinel Audit is a Python and Flask web application for authorised educational web security auditing. It performs limited, non-destructive configuration checks against a single submitted page and presents results in a polished charcoal, lime, and soft-gray dashboard.

Sentinel Audit performs limited, non-destructive configuration checks. It is not a replacement for a professional penetration test, compliance audit, or manual security assessment.

## Features

- User registration, login, logout, password hashing, CSRF protection, and protected routes.
- Safe URL validation with SSRF protections, redirect revalidation, request timeouts, response-size limits, and optional domain allowlist.
- Checks for HTTPS usage, HTTP-to-HTTPS redirects, TLS certificate validity and expiry, security headers, cookie attributes, forms, possible missing CSRF tokens, information disclosure headers, mixed-content references, safe public paths, and basic configuration weaknesses.
- SQLite storage for scans, findings, and scan metrics.
- Educational 0-100 security score, risk level, scan comparison, printable HTML reports, and ReportLab PDF downloads.
- Dashboard statistics, recent-scan charts, risk distribution charts, history filters, and responsive mobile layout.

## Technology Stack

Backend: Python 3.11+, Flask, Flask-SQLAlchemy, Flask-Login, Flask-WTF, WTForms, Requests, BeautifulSoup4, ReportLab, Werkzeug, ssl, socket, ipaddress, urllib.parse, datetime.

Frontend: HTML5, CSS3, vanilla JavaScript, Jinja2 templates, Chart.js, and inline SVG icons only.

## Screenshot Placeholders

- Dashboard: add a screenshot after running a few demo scans.
- New Scan: add a screenshot of the authorised scan form.
- Results: add a screenshot of the score circle and findings filters.

## Project Structure

```text
sentinel-audit/
├── run.py
├── config.py
├── requirements.txt
├── .env.example
├── app/
│   ├── auth/
│   ├── dashboard/
│   ├── reports/
│   ├── scans/
│   ├── scanners/
│   ├── static/
│   └── templates/
├── instance/
├── reports/
└── tests/
```

## Installation on Windows

```powershell
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env
python run.py
```

## Installation on macOS and Linux

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
python run.py
```

Open the application at:

```text
http://127.0.0.1:5000
```

The SQLite database is created automatically on first startup. You can add demonstration scan history with:

```bash
flask --app run.py seed-demo
```

Demo account after seeding:

```text
Email: demo@sentinel.local
Password: ChangeMe12345
```

## Environment Configuration

Copy `.env.example` to `.env` and update `SECRET_KEY`. Important settings:

- `ALLOW_LOCAL_TARGETS=true` allows localhost and private IP targets for isolated educational laboratories.
- `ALLOW_LOCAL_TARGETS=false` blocks localhost, private, link-local, multicast, reserved, unspecified, and cloud metadata addresses.
- `ALLOWED_DOMAINS=` can contain comma-separated domains. When set, only those domains and their subdomains may be scanned.
- `MAX_REDIRECTS=3` limits redirect following and every redirect destination is revalidated.
- `MAX_RESPONSE_BYTES=2097152` prevents large downloads.

## Running Tests

```bash
pytest
```

## Safe Testing Targets

Use Sentinel Audit only against:

- Websites you own.
- Local development websites.
- Deliberately vulnerable training applications.
- Isolated laboratory systems.
- Systems with written testing permission.

## Security Limitations

Sentinel Audit does not perform exploitation, payload injection, authentication bypass, password attacks, credential testing, brute-force attempts, port scanning, network discovery, directory brute-forcing, custom wordlists, data exfiltration, command execution, malware behavior, destructive requests, or denial-of-service activity.

The score is a transparent educational assessment, not an official certification or proof of compliance.

## Troubleshooting

- If a local target is blocked, set `ALLOW_LOCAL_TARGETS=true` in `.env` for lab-only use.
- If scans fail with DNS errors, verify the hostname resolves from your machine.
- If PDF downloads fail, confirm the `reports/` directory is writable.
- If Chart.js does not load, confirm the machine can reach `cdn.jsdelivr.net`.
- If registration email validation fails, reinstall dependencies with `pip install -r requirements.txt`.
