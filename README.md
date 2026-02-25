# IT Services Website + Headless Backend

A professional IT Services website with a Flask backend and optional admin panel. Powered by Python Flask + SQLite/PostgreSQL.

## What It Does

- **Public Website**: Professional IT services company site with Home, About, Services, Blog, and Contact pages
- **Optional Admin Panel**: Built-in dashboard at `/admin` (can be ignored if you use a headless CMS)
- **Headless Sync API**: Push/pull content from external headless CMS platforms (WordPress, Strapi, Directus, Contentful, etc.)
- **Content Types**: Services, Team Members, Blog Posts, Testimonials, Media Library, Contact Submissions, Site Settings

## Quick Start (Local Development)

```bash
cd app
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python run.py
```

The site will be available at `http://127.0.0.1:5000`.

### Admin Credentials
- **URL**: `http://127.0.0.1:5000/admin/login`
- **Username**: `admin`
- **Password**:
  - If `app/site.db` already exists, use your existing password.
  - On first boot of a fresh database, the app generates a strong random password and prints it in the startup logs.
  - You can set `ADMIN_PASSWORD` before first boot to use a custom initial password.

### Running Tests

```bash
cd app
source venv/bin/activate
pip install -r requirements-dev.txt
python -m pytest -q
```

## Managing Content

**Services**: Add, edit, and reorder IT services displayed on the website. Mark services as "Featured" to show them on the homepage.

**Team Members**: Manage your team with photos, bios, positions, and LinkedIn profiles.

**Blog Posts**: Create and publish blog posts with a rich text editor (TinyMCE). Organize posts into categories.

**Testimonials**: Add client reviews with ratings. Featured testimonials appear on the homepage.

**Media Library**: Upload and manage images used throughout the site.

**Site Settings**: Customize company name, tagline, contact info, social media links, and SEO metadata.

**Contact Submissions**: View messages submitted through the public contact form.

**Security Events**: Review Turnstile verification failures and rate-limited form attempts from the admin panel (`/admin/security-events`).

## API Documentation

### Headless CMS Sync API

Use these endpoints to keep the current frontend templates while managing content in an external headless CMS.

- `GET /api/headless/export`
  - Auth: `Authorization: Bearer <HEADLESS_SYNC_TOKEN>` or `X-Headless-Token: <HEADLESS_SYNC_TOKEN>`
  - Returns current content payload (`site_settings`, `content_blocks`, `services`, `industries`, `posts`)
  - Query: `?include_drafts=1` to include draft content
- `POST /api/headless/sync`
  - Auth: same token header
  - Accepts upsert payload keys: `site_settings`, `content_blocks`, `services`, `industries`, `posts`
  - Optional: `dry_run: true` to validate payload without committing database changes

Example:

```bash
SYNC_TOKEN="change-me"

# Export published content
curl -s https://www.righttechexperts.com/api/headless/export \
  -H "Authorization: Bearer $SYNC_TOKEN"

# Sync content from external CMS
curl -s -X POST https://www.righttechexperts.com/api/headless/sync \
  -H "Authorization: Bearer $SYNC_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "site_settings": {"company_phone": "+1 (555) 123-4567"},
    "services": [
      {
        "slug": "managed-it-services",
        "title": "Managed IT Services",
        "description": "24/7 monitoring, helpdesk, patching, and reporting.",
        "workflow_status": "published"
      }
    ]
  }'
```

### JavaScript (Fetch)

```javascript
// Read CSRF token from a page first
const html = await (await fetch('http://127.0.0.1:5000/contact')).text();
const doc = new DOMParser().parseFromString(html, 'text/html');
const csrf = doc.querySelector('input[name="_csrf_token"]').value;

// Submit a contact form
const response = await fetch('http://127.0.0.1:5000/contact', {
  method: 'POST',
  credentials: 'include',
  headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  body: new URLSearchParams({
    _csrf_token: csrf,
    name: 'John Doe',
    email: 'john@example.com',
    phone: '555-0123',
    subject: 'Project Inquiry',
    message: 'I need help with cloud migration.'
  })
});

// Get blog posts
const response = await fetch('http://127.0.0.1:5000/blog');

// Get blog posts by category
const response = await fetch('http://127.0.0.1:5000/blog?category=technology');

// Search blog posts
const response = await fetch('http://127.0.0.1:5000/blog?q=cloud');
```

### Python (Requests)

```python
import requests
import re

BASE = 'http://127.0.0.1:5000'

# Read CSRF token from form page
session = requests.Session()
form_html = session.get(f'{BASE}/contact').text
csrf = re.search(r'name=\"_csrf_token\" value=\"([^\"]+)\"', form_html).group(1)

# Submit contact form
response = session.post(f'{BASE}/contact', data={
    '_csrf_token': csrf,
    'name': 'Jane Smith',
    'email': 'jane@example.com',
    'subject': 'Service Inquiry',
    'message': 'Interested in cybersecurity services.'
})

# Get services page
response = requests.get(f'{BASE}/services')

# Get specific blog post
response = requests.get(f'{BASE}/blog/the-future-of-cloud-computing-in-2025')
```

### cURL

```bash
# Get homepage
curl http://127.0.0.1:5000/

# Submit contact form (with CSRF)
CSRF=$(curl -c /tmp/mylauncher.cookies -s http://127.0.0.1:5000/contact | sed -n 's/.*name="_csrf_token" value="\\([^"]*\\)".*/\\1/p' | head -n1)
curl -b /tmp/mylauncher.cookies -X POST http://127.0.0.1:5000/contact \
  -d "_csrf_token=$CSRF" \
  -d "name=John+Doe" \
  -d "email=john@example.com" \
  -d "subject=Inquiry" \
  -d "message=Hello"

# Get blog listing
curl http://127.0.0.1:5000/blog

# Search blog posts
curl "http://127.0.0.1:5000/blog?q=security"
```

## Tech Stack

- **Backend**: Flask 3.1, Flask-SQLAlchemy, Flask-Login
- **Database**: SQLite (local), PostgreSQL (production)
- **Frontend**: Bootstrap 5.3, Font Awesome 6, TinyMCE 6

## Production Deployment

The app supports production deployment with Gunicorn and env-based config:

- `app/wsgi.py` (WSGI entrypoint)
- `/healthz` endpoint for platform health checks
- `DATABASE_URL` support (Postgres recommended for production)
- Optional SMTP notifications for contact and ticket submissions

### Example Start Command

```bash
cd app
gunicorn wsgi:app --bind 0.0.0.0:$PORT --workers 2 --threads 4 --timeout 120
```

### Environment Setup

1. Set at minimum:
   - `SECRET_KEY`
   - `DATABASE_URL`
   - `APP_BASE_URL`
   - `ADMIN_PASSWORD` (known admin login password)
   - `SESSION_COOKIE_SECURE=1`
   - `TRUST_PROXY_HEADERS=1`
   - `FORCE_HTTPS=1`
2. Optional admin recovery controls:
   - `ADMIN_USERNAME` (default: `admin`)
   - `ADMIN_EMAIL` (default: `admin@example.com`)
3. For email delivery:
   - `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`
   - `MAIL_FROM`
   - `CONTACT_NOTIFICATION_EMAILS`
   - `TICKET_NOTIFICATION_EMAILS`
4. For anti-spam and abuse controls:
   - `TURNSTILE_SITE_KEY`, `TURNSTILE_SECRET_KEY`, `TURNSTILE_ENFORCED`
   - `CONTACT_FORM_LIMIT`, `CONTACT_FORM_WINDOW_SECONDS`
   - `QUOTE_FORM_LIMIT`, `QUOTE_FORM_WINDOW_SECONDS`
5. For observability:
   - `SENTRY_DSN`
   - `SENTRY_ENVIRONMENT`
   - `SENTRY_TRACES_SAMPLE_RATE`
6. For headless CMS sync:
   - `HEADLESS_SYNC_TOKEN` (required to enable API auth)
   - `HEADLESS_SYNC_ENABLED` (default: `1`)
   - `HEADLESS_SYNC_MAX_ITEMS` (default: `250`)

### Cloudflare (JS Worker + D1/R2)

A JavaScript Worker rewrite is included for Cloudflare deploys:

- Worker entry: `src/index.js`
- Wrangler config: `wrangler.jsonc`
- D1 bootstrap schema: `sql/bootstrap.sql`

#### Deploy Commands

```bash
# 1) Create D1 database (one-time)
npx wrangler d1 create right-db

# 2) Put returned database_id into wrangler.jsonc d1_databases block

# 3) Initialize schema/data
npx wrangler d1 execute right-db --remote --file=sql/bootstrap.sql

# 4) Deploy Worker
npx wrangler deploy --config wrangler.jsonc
```

#### Cloudflare API Endpoints

- `GET /healthz`
- `GET /api/services`
- `GET /api/posts`
- `POST /api/contact`
- `POST /api/quote`

### Render Blueprint

A starter Render blueprint is provided at `render.yaml` (web service + Postgres + health check).

### Full Go-Live Checklist

Use `DEPLOYMENT_TODO.md` for the prioritized launch checklist (P0/P1/P2 + launch-day validation).
