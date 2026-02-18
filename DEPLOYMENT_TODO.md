# Deployment TODO (Go-Live Readiness)

This checklist is ordered by priority for taking the website online and ensuring contact messages + support tickets are reliably received.

## P0 - Must Complete Before Launch

- [ ] Choose hosting target and create environments
  - [ ] Production service
  - [ ] Staging service
  - [ ] Separate Postgres databases for staging/production
- [ ] Configure production environment variables
  - [ ] `SECRET_KEY`
  - [ ] `DATABASE_URL` (Postgres, not local SQLite)
  - [ ] `APP_BASE_URL` (final public URL)
  - [ ] `SESSION_COOKIE_SECURE=1`
  - [ ] `TRUST_PROXY_HEADERS=1`
  - [ ] `TRUSTED_HOSTS=<your domain(s)>`
- [ ] Configure email delivery for notifications
  - [ ] `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`
  - [ ] `MAIL_FROM`
  - [ ] `CONTACT_NOTIFICATION_EMAILS`
  - [ ] `TICKET_NOTIFICATION_EMAILS`
  - [ ] Send test contact form and verify inbox receipt
  - [ ] Create test support ticket and verify inbox receipt
- [ ] Verify persistent file storage for uploads
  - [ ] Use mounted persistent disk or object storage
  - [ ] Confirm uploaded media survives app restart/redeploy
- [ ] Verify health checks and startup
  - [ ] Confirm `/healthz` returns HTTP 200
  - [ ] Confirm Gunicorn startup command works
  - [ ] Confirm admin login works in production
- [ ] Security baseline
  - [ ] Enforce HTTPS in hosting provider
  - [ ] Confirm HSTS header appears over HTTPS
  - [ ] Rotate default admin credentials immediately after first boot

## P1 - Should Complete In Week 1

- [ ] Email domain authentication
  - [ ] SPF record configured
  - [ ] DKIM record configured
  - [ ] DMARC record configured
- [ ] Anti-spam + abuse controls
  - [ ] Add CAPTCHA/Turnstile to public forms
  - [ ] Add form-level rate limiting for contact/quote endpoints
- [ ] Database reliability
  - [ ] Daily backups enabled
  - [ ] Restore test performed
  - [ ] Backup retention policy documented
- [ ] Observability
  - [ ] Error monitoring integrated (Sentry or equivalent)
  - [ ] Uptime monitoring for `/healthz`
  - [ ] Alert channel configured (email/Slack)

## P2 - Optimization / Scale

- [ ] Move media uploads to object storage CDN
- [ ] Add database migrations workflow (Alembic / Flask-Migrate)
- [ ] Add cache/CDN policy tuning for static and uploaded assets
- [ ] Add structured audit logs for ticket lifecycle updates
- [ ] Add SLO dashboard (requests, errors, latency)

## Launch-Day Validation

- [ ] Homepage, services, blog, contact all return HTTP 200
- [ ] Contact form submission creates `ContactSubmission` in DB
- [ ] Support portal registration/login works
- [ ] New support ticket appears in admin support ticket view
- [ ] New quote request appears as support ticket in admin
- [ ] Notification emails are delivered for each submission type
- [ ] SSL certificate valid and auto-renewing
- [ ] DNS A/AAAA/CNAME records resolve correctly
