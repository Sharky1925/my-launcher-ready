# Security Best Practices Audit Report

## Executive Summary
This audit reviewed Flask backend security controls, auth/session handling, CSRF behavior, and frontend sink usage. The current hardened state includes fixes for open redirect risk on CSRF failures, spoofable auth throttling keys, session fixation risk, nonce-based CSP script and style enforcement, persistent DB-backed auth rate-limit buckets, and full removal of inline `style=` attributes from templates.

## Findings (Fixed)

### F-001
- Rule ID: FLASK-CSRF-REDIRECT-001
- Severity: High
- Location: `app/__init__.py:177`
- Evidence: CSRF error handler previously redirected to `request.referrer` without origin validation.
- Impact: External open redirect via attacker-controlled `Referer` header on CSRF failure responses.
- Fix: Added `safe_referrer_path()` allowlisting same-host paths only and fallback to `main.index`.
- Mitigation: Keep using CSRF tokens + SameSite cookies; avoid redirect targets sourced directly from headers.
- False positive notes: None.

### F-002
- Rule ID: FLASK-AUTH-RATELIMIT-001
- Severity: High
- Location: `app/routes/admin.py:158`, `app/routes/main.py:554`
- Evidence: Auth throttling previously keyed directly off `X-Forwarded-For` when present.
- Impact: Brute-force controls could be bypassed by spoofing `X-Forwarded-For`.
- Fix: Added strict IP normalization and `get_request_ip()` with secure default `TRUST_PROXY_HEADERS=False`; only trust forwarded headers when explicitly enabled.
- Mitigation: For multi-node/production deployments, migrate counters to shared storage (e.g., Redis).
- False positive notes: If an upstream proxy is trusted, set `TRUST_PROXY_HEADERS=1` intentionally.

### F-003
- Rule ID: FLASK-SESS-002
- Severity: Medium
- Location: `app/routes/admin.py:256`, `app/routes/main.py:979`, `app/routes/main.py:1014`
- Evidence: Auth success paths previously reused existing session state.
- Impact: Increased session fixation risk if a prior session context is reused.
- Fix: Added `session.clear()` before establishing authenticated session state.
- Mitigation: Continue using short-lived sessions and secure cookie flags in production.
- False positive notes: Flask uses signed cookie sessions; this is a hardening change to prevent stale state carry-over.

## Hardening Added
- Added config switches in `app/config.py:28`:
  - `TRUST_PROXY_HEADERS` (default `False`)
  - `TRUSTED_HOSTS` (optional env-driven host allowlist for Flask host validation)
- CSP tightened in `app/__init__.py:168`:
  - `script-src` now requires per-request nonce and no longer allows `'unsafe-inline'`.
  - `style-src` now requires per-request nonce and no longer allows `'unsafe-inline'`.
  - Added `object-src 'none'`.
- Added per-request nonce injection in templates via `csp_nonce` context variable and nonce attributes on script tags.
- Replaced all inline style attributes in templates with class-based styling and utility classes in `app/static/css/style.css`.
- Added persistent rate-limit buckets using `AuthRateLimitBucket` in `app/models.py:155`, used by:
  - Admin auth throttling in `app/routes/admin.py:158`
  - Remote support auth throttling in `app/routes/main.py:554`

## Verification
- Static compile checks passed for modified Python files.
- Targeted security test suite passed: `13 passed`.
- Added regression tests:
  - `test_admin_login_rate_limit_not_bypassable_with_spoofed_xff`
  - `test_csrf_failure_redirect_rejects_external_referrer`
  - CSP header now asserted to include nonce and exclude `script-src 'unsafe-inline'`.
  - `test_hsts_header_on_https_requests`

## 2026-02-18 Pre-Deployment Audit Addendum

### Scope
- Full test run and compile checks
- Dependency integrity and vulnerability scan
- Route crawl + internal link health scan
- Icon class integrity scan on rendered pages
- Security header and CSRF/form checks

### Results
- `pytest -q`: `13 passed`
- `python -m compileall -q .`: passed
- `python -m pip check`: no broken requirements
- `pip-audit -r requirements.txt`: no known vulnerabilities
- Internal route crawl: `32` unique paths visited, `0` broken pages/links
- Icon integrity: `2253` rendered icons scanned, `0` invalid icon classes
- Security headers validated (CSP nonce, frame/content protections, HSTS on HTTPS)

### Remediations Applied
- Added HSTS on secure requests:
  - `Strict-Transport-Security: max-age=31536000; includeSubDomains`
  - Implemented at `app/__init__.py:171`
- Updated vulnerable dependencies in `app/requirements.txt`:
  - `Flask==3.1.1`
  - `Werkzeug==3.1.5`
  - `Pillow==12.1.1`

### Notes
- `bandit` static scan flags one medium finding on `Markup(...)` in CSRF hidden input generation (`app/__init__.py:58`).
- This is an expected false positive in current usage because token content is server-generated and not user-controlled.

## Remaining Risk / Recommended Next Steps
1. `AuthRateLimitBucket` uses the app DB. For horizontally scaled production, ensure all app instances share the same DB backend.
2. Set `ADMIN_PASSWORD` explicitly in production and rotate periodically to avoid unmanaged bootstrap credentials.

## 2026-02-22 Intensive Audit Addendum

### Executive Summary
Completed a full code + runtime security audit and applied hardening fixes for credential leakage, auth timing behavior, upload path safety, and header handling. No regression was introduced (`22` tests passing).

### Findings (Fixed)

#### F-004
- Rule ID: FLASK-CONFIG-001
- Severity: High
- Location: `app/seed.py:29`
- Evidence: bootstrap flow printed generated admin password directly to stdout.
- Impact: secrets exposure in deployment logs.
- Fix: removed plaintext password logging; startup now logs only a rotation instruction.
- Mitigation: always set `ADMIN_PASSWORD` in production and rotate through environment.

#### F-005
- Rule ID: FLASK-AUTH-ENUM-001
- Severity: Medium
- Location: `app/routes/admin.py:304`, `app/routes/main.py:1723`
- Evidence: login flow only performed password hash checks for existing accounts.
- Impact: measurable timing differences can help username/email enumeration.
- Fix: added dummy hash verification path for unknown principals to reduce timing signal.
- Mitigation: keep rate limits enabled and monitor repeated auth failures.

#### F-006
- Rule ID: FLASK-FILE-TRAVERSAL-001
- Severity: Medium
- Location: `app/routes/admin.py:84`, `app/routes/admin.py:853`
- Evidence: media delete path previously relied on DB file path directly.
- Impact: tampered DB path could trigger file deletion outside upload directory.
- Fix: centralized `_safe_upload_path()` now enforces basename + commonpath confinement before file access/removal.
- Mitigation: continue validating upload filenames and keep DB access restricted.

#### F-007
- Rule ID: FLASK-FILE-SERVE-001
- Severity: Medium
- Location: `app/routes/admin.py:281`
- Evidence: uploaded non-image files were served inline without forced download behavior.
- Impact: increased browser attack surface for user-uploaded active document types.
- Fix: serve uploads with conditional/etag and force `Content-Disposition: attachment` for non-image files.
- Mitigation: keep allowed MIME/extensions strict and avoid enabling SVG/HTML uploads.

#### F-008
- Rule ID: FLASK-CONFIG-HSTS-001
- Severity: Low
- Location: `app/config.py:77`, `app/__init__.py:248`
- Evidence: HSTS policy was hardcoded with `preload`.
- Impact: preload can cause difficult domain lock-in/outage scenarios when not fully prepared.
- Fix: made HSTS configurable (`HSTS_ENABLED`, `HSTS_MAX_AGE`, `HSTS_INCLUDE_SUBDOMAINS`, `HSTS_PRELOAD`) and disabled preload by default.
- Mitigation: enable `HSTS_PRELOAD=1` only after domain/subdomain readiness verification.

#### F-009
- Rule ID: FLASK-EMAIL-HEADER-001
- Severity: Medium
- Location: `app/notifications.py:11`
- Evidence: user-influenced subject fields were passed to email headers without explicit CR/LF sanitization.
- Impact: potential header-injection edge cases and delivery instability.
- Fix: added `_safe_header_value()` and applied it to sender, recipients, and subject paths before SMTP/Mailgun send.
- Mitigation: keep input validation in contact/quote routes and reject malformed emails.

#### F-010
- Rule ID: FLASK-CONFIG-COOKIE-001
- Severity: Medium
- Location: `app/config.py:11`
- Evidence: secure cookie and proxy trust defaults could be missed in production unless env vars were manually set.
- Impact: insecure session cookie transport and missing HTTPS/proxy awareness in managed deployments.
- Fix: added managed/production runtime detection and hardened defaults:
  - `SESSION_COOKIE_SECURE` now defaults to enabled in production runtimes.
  - `TRUST_PROXY_HEADERS` now defaults to enabled on managed platforms (Railway/Render/Vercel), while still overridable via env vars.
- Mitigation: explicitly set `SESSION_COOKIE_SECURE=1` and `TRUST_PROXY_HEADERS=1` in production environment config for clarity.

### Verification
- `cd app && source venv/bin/activate && PYTHONPATH=/Users/umutdemirkapu/mylauncher pytest -q tests` -> `22 passed`
- `cd app && source venv/bin/activate && python -m compileall -q .` -> passed
- `cd app && source venv/bin/activate && pip-audit -r requirements.txt` -> `No known vulnerabilities found`
- `cd app && source venv/bin/activate && bandit -q -r . -x ./venv,./tests,.pytest_cache` -> no findings (only `# nosec` warning on intentional safe markup helper)
- Route smoke crawl with Flask test client -> `35` paths checked, `0` failures
