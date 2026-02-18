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
2. Seed/bootstrap path prints generated admin password to stdout when `ADMIN_PASSWORD` is unset (`app/seed.py:18`). Avoid log exposure in production environments.
