# Security Audit (OWASP-Aligned) — 2026-02-22

## Executive Summary
The app already had strong baseline controls (CSRF on mutating routes, RBAC permissions map, upload validation, CSP/security headers, login throttling, audit events). This pass closed additional high-impact gaps around configuration hygiene, observability, and CMS/dashboard route governance.

## Findings

### High
1. SEC-001: MCP server URL scheme validation missing (fixed)
- Affected: `/Users/umutdemirkapu/mylauncher/app/routes/admin.py:3689`, `/Users/umutdemirkapu/mylauncher/app/routes/admin.py:3744` (pre-fix behavior)
- Exploit scenario: Non-http(s) schemes could be stored in integration config and later used unsafely by downstream tooling.
- Fix applied: strict `http/https + netloc` validation in `/Users/umutdemirkapu/mylauncher/app/routes/admin.py:350`, enforced at `/Users/umutdemirkapu/mylauncher/app/routes/admin.py:3707` and `/Users/umutdemirkapu/mylauncher/app/routes/admin.py:3764`.
- Regression test: `test_acp_mcp_server_rejects_invalid_url_scheme`.

2. SEC-002: No canonical route/page registry synchronization (fixed)
- Affected architecture: public routes vs MSC page records.
- Exploit scenario: unmanaged pages and stale content governance paths (security/approval bypass by omission).
- Fix applied:
  - New registry model `/Users/umutdemirkapu/mylauncher/app/models.py:572`.
  - Sync engine `/Users/umutdemirkapu/mylauncher/app/page_sync.py:163`.
  - Admin status/remediation endpoints `/Users/umutdemirkapu/mylauncher/app/routes/admin.py:2734` and `/Users/umutdemirkapu/mylauncher/app/routes/admin.py:2759`.
- Regression test: `test_acp_sync_status_scan_and_autoregister`.

### Medium
3. SEC-003: Session invalidation incomplete on logout (fixed)
- Affected: logout flows retained session envelope.
- Fix applied: `session.clear()` in admin and support logout:
  - `/Users/umutdemirkapu/mylauncher/app/routes/admin.py:1163`
  - `/Users/umutdemirkapu/mylauncher/app/routes/main.py:1824`

4. SEC-004: Readiness and structured request tracing gaps (fixed)
- Impact: hard to detect warm-up/degraded behavior and correlate incidents.
- Fix applied:
  - JSON request-aware logging `/Users/umutdemirkapu/mylauncher/app/__init__.py:59`
  - request IDs injected `/Users/umutdemirkapu/mylauncher/app/__init__.py:301` and `/Users/umutdemirkapu/mylauncher/app/__init__.py:379`
  - readiness probe `/Users/umutdemirkapu/mylauncher/app/__init__.py:456`
- Regression test: `test_readiness_endpoint_reports_ready`.

5. SEC-005: Dependency vulnerability scans not enforced in CI (fixed)
- Fix applied: new workflow `.github/workflows/security-and-regression.yml` with pytest + bandit + pip-audit.

### Low
6. SEC-006: SQLAlchemy legacy API warnings
- Impact: future compatibility, not immediate exploit.
- Mitigation: plan migration from `Query.get()` to `Session.get()`.

## Existing Security Controls Verified
- CSRF enforcement for mutating methods: `/Users/umutdemirkapu/mylauncher/app/__init__.py:309`
- Login brute-force controls for admin and support auth buckets.
- Secure upload validation (MIME + extension + file signature/image verification).
- Security headers + CSP.
- RBAC gating via endpoint permission map and server-side checks.
- Mutation audit logs for ACP domains.

## Security Regression Tests Added/Updated
- `test_acp_sync_status_scan_and_autoregister`
- `test_acp_mcp_server_rejects_invalid_url_scheme`
- `test_readiness_endpoint_reports_ready`

## Verification Checklist (Post-Fix)
1. `GET /readyz` returns 200 with all checks `true`.
2. `POST /admin/acp/mcp/servers/new` rejects non-http(s) URLs.
3. `POST /admin/acp/sync-status/resync` (autoregister) creates/updates route bindings.
4. `POST /admin/logout` and `POST /remote-support/logout` clear session.
5. Response contains `X-Request-ID`; logs include request metadata.

## Notes
- Local pip-audit execution was not possible in this environment due restricted network; CI workflow now runs it in GitHub Actions.
