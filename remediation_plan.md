# Remediation Plan (PR-Sized) — 2026-02-22

## PR-1 (Shipped): Observability + Session Hardening
- Files touched:
  - `/Users/umutdemirkapu/mylauncher/app/__init__.py`
  - `/Users/umutdemirkapu/mylauncher/app/config.py`
  - `/Users/umutdemirkapu/mylauncher/app/routes/admin.py`
  - `/Users/umutdemirkapu/mylauncher/app/routes/main.py`
  - `/Users/umutdemirkapu/mylauncher/app/tests/test_security_and_cms.py`
- Exact changes:
  - Added JSON structured logging formatter and app-level logging configuration.
  - Added request-id assignment and `X-Request-ID` response header.
  - Added `/readyz` readiness endpoint with DB + seed checks.
  - Added `session.clear()` on admin/support logout.
- Tests:
  - `test_readiness_endpoint_reports_ready`
  - Full regression suite.
- Acceptance criteria:
  - `/readyz` returns 200 when ready.
  - Logout clears session state.
  - Request ID visible in response headers.

## PR-2 (Shipped): MCP URL Validation
- Files touched:
  - `/Users/umutdemirkapu/mylauncher/app/routes/admin.py`
  - `/Users/umutdemirkapu/mylauncher/app/tests/test_security_and_cms.py`
- Exact changes:
  - Added `is_valid_https_url()` helper.
  - Enforced URL validation in MCP server add/edit flows.
- Tests:
  - `test_acp_mcp_server_rejects_invalid_url_scheme`
- Acceptance criteria:
  - Non-http(s) URLs are rejected and no DB row is created.

## PR-3 (Shipped): Route Sync Registry + Admin Sync Status
- Files touched:
  - `/Users/umutdemirkapu/mylauncher/app/models.py`
  - `/Users/umutdemirkapu/mylauncher/app/page_sync.py`
  - `/Users/umutdemirkapu/mylauncher/app/routes/admin.py`
  - `/Users/umutdemirkapu/mylauncher/app/templates/admin/acp/sync_status.html`
  - `/Users/umutdemirkapu/mylauncher/app/templates/admin/acp/pages.html`
  - `/Users/umutdemirkapu/mylauncher/app/templates/admin/acp/studio.html`
  - `/Users/umutdemirkapu/mylauncher/app/templates/admin/base.html`
  - `/Users/umutdemirkapu/mylauncher/app/tests/test_security_and_cms.py`
- Exact changes:
  - Added `AcpPageRouteBinding` table.
  - Implemented route introspection + sync report + auto-registration logic.
  - Added `/admin/acp/sync-status` and `/admin/acp/sync-status/resync`.
  - Added ACP nav entries and studio metrics for out-of-sync routes.
- Tests:
  - `test_acp_sync_status_scan_and_autoregister`
- Acceptance criteria:
  - Sync screen lists route status.
  - Resync creates bindings and can auto-register missing page docs.
  - Audit event emitted for sync runs.

## PR-4 (Shipped): CI Security + Regression Gates
- Files touched:
  - `/Users/umutdemirkapu/mylauncher/.github/workflows/security-and-regression.yml`
- Exact changes:
  - Added GitHub Actions workflow for pytest, bandit, pip-audit.
- Acceptance criteria:
  - Push/PR runs tests + static security checks + dependency scan.

## PR-5 (Next): Delivery Rendering Contract Migration (Flagged Rollout)
- Scope:
  - Migrate static page rendering to consume `AcpPageDocument` for selected routes under a feature flag.
- Planned files:
  - `/Users/umutdemirkapu/mylauncher/app/routes/main.py`
  - `/Users/umutdemirkapu/mylauncher/app/templates/*.html`
  - `/Users/umutdemirkapu/mylauncher/app/page_sync.py`
- Tests to add:
  - Integration: page edit -> preview -> publish -> live render.
  - Contract tests for `blocks_tree` component schema enforcement.
- Acceptance criteria:
  - No hard-coded-only page for thin-slice routes.
  - Rollback path via feature flag.
