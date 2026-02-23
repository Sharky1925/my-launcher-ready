# Professional Bug Audit (2026-02-22)

## Critical
- None currently open after remediation pass.

## High
1. BUG-001: Web route inventory not synchronized to MSC page registry
- Root cause: App routes existed independently from `AcpPageDocument`; there was no canonical route-binding registry or drift report.
- Evidence: new sync implementation introduced in `/Users/umutdemirkapu/mylauncher/app/page_sync.py:163` and `/Users/umutdemirkapu/mylauncher/app/models.py:572` because this capability was previously absent.
- Impact: Pages can disappear from managed editing scope; dashboard state diverges from live routes.
- Fix summary:
  - Added `AcpPageRouteBinding` model.
  - Added deterministic sync engine with missing/orphan/unpublished detection.
  - Added admin screen and manual resync + auto-register actions.
- Tests: `test_acp_sync_status_scan_and_autoregister`.

## Medium
2. BUG-002: Missing readiness endpoint
- Root cause: Only `/healthz` existed; no startup/seed/readiness probe contract.
- Evidence: readiness added at `/Users/umutdemirkapu/mylauncher/app/__init__.py:456`.
- Impact: Deployments could route traffic before app is actually ready.
- Fix summary: Added `/readyz` with checks for DB + seeded core data.
- Tests: `test_readiness_endpoint_reports_ready`.

3. BUG-003: Incomplete session invalidation on logout
- Root cause: Logout endpoints removed user identity but did not clear full session envelope.
- Evidence: fixes at `/Users/umutdemirkapu/mylauncher/app/routes/admin.py:1163` and `/Users/umutdemirkapu/mylauncher/app/routes/main.py:1824`.
- Impact: Session residue risk (stale keys, predictable post-logout state).
- Fix summary: `session.clear()` added on admin and support logout flows.
- Tests: existing auth flow tests + full regression suite.

4. BUG-004: MCP server URL accepted non-http(s) schemes
- Root cause: URL format validation only checked required field presence.
- Evidence: URL validator added at `/Users/umutdemirkapu/mylauncher/app/routes/admin.py:350`, enforced on create/edit at `/Users/umutdemirkapu/mylauncher/app/routes/admin.py:3707` and `/Users/umutdemirkapu/mylauncher/app/routes/admin.py:3764`.
- Impact: Invalid or dangerous URL schemes could enter config.
- Fix summary: Strict `http/https + netloc` validation on MCP server forms.
- Tests: `test_acp_mcp_server_rejects_invalid_url_scheme`.

## Low
5. BUG-005: SQLAlchemy legacy API warnings (`Query.get`) in tests
- Root cause: test and some helper code still use legacy accessor.
- Evidence: pytest warnings in regression output.
- Impact: Non-breaking today, but upgrade risk.
- Fix summary: deferred to next cleanup slice (move to `db.session.get`).

## Additional Previously Fixed Runtime Exception
- Theme Token editor crash was fixed just prior to this audit pass:
  - cause: Jinja template string quoting bug in `theme_token_form.html`
  - status: resolved (commit `f3eff23`), covered by ACP admin render test.

## PR-Sized Change Grouping
- Fast fixes (shipped): readiness endpoint, logout invalidation, MCP URL validation, route sync status UI/API.
- Structural fixes (shipped): route-binding model + sync engine module.
- Risky changes (deferred behind planning): full runtime rendering from `AcpPageDocument` for all non-dynamic pages.
