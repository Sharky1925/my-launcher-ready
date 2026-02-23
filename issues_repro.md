# Issue Reproduction Checklist (2026-02-22)

## 1) Theme token editor crash (fixed)
Status: Fixed in previous commit `f3eff23`.

Repro (pre-fix):
1. Login to admin.
2. Open `/admin/acp/theme/new` or `/admin/acp/theme/<id>/edit`.
3. Server raises Jinja `TemplateSyntaxError` due to malformed default JSON string in template.

Validation:
- `GET /admin/acp/theme/new` returns 200.
- `GET /admin/acp/theme/<id>/edit` returns 200.
- Covered by `test_acp_phase1_admin_sections_render`.

## 2) Route/page sync drift (fixed with new sync engine)
Status: Fixed with route sync module and admin screen.

Repro (before fix):
1. Run sync analysis against app routes.
2. Observe public routes existing without MSC page records.
3. Dashboard had no deterministic sync status UI or remediation action.

Observed baseline before fix-like state (fresh seeded app):
- `routes_scanned=16`
- `missing_page_document=16`

Validation (after fix):
- Visit `/admin/acp/sync-status`.
- Run `Auto-Register Missing Pages`.
- `AcpPageRouteBinding` rows are created/updated and mapped to slugs.
- Covered by `test_acp_sync_status_scan_and_autoregister`.

## 3) MCP server URL validation gap (fixed)
Status: Fixed.

Repro (pre-fix):
1. Login to admin.
2. POST `/admin/acp/mcp/servers/new` with `server_url=javascript:alert(1)`.
3. Record accepted because only presence was validated.

Validation (after fix):
- Non-http(s) URL is rejected with validation error.
- Covered by `test_acp_mcp_server_rejects_invalid_url_scheme`.

## 4) Session invalidation on logout (fixed)
Status: Fixed.

Repro (pre-fix):
1. Login as admin or support client.
2. Logout endpoint removed identity, but did not clear all session keys.
3. Session residue could persist non-auth session data.

Validation (after fix):
- Admin logout and support logout both call `session.clear()`.

## 5) Missing readiness endpoint (fixed)
Status: Fixed.

Repro (pre-fix):
- `/readyz` did not exist; deployment could only use liveness probe.

Validation:
- `GET /readyz` returns readiness with checks.
- Covered by `test_readiness_endpoint_reports_ready`.
