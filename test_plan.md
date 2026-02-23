# Test Plan

## Unit-Level Targets
- Route sync logic (`run_page_route_sync`) state transitions:
  - missing docs
  - unpublished docs
  - auto-register behavior
  - orphan binding detection
- URL validation helper for MCP server config.
- Request-id and readiness checks.

## Integration Targets
- Admin auth + CSRF flow.
- ACP sync status page render and resync action.
- ACP MCP server form validation errors.
- Delivery endpoints return only published resources.

## End-to-End Thin Slice
1. Login to admin.
2. Open `/admin/acp/sync-status`.
3. Run `Auto-Register Missing Pages`.
4. Verify bindings and page docs exist.
5. Edit a page doc and keep in draft.
6. Publish page and verify delivery API visibility.

## Automated Command
- `PYTHONPATH=/Users/umutdemirkapu/mylauncher pytest -q /Users/umutdemirkapu/mylauncher/app/tests/test_security_and_cms.py`

## CI Gates
- GitHub Action: `.github/workflows/security-and-regression.yml`
  - pytest
  - bandit
  - pip-audit

## Current Result
- 43 tests passing locally.
