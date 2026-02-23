# Release Checklist

## Code + Quality
- [ ] Regression suite passes locally and in CI.
- [ ] No new 500s on key routes (`/`, `/services`, `/industries`, `/admin/login`, `/admin/acp/sync-status`).
- [ ] ACP sync actions create audit events.

## Security
- [ ] Verify CSRF protections on all mutating forms.
- [ ] Verify logout invalidates session for admin and support.
- [ ] Verify security headers and `X-Request-ID` present.
- [ ] Verify MCP server URL validation rejects non-http(s) values.

## Sync Governance
- [ ] Run `/admin/acp/sync-status` scan.
- [ ] Resolve `missing_page_document` with auto-register or manual page creation.
- [ ] Resolve `unpublished_page_document` per editorial workflow.
- [ ] Review orphan page documents before archival.

## Deployment
- [ ] Confirm `SECRET_KEY`, DB URL, SMTP, and Turnstile secrets are set in environment.
- [ ] Confirm health checks:
  - [ ] `/healthz` liveness
  - [ ] `/readyz` readiness
- [ ] Verify admin login works after deploy.

## Post-Deploy Validation
- [ ] Smoke test ticket search, support portal, and quote flow.
- [ ] Check logs include structured JSON and request IDs.
- [ ] Confirm CI workflow status green on pushed commit.
