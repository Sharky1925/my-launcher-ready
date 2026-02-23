# Operations Runbook

## 1) Deploy
1. Push to `main`.
2. Confirm CI (`Security and Regression CI`) is green.
3. Deploy on Railway with current service config.
4. Verify startup logs show no migration/seed exceptions.

## 2) Post-Deploy Health
- Liveness: `GET /healthz` must return `200`.
- Readiness: `GET /readyz` must return `200` and all checks true.

## 3) Verify Security Headers
Check a public route and admin route:
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Content-Security-Policy` present
- `X-Request-ID` present
- `X-Robots-Tag` for `/admin/*` and `/remote-support*`

## 4) Verify Route Sync Governance
1. Login to admin.
2. Open `/admin/acp/sync-status`.
3. Run `Run Sync Scan`.
4. If missing routes exist, run `Auto-Register Missing Pages`.
5. Review unpublished pages and publish through normal workflow.

## 5) Secret Rotation
Rotate and verify at least:
- `SECRET_KEY`
- `DATABASE_URL`
- `TURNSTILE_SECRET_KEY`
- SMTP credentials
- Any MCP connector secrets

After rotation:
- Redeploy.
- Re-test admin login, contact form, quote flow, support portal login.

## 6) Rollback
1. Roll back to previous known-good commit in git.
2. Redeploy previous artifact.
3. Verify `/healthz`, `/readyz`, admin login, and public homepage.
4. Re-run ACP sync scan to verify route bindings consistency.

## 7) Incident Triage
- Use request ID from response headers to correlate logs.
- Inspect:
  - app error logs
  - ACP audit timeline `/admin/acp/audit`
  - MCP audit `/admin/acp/mcp/audit`
  - Security events `/admin/security-events`

## 8) Scheduled Maintenance Checks
- Weekly: run ACP route sync scan and resolve drift.
- Weekly: review security events dashboard.
- Monthly: review dependency vulnerabilities and rotate long-lived secrets.
