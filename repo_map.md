# Repository Map (2026-02-22)

## Runtime Entrypoints
- `app/run.py`: local development entrypoint.
- `app/wsgi.py`: production WSGI object for Gunicorn.
- `app/__init__.py`: Flask app factory, security middleware, headers, health/readiness, blueprint registration.

## Application Layers
- Public webapp routes: `app/routes/main.py`
- Admin + MSC + ACP/MCP dashboard routes: `app/routes/admin.py`
- Models and workflow/RBAC constants: `app/models.py`
- Content section schemas for legacy CMS blocks: `app/content_schemas.py`
- Shared utility helpers: `app/utils.py`
- Bootstrap/seed/backfill logic: `app/seed.py`

## Data and Source of Truth
- Legacy page section CMS (per-page/per-section JSON): `ContentBlock` model.
- Core service/business content: `Service`, `Industry`, `Post`, `Category`, `Testimonial`, `TeamMember`.
- Support/ticket domain: `SupportClient`, `SupportTicket`, `SupportTicketEvent`.
- ACP page/dashboard/content/theme domain:
  - `AcpPageDocument`, `AcpDashboardDocument`, `AcpContentType`, `AcpContentEntry`, `AcpThemeTokenSet`
  - version tables: `AcpPageVersion`, `AcpDashboardVersion`, `AcpContentTypeVersion`, `AcpContentEntryVersion`, `AcpThemeTokenVersion`
- Registry/metrics/extensions: `AcpComponentDefinition`, `AcpWidgetDefinition`, `AcpMetricDefinition`, `AcpMcpServer`, `AcpMcpAuditEvent`.
- Environment/promotion/audit: `AcpEnvironment`, `AcpPromotionEvent`, `AcpAuditEvent`.
- Route sync registry (new): `AcpPageRouteBinding`.

## New Sync Module
- `app/page_sync.py`:
  - Enumerates public Flask routes.
  - Maps route rules to canonical page slugs.
  - Detects missing/unpublished/unmapped pages and orphan docs/bindings.
  - Optionally auto-registers missing `AcpPageDocument` entries.

## Templates and UI
- Public templates: `app/templates/*.html`
- Admin templates: `app/templates/admin/*.html`
- ACP templates: `app/templates/admin/acp/*.html`
- New sync UI: `app/templates/admin/acp/sync_status.html`

## Tests
- Primary regression/security/ACP tests: `app/tests/test_security_and_cms.py`

## CI
- New workflow: `.github/workflows/security-and-regression.yml`
  - pytest regression suite
  - Bandit scan
  - pip-audit dependency scan
