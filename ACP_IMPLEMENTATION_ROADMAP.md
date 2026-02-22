# Application Control Platform (ACP) Implementation Roadmap

## Current Stack Baseline (Inspected)
- Runtime: Flask + Gunicorn (`app/run.py`, `app/wsgi.py`)
- Rendering: Server-rendered Jinja templates (`app/templates/*`)
- Data: SQLAlchemy models in `app/models.py` (SQLite/Postgres)
- Auth: `flask-login` with role-based permission checks
- Admin: Single admin blueprint at `/admin/*` (`app/routes/admin.py`)
- Public delivery: Main blueprint (`app/routes/main.py`)

## Thin-Slice Implemented In This Iteration
- New ACP data models for page/dashboard documents, versions, registries, metrics, environments, promotion, and audit.
- New admin ACP routes:
  - `/admin/acp/studio`
  - `/admin/acp/pages` + create/edit/snapshot/publish
  - `/admin/acp/dashboards` + create/edit/snapshot/publish
  - `/admin/acp/registry`
  - `/admin/acp/metrics`
  - `/admin/acp/audit`
  - `/admin/acp/promote`
  - `/admin/acp/api/pages/<slug>`
  - `/admin/acp/api/dashboards/<dashboard_id>`
- New public delivery APIs:
  - `/api/delivery/pages/<slug>`
  - `/api/delivery/dashboards/<dashboard_id>`
- Seeded thin-slice defaults:
  - 3 components
  - 3 widgets
  - 1 metric
  - 1 published page document
  - 1 published dashboard document
  - environments + initial audit seed event
- Permission expansion with ACP domains.

## Milestone Plan (Customized)

### Milestone 0 — Discovery & Baseline
- Tasks:
  - Map current module boundaries and data flow.
  - Define ACP source-of-truth entities (content, page docs, dashboard docs, registries, tokens, audit).
  - Publish editable capability matrix.
- Modules/files:
  - `ACP_IMPLEMENTATION_ROADMAP.md`
- DB additions:
  - None.
- Endpoints/UI:
  - None.
- Acceptance:
  - Signed architecture baseline and prioritized backlog.
- Risks:
  - Scope creep.
- Mitigation:
  - Freeze thin-slice scope before coding.

### Milestone 1 — Foundations (Auth/RBAC/Audit/Environments)
- Tasks:
  - Add ACP permission domains and enforcement in admin endpoint map.
  - Add ACP audit event model and audit timeline view.
  - Add environment model and promotion event log.
- Modules/files:
  - `app/models.py`
  - `app/routes/admin.py`
  - `app/templates/admin/base.html`
  - `app/templates/admin/acp/studio.html`
  - `app/templates/admin/acp/audit.html`
- DB additions:
  - `AcpAuditEvent`, `AcpEnvironment`, `AcpPromotionEvent`
- Endpoints:
  - `/admin/acp/audit`, `/admin/acp/promote`
- UI routes/screens:
  - ACP Studio + ACP Audit screens.
- Acceptance:
  - Role-restricted ACP access and queryable audit records.
- Risks:
  - Over-permissive role mapping.
- Mitigation:
  - Explicit endpoint-permission mapping + tests.

### Milestone 2 — Content Modeling
- Tasks:
  - Introduce schema-driven content type + entry builder for ACP-managed content (next step).
  - Add content schema versioning tables.
- Modules/files:
  - Planned: `app/models.py`, `app/routes/admin.py`, new ACP templates.
- DB additions (planned):
  - `content_types`, `content_type_versions`, `content_entries`, `content_entry_versions`.
- Endpoints (planned):
  - `/admin/acp/content-types`, `/admin/acp/content-entries`.
- Acceptance:
  - Content types and entries editable end-to-end with version snapshots.
- Risks:
  - Dynamic schema validation complexity.
- Mitigation:
  - JSON-schema validation and field constraints.

### Milestone 3 — Visual Page Builder
- Tasks:
  - Implement page document editing (done thin-slice).
  - Add component registry guardrails (done thin-slice seed + list view).
  - Add drag/drop canvas (next iteration).
- Modules/files:
  - `app/models.py`
  - `app/routes/admin.py`
  - `app/templates/admin/acp/pages.html`
  - `app/templates/admin/acp/page_form.html`
- DB additions:
  - `AcpPageDocument`, `AcpPageVersion`, `AcpComponentDefinition`
- Endpoints:
  - `/admin/acp/pages*`, `/admin/acp/api/pages/<slug>`
  - `/api/delivery/pages/<slug>`
- Acceptance:
  - Non-dev can create/edit/snapshot/publish one schema-driven page document.
- Risks:
  - Invalid JSON documents.
- Mitigation:
  - Server-side JSON parse/validation and workflow gate checks.

### Milestone 4 — Dashboard Studio
- Tasks:
  - Implement dashboard document CRUD + snapshot + publish (done thin-slice).
  - Add widget registry guardrails and role visibility rules (done data model and editor fields).
  - Add visual grid drag/resize builder (next iteration).
- Modules/files:
  - `app/models.py`
  - `app/routes/admin.py`
  - `app/templates/admin/acp/dashboards.html`
  - `app/templates/admin/acp/dashboard_form.html`
  - `app/templates/admin/acp/registry.html`
- DB additions:
  - `AcpDashboardDocument`, `AcpDashboardVersion`, `AcpWidgetDefinition`
- Endpoints:
  - `/admin/acp/dashboards*`, `/admin/acp/api/dashboards/<dashboard_id>`
  - `/api/delivery/dashboards/<dashboard_id>`
- Acceptance:
  - One dashboard with at least 3 widget types can be published and delivered.
- Risks:
  - Widget contract drift.
- Mitigation:
  - Registry metadata + standardized data contract fields.

### Milestone 5 — Metrics Layer
- Tasks:
  - Create metrics catalog and bind widgets via metric keys (done thin-slice model + seed metric).
  - Add query service with parameterized templates and caching (next).
- Modules/files:
  - `app/models.py`
  - `app/templates/admin/acp/metrics.html`
- DB additions:
  - `AcpMetricDefinition`
- Endpoints (next):
  - `/admin/acp/metrics`, `/api/metrics/query` (admin-only), delivery aggregator.
- Acceptance:
  - Widgets consume metric keys from a central catalog.
- Risks:
  - Direct query bypass.
- Mitigation:
  - Enforce widget->metric indirection server-side.

### Milestone 6 — Theme + Design Tokens
- Tasks:
  - Add global/scoped token model and token editor.
  - Map tokens to CSS variables and widget/page render paths.
- DB additions (planned):
  - `theme_tokens`, `theme_versions`.
- Endpoints/UI (planned):
  - `/admin/acp/theme`.
- Acceptance:
  - Changing tokens updates website + dashboard rendering.
- Risks:
  - Token inconsistencies across old templates.
- Mitigation:
  - Progressive token fallback to existing CSS vars.

### Milestone 7 — Media/Icons/Animations
- Tasks:
  - Extend media library metadata + icon/animation catalogs.
- DB additions (planned):
  - `icon_catalog`, `animation_presets`, media metadata extensions.
- Endpoints/UI (planned):
  - `/admin/acp/media`, `/admin/acp/icons`, `/admin/acp/animations`.
- Acceptance:
  - Editors can pick approved icons and motion presets in page/dashboard docs.
- Risks:
  - Asset bloat and invalid SVG uploads.
- Mitigation:
  - Strict upload validation + sanitization pipeline.

### Milestone 8 — Workflow Engine
- Tasks:
  - Extend to review/approve/scheduled/archived + comments/mentions.
  - Add structural diff viewer for JSON docs.
- DB additions (planned):
  - `workflow_comments`, `workflow_assignments`, `workflow_transitions`.
- Endpoints/UI (planned):
  - `/admin/acp/workflow/*`.
- Acceptance:
  - Team collaboration and approvals with rollback safety.
- Risks:
  - State transition edge cases.
- Mitigation:
  - Explicit transition matrix and integration tests.

### Milestone 9 — Plugin SDK
- Tasks:
  - Define plugin manifest and loader.
  - Allow plugin field types/components/widgets/connectors.
- DB additions (planned):
  - `acp_plugins`, `acp_plugin_versions`, `acp_plugin_permissions`.
- Endpoints/UI (planned):
  - `/admin/acp/plugins`.
- Acceptance:
  - One plugin can add a page block + dashboard widget without core edits.
- Risks:
  - Plugin safety and dependency conflicts.
- Mitigation:
  - Permission-scoped plugin sandbox and version pinning.

## Thin-Slice MVP Definition
- 1 content representation: `AcpPageDocument` with schema-driven `blocks_tree`.
- 1 page template: `landing-v1` seeded.
- 3 registered components: `layout.container`, `marketing.hero`, `content.serviceCards`.
- 1 dashboard: `operations-overview` seeded.
- 3 widget types: `kpi-card`, `line-chart`, `table`.
- 1 metric: `support_open_tickets`.
- Basic RBAC: ACP domain permissions integrated with existing roles.
- Draft/publish + scheduling + snapshots + audit trail.

## Refactoring Plan
- Keep Flask monolith, isolate ACP logic into dedicated modules next:
  - `app/acp/services.py` (workflow, versioning, audit)
  - `app/acp/serializers.py` (document serialization)
  - `app/routes/acp_admin.py` (split from `app/routes/admin.py`)
  - `app/routes/acp_delivery.py` (public delivery layer)
- Introduce explicit service layer to reduce route complexity.

## Migration Strategy
- Current approach: additive tables with `db.create_all()` plus idempotent seed.
- Next hardening steps:
  - Add migration scripts for production schema evolution.
  - Backfill existing `ContentBlock` sections to ACP page documents in batches.
  - Feature-flag ACP rendering paths while legacy templates remain primary.
  - Parallel-run both systems; rollback by toggling delivery source.

## Scaling Roadmap
- To 1M entries:
  - Move ACP document and version tables to Postgres partition strategy by date and entity.
  - Add pagination + selective projections for admin APIs.
  - Use Redis for hot delivery JSON cache and invalidation on publish.
- Dashboard large datasets:
  - Query service with read-only warehouse views, parameterized templates, timeout/rate limits.
  - Materialized aggregates for heavy KPIs.
- Multi-tenant readiness:
  - Add `tenant_id` to ACP entities and RBAC checks.
  - Per-tenant isolated environments and cache keys.
- Horizontal scale:
  - Stateless admin/delivery instances behind load balancer.
  - Queue-based publish jobs and background version diffs.
