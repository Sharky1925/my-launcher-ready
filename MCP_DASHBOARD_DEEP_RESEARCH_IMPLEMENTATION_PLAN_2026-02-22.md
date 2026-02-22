# MCP + Dashboard Deep Research and Implementation Plan (2026-02-22)

## Goal
Enable admins and non-developers to safely manage **all webapp parameters** from one platform:
- content and structured data
- pages/routes/layouts/components
- fonts, typography, color/theme tokens
- icons, media, animations
- dashboard layouts/widgets/KPIs/filters/role views
- workflow, approvals, scheduling, versioning, rollback
- MCP-powered integrations and tools

This plan is customized to the current codebase:
- Flask + SQLAlchemy monolith
- Jinja SSR frontend
- ACP thin-slice already present in admin and delivery APIs

---

## 1) Current System Audit (What You Already Have)

### Stack and architecture (current)
- Flask app with admin/public blueprints.
- SQLAlchemy models in `app/models.py`.
- Admin permission map and role checks in `app/routes/admin.py`.
- ACP entities already implemented:
  - `AcpPageDocument`, `AcpPageVersion`
  - `AcpDashboardDocument`, `AcpDashboardVersion`
  - `AcpComponentDefinition`, `AcpWidgetDefinition`
  - `AcpMetricDefinition`
  - `AcpEnvironment`, `AcpPromotionEvent`, `AcpAuditEvent`
- Delivery APIs already split from admin APIs:
  - `GET /api/delivery/pages/<slug>`
  - `GET /api/delivery/dashboards/<dashboard_id>`

### Strengths (already aligned with enterprise patterns)
- Draft/review/approved/published states and scheduled publishing support.
- Snapshot/version history for pages and dashboards.
- Audit trail with actor, before/after, environment.
- Registry-based guardrails for components and widgets.
- Role-gated admin endpoints.

### Major gaps vs your target outcome
- No content type/model builder for arbitrary structured data.
- Page builder is mostly top-level JSON editing + simple drag/reorder; no deep nested visual layout engine.
- Theme/font/icon/animation management is not first-class in ACP.
- Dashboard builder lacks full grid behavior (snap, responsive breakpoints, drilldown, saved views).
- Metrics layer is not fully isolated behind a query service and connector framework.
- RBAC is role-based but not domain+attribute granular enough for "edit everything safely".
- No MCP integration control plane (servers, tool allowlists, approvals, credential lifecycle, audit).
- No plugin SDK/manager for extending fields, blocks, widgets, connectors.

---

## 2) Deep Research Findings Mapped to Your Goal

### MCP-specific design requirements
- MCP uses host-client-server boundaries and capability negotiation; servers should stay isolated and only receive necessary context.
- OAuth-based auth and token validation requirements are explicit in MCP authorization spec.
- MCP security docs explicitly call out:
  - token passthrough anti-pattern
  - SSRF risks during metadata discovery
  - per-client consent and strict redirect/state handling
- OpenAI tooling supports MCP with:
  - `type: "mcp"`
  - `server_url` or connector IDs
  - `allowed_tools`
  - `require_approval` policies
  - explicit approval flow via `mcp_approval_request` / `mcp_approval_response`

### CMS/dashboard product patterns repeatedly seen in top platforms
- Visual editing with click-to-edit and live preview (Payload, Sanity, Storyblok).
- Draft/publish + workflow stages + assignee/review (Strapi, Storyblok).
- Versions/diffs/rollback (Payload, Directus revisions/activity).
- Fine-grained RBAC and environment governance (Contentful, Grafana, Superset, Metabase).
- Dashboard modularity via panel/widget registries and drag-drop layouts (Directus, Grafana, Superset).
- Role-aware filtering and row-level data controls (Superset, Metabase).
- Environment promotion / serialization for stage->prod safety (Contentful aliases, Metabase serialization, Grafana provisioning as code).

Implication: your target is feasible in your stack, but needs a structured ACP expansion, not one-off route edits.

---

## 3) Target Architecture (Customized to Flask ACP)

### Layer A: Delivery Layer (Public, Read-only)
- Keep `main.py` delivery endpoints, but enforce strict read-only, schema-validated, cacheable payloads.
- Add token/theme delivery endpoint and resolved navigation delivery endpoint.
- Add `ETag` + environment-aware cache keys.

### Layer B: Admin Layer (ACP Studio)
- Expand `/admin/acp/*` into domain modules:
  - content models
  - entries
  - pages/templates
  - theme/fonts/icons/animations
  - dashboards/widgets
  - metrics/connectors
  - MCP integrations
  - workflows/approvals/comments
  - plugins

### Layer C: Registry + Validation Layer
- Keep developer-registered components/widgets, but formalize:
  - `prop_schema`/`config_schema` as JSON Schema
  - allowed nesting constraints
  - instance limits
  - role restrictions
- Server-side schema validation on every write.

### Layer D: Data + Version Layer
- Extend current ACP tables with content modeling, tokens, assets, and MCP integration control plane.
- Maintain immutable versions and structured diffs.

### Layer E: Observability + Governance
- Expand audit model scope and add query/audit logs for metrics and MCP tool calls.
- Environment promotion for both content and dashboard config remains mandatory.

---

## 4) What to Modify/Add/Develop in Your Current CMS/Dashboard

## 4.1 Database Model Additions
Add these new tables (SQLAlchemy models in `app/models.py`):

1. `AcpContentType`
- `key`, `name`, `schema_json`, `is_enabled`, `environment`, `created_by`, timestamps.

2. `AcpContentTypeVersion`
- `content_type_id`, `version_number`, `snapshot_json`, `change_note`, `created_by`.

3. `AcpContentEntry`
- `content_type_id`, `entry_key`, `status`, `data_json`, `locale`, scheduling fields, publish fields.

4. `AcpContentEntryVersion`
- version snapshots for entries.

5. `AcpThemeTokenSet`
- token set by environment/brand (colors, spacing, typography scale, radius, shadows, z-index, motion defaults).

6. `AcpThemeTokenVersion`
- snapshot and rollback for token sets.

7. `AcpFontAsset`
- font family name, source, fallback stack, licensing metadata.

8. `AcpIconAsset`
- SVG source/sanitized payload, category, tags, usage constraints.

9. `AcpAnimationPreset`
- name, easing, duration, transform/opacity recipe, allowed targets.

10. `AcpNavigationDocument`
- structured menus/links/visibility/locale.

11. `AcpSeoRule`
- route-level and model-level SEO defaults/validation rules.

12. `AcpDashboardSavedView`
- per-user filter state and optional layout presets.

13. `AcpDashboardPersonalization`
- per-role/per-user widget visibility and layout overrides.

14. `AcpDataConnector`
- connector type (`db_view`, `internal_api`, `external_api`, `mcp`), config JSON, status.

15. `AcpMetricQueryLog`
- metric execution logs for traceability/perf.

16. `AcpMcpServer`
- server label, URL, connector mode, auth mode, environment, enabled flag.

17. `AcpMcpToolPolicy`
- allowed tools, approval policy, read/write sensitivity flags.

18. `AcpMcpCredentialRef`
- reference to encrypted secrets (not plain text).

19. `AcpMcpAuditEvent`
- request/approval/call/result/error logs (redacted payloads).

20. `AcpWorkflowComment` and `AcpWorkflowAssignment`
- comments, mentions, assignee, due date, status transitions.

21. `AcpPlugin` and `AcpPluginInstall`
- manifest, entry points, required permissions, enabled/version state.

## 4.2 RBAC Expansion
Current roles are too coarse for your target. Add domain-scoped + attribute-scoped permissions:

- New role families:
  - `viewer`
  - `content_editor`
  - `layout_editor`
  - `designer`
  - `dashboard_editor`
  - `analyst`
  - `developer`
  - `admin`
- Domain permissions:
  - `acp:content_types:*`
  - `acp:content_entries:*`
  - `acp:pages:*`
  - `acp:components_registry:*`
  - `acp:theme:*`
  - `acp:assets:*`
  - `acp:dashboard:*`
  - `acp:widgets_registry:*`
  - `acp:metrics:*`
  - `acp:mcp:*`
  - `acp:plugins:*`
  - `acp:publish`
  - `acp:environments:*`
- Attribute examples:
  - edit only specific content types
  - publish only from stage, not prod
  - dashboard edit without metrics connector edit

## 4.3 API Surface (Admin vs Delivery)

### Admin APIs (authenticated)
Implement in `app/routes/admin.py` (then split into modules):
- `/admin/acp/content-types` (list/create/edit/version)
- `/admin/acp/content-entries` (list/filter/edit/version)
- `/admin/acp/theme`
- `/admin/acp/fonts`
- `/admin/acp/icons`
- `/admin/acp/animations`
- `/admin/acp/navigation`
- `/admin/acp/seo`
- `/admin/acp/widgets`
- `/admin/acp/connectors`
- `/admin/acp/mcp/servers`
- `/admin/acp/mcp/policies`
- `/admin/acp/workflow`
- `/admin/acp/plugins`

### Delivery APIs (public read-only)
Implement in `app/routes/main.py`:
- `/api/delivery/content/<type>/<entry_key>`
- `/api/delivery/theme/<token_set>`
- `/api/delivery/navigation/<name>`
- `/api/delivery/seo/<route>`
- keep existing page/dashboard APIs and add schema version + ETag.

### Internal service APIs
- Metrics query endpoint (admin/internal only) with strict param allowlists.
- MCP proxy endpoint for controlled tool execution with approvals and audit.

## 4.4 UI/Studio Work Required

### Visual Page Builder
Upgrade `app/templates/admin/acp/page_form.html` + JS:
- nested tree editing (not only top-level children)
- breakpoint previews
- inline click-to-edit from preview iframe
- undo/redo stack
- schema-derived prop forms with field-level constraints

### Dashboard Studio
Upgrade `app/templates/admin/acp/dashboard_form.html` + JS:
- real grid drag/resize/snap
- responsive layouts
- filter binding UI
- role-visibility matrix
- saved views and personalization controls

### Design System Control
Add new admin screens:
- token editor with live CSS variable preview
- font manager
- icon picker and SVG sanitization UI
- animation preset manager with guardrails

### Workflow UI
Add comments, mentions, assignee, approval queue, schedule timeline, and rollback diff.

## 4.5 CSS/Frontend Runtime Changes

To truly manage "font color/size/animations/icons" globally:
- Move hardcoded root design values in `app/static/css/style.css` into runtime tokens.
- Inject resolved tokens from ACP into page render (CSS variables in base template).
- Ensure components read from token variables, not hardcoded values.

Files:
- `app/templates/base.html`
- `app/static/css/style.css`
- `app/templates/_hero_slogan.html` and other shared partials

## 4.6 MCP Integration Control Plane

Create ACP module for MCP governance:
- register remote MCP servers and first-party connectors
- per-server allowed tool list
- approval mode:
  - always
  - never
  - selective by tool name
- data redaction rules for logs
- tool execution audit and replay visibility

Key rule:
- never allow token passthrough; always validate intended audience and bind credentials server-side.

---

## 5) Refactoring Plan for Maintainability

Current `app/routes/admin.py` is too large for this scope. Split by domain:

- `app/acp/services/`:
  - `workflow_service.py`
  - `versioning_service.py`
  - `audit_service.py`
  - `schema_validation_service.py`
  - `metrics_service.py`
  - `mcp_service.py`
- `app/acp/serializers/`
- `app/acp/permissions/`
- `app/routes/acp_admin_pages.py`
- `app/routes/acp_admin_dashboards.py`
- `app/routes/acp_admin_content.py`
- `app/routes/acp_admin_design.py`
- `app/routes/acp_admin_mcp.py`

This keeps route handlers thin and testable.

---

## 6) Security and Reliability Requirements (Mandatory)

1. Strict admin/delivery separation (already started; must continue).
2. JSON schema validation server-side for all ACP JSON payloads.
3. Rich text and SVG sanitization hardening.
4. Secret storage for MCP/connectors (no plaintext secrets in DB).
5. CSRF and session hardening on all admin mutations.
6. Rate limiting for admin auth and heavy query endpoints.
7. Audit every mutation with before/after snapshots.
8. Query timeouts, allowlists, and caching in metrics layer.
9. SSRF protections for MCP metadata discovery and connector callbacks.
10. Environment promotion workflow with immutable version references.

---

## 7) Performance Strategy

- Cache delivery payloads with ETag and short TTL + stale-while-revalidate.
- Add DB indexes for `status`, `updated_at`, `environment`, `slug`, `dashboard_id`, and foreign keys.
- Paginate every admin listing by default.
- Use lazy-loaded admin editors (token/icon/animation library screens).
- Precompute dashboard widget query plans where possible.
- Add worker queue for scheduled publishing, heavy imports, and connector sync jobs.

---

## 8) Execution Plan (Recommended)

### Phase 1 (High value, low risk)
- Content type + content entry builder (basic field set).
- Theme token set + runtime CSS variable injection.
- Enhanced page builder nesting + schema validation.
- MCP server registry + approval policy model (no write tools yet).

### Phase 2
- Dashboard Studio grid/snap/responsive + saved views.
- Metrics query service + connector registry.
- Role variants and row-level constraints for dashboard outputs.

### Phase 3
- Fonts/icons/animations managers.
- Workflow comments/mentions/assignment and richer diff UI.
- Plugin SDK and plugin manager.

### Phase 4
- Advanced personalization and A/B hooks.
- Multi-brand token inheritance and locale-theme combinations.

---

## 9) Immediate Implementation Backlog (What I should build next)

1. Add migration-safe models for:
- content types/entries (+ versions)
- theme tokens (+ versions)
- MCP servers/policies/audit

2. Build admin screens:
- `/admin/acp/content-types`
- `/admin/acp/content-entries`
- `/admin/acp/theme`
- `/admin/acp/mcp/servers`

3. Add delivery endpoints:
- `/api/delivery/content/<type>/<entry_key>`
- `/api/delivery/theme/default`

4. Wire runtime tokens into `base.html` and refactor CSS to consume variables.

5. Expand tests in `app/tests/test_security_and_cms.py`:
- permission boundaries
- schema validation failures
- workflow transition checks
- MCP approval/audit flow

---

## 10) Source Links (Official Docs)

### MCP / OpenAI
- MCP architecture: https://modelcontextprotocol.io/specification/2024-11-05/architecture/index
- MCP spec 2025-03-26: https://modelcontextprotocol.io/specification/2025-03-26
- MCP authorization: https://modelcontextprotocol.io/specification/2025-03-26/basic/authorization
- MCP transports: https://modelcontextprotocol.io/specification/2025-03-26/basic/transports
- MCP security best practices: https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices
- OpenAI MCP guide: https://developers.openai.com/api/docs/mcp
- OpenAI connectors + MCP guide: https://developers.openai.com/api/docs/guides/tools-connectors-mcp

### Visual CMS / Governance / Workflows
- Payload live preview: https://payloadcms.com/docs/live-preview
- Payload versions/drafts: https://payloadcms.com/docs/versions/overview/
- Payload access control: https://payloadcms.com/docs/access-control/collections
- Storyblok visual editor: https://www.storyblok.com/docs/concepts/visual-editor
- Storyblok workflows: https://www.storyblok.com/docs/manuals/workflows
- Sanity presentation tool: https://www.sanity.io/docs/configuring-the-presentation-tool
- Sanity overlays/click-to-edit: https://www.sanity.io/docs/visual-editing-overlays
- Strapi draft & publish: https://docs.strapi.io/cms/features/draft-and-publish
- Strapi review workflows: https://docs.strapi.io/cms/features/review-workflows
- Contentful custom roles and permissions: https://www.contentful.com/help/roles/space-roles-and-permissions/custom-roles-and-permissions/
- Contentful environments permissions: https://www.contentful.com/help/roles/space-roles-and-permissions/environments-permissions/
- Contentful scheduled publishing: https://www.contentful.com/help/scheduled-publishing/

### Dashboard / Analytics Platform Patterns
- Directus dashboards: https://docs.directus.io/user-guide/insights/dashboards
- Directus revisions: https://docs.directus.io/reference/system/revisions
- Directus activity log: https://docs.directus.io/reference/system/activity
- Grafana roles and permissions: https://grafana.com/docs/grafana/latest/administration/roles-and-permissions/
- Grafana dashboard permissions: https://grafana.com/docs/grafana/latest/administration/user-management/manage-dashboard-permissions/
- Superset security + dashboard RBAC: https://superset.apache.org/docs/security/
- Superset import/export: https://superset.apache.org/docs/api/import-export
- Metabase collection permissions: https://www.metabase.com/docs/latest/permissions/collections
- Metabase row and column security: https://www.metabase.com/docs/latest/permissions/row-and-column-security
- Metabase serialization (env promotion pattern): https://www.metabase.com/docs/latest/installation-and-operation/serialization

### Design Tokens
- DTCG stable spec announcement (W3C CG): https://www.w3.org/community/design-tokens/
- DTCG home/spec resources: https://www.designtokens.org/
- Figma variables guide: https://help.figma.com/hc/en-us/articles/15339657135383-Guide-to-variables-in-Figma
- Figma import modes for variables (DTCG JSON format): https://help.figma.com/hc/en-us/articles/15343816063383-Modes-for-variables
