# MSC ↔ MCP ↔ Webapp Sync Architecture (Thin Slice, Implemented)

## 1) Canonical Models
- Page document (MSC source of truth): `AcpPageDocument`
  - key fields: `slug`, `template_id`, `status`, `seo_json`, `blocks_tree`, `theme_override_json`, version metadata.
- Route registry (new): `AcpPageRouteBinding`
  - key fields: `route_rule`, `endpoint`, `methods_json`, `page_slug`, `page_id`, `sync_status`, `is_active`, `last_seen_at`.

## 2) Ownership Boundaries
- MSC owns:
  - `AcpPageDocument`, `AcpContentType`, `AcpContentEntry`, `AcpThemeTokenSet`
- MCP/Dashboard owns:
  - `AcpDashboardDocument`, `AcpWidgetDefinition`, `AcpMetricDefinition`, role visibility rules
- Sync layer owns:
  - route introspection and route↔page consistency status (`AcpPageRouteBinding`)

## 3) Data Flow
1. Route inventory extracted from Flask `url_map` for public `main.*` GET routes.
2. Each route mapped to expected page slug by rule map.
3. Registry binding upserted with sync status:
   - `synced`
   - `missing_page_document`
   - `unpublished_page_document`
   - `unmapped_route`
   - `orphan_route_binding`
4. Optional auto-register creates missing `AcpPageDocument` in `draft`.
5. ACP audit event recorded for each sync execution.

## 4) Admin Operations
- Sync status screen: `/admin/acp/sync-status`
- Manual actions: `/admin/acp/sync-status/resync`
  - `action=scan`: recompute and persist bindings.
  - `action=autoregister`: scan + create missing page docs.
- UI includes:
  - route scan table
  - orphan pages table
  - stored route bindings table
  - sync counters and status badges

## 5) Rendering Contract (Current + Next)
- Current delivery:
  - Core public pages still rendered from existing route handlers/templates.
  - Delivery APIs expose published page/theme/content/dashboard documents.
- Next target (planned):
  - progressive rendering from `AcpPageDocument.blocks_tree` for selected routes behind feature flag.

## 6) Consistency Rules Enforced
- Every public route can be inspected against expected MSC slug.
- Every sync run is deterministic and auditable.
- Missing pages are visible and remediable.
- Unpublished docs are reported as sync risk for live-route governance.

## 7) Deterministic Consistency Check
- Engine: `run_page_route_sync()` in `/Users/umutdemirkapu/mylauncher/app/page_sync.py`
- Inputs: Flask route map + page documents + existing bindings
- Outputs: full report object with totals, per-route state, orphan bindings/pages, and auto-registered docs.

## 8) Residual Gap (Known)
- Thin-slice currently synchronizes and governs route/document inventory.
- Full runtime rendering of every route from page documents is not yet complete for all legacy templates and dynamic detail routes.
