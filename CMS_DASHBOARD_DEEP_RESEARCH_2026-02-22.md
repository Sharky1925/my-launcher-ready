# CMS + Dashboard Deep Research (2026-02-22)

## Objective
Define a research-backed plan to improve the current CMS and deliver an integrated admin dashboard that manages content, leads, support operations, and security from one place.

## Research Method
- Reviewed official documentation from major CMS platforms and workflow/dashboard tooling.
- Focused on common capabilities that repeatedly appear in top platforms:
  - role-based access and governance,
  - editorial workflow/review stages,
  - release and publishing controls,
  - dashboard insights and operational queues,
  - content quality and SEO readiness checks.

## Competitor/Platform Set
1. WordPress
2. Drupal
3. Strapi
4. Contentful
5. Directus
6. Sanity
7. Webflow CMS
8. Storyblok
9. Ghost
10. Joomla

## What Top CMS Platforms Consistently Do

### 1) Workflow + Publishing Controls
- Editorial states and moderation workflows (draft/review/published).
- Scheduled publishing and release orchestration.
- Versioning and content review checkpoints.

### 2) Governance + Access
- Role-based permissions and scoped access to content and operations.
- Admin/user role separation for security and accountability.

### 3) Integrated Operational Dashboards
- One-screen visibility for key queues (leads, tickets, unresolved tasks).
- KPIs and trend snapshots (content health, traffic/signal proxies, support backlog).
- Fast navigation to the exact record that needs action.

### 4) Content Quality + SEO Signals
- Metadata completeness checks and publish-readiness guardrails.
- “What is missing” surfaced as actionable tasks (not hidden in forms).

## Gap Analysis Against Current CMS

## Existing Strengths
- Strong CRUD coverage across services, industries, posts, media, contacts, tickets, users.
- Security event logging and rate-limiting signals already present.
- Clean admin UI baseline with clear navigation.

## Gaps Identified
- Dashboard was mostly metric cards + two recent tables, not a command center.
- No unified search from the dashboard across all major entities.
- Limited operational prioritization (urgent tickets, unread leads, stale drafts).
- Limited quality visibility (SEO/content completeness surfaced only inside edit screens).

## Implementation Applied in This Iteration

### 1) Integrated Control Center on `/admin`
- Replaced basic dashboard with a unified operations dashboard that includes:
  - CMS + operations health score,
  - unread leads and support queue metrics,
  - quote/support pipeline split,
  - security snapshot,
  - content + SEO quality issue counters.

### 2) Actionable Operational Queues
- Added dedicated queue sections for:
  - urgent high/critical tickets,
  - unread contact submissions,
  - stale draft posts (14+ days old).

### 3) CMS Health Panel
- Added issue-based health checks for:
  - content structure completeness,
  - SEO readiness,
  - response backlog,
  - security watchlist.
- Added missing-settings visibility for critical global metadata fields.

### 4) Support + Demand Visibility
- Added ticket status stack view.
- Added top requested service list based on ticket demand.

### 5) Unified Search
- Added dashboard-level search across:
  - services,
  - industries,
  - posts,
  - contacts,
  - support tickets.

### 6) Unified Activity Feed
- Added cross-entity activity timeline (contacts, tickets, posts, security events).

## Phase-2 Recommendations (Next)

1. Introduce explicit editorial states for posts/services/industries (`draft`, `review`, `approved`, `published`).
2. Add scheduled publishing for posts and service-page updates.
3. Add field-level “publish blockers” for required SEO fields before publish.
4. Add role tiers (`content_editor`, `ops_manager`, `security_admin`) with per-module permissions.
5. Add change history/audit trail for critical content models.
6. Add dashboard trend charts (7/30-day volume trends for leads/tickets/security events).

## Primary Sources
- W3Techs CMS usage statistics: https://w3techs.com/technologies/overview/content_management
- WordPress dashboard docs: https://wordpress.org/documentation/article/dashboard-screen/
- WordPress site health docs: https://wordpress.org/documentation/article/site-health-screen/
- Drupal workflows + content moderation: https://www.drupal.org/docs/core-modules-and-themes/core-modules/workflows-module
- Strapi review workflows: https://strapi.io/features/review-workflows
- Strapi releases: https://strapi.io/features/releases
- Contentful workflows app: https://www.contentful.com/marketplace/workflows/
- Contentful roles + permissions: https://www.contentful.com/help/roles/creating-and-editing-roles/
- Directus dashboards guide: https://directus.io/docs/guides/dashboards/getting-started-with-dashboards
- Directus insights: https://directus.io/docs/guides/dashboards/insights
- Sanity custom workflows: https://www.sanity.io/docs/studio/custom-workflows
- Sanity roles: https://www.sanity.io/docs/user-guides/roles
- Webflow editor mode: https://help.webflow.com/hc/en-us/articles/33961242329939-Editor-mode
- Webflow account roles: https://help.webflow.com/hc/en-us/articles/33961330918035-Account-level-roles
- Storyblok content stages: https://www.storyblok.com/docs/concepts/content-stages
- Ghost user roles: https://ghost.org/help/organising-your-team/
- Joomla workflows: https://docs.joomla.org/Category:Workflows
