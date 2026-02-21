# SEO Executive Marketing Plan

Date: 2026-02-21
Scope: All service detail pages (`/services/<slug>`) with deeper positioning for technical repair pages

## Deep Research Scope (20+ Competitors)

### A) Top IT Services / MSP Leaders (Ranking Signals)

Primary ranking sources reviewed:
- Channel Futures MSP 501 (2025) and top-50 breakout examples
- CRN MSP 500 (2025)
- CRN Elite 150 (2024)

Competitor set captured from ranking pages and leader profiles:
1. Ensono (MSP 501 #1)
2. Zayo Group (MSP 501 #2)
3. Expedient (MSP 501 top cohort)
4. Assured Data Protection (MSP 501 top cohort)
5. Fifosys (MSP 501 top cohort)
6. Align (MSP 501 rank #26)
7. BCA IT (MSP 501 rank #42)
8. Spectrotel (CRN MSP 500 rank #33)
9. Netgain (CRN MSP 500 rank #38)
10. NexusTek (CRN MSP 500)
11. Sentinel Technologies (CRN MSP 500)
12. Anunta (CRN MSP 500 top 100 reference)
13. Integris (managed IT competitor signal set)

### B) Top Data Recovery Competitors (Ranking Signals)

Primary ranking sources reviewed:
- Forbes Advisor: Best Data Recovery Services (2026)
- TechRadar: Best Data Recovery Services (2024)

Competitor set captured:
14. CBL Data Recovery
15. Ontrack Data Recovery
16. SalvageData Recovery Services
17. DriveSavers Data Recovery
18. Seagate In-Lab Data Recovery
19. Stellar Data Recovery
20. WeRecoverData
21. Disk Doctors

### C) Top Computer / Mobile Repair Competitors (Nationwide Signals)

Primary ranking/scale signals reviewed:
- Entrepreneur Franchise 500 (CPR ranking mention)
- Official location scale and service-positioning pages

Competitor set captured:
22. CPR Cell Phone Repair (franchise-ranked + 850+ stores claim)
23. uBreakiFix by Asurion (700+ store footprint signal)
24. Batteries Plus (700+ US locations signal)
25. iFixandRepair (700+ location footprint signal)
26. Geek Squad (nationwide device service offering)

## Competitive SEO Patterns Observed

### High-performing page architecture
- Intent-aligned H1 + title with service + location + commercial modifier.
- Trust-first hero (speed, warranty/assurance, security/compliance, clear process).
- Programized service modules (not generic bullets): specific sub-services and outcomes.
- Conversion framing on every viewport depth (assessment, message, remote support).
- Strong internal clusters (related services, industries, related posts) for topical authority.

### Data recovery-specific ranking patterns
- Explicit emergency language (`24/7`, `priority`, `expedited` pathways).
- Confidence framing (`no data, no fee`, secure handling, encrypted delivery).
- Technical specificity (`RAID`, `NAS`, `SSD`, `cleanroom`, `forensic workflow`).
- Chain-of-custody and integrity validation messaging for business/legal trust.

### Computer/mobile repair-specific ranking patterns
- Short-turnaround positioning (same-day triage and common repairs).
- Component-level intent keywords (screen, battery, charging port, motherboard, HDMI).
- Quality assurance hooks (post-repair testing, warranty-backed repair, data-safe handling).
- Brand-compatible service mapping (Apple/Samsung/Dell/etc.) for branded search capture.

## Keyword Cluster Strategy Applied

Per service page, we expanded from generic terms to multi-intent clusters:
- Core commercial: `service + company/provider + location`
- Problem/issue intent: `symptom + repair/recovery/fix`
- Component intent: `battery/screen/RAID/port/thermal/etc.`
- Buyer confidence intent: `warranty`, `same-day`, `secure`, `managed`, `compliance`
- B2B intent: `business`, `enterprise`, `SLA`, `managed`, `governance`

## Implementation Plan (Executed)

### 1) Service profile SEO overlays
- Added `app/service_seo_overrides.py`.
- Created research-driven overlays for **every** service slug.
- For each page, added:
  - `meta_title`
  - expanded keyword clusters
  - positioning badge
  - hero trust badges
  - specialized service module cards
  - long-form narrative blocks for intent depth
  - upgraded proof points (and for repair, stronger trust handling language)

### 2) Route-level profile merge logic
- Updated `app/routes/main.py`:
  - imports SEO overlays
  - merges overlays into default profiles when no custom DB profile exists
  - normalizes new fields (`meta_title`, `positioning_badge`, `hero_badges`, `service_modules`, `narrative_title`, `seo_content_blocks`)

### 3) Service template upgrades
- Updated `app/templates/service_detail.html`:
  - title and OG title now use per-service `meta_title`
  - added hero positioning badge + service trust badges
  - added new `Service Scope` module section
  - added new `Service Positioning` narrative section
  - enriched WebPage schema with keyword serialization

## KPI Targets (90 Days)

- +30% organic entrances to `/services/*` pages
- +25% increase in technical repair page entrances
- +20% increase in contact/quote conversion rate from service pages
- +30% internal click-through from service pages to related services/industries
- Broader Search Console impression coverage for long-tail service-intent queries

## Next SEO Iterations

1. Add service-specific case studies and proof snippets per slug.
2. Add city-intent support pages only where Search Console confirms demand.
3. Add service-by-service conversion event tracking reports in GA4 and Search Console.
4. Build FAQ expansion from live sales/support query logs every month.
