import json
import re

try:
    from .models import (
        AcpPageDocument,
        AcpPageRouteBinding,
        WORKFLOW_DRAFT,
        WORKFLOW_PUBLISHED,
        db,
    )
    from .utils import utc_now_naive
except ImportError:  # pragma: no cover - fallback when running from app/ cwd
    from models import (
        AcpPageDocument,
        AcpPageRouteBinding,
        WORKFLOW_DRAFT,
        WORKFLOW_PUBLISHED,
        db,
    )
    from utils import utc_now_naive


SYSTEM_ROUTE_RULES = {
    '/healthz',
    '/readyz',
    '/robots.txt',
    '/sitemap.xml',
}
EXCLUDED_RULE_PREFIXES = (
    '/admin/',
    '/api/',
    '/static/',
)
EXCLUDED_ENDPOINT_PREFIXES = (
    'admin.',
    'static',
)
PAGE_RULE_TO_SLUG = {
    '/': 'home',
    '/about': 'about',
    '/services': 'services',
    '/services/it-services': 'services-it-track',
    '/services/repair-services': 'services-repair-track',
    '/services/<slug>': 'service-detail',
    '/blog': 'blog',
    '/blog/<slug>': 'blog-post',
    '/industries': 'industries',
    '/industries/<slug>': 'industry-detail',
    '/remote-support': 'remote-support',
    '/ticket-search': 'ticket-search',
    '/ticket-status': 'ticket-search',
    '/request-quote': 'request-quote',
    '/request-quote/personal': 'request-quote-personal',
    '/contact': 'contact',
}
PAGE_TEMPLATE_HINTS = {
    '/': 'home-landing',
    '/services/<slug>': 'service-detail',
    '/blog/<slug>': 'blog-post',
    '/industries/<slug>': 'industry-detail',
    '/remote-support': 'remote-support',
    '/ticket-search': 'ticket-search',
    '/ticket-status': 'ticket-search',
}


def _to_json(value, fallback):
    try:
        return json.dumps(value, ensure_ascii=False)
    except (TypeError, ValueError):
        return json.dumps(fallback, ensure_ascii=False)


def _build_default_page_document(slug, route_rule, endpoint):
    title = re.sub(r'[-_]+', ' ', slug).strip().title() or 'Managed Page'
    template_id = PAGE_TEMPLATE_HINTS.get(route_rule, 'managed-template')
    seo = {
        'title': title,
        'description': f'Managed page document for route {route_rule}.',
        'canonical_route': route_rule,
        'endpoint': endpoint,
    }
    blocks_tree = {
        'type': 'layout.container',
        'props': {
            'maxWidth': '1200px',
            'paddingY': '32px',
            'managedBy': 'msc-mcp-sync',
        },
        'children': [
            {
                'type': 'marketing.hero',
                'props': {
                    'title': title,
                    'subtitle': f'Auto-registered page document for {route_rule}.',
                    'primaryCtaLabel': 'Contact Us',
                    'primaryCtaHref': '/contact',
                },
            }
        ],
    }
    return AcpPageDocument(
        slug=slug,
        title=title,
        template_id=template_id,
        locale='en-US',
        status=WORKFLOW_DRAFT,
        seo_json=_to_json(seo, {}),
        blocks_tree=_to_json(blocks_tree, {}),
        theme_override_json='{}',
    )


def _is_candidate_public_route(rule):
    if rule in SYSTEM_ROUTE_RULES:
        return False
    for prefix in EXCLUDED_RULE_PREFIXES:
        if rule.startswith(prefix):
            return False
    return True


def _collect_page_routes(flask_app):
    entries = []
    for rule in flask_app.url_map.iter_rules():
        endpoint = (rule.endpoint or '').strip()
        if not endpoint.startswith('main.'):
            continue
        if endpoint.startswith(EXCLUDED_ENDPOINT_PREFIXES):
            continue
        methods = sorted(m for m in (rule.methods or set()) if m not in {'HEAD', 'OPTIONS'})
        if 'GET' not in methods:
            continue
        route_rule = str(rule.rule or '').strip()
        if not route_rule or not _is_candidate_public_route(route_rule):
            continue
        entries.append(
            {
                'rule': route_rule,
                'endpoint': endpoint,
                'methods': methods,
                'is_dynamic': '<' in route_rule and '>' in route_rule,
                'expected_slug': PAGE_RULE_TO_SLUG.get(route_rule, ''),
            }
        )
    entries.sort(key=lambda item: item['rule'])
    return entries


def _sync_state_for_route(expected_slug, page_document):
    if not expected_slug:
        return 'unmapped_route', 'No page registry mapping configured for this route.'
    if not page_document:
        return 'missing_page_document', f'No page document exists for slug "{expected_slug}".'
    if page_document.status != WORKFLOW_PUBLISHED:
        return 'unpublished_page_document', (
            f'Page slug "{expected_slug}" exists but status is "{page_document.status}".'
        )
    return 'synced', ''


def run_page_route_sync(flask_app, *, auto_register=False, persist=False):
    now = utc_now_naive()
    route_inventory = _collect_page_routes(flask_app)
    page_documents = AcpPageDocument.query.order_by(AcpPageDocument.slug.asc()).all()
    page_by_slug = {item.slug: item for item in page_documents}
    bindings_by_rule = {}
    if persist:
        bindings = AcpPageRouteBinding.query.all()
        bindings_by_rule = {binding.route_rule: binding for binding in bindings}

    sync_rows = []
    expected_slugs = set()
    auto_registered_pages = []
    for route in route_inventory:
        route_rule = route['rule']
        expected_slug = route['expected_slug']
        if expected_slug:
            expected_slugs.add(expected_slug)
        page_document = page_by_slug.get(expected_slug) if expected_slug else None

        if auto_register and persist and expected_slug and page_document is None:
            page_document = _build_default_page_document(
                expected_slug,
                route_rule,
                route['endpoint'],
            )
            db.session.add(page_document)
            db.session.flush()
            page_by_slug[expected_slug] = page_document
            auto_registered_pages.append(expected_slug)

        sync_status, issue = _sync_state_for_route(expected_slug, page_document)
        row = {
            'rule': route_rule,
            'endpoint': route['endpoint'],
            'methods': route['methods'],
            'is_dynamic': route['is_dynamic'],
            'expected_slug': expected_slug,
            'page_id': page_document.id if page_document else None,
            'page_status': page_document.status if page_document else '',
            'sync_status': sync_status,
            'issue': issue,
        }
        sync_rows.append(row)

        if persist:
            binding = bindings_by_rule.get(route_rule)
            if not binding:
                binding = AcpPageRouteBinding(route_rule=route_rule)
                db.session.add(binding)
                bindings_by_rule[route_rule] = binding
            binding.endpoint = route['endpoint']
            binding.methods_json = _to_json(route['methods'], [])
            binding.page_slug = expected_slug or None
            binding.page_id = page_document.id if page_document else None
            binding.sync_status = sync_status
            binding.issue_detail = issue[:320] if issue else None
            binding.is_dynamic = bool(route['is_dynamic'])
            binding.is_active = True
            binding.last_seen_at = now

    orphan_bindings = []
    if persist:
        scanned_rules = {row['rule'] for row in sync_rows}
        for binding in bindings_by_rule.values():
            if binding.route_rule in scanned_rules:
                continue
            binding.sync_status = 'orphan_route_binding'
            binding.issue_detail = 'Route no longer exists in Flask url_map.'
            binding.is_active = False
            binding.updated_at = now
            orphan_bindings.append(
                {
                    'route_rule': binding.route_rule,
                    'endpoint': binding.endpoint,
                    'page_slug': binding.page_slug,
                    'sync_status': binding.sync_status,
                }
            )

    mapped_slugs = {slug for slug in expected_slugs if slug}
    orphan_pages = []
    for page in page_documents:
        if page.slug in mapped_slugs:
            continue
        orphan_pages.append(
            {
                'id': page.id,
                'slug': page.slug,
                'title': page.title,
                'status': page.status,
            }
        )
    orphan_pages.sort(key=lambda item: item['slug'])

    totals = {
        'routes_scanned': len(sync_rows),
        'synced': sum(1 for row in sync_rows if row['sync_status'] == 'synced'),
        'missing_page_document': sum(1 for row in sync_rows if row['sync_status'] == 'missing_page_document'),
        'unpublished_page_document': sum(1 for row in sync_rows if row['sync_status'] == 'unpublished_page_document'),
        'unmapped_route': sum(1 for row in sync_rows if row['sync_status'] == 'unmapped_route'),
        'orphan_bindings': len(orphan_bindings),
        'orphan_pages': len(orphan_pages),
        'auto_registered_pages': len(auto_registered_pages),
    }

    if persist:
        db.session.commit()

    return {
        'generated_at': now,
        'totals': totals,
        'routes': sync_rows,
        'orphan_bindings': orphan_bindings,
        'orphan_pages': orphan_pages,
        'auto_registered_pages': auto_registered_pages,
    }
