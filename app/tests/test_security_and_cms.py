import re
import hashlib
import uuid
from datetime import timedelta

import pytest

try:
    from app import notifications as notifications_module
    from app.seed import backfill_phase2_defaults, seed_database
    from app.routes import admin as admin_routes
    from app.routes import main as main_routes
    from app import create_app
    from app.models import (
        Category,
        ContactSubmission,
        Post,
        Service,
        SiteSetting,
        User,
        SupportClient,
        SupportTicket,
        SupportTicketEvent,
        SupportTicketEmailVerification,
        AuthRateLimitBucket,
        SecurityEvent,
        AcpPageDocument,
        AcpPageRouteBinding,
        AcpDashboardDocument,
        AcpContentType,
        AcpContentEntry,
        AcpThemeTokenSet,
        AcpMcpServer,
        AcpMcpOperation,
        Industry,
        WORKFLOW_APPROVED,
        WORKFLOW_PUBLISHED,
        WORKFLOW_DRAFT,
        ROLE_EDITOR,
        ROLE_SUPPORT,
        SUPPORT_TICKET_STATUS_IN_PROGRESS,
        SUPPORT_TICKET_STATUS_RESOLVED,
        SUPPORT_TICKET_STATUS_CLOSED,
        db,
    )
    from app.utils import utc_now_naive
except ModuleNotFoundError:  # pragma: no cover - fallback for direct app/ cwd test runs
    import notifications as notifications_module
    from seed import backfill_phase2_defaults, seed_database
    import routes.admin as admin_routes
    import routes.main as main_routes
    from __init__ import create_app
    from models import (
        Category,
        ContactSubmission,
        Post,
        Service,
        SiteSetting,
        User,
        SupportClient,
        SupportTicket,
        SupportTicketEvent,
        SupportTicketEmailVerification,
        AuthRateLimitBucket,
        SecurityEvent,
        AcpPageDocument,
        AcpPageRouteBinding,
        AcpDashboardDocument,
        AcpContentType,
        AcpContentEntry,
        AcpThemeTokenSet,
        AcpMcpServer,
        AcpMcpOperation,
        Industry,
        WORKFLOW_APPROVED,
        WORKFLOW_PUBLISHED,
        WORKFLOW_DRAFT,
        ROLE_EDITOR,
        ROLE_SUPPORT,
        SUPPORT_TICKET_STATUS_IN_PROGRESS,
        SUPPORT_TICKET_STATUS_RESOLVED,
        SUPPORT_TICKET_STATUS_CLOSED,
        db,
    )
    from utils import utc_now_naive

CSRF_TOKEN_RE = re.compile(r'name="_csrf_token" value="([^"]+)"')


def extract_csrf_token(html):
    match = CSRF_TOKEN_RE.search(html or "")
    return match.group(1) if match else None


def build_test_app(tmp_path, monkeypatch, overrides=None):
    db_path = tmp_path / f"site_test_{uuid.uuid4().hex[:8]}.db"
    upload_path = tmp_path / f"uploads_{uuid.uuid4().hex[:8]}"

    monkeypatch.setenv("ADMIN_PASSWORD", "admin123")

    config = {
        "TESTING": True,
        "SECRET_KEY": "test-secret-key",
        "SQLALCHEMY_DATABASE_URI": f"sqlite:///{db_path}",
        "UPLOAD_FOLDER": str(upload_path),
        "TURNSTILE_SITE_KEY": "",
        "TURNSTILE_SECRET_KEY": "",
    }
    if overrides:
        config.update(overrides)

    app = create_app(config)
    with app.app_context():
        AuthRateLimitBucket.query.delete()
        db.session.commit()
    return app


@pytest.fixture()
def app(tmp_path, monkeypatch):
    return build_test_app(tmp_path, monkeypatch)


@pytest.fixture()
def client(app):
    return app.test_client()


def admin_login(client):
    return admin_login_as(client, "admin", "admin123")


def admin_login_as(client, username, password):
    login_page = client.get("/admin/login")
    csrf_token = extract_csrf_token(login_page.get_data(as_text=True))
    assert csrf_token

    response = client.post(
        "/admin/login",
        data={
            "_csrf_token": csrf_token,
            "username": username,
            "password": password,
        },
        follow_redirects=False,
    )
    assert response.status_code in (302, 303)


def test_public_pages_and_security_headers(client):
    response = client.get("/")
    assert response.status_code == 200
    assert "Content-Security-Policy" in response.headers
    csp = response.headers.get("Content-Security-Policy", "")
    server_timing = response.headers.get("Server-Timing", "")
    assert "script-src 'self' 'nonce-" in csp
    assert "script-src 'self' 'unsafe-inline'" not in csp
    assert "style-src 'self' 'nonce-" in csp
    assert "style-src 'self' 'unsafe-inline'" not in csp
    assert server_timing.startswith("app;dur=")
    assert response.headers.get("X-Frame-Options") == "DENY"
    assert response.headers.get("X-Content-Type-Options") == "nosniff"
    assert response.headers.get("Cross-Origin-Resource-Policy") == "same-origin"
    assert response.headers.get("X-Permitted-Cross-Domain-Policies") == "none"
    assert response.headers.get("Origin-Agent-Cluster") == "?1"
    html = response.get_data(as_text=True)
    assert 'href="#main-content"' in html
    assert 'id="main-content"' in html
    assert 'class="navbar navbar-expand-lg navbar-main"' in html
    assert 'aria-label="Toggle navigation menu"' not in html
    assert '<script nonce="' in html
    assert "style=" not in html

    for path in ["/about", "/services", "/blog", "/industries", "/remote-support", "/contact", "/request-quote"]:
        page = client.get(path)
        assert page.status_code == 200
    assert client.get("/remote-support").headers.get("X-Robots-Tag") == "noindex, nofollow, noarchive"

    admin_login_page = client.get("/admin/login")
    assert admin_login_page.status_code == 200
    assert admin_login_page.headers.get("X-Robots-Tag") == "noindex, nofollow, noarchive"
    admin_login_html = admin_login_page.get_data(as_text=True)
    assert '<style nonce="' in admin_login_html
    assert "style=" not in admin_login_html


def test_theme_script_falls_back_to_server_default_mode(client):
    response = client.get("/")
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "root.getAttribute('data-theme')" in html
    assert "window.matchMedia&&window.matchMedia('(prefers-color-scheme: dark)').matches" in html


def test_theme_css_vars_scope_dark_only_for_single_palette_tokens(client, app):
    with app.app_context():
        setting = SiteSetting.query.filter_by(key="theme_mode").first()
        if setting is None:
            setting = SiteSetting(key="theme_mode", value="light")
            db.session.add(setting)
        else:
            setting.value = "light"

        token_set = AcpThemeTokenSet.query.filter_by(key="default").first()
        if token_set is None:
            token_set = AcpThemeTokenSet(
                key="default",
                name="Default Theme",
                status=WORKFLOW_PUBLISHED,
                tokens_json='{"css_vars":{"--bg-gradient":"linear-gradient(180deg, #000000, #111111)","--font-body":"\'Manrope\', sans-serif"}}',
                published_at=utc_now_naive(),
            )
            db.session.add(token_set)
        else:
            token_set.status = WORKFLOW_PUBLISHED
            token_set.tokens_json = '{"css_vars":{"--bg-gradient":"linear-gradient(180deg, #000000, #111111)","--font-body":"\'Manrope\', sans-serif"}}'
        db.session.commit()

    response = client.get("/")
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "html {" in html
    assert "[data-theme=\"dark\"] {" in html
    assert "--bg-gradient: linear-gradient(180deg, #000000, #111111);" in html
    assert ":root {" not in html


def test_admin_dashboard_control_center_search_renders(client):
    admin_login(client)
    response = client.get("/admin/?q=service")
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "Unified Control Center" in html
    assert "Unified Search Results" in html


def test_dashboard_content_structure_uses_profile_fallback_registry(client):
    admin_login(client)
    response = client.get("/admin/")
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    match = re.search(
        r'Content Structure</span>\s*<span class="check-badge [^"]+">(\d+) issue',
        html,
    )
    assert match is not None
    assert int(match.group(1)) == 0


def test_admin_control_center_two_main_sections_render(client):
    admin_login(client)
    response = client.get("/admin/control-center")
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "Two Main Sections: Website Studio + Operations Hub" in html
    assert "1. Website Studio" in html
    assert "2. Operations Hub" in html
    assert "Theme, Fonts, Icons, Motion" in html
    assert "Support Tickets" in html


def test_acp_studio_pages_and_dashboards_render_for_admin(client):
    admin_login(client)
    studio = client.get("/admin/acp/studio")
    assert studio.status_code == 200
    studio_html = studio.get_data(as_text=True)
    assert "Application Control Platform" in studio_html

    pages = client.get("/admin/acp/pages")
    assert pages.status_code == 200
    assert "Page Documents" in pages.get_data(as_text=True)

    dashboards = client.get("/admin/acp/dashboards")
    assert dashboards.status_code == 200
    assert "Dashboard Documents" in dashboards.get_data(as_text=True)


def test_acp_sync_status_scan_and_autoregister(client, app):
    admin_login(client)

    sync_page = client.get("/admin/acp/sync-status")
    assert sync_page.status_code == 200
    sync_html = sync_page.get_data(as_text=True)
    assert "Route ↔ MSC Page Registry Sync" in sync_html
    csrf_token = extract_csrf_token(sync_html)
    assert csrf_token

    sync_action = client.post(
        "/admin/acp/sync-status/resync",
        data={"_csrf_token": csrf_token, "action": "autoregister"},
        follow_redirects=False,
    )
    assert sync_action.status_code in (302, 303)

    with app.app_context():
        binding = AcpPageRouteBinding.query.filter_by(route_rule="/services").first()
        assert binding is not None
        assert binding.page_slug == "services"
        assert binding.sync_status == "synced"

        managed_page = AcpPageDocument.query.filter_by(slug="services").first()
        assert managed_page is not None
        verify_binding = AcpPageRouteBinding.query.filter_by(route_rule="/ticket-verify").first()
        assert verify_binding is not None
        assert verify_binding.page_slug == "ticket-search"
        assert verify_binding.sync_status == "synced"


def test_acp_page_form_includes_visual_block_builder(client, app):
    admin_login(client)
    with app.app_context():
        page = AcpPageDocument.query.order_by(AcpPageDocument.id.asc()).first()
        assert page is not None
        page_id = page.id

    response = client.get(f"/admin/acp/pages/{page_id}/edit")
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "Visual Block Builder (Drag and Drop)" in html
    assert "Registered Components" in html


def test_acp_dashboard_preview_applies_role_visibility(client, app):
    with app.app_context():
        dashboard = AcpDashboardDocument(
            dashboard_id=f"preview-{uuid.uuid4().hex[:8]}",
            title="Preview Visibility Test",
            route=f"/dashboard/preview-{uuid.uuid4().hex[:8]}",
            layout_type="grid",
            status=WORKFLOW_DRAFT,
            layout_config_json='{\"columns\":12}',
            widgets_json=(
                '[{\"id\":\"open-widget\",\"type\":\"kpi-card\",\"title\":\"Open Widget\",\"metric\":\"support_open_tickets\"},'
                '{\"id\":\"hidden-widget\",\"type\":\"kpi-card\",\"title\":\"Top Secret KPI\",\"metric\":\"secret_metric\"}]'
            ),
            global_filters_json='[]',
            role_visibility_json='{\"support\":{\"hiddenWidgets\":[\"hidden-widget\"]}}',
        )
        db.session.add(dashboard)
        db.session.commit()
        dashboard_row_id = dashboard.id

    admin_login(client)
    response = client.get(f"/admin/acp/dashboards/{dashboard_row_id}/preview?role=support")
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "Open Widget" in html
    assert "Top Secret KPI" not in html


def test_acp_delivery_api_returns_only_published_documents(client, app):
    published_slug = f"published-page-{uuid.uuid4().hex[:8]}"
    draft_slug = f"draft-page-{uuid.uuid4().hex[:8]}"
    published_dashboard_id = f"ops-{uuid.uuid4().hex[:8]}"
    draft_dashboard_id = f"draft-{uuid.uuid4().hex[:8]}"

    with app.app_context():
        db.session.add(AcpPageDocument(
            slug=published_slug,
            title="Published Test Page",
            template_id="landing-v1",
            locale="en-US",
            status=WORKFLOW_PUBLISHED,
            seo_json='{\"title\":\"Published\"}',
            blocks_tree='{\"type\":\"Container\"}',
            theme_override_json='{}',
            published_at=utc_now_naive(),
        ))
        db.session.add(AcpPageDocument(
            slug=draft_slug,
            title="Draft Test Page",
            template_id="landing-v1",
            locale="en-US",
            status=WORKFLOW_DRAFT,
            seo_json='{\"title\":\"Draft\"}',
            blocks_tree='{\"type\":\"Container\"}',
            theme_override_json='{}',
        ))
        db.session.add(AcpDashboardDocument(
            dashboard_id=published_dashboard_id,
            title="Published Dashboard",
            route=f"/dashboard/{published_dashboard_id}",
            layout_type="grid",
            status=WORKFLOW_PUBLISHED,
            layout_config_json='{\"columns\":12}',
            widgets_json='[]',
            global_filters_json='[]',
            role_visibility_json='{}',
            published_at=utc_now_naive(),
        ))
        db.session.add(AcpDashboardDocument(
            dashboard_id=draft_dashboard_id,
            title="Draft Dashboard",
            route=f"/dashboard/{draft_dashboard_id}",
            layout_type="grid",
            status=WORKFLOW_DRAFT,
            layout_config_json='{\"columns\":12}',
            widgets_json='[]',
            global_filters_json='[]',
            role_visibility_json='{}',
        ))
        db.session.commit()

    published_page_resp = client.get(f"/api/delivery/pages/{published_slug}")
    assert published_page_resp.status_code == 200
    assert published_page_resp.get_json()["slug"] == published_slug
    assert "stale-while-revalidate=" in (published_page_resp.headers.get("Cache-Control") or "")
    page_etag = published_page_resp.headers.get("ETag")
    assert page_etag
    published_page_cached = client.get(
        f"/api/delivery/pages/{published_slug}",
        headers={"If-None-Match": page_etag},
    )
    assert published_page_cached.status_code == 304

    draft_page_resp = client.get(f"/api/delivery/pages/{draft_slug}")
    assert draft_page_resp.status_code == 404

    published_dash_resp = client.get(f"/api/delivery/dashboards/{published_dashboard_id}")
    assert published_dash_resp.status_code == 200
    assert published_dash_resp.get_json()["dashboard_id"] == published_dashboard_id
    assert published_dash_resp.headers.get("ETag")

    draft_dash_resp = client.get(f"/api/delivery/dashboards/{draft_dashboard_id}")
    assert draft_dash_resp.status_code == 404


def test_acp_phase1_admin_sections_render(client):
    admin_login(client)
    assert client.get("/admin/acp/content-types").status_code == 200
    assert client.get("/admin/acp/content-entries").status_code == 200
    assert client.get("/admin/acp/theme").status_code == 200
    assert client.get("/admin/acp/theme/new").status_code == 200
    assert client.get("/admin/acp/mcp/servers").status_code == 200
    assert client.get("/admin/acp/mcp/operations").status_code == 200
    assert client.get("/admin/acp/mcp/audit").status_code == 200

    with client.application.app_context():
        token_set = AcpThemeTokenSet.query.first()
        assert token_set is not None
        token_id = token_set.id
    assert client.get(f"/admin/acp/theme/{token_id}/edit").status_code == 200


def test_acp_mcp_server_rejects_invalid_url_scheme(client, app):
    admin_login(client)
    page = client.get("/admin/acp/mcp/servers/new")
    assert page.status_code == 200
    csrf_token = extract_csrf_token(page.get_data(as_text=True))
    assert csrf_token

    response = client.post(
        "/admin/acp/mcp/servers/new",
        data={
            "_csrf_token": csrf_token,
            "name": "Invalid MCP URL",
            "key": f"invalid-url-{uuid.uuid4().hex[:8]}",
            "server_url": "javascript:alert(1)",
            "transport": "http",
            "auth_mode": "oauth",
            "environment": "production",
            "allowed_tools_json": "[]",
            "require_approval": "always",
        },
        follow_redirects=False,
    )
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "Server URL must be a valid http(s) URL." in html

    with app.app_context():
        created = AcpMcpServer.query.filter_by(name="Invalid MCP URL").first()
        assert created is None


def test_acp_mcp_operations_create_pending_approval(client, app):
    admin_login(client)
    with app.app_context():
        server = AcpMcpServer(
            key=f"ops-{uuid.uuid4().hex[:8]}",
            name="Ops MCP",
            server_url="https://example.com/mcp",
            transport="http",
            auth_mode="oauth",
            environment="test",
            allowed_tools_json='["tickets.search"]',
            require_approval="always",
            is_enabled=True,
        )
        db.session.add(server)
        db.session.commit()
        server_id = server.id

    page = client.get("/admin/acp/mcp/operations")
    assert page.status_code == 200
    csrf_token = extract_csrf_token(page.get_data(as_text=True))
    assert csrf_token

    response = client.post(
        "/admin/acp/mcp/operations/create",
        data={
            "_csrf_token": csrf_token,
            "server_id": str(server_id),
            "tool_name": "tickets.search",
            "arguments_json": '{"ticket_number":"RS-TEST-001"}',
            "max_attempts": "3",
            "execute_now": "1",
        },
        follow_redirects=False,
    )
    assert response.status_code in (302, 303)

    with app.app_context():
        op = AcpMcpOperation.query.filter_by(server_id=server_id).order_by(AcpMcpOperation.id.desc()).first()
        assert op is not None
        assert op.status == "pending_approval"
        assert op.approval_status == "pending"


def test_acp_mcp_operations_approve_and_execute_success(client, app, monkeypatch):
    admin_login(client)
    with app.app_context():
        server = AcpMcpServer(
            key=f"ops-{uuid.uuid4().hex[:8]}",
            name="Ops MCP Execute",
            server_url="https://example.com/mcp",
            transport="http",
            auth_mode="oauth",
            environment="test",
            allowed_tools_json='["tickets.search"]',
            require_approval="always",
            is_enabled=True,
        )
        db.session.add(server)
        db.session.flush()
        op = AcpMcpOperation(
            server_id=server.id,
            request_id=str(uuid.uuid4()),
            tool_name="tickets.search",
            arguments_json='{"ticket_number":"RS-TEST-002"}',
            status="pending_approval",
            approval_status="pending",
            requires_approval=True,
            max_attempts=3,
        )
        db.session.add(op)
        db.session.commit()
        op_id = op.id

    def fake_invoke(server, tool_name, arguments, request_id):
        return {
            "http_status": 200,
            "result": {"ticket_number": arguments.get("ticket_number"), "status": "open"},
            "raw": {"ok": True},
        }

    monkeypatch.setattr(admin_routes, "_invoke_mcp_http", fake_invoke)

    page = client.get("/admin/acp/mcp/operations")
    csrf_token = extract_csrf_token(page.get_data(as_text=True))
    assert csrf_token
    approve = client.post(
        f"/admin/acp/mcp/operations/{op_id}/approve",
        data={"_csrf_token": csrf_token, "execute_now": "1"},
        follow_redirects=False,
    )
    assert approve.status_code in (302, 303)

    with app.app_context():
        refreshed = db.session.get(AcpMcpOperation, op_id)
        assert refreshed is not None
        assert refreshed.status == "succeeded"
        assert refreshed.approval_status == "approved"
        assert refreshed.response_json


def test_acp_phase1_delivery_content_and_theme_endpoints(client, app):
    type_key = f"type-{uuid.uuid4().hex[:8]}"
    published_key = f"entry-{uuid.uuid4().hex[:8]}"
    draft_key = f"draft-{uuid.uuid4().hex[:8]}"
    theme_key = f"theme-{uuid.uuid4().hex[:8]}"
    draft_theme_key = f"theme-draft-{uuid.uuid4().hex[:8]}"

    with app.app_context():
        content_type = AcpContentType(
            key=type_key,
            name="Delivery Test Type",
            schema_json='{"type":"object","properties":{"headline":{"type":"string"}}}',
            is_enabled=True,
        )
        db.session.add(content_type)
        db.session.flush()

        db.session.add(AcpContentEntry(
            content_type_id=content_type.id,
            entry_key=published_key,
            title="Published Entry",
            locale="en-US",
            status=WORKFLOW_PUBLISHED,
            data_json='{"headline":"Published headline"}',
            published_at=utc_now_naive(),
        ))
        db.session.add(AcpContentEntry(
            content_type_id=content_type.id,
            entry_key=draft_key,
            title="Draft Entry",
            locale="en-US",
            status=WORKFLOW_DRAFT,
            data_json='{"headline":"Draft headline"}',
        ))
        db.session.add(AcpThemeTokenSet(
            key=theme_key,
            name="Delivery Theme",
            status=WORKFLOW_PUBLISHED,
            tokens_json='{"css_vars":{"--accent-cyan":"#123456"}}',
            published_at=utc_now_naive(),
        ))
        db.session.add(AcpThemeTokenSet(
            key=draft_theme_key,
            name="Draft Theme",
            status=WORKFLOW_DRAFT,
            tokens_json='{"css_vars":{"--accent-cyan":"#abcdef"}}',
        ))
        db.session.commit()

    published_entry_resp = client.get(f"/api/delivery/content/{type_key}/{published_key}")
    assert published_entry_resp.status_code == 200
    published_entry_payload = published_entry_resp.get_json()
    assert published_entry_payload["entry_key"] == published_key
    assert published_entry_payload["content_type"]["key"] == type_key
    assert published_entry_payload["data"]["headline"] == "Published headline"
    assert "stale-if-error=" in (published_entry_resp.headers.get("Cache-Control") or "")
    assert published_entry_resp.headers.get("ETag")

    draft_entry_resp = client.get(f"/api/delivery/content/{type_key}/{draft_key}")
    assert draft_entry_resp.status_code == 404

    published_theme_resp = client.get(f"/api/delivery/theme/{theme_key}")
    assert published_theme_resp.status_code == 200
    published_theme_payload = published_theme_resp.get_json()
    assert published_theme_payload["key"] == theme_key
    assert published_theme_payload["tokens"]["css_vars"]["--accent-cyan"] == "#123456"
    assert published_theme_resp.headers.get("ETag")

    draft_theme_resp = client.get(f"/api/delivery/theme/{draft_theme_key}")
    assert draft_theme_resp.status_code == 404


def test_backfill_repairs_legacy_draft_only_service_and_industry_states(app):
    with app.app_context():
        Service.query.delete()
        Industry.query.delete()
        db.session.commit()

        service = Service(
            title="Legacy Service",
            slug=f"legacy-service-{uuid.uuid4().hex[:6]}",
            description="Legacy row before workflow columns existed.",
            service_type="professional",
            workflow_status=WORKFLOW_DRAFT,
            reviewed_at=None,
            approved_at=None,
            published_at=None,
        )
        industry = Industry(
            title="Legacy Industry",
            slug=f"legacy-industry-{uuid.uuid4().hex[:6]}",
            description="Legacy industry row before workflow columns existed.",
            workflow_status=WORKFLOW_DRAFT,
            reviewed_at=None,
            approved_at=None,
            published_at=None,
        )
        db.session.add(service)
        db.session.add(industry)
        db.session.commit()

        backfill_phase2_defaults()
        db.session.expire_all()

        refreshed_service = db.session.get(Service, service.id)
        refreshed_industry = db.session.get(Industry, industry.id)
        assert refreshed_service.workflow_status == WORKFLOW_PUBLISHED
        assert refreshed_industry.workflow_status == WORKFLOW_PUBLISHED
        assert refreshed_service.published_at is not None
        assert refreshed_industry.published_at is not None


def test_support_role_cannot_access_acp_page_builder(client, app):
    with app.app_context():
        user = User(username="support_user", email="support@example.com", role=ROLE_SUPPORT)
        user.set_password("Support123!")
        db.session.add(user)
        db.session.commit()

    admin_login_as(client, "support_user", "Support123!")
    response = client.get("/admin/acp/pages", follow_redirects=False)
    assert response.status_code in (302, 303)
    assert response.headers["Location"].endswith("/admin/")


def test_hsts_header_on_https_requests(client):
    response = client.get("/", base_url="https://example.com")
    assert response.status_code == 200
    assert response.headers.get("Strict-Transport-Security") == "max-age=31536000; includeSubDomains"


def test_hsts_header_on_trusted_forwarded_proto(tmp_path, monkeypatch):
    proxied_app = build_test_app(tmp_path, monkeypatch, {"TRUST_PROXY_HEADERS": True})
    proxied_client = proxied_app.test_client()
    response = proxied_client.get("/", base_url="http://example.com", headers={"X-Forwarded-Proto": "https"})
    assert response.status_code == 200
    assert response.headers.get("Strict-Transport-Security") == "max-age=31536000; includeSubDomains"


def test_public_metadata_urls_use_configured_https_base_url(tmp_path, monkeypatch):
    secure_app = build_test_app(
        tmp_path,
        monkeypatch,
        {"APP_BASE_URL": "https://www.example.com", "PREFERRED_URL_SCHEME": "https"},
    )
    secure_client = secure_app.test_client()
    response = secure_client.get("/", base_url="http://internal.local")
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert '<link rel="canonical" href="https://www.example.com/">' in html
    assert '<meta property="og:url" content="https://www.example.com/">' in html
    assert '"url": "https://www.example.com"' in html
    assert '"image": "https://www.example.com/static/icon.png"' in html
    assert "http://www.example.com" not in html


def test_service_detail_structured_data_uses_https_public_urls(tmp_path, monkeypatch):
    secure_app = build_test_app(
        tmp_path,
        monkeypatch,
        {"APP_BASE_URL": "https://www.example.com", "PREFERRED_URL_SCHEME": "https"},
    )
    secure_client = secure_app.test_client()
    with secure_app.app_context():
        service = Service.query.first()
        assert service is not None
        slug = service.slug
    response = secure_client.get(f"/services/{slug}", base_url="http://internal.local")
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert f'"url": "https://www.example.com/services/{slug}"' in html
    assert '"item": "https://www.example.com/services"' in html
    assert "http://www.example.com/services/" not in html


def test_force_https_redirects_insecure_requests(tmp_path, monkeypatch):
    secure_app = build_test_app(tmp_path, monkeypatch, {"FORCE_HTTPS": True})
    secure_client = secure_app.test_client()
    response = secure_client.get("/services?kind=repair", base_url="http://example.com", follow_redirects=False)
    assert response.status_code == 308
    assert response.headers.get("Location") == "https://example.com/services?kind=repair"


def test_force_https_exempt_paths_do_not_redirect(tmp_path, monkeypatch):
    secure_app = build_test_app(tmp_path, monkeypatch, {"FORCE_HTTPS": True})
    secure_client = secure_app.test_client()
    response = secure_client.get("/healthz", base_url="http://example.com", follow_redirects=False)
    assert response.status_code == 200


def test_health_endpoint_reports_ok(client):
    response = client.get("/healthz")
    assert response.status_code == 200
    payload = response.get_json()
    assert payload["status"] == "ok"


def test_health_endpoint_handles_whitespace_prefixed_path_segment(client):
    response = client.get("/", environ_overrides={"PATH_INFO": "/ /healthz"})
    assert response.status_code == 200
    payload = response.get_json()
    assert payload["status"] == "ok"


def test_readiness_endpoint_reports_ready(client):
    response = client.get("/readyz")
    assert response.status_code == 200
    payload = response.get_json()
    assert payload["status"] == "ready"
    assert payload["checks"]["database"] is True
    assert payload["checks"]["site_settings_seeded"] is True
    assert payload["checks"]["admin_user_seeded"] is True


def test_seed_database_creates_admin_when_content_exists_without_user(app):
    with app.app_context():
        db.drop_all()
        db.create_all()
        db.session.add(Category(name="Technology", slug="technology"))
        db.session.commit()

        assert User.query.first() is None
        assert Category.query.filter_by(slug="technology").count() == 1

        seed_database()
        db.session.expire_all()

        admin = User.query.filter_by(username="admin").first()
        assert admin is not None
        assert Category.query.filter_by(slug="technology").count() == 1


def test_seed_database_restores_named_admin_from_env_when_missing(app, monkeypatch):
    monkeypatch.setenv("ADMIN_PASSWORD", "RecoveryPass!123")
    monkeypatch.setenv("ADMIN_USERNAME", "admin")
    monkeypatch.setenv("ADMIN_EMAIL", "admin@example.com")

    with app.app_context():
        db.drop_all()
        db.create_all()
        existing_user = User(username="operator", email="admin@example.com")
        existing_user.set_password("OperatorPass!123")
        db.session.add(existing_user)
        db.session.commit()

        assert User.query.filter_by(username="admin").first() is None

        seed_database()
        db.session.expire_all()

        restored_admin = User.query.filter_by(username="admin").first()
        assert restored_admin is not None
        assert restored_admin.email != "admin@example.com"
        assert restored_admin.check_password("RecoveryPass!123")


def test_seed_database_bootstraps_catalog_when_user_exists_but_content_is_empty(app, monkeypatch):
    monkeypatch.setenv("ADMIN_PASSWORD", "BootstrapPass!123")
    monkeypatch.setenv("ADMIN_USERNAME", "admin")
    monkeypatch.setenv("ADMIN_EMAIL", "admin@example.com")

    with app.app_context():
        db.drop_all()
        db.create_all()
        existing_user = User(username="operator", email="operator@example.com")
        existing_user.set_password("OperatorPass!123")
        db.session.add(existing_user)
        db.session.commit()

        assert Service.query.count() == 0
        assert Industry.query.count() == 0
        assert SiteSetting.query.count() == 0
        assert Post.query.count() == 0

        seed_database()
        db.session.expire_all()

        admin = User.query.filter_by(username="admin").first()
        assert admin is not None
        assert admin.check_password("BootstrapPass!123")
        assert Service.query.count() > 0
        assert Industry.query.count() > 0
        assert SiteSetting.query.count() > 0
        assert Post.query.count() > 0


def test_contact_page_form_has_accessibility_autocomplete(client):
    response = client.get("/contact")
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert 'id="name"' in html and 'autocomplete="name"' in html
    assert 'id="email"' in html and 'autocomplete="email"' in html
    assert 'id="phone"' in html and 'autocomplete="tel"' in html
    assert 'minlength="10"' in html


def test_contact_post_requires_csrf(client):
    response = client.post(
        "/contact",
        data={
            "name": "No Token",
            "email": "notoken@example.com",
            "message": "Should fail",
        },
        follow_redirects=False,
    )
    assert response.status_code in (302, 400)


def test_admin_login_post_requires_csrf(client):
    response = client.post(
        "/admin/login",
        data={"username": "admin", "password": "admin123"},
        follow_redirects=False,
    )
    assert response.status_code in (302, 400)
    blocked_dashboard = client.get("/admin/", follow_redirects=False)
    assert blocked_dashboard.status_code in (302, 303)


def test_admin_logout_post_requires_csrf(client):
    admin_login(client)
    response = client.post("/admin/logout", data={}, follow_redirects=False)
    assert response.status_code in (302, 400)
    still_logged_in = client.get("/admin/", follow_redirects=False)
    assert still_logged_in.status_code == 200


def test_contact_post_with_csrf_succeeds(client, app):
    email = f"contact-{uuid.uuid4().hex[:8]}@example.com"
    contact_page = client.get("/contact")
    csrf_token = extract_csrf_token(contact_page.get_data(as_text=True))
    assert csrf_token

    response = client.post(
        "/contact",
        data={
            "_csrf_token": csrf_token,
            "name": "QA Contact",
            "email": email,
            "phone": "123",
            "subject": "Testing",
            "message": "Contact smoke test",
        },
        follow_redirects=False,
    )
    assert response.status_code in (302, 303)

    with app.app_context():
        saved = ContactSubmission.query.filter_by(email=email).first()
        assert saved is not None
        assert saved.message == "Contact smoke test"
        ticket = (
            SupportTicket.query
            .filter(SupportTicket.details.contains(email))
            .order_by(SupportTicket.created_at.desc(), SupportTicket.id.desc())
            .first()
        )
        assert ticket is not None
        assert ticket.ticket_number.startswith("RS-")
        verification = SupportTicketEmailVerification.query.filter_by(
            ticket_id=ticket.id,
            requester_email=email,
        ).first()
        assert verification is not None


def test_contact_turnstile_requires_token_when_enabled(client, app):
    app.config.update(
        {
            "TURNSTILE_SITE_KEY": "site-test-key",
            "TURNSTILE_SECRET_KEY": "secret-test-key",
            "TURNSTILE_ENFORCED": True,
        }
    )
    email = f"turnstile-contact-{uuid.uuid4().hex[:8]}@example.com"
    contact_page = client.get("/contact")
    html = contact_page.get_data(as_text=True)
    assert "cf-turnstile" in html
    csrf_token = extract_csrf_token(html)
    assert csrf_token

    response = client.post(
        "/contact",
        data={
            "_csrf_token": csrf_token,
            "name": "Blocked Contact",
            "email": email,
            "subject": "Turnstile Test",
            "message": "This should be blocked without turnstile token.",
        },
        follow_redirects=False,
    )
    assert response.status_code in (302, 303)

    with app.app_context():
        saved = ContactSubmission.query.filter_by(email=email).first()
        assert saved is None
        event = SecurityEvent.query.filter_by(event_type="turnstile_failed", scope="contact_form").first()
        assert event is not None
        assert event.path == "/contact"


def test_contact_form_rate_limit_blocks_second_submission(client, app):
    app.config.update(
        {
            "CONTACT_FORM_LIMIT": 1,
            "CONTACT_FORM_WINDOW_SECONDS": 3600,
        }
    )
    email_one = f"rate-contact-1-{uuid.uuid4().hex[:8]}@example.com"
    email_two = f"rate-contact-2-{uuid.uuid4().hex[:8]}@example.com"

    first_page = client.get("/contact")
    first_csrf = extract_csrf_token(first_page.get_data(as_text=True))
    assert first_csrf
    first_response = client.post(
        "/contact",
        data={
            "_csrf_token": first_csrf,
            "name": "Rate Limited Contact 1",
            "email": email_one,
            "phone": "+1 (555) 100-1000",
            "subject": "Rate Test 1",
            "message": "First message should pass.",
        },
        follow_redirects=False,
    )
    assert first_response.status_code in (302, 303)

    second_page = client.get("/contact")
    second_csrf = extract_csrf_token(second_page.get_data(as_text=True))
    assert second_csrf
    second_response = client.post(
        "/contact",
        data={
            "_csrf_token": second_csrf,
            "name": "Rate Limited Contact 2",
            "email": email_two,
            "phone": "+1 (555) 200-2000",
            "subject": "Rate Test 2",
            "message": "Second message should be blocked by rate limit.",
        },
        follow_redirects=False,
    )
    assert second_response.status_code in (302, 303)

    with app.app_context():
        saved_one = ContactSubmission.query.filter_by(email=email_one).first()
        saved_two = ContactSubmission.query.filter_by(email=email_two).first()
        assert saved_one is not None
        assert saved_two is None
        event = SecurityEvent.query.filter_by(event_type="rate_limited", scope="contact_form").first()
        assert event is not None


def test_request_quote_creates_cms_ticket(client, app):
    quote_page = client.get("/request-quote")
    csrf_token = extract_csrf_token(quote_page.get_data(as_text=True))
    assert csrf_token

    with app.app_context():
        service = Service.query.first()
        assert service is not None
        service_slug = service.slug

    requester_email = f"quote-{uuid.uuid4().hex[:8]}@example.com"
    response = client.post(
        "/request-quote",
        data={
            "_csrf_token": csrf_token,
            "full_name": "Quote User",
            "email": requester_email,
            "phone": "+1 (555) 000-0000",
            "company": "Quote Corp",
            "website": "https://example.com",
            "project_title": "Network and Security Upgrade",
            "primary_service_slug": service_slug,
            "budget_range": "15k_50k",
            "timeline": "30_days",
            "urgency": "high",
            "preferred_contact": "email",
            "team_size": "42",
            "location_count": "2",
            "compliance": "soc2",
            "business_goals": "Improve operational uptime, strengthen security posture, and standardize support workflows.",
            "pain_points": "Too many recurring outages, inconsistent endpoint policies, and no central visibility across locations.",
            "current_environment": "Mixed on-prem servers, Microsoft 365, and unmanaged endpoints.",
            "integrations": "Microsoft 365, QuickBooks, HubSpot",
            "additional_notes": "Need phased rollout with minimal business disruption.",
        },
        follow_redirects=False,
    )
    assert response.status_code in (302, 303)

    with app.app_context():
        ticket = SupportTicket.query.order_by(SupportTicket.created_at.desc()).first()
        assert ticket is not None
        assert ticket.subject.startswith("Quote Request:")
        assert ticket.service_slug == service_slug
        assert ticket.priority == "high"
        assert requester_email in ticket.details
        assert "Quote Corp" in ticket.details
        verification = SupportTicketEmailVerification.query.filter_by(
            ticket_id=ticket.id,
            requester_email=requester_email,
        ).first()
        assert verification is not None


def test_admin_ticket_notification_excludes_requester_email(app, monkeypatch):
    captured = {}

    def fake_send_email(subject, body, recipients):
        captured['subject'] = subject
        captured['body'] = body
        captured['recipients'] = recipients
        return True

    monkeypatch.setattr(notifications_module, '_send_email', fake_send_email)

    with app.app_context():
        service = Service.query.first()
        assert service is not None
        requester_email = f"notify-{uuid.uuid4().hex[:8]}@example.com"
        support_client = SupportClient(
            full_name="Requester User",
            email=requester_email,
            company="Requester Co",
            phone="+1 (555) 222-0000",
        )
        support_client.set_password("NotifyRequester123!")
        db.session.add(support_client)
        db.session.commit()

        ticket = SupportTicket(
            ticket_number=f"RS-N-{uuid.uuid4().hex[:10].upper()}",
            client_id=support_client.id,
            subject="Requester exclusion",
            service_slug=service.slug,
            priority="normal",
            status="open",
            details="Internal recipient filter coverage.",
        )
        db.session.add(ticket)
        db.session.commit()
        ticket_id = ticket.id

        app.config['TICKET_NOTIFICATION_EMAILS'] = f'{requester_email},ops@example.com'
        current_ticket = db.session.get(SupportTicket, ticket_id)
        sent = notifications_module.send_ticket_notification(
            current_ticket,
            ticket_kind='support',
            exclude_emails=[requester_email],
        )

    assert sent is True
    assert captured.get('recipients') == ['ops@example.com']


def test_client_verification_email_uses_single_secure_status_link(app, monkeypatch):
    captured = {}

    def fake_send_email(subject, body, recipients):
        captured['subject'] = subject
        captured['body'] = body
        captured['recipients'] = recipients
        return True

    monkeypatch.setattr(notifications_module, '_send_email', fake_send_email)

    with app.app_context():
        service = Service.query.first()
        assert service is not None
        support_client = SupportClient(
            full_name="Secure Link User",
            email=f"secure-link-{uuid.uuid4().hex[:8]}@example.com",
            company="Secure Link Co",
            phone="+1 (555) 333-0000",
        )
        support_client.set_password("SecureLink123!")
        db.session.add(support_client)
        db.session.commit()

        ticket = SupportTicket(
            ticket_number=f"RS-L-{uuid.uuid4().hex[:10].upper()}",
            client_id=support_client.id,
            subject="Secure status link",
            service_slug=service.slug,
            priority="normal",
            status="open",
            details="Status link coverage.",
        )
        db.session.add(ticket)
        db.session.commit()
        ticket_id = ticket.id

    with app.test_request_context('/'):
        app.config['APP_BASE_URL'] = 'https://mylauncher-ready-production.up.railway.app'
        with app.app_context():
            current_ticket = db.session.get(SupportTicket, ticket_id)
            sent = notifications_module.send_ticket_verification_email(
                current_ticket,
                "client@example.com",
                "test-token-123",
                ticket_kind='support',
            )

    assert sent is True
    body = captured.get('body', '')
    assert "Use this secure link to check ticket status:" in body
    assert "ticket-search?ticket_number=" in body
    assert "token=test-token-123" in body


def test_request_quote_form_rate_limit_blocks_second_submission(client, app):
    app.config.update(
        {
            "QUOTE_FORM_LIMIT": 1,
            "QUOTE_FORM_WINDOW_SECONDS": 3600,
        }
    )
    quote_page = client.get("/request-quote")
    csrf_token = extract_csrf_token(quote_page.get_data(as_text=True))
    assert csrf_token

    with app.app_context():
        service = Service.query.first()
        assert service is not None
        service_slug = service.slug

    first_email = f"rate-quote-1-{uuid.uuid4().hex[:8]}@example.com"
    first_response = client.post(
        "/request-quote",
        data={
            "_csrf_token": csrf_token,
            "full_name": "Rate Quote One",
            "email": first_email,
            "phone": "+1 (555) 010-0001",
            "company": "Rate Corp One",
            "website": "https://example.com",
            "project_title": "Rate Limit Quote One",
            "primary_service_slug": service_slug,
            "budget_range": "15k_50k",
            "timeline": "30_days",
            "urgency": "normal",
            "preferred_contact": "email",
            "team_size": "20",
            "location_count": "2",
            "compliance": "none",
            "business_goals": "Improve reliability and reduce support overhead across operational workflows.",
            "pain_points": "Recurring outages, fragmented toolsets, and reactive support are reducing service quality.",
            "current_environment": "Mixed cloud and on-prem systems with manual processes.",
            "integrations": "Microsoft 365",
            "additional_notes": "Need phased rollout with clear milestones.",
        },
        follow_redirects=False,
    )
    assert first_response.status_code in (302, 303)

    second_page = client.get("/request-quote")
    second_csrf = extract_csrf_token(second_page.get_data(as_text=True))
    assert second_csrf
    second_email = f"rate-quote-2-{uuid.uuid4().hex[:8]}@example.com"
    second_response = client.post(
        "/request-quote",
        data={
            "_csrf_token": second_csrf,
            "full_name": "Rate Quote Two",
            "email": second_email,
            "phone": "+1 (555) 010-0002",
            "company": "Rate Corp Two",
            "website": "https://example.org",
            "project_title": "Rate Limit Quote Two",
            "primary_service_slug": service_slug,
            "budget_range": "15k_50k",
            "timeline": "30_days",
            "urgency": "normal",
            "preferred_contact": "email",
            "team_size": "25",
            "location_count": "3",
            "compliance": "none",
            "business_goals": "Standardize service delivery and strengthen system resilience across locations.",
            "pain_points": "Slow incident response and inconsistent endpoint controls are affecting operations.",
            "current_environment": "Distributed teams with mixed endpoint and network policies.",
            "integrations": "Microsoft 365, HubSpot",
            "additional_notes": "Need practical implementation plan.",
        },
        follow_redirects=False,
    )
    assert second_response.status_code == 429

    with app.app_context():
        total_tickets = SupportTicket.query.count()
        assert total_tickets == 1
        event = SecurityEvent.query.filter_by(event_type="rate_limited", scope="quote_form").first()
        assert event is not None
        assert event.path == "/request-quote"


def test_admin_security_events_page_renders(client, app):
    with app.app_context():
        db.session.add(
            SecurityEvent(
                event_type="turnstile_failed",
                scope="contact_form",
                ip="127.0.0.1",
                path="/contact",
                method="POST",
                user_agent="pytest",
                details="missing_or_invalid_turnstile_token",
            )
        )
        db.session.add(
            SecurityEvent(
                event_type="rate_limited",
                scope="quote_form",
                ip="127.0.0.1",
                path="/request-quote",
                method="POST",
                user_agent="pytest",
                details="limit=1 window=3600s",
            )
        )
        db.session.commit()

    admin_login(client)
    response = client.get("/admin/security-events")
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "Security Events" in html
    assert "turnstile_failed" in html
    assert "rate_limited" in html


def test_request_quote_company_optional(client, app):
    quote_page = client.get("/request-quote")
    csrf_token = extract_csrf_token(quote_page.get_data(as_text=True))
    assert csrf_token

    with app.app_context():
        service = Service.query.first()
        assert service is not None
        service_slug = service.slug

    requester_email = f"quote-nocompany-{uuid.uuid4().hex[:8]}@example.com"
    response = client.post(
        "/request-quote",
        data={
            "_csrf_token": csrf_token,
            "full_name": "Quote User No Company",
            "email": requester_email,
            "phone": "+1 (555) 999-9999",
            "company": "",
            "website": "https://example.org",
            "project_title": "Core Infrastructure Refresh",
            "primary_service_slug": service_slug,
            "budget_range": "15k_50k",
            "timeline": "30_days",
            "urgency": "normal",
            "preferred_contact": "email",
            "team_size": "15",
            "location_count": "1",
            "compliance": "none",
            "business_goals": "Increase reliability and reduce recurring outages across endpoint and network operations.",
            "pain_points": "Aging hardware, reactive support cycles, and fragmented tooling are creating downtime.",
            "current_environment": "Single office with mixed devices and cloud collaboration tools.",
            "integrations": "Microsoft 365",
            "additional_notes": "Need practical phased implementation.",
        },
        follow_redirects=False,
    )
    assert response.status_code in (302, 303)

    with app.app_context():
        ticket = SupportTicket.query.order_by(SupportTicket.created_at.desc()).first()
        assert ticket is not None
        assert ticket.subject == "Quote Request: Core Infrastructure Refresh"
        assert requester_email in ticket.details
        assert "- Company: Not provided" in ticket.details


def test_admin_support_ticket_type_filtering(client, app):
    with app.app_context():
        service = Service.query.first()
        assert service is not None

        quote_client = SupportClient(
            full_name="Quote Intake",
            email=f"quote-intake-{uuid.uuid4().hex[:8]}@rightonrepair.local",
            company="Right On Repair",
            phone="",
        )
        quote_client.set_password("quote-secret")

        support_client = SupportClient(
            full_name="Support User",
            email=f"support-{uuid.uuid4().hex[:8]}@example.com",
            company="Support Corp",
            phone="+1 (555) 111-1111",
        )
        support_client.set_password("support-secret")

        db.session.add_all([quote_client, support_client])
        db.session.commit()

        quote_ticket = SupportTicket(
            ticket_number=f"RS-Q-{uuid.uuid4().hex[:10].upper()}",
            client_id=quote_client.id,
            subject="Quote Request: Managed IT Expansion - Quote Corp",
            service_slug=service.slug,
            priority="high",
            status="open",
            details="Quote Intake Submission\nRequester: Quote User",
        )
        support_ticket = SupportTicket(
            ticket_number=f"RS-S-{uuid.uuid4().hex[:10].upper()}",
            client_id=support_client.id,
            subject="Printer offline in accounting",
            service_slug=service.slug,
            priority="normal",
            status="open",
            details="Need on-site troubleshooting.",
        )
        db.session.add_all([quote_ticket, support_ticket])
        db.session.commit()

        quote_number = quote_ticket.ticket_number
        support_number = support_ticket.ticket_number

    admin_login(client)

    quote_only = client.get("/admin/support-tickets?type=quote")
    assert quote_only.status_code == 200
    quote_html = quote_only.get_data(as_text=True)
    assert quote_number in quote_html
    assert support_number not in quote_html
    assert "Quote Request" in quote_html

    support_only = client.get("/admin/support-tickets?type=support")
    assert support_only.status_code == 200
    support_html = support_only.get_data(as_text=True)
    assert support_number in support_html
    assert quote_number not in support_html


def test_admin_support_ticket_search_by_ticket_number(client, app):
    with app.app_context():
        service = Service.query.first()
        assert service is not None

        target_client = SupportClient(
            full_name="Lookup Target",
            email=f"lookup-target-{uuid.uuid4().hex[:8]}@example.com",
            company="Lookup Corp",
            phone="+1 (555) 777-1111",
        )
        target_client.set_password("lookup-target-secret")
        other_client = SupportClient(
            full_name="Lookup Other",
            email=f"lookup-other-{uuid.uuid4().hex[:8]}@example.com",
            company="Lookup Corp",
            phone="+1 (555) 777-2222",
        )
        other_client.set_password("lookup-other-secret")
        db.session.add_all([target_client, other_client])
        db.session.commit()

        target_ticket = SupportTicket(
            ticket_number=f"RS-L-{uuid.uuid4().hex[:10].upper()}",
            client_id=target_client.id,
            subject="Need exact ticket search",
            service_slug=service.slug,
            priority="normal",
            status="open",
            details="Target ticket row for search tests.",
        )
        other_ticket = SupportTicket(
            ticket_number=f"RS-L-{uuid.uuid4().hex[:10].upper()}",
            client_id=other_client.id,
            subject="Different ticket",
            service_slug=service.slug,
            priority="normal",
            status="open",
            details="Other ticket row for search tests.",
        )
        db.session.add_all([target_ticket, other_ticket])
        db.session.commit()
        target_number = target_ticket.ticket_number
        other_number = other_ticket.ticket_number

    admin_login(client)
    response = client.get("/admin/support-tickets", query_string={"q": target_number.lower()})
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert target_number in html
    assert other_number not in html


def test_admin_dashboard_ticket_lookup_returns_target_ticket(client, app):
    with app.app_context():
        service = Service.query.first()
        assert service is not None
        lookup_client = SupportClient(
            full_name="Dashboard Lookup",
            email=f"dashboard-lookup-{uuid.uuid4().hex[:8]}@example.com",
            company="Dashboard Lookup Co",
            phone="+1 (555) 888-3333",
        )
        lookup_client.set_password("dashboard-lookup-secret")
        db.session.add(lookup_client)
        db.session.commit()

        ticket = SupportTicket(
            ticket_number=f"RS-D-{uuid.uuid4().hex[:10].upper()}",
            client_id=lookup_client.id,
            subject="Dashboard finder ticket",
            service_slug=service.slug,
            priority="normal",
            status="in_progress",
            details="Dashboard lookup result coverage.",
        )
        db.session.add(ticket)
        db.session.commit()
        ticket_number = ticket.ticket_number

    admin_login(client)
    response = client.get("/admin/", query_string={"ticket_number": ticket_number.lower()})
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "Ticket Lookup" in html
    assert ticket_number in html
    assert "Dashboard finder ticket" in html


def test_admin_ticket_review_actions_sync_pending_done_closed(client, app):
    with app.app_context():
        service = Service.query.first()
        assert service is not None
        ticket_client = SupportClient(
            full_name="Review User",
            email=f"review-{uuid.uuid4().hex[:8]}@example.com",
            company="Review Corp",
            phone="+1 (555) 222-2222",
        )
        ticket_client.set_password("review-secret")
        db.session.add(ticket_client)
        db.session.commit()

        ticket = SupportTicket(
            ticket_number=f"RS-R-{uuid.uuid4().hex[:10].upper()}",
            client_id=ticket_client.id,
            subject="Need quick admin review",
            service_slug=service.slug,
            priority="normal",
            status="open",
            details="Testing pending/done/closed workflow sync.",
        )
        db.session.add(ticket)
        db.session.commit()
        ticket_id = ticket.id

    admin_login(client)

    ticket_page = client.get(f"/admin/support-tickets/{ticket_id}")
    csrf_token = extract_csrf_token(ticket_page.get_data(as_text=True))
    assert csrf_token

    pending_resp = client.post(
        f"/admin/support-tickets/{ticket_id}/review",
        data={"_csrf_token": csrf_token, "review_action": "pending"},
        follow_redirects=False,
    )
    assert pending_resp.status_code in (302, 303)

    with app.app_context():
        pending_ticket = db.session.get(SupportTicket, ticket_id)
        assert pending_ticket.status == SUPPORT_TICKET_STATUS_IN_PROGRESS

    ticket_page = client.get(f"/admin/support-tickets/{ticket_id}")
    csrf_token = extract_csrf_token(ticket_page.get_data(as_text=True))
    assert csrf_token
    done_resp = client.post(
        f"/admin/support-tickets/{ticket_id}/review",
        data={"_csrf_token": csrf_token, "review_action": "done", "review_note": "Issue completed"},
        follow_redirects=False,
    )
    assert done_resp.status_code in (302, 303)

    with app.app_context():
        done_ticket = db.session.get(SupportTicket, ticket_id)
        assert done_ticket.status == SUPPORT_TICKET_STATUS_RESOLVED
        assert "Issue completed" in (done_ticket.internal_notes or "")

    ticket_page = client.get(f"/admin/support-tickets/{ticket_id}")
    csrf_token = extract_csrf_token(ticket_page.get_data(as_text=True))
    assert csrf_token
    close_resp = client.post(
        f"/admin/support-tickets/{ticket_id}/review",
        data={"_csrf_token": csrf_token, "review_action": "closed"},
        follow_redirects=False,
    )
    assert close_resp.status_code in (302, 303)

    with app.app_context():
        closed_ticket = db.session.get(SupportTicket, ticket_id)
        assert closed_ticket.status == SUPPORT_TICKET_STATUS_CLOSED
        ticket_events = (
            SupportTicketEvent.query
            .filter(SupportTicketEvent.ticket_id == ticket_id)
            .order_by(SupportTicketEvent.created_at.asc(), SupportTicketEvent.id.asc())
            .all()
        )
        assert len(ticket_events) == 3
        assert [event.event_type for event in ticket_events] == ['review_action', 'review_action', 'review_action']
        assert ticket_events[0].status_from == 'open'
        assert ticket_events[0].status_to == SUPPORT_TICKET_STATUS_IN_PROGRESS
        assert ticket_events[1].status_from == SUPPORT_TICKET_STATUS_IN_PROGRESS
        assert ticket_events[1].status_to == SUPPORT_TICKET_STATUS_RESOLVED
        assert 'Review note added.' in (ticket_events[1].message or '')
        assert ticket_events[2].status_to == SUPPORT_TICKET_STATUS_CLOSED

    timeline_page = client.get(f"/admin/support-tickets/{ticket_id}")
    timeline_html = timeline_page.get_data(as_text=True)
    assert "Activity Timeline" in timeline_html
    assert "Review Action" in timeline_html


def test_admin_ticket_view_post_records_admin_update_timeline_event(client, app):
    with app.app_context():
        service = Service.query.first()
        assert service is not None
        ticket_client = SupportClient(
            full_name="Ticket Editor",
            email=f"editor-{uuid.uuid4().hex[:8]}@example.com",
            company="Editor Corp",
            phone="+1 (555) 444-4444",
        )
        ticket_client.set_password("editor-secret")
        db.session.add(ticket_client)
        db.session.commit()

        ticket = SupportTicket(
            ticket_number=f"RS-U-{uuid.uuid4().hex[:10].upper()}",
            client_id=ticket_client.id,
            subject="Update from admin view",
            service_slug=service.slug,
            priority="normal",
            status="open",
            details="Testing timeline for admin update POST.",
        )
        db.session.add(ticket)
        db.session.commit()
        ticket_id = ticket.id

    admin_login(client)
    ticket_page = client.get(f"/admin/support-tickets/{ticket_id}")
    csrf_token = extract_csrf_token(ticket_page.get_data(as_text=True))
    assert csrf_token

    update_resp = client.post(
        f"/admin/support-tickets/{ticket_id}",
        data={
            "_csrf_token": csrf_token,
            "status": "waiting_customer",
            "priority": "high",
            "internal_notes": "Pending client callback",
            "review_note": "Waiting for customer confirmation",
        },
        follow_redirects=False,
    )
    assert update_resp.status_code in (302, 303)

    with app.app_context():
        updated = db.session.get(SupportTicket, ticket_id)
        assert updated.status == 'waiting_customer'
        assert updated.priority == 'high'
        events = (
            SupportTicketEvent.query
            .filter(SupportTicketEvent.ticket_id == ticket_id)
            .order_by(SupportTicketEvent.created_at.asc(), SupportTicketEvent.id.asc())
            .all()
        )
        assert len(events) == 1
        assert events[0].event_type == 'admin_update'
        assert events[0].status_from == 'open'
        assert events[0].status_to == 'waiting_customer'
        assert 'Review note added' in (events[0].message or '')


def test_public_ticket_search_page_lookup(client, app):
    with app.app_context():
        service = Service.query.first()
        assert service is not None
        portal_client = SupportClient(
            full_name="Public Lookup User",
            email=f"public-lookup-{uuid.uuid4().hex[:8]}@example.com",
            company="Public Lookup Co",
            phone="+1 (555) 999-1010",
        )
        portal_client.set_password("PublicLookup123!")
        db.session.add(portal_client)
        db.session.commit()

        ticket = SupportTicket(
            ticket_number=f"RS-P-{uuid.uuid4().hex[:10].upper()}",
            client_id=portal_client.id,
            subject="Public search ticket",
            service_slug=service.slug,
            priority="high",
            status="waiting_customer",
            details="Public ticket search route coverage.",
        )
        db.session.add(ticket)
        db.session.commit()
        ticket_number = ticket.ticket_number
        ticket_id = ticket.id
        portal_email = portal_client.email

    search_page = client.get("/ticket-search", query_string={"ticket_number": ticket_number.lower()})
    assert search_page.status_code == 200
    html = search_page.get_data(as_text=True)
    assert "Verify Email to View Status" in html
    assert "Ticket Found" not in html
    csrf_token = extract_csrf_token(html)
    assert csrf_token

    request_access_response = client.post(
        "/ticket-search/request-access",
        data={
            "_csrf_token": csrf_token,
            "ticket_number": ticket_number,
            "email": portal_email,
        },
        follow_redirects=False,
    )
    assert request_access_response.status_code in (302, 303)

    verification_token = f"verify-{uuid.uuid4().hex}"
    with app.app_context():
        verification = SupportTicketEmailVerification.query.filter_by(
            ticket_id=ticket_id,
            requester_email=portal_email,
        ).first()
        assert verification is not None
        verification.token_hash = hashlib.sha256(verification_token.encode("utf-8")).hexdigest()
        verification.is_verified = False
        verification.verified_at = None
        verification.expires_at = utc_now_naive() + timedelta(hours=4)
        db.session.commit()

    verify_response = client.get(
        "/ticket-verify",
        query_string={"ticket_number": ticket_number, "token": verification_token},
        follow_redirects=False,
    )
    assert verify_response.status_code in (302, 303)
    verify_location = verify_response.headers.get('Location', '')
    assert 'token=' in verify_location

    verified_search_page = client.get(verify_location, follow_redirects=False)
    assert verified_search_page.status_code == 200
    verified_html = verified_search_page.get_data(as_text=True)
    assert "Ticket Found" in verified_html
    assert ticket_number in verified_html
    assert "Waiting on Client" in verified_html

    index_page = client.get("/")
    index_html = index_page.get_data(as_text=True)
    assert 'action="/ticket-search"' in index_html or 'action="/ticket-status"' in index_html
    assert "Track Ticket #" in index_html


def test_remote_support_ticket_creation_creates_email_verification(client, app):
    email = f"ticket-owner-{uuid.uuid4().hex[:8]}@example.com"
    with app.app_context():
        portal_client = SupportClient(
            full_name="Portal Ticket Owner",
            email=email,
            company="Portal Ticket Co",
            phone="+1 (555) 123-4567",
        )
        portal_client.set_password("PortalTicket123!")
        db.session.add(portal_client)
        db.session.commit()

    login_page = client.get("/remote-support")
    login_csrf = extract_csrf_token(login_page.get_data(as_text=True))
    assert login_csrf

    login_response = client.post(
        "/remote-support/login",
        data={
            "_csrf_token": login_csrf,
            "email": email,
            "password": "PortalTicket123!",
        },
        follow_redirects=False,
    )
    assert login_response.status_code in (302, 303)

    ticket_page = client.get("/remote-support")
    ticket_csrf = extract_csrf_token(ticket_page.get_data(as_text=True))
    assert ticket_csrf

    create_response = client.post(
        "/remote-support/tickets",
        data={
            "_csrf_token": ticket_csrf,
            "subject": "Portal verification ticket",
            "priority": "normal",
            "details": "Need status updates from public ticket search.",
        },
        follow_redirects=False,
    )
    assert create_response.status_code in (302, 303)

    with app.app_context():
        ticket = (
            SupportTicket.query
            .filter_by(subject="Portal verification ticket")
            .order_by(SupportTicket.created_at.desc(), SupportTicket.id.desc())
            .first()
        )
        assert ticket is not None
        verification = SupportTicketEmailVerification.query.filter_by(
            ticket_id=ticket.id,
            requester_email=email,
        ).first()
        assert verification is not None


def test_remote_support_uses_stage_labels_for_ticket_sync(client, app):
    email = f"portal-{uuid.uuid4().hex[:8]}@example.com"
    with app.app_context():
        portal_client = SupportClient(
            full_name="Portal Sync User",
            email=email,
            company="Portal Co",
            phone="+1 (555) 333-3333",
        )
        portal_client.set_password("PortalSync123!")
        db.session.add(portal_client)
        db.session.commit()

        db.session.add_all([
            SupportTicket(
                ticket_number=f"RS-P-{uuid.uuid4().hex[:10].upper()}",
                client_id=portal_client.id,
                subject="Pending ticket",
                priority="normal",
                status="in_progress",
                details="Pending state ticket.",
            ),
            SupportTicket(
                ticket_number=f"RS-D-{uuid.uuid4().hex[:10].upper()}",
                client_id=portal_client.id,
                subject="Done ticket",
                priority="normal",
                status="resolved",
                details="Done state ticket.",
            ),
            SupportTicket(
                ticket_number=f"RS-C-{uuid.uuid4().hex[:10].upper()}",
                client_id=portal_client.id,
                subject="Closed ticket",
                priority="normal",
                status="closed",
                details="Closed state ticket.",
            ),
        ])
        db.session.commit()

    login_page = client.get("/remote-support")
    csrf_token = extract_csrf_token(login_page.get_data(as_text=True))
    assert csrf_token

    login_resp = client.post(
        "/remote-support/login",
        data={
            "_csrf_token": csrf_token,
            "email": email,
            "password": "PortalSync123!",
        },
        follow_redirects=False,
    )
    assert login_resp.status_code in (302, 303)

    portal = client.get("/remote-support")
    assert portal.status_code == 200
    html = portal.get_data(as_text=True)
    assert "Pending" in html
    assert "Done" in html
    assert "Closed" in html


def test_admin_validation_paths_no_500(client, app):
    admin_login(client)

    # Duplicate category should not crash.
    categories_page = client.get("/admin/categories")
    category_token = extract_csrf_token(categories_page.get_data(as_text=True))
    duplicate_category = client.post(
        "/admin/categories/add",
        data={"_csrf_token": category_token, "name": "Technology"},
        follow_redirects=False,
    )
    assert duplicate_category.status_code < 500

    unique_service_title = f"QA Service {uuid.uuid4().hex[:6]}"
    service_page = client.get("/admin/services/add")
    service_token = extract_csrf_token(service_page.get_data(as_text=True))
    invalid_sort_service = client.post(
        "/admin/services/add",
        data={
            "_csrf_token": service_token,
            "title": unique_service_title,
            "description": "Validation test service",
            "icon_class": "fa-solid fa-gear",
            "service_type": "professional",
            "sort_order": "abc",
        },
        follow_redirects=False,
    )
    assert invalid_sort_service.status_code < 500

    team_page = client.get("/admin/team/add")
    team_token = extract_csrf_token(team_page.get_data(as_text=True))
    invalid_sort_team = client.post(
        "/admin/team/add",
        data={
            "_csrf_token": team_token,
            "name": f"QA Member {uuid.uuid4().hex[:6]}",
            "position": "Engineer",
            "bio": "Validation test member",
            "sort_order": "not-a-number",
        },
        follow_redirects=False,
    )
    assert invalid_sort_team.status_code < 500

    testimonial_page = client.get("/admin/testimonials/add")
    testimonial_token = extract_csrf_token(testimonial_page.get_data(as_text=True))
    invalid_rating = client.post(
        "/admin/testimonials/add",
        data={
            "_csrf_token": testimonial_token,
            "client_name": "QA Client",
            "company": "Acme",
            "content": "Validation test testimonial",
            "rating": "invalid",
        },
        follow_redirects=False,
    )
    assert invalid_rating.status_code < 500

    post_title = f"Invalid Category Post {uuid.uuid4().hex[:6]}"
    post_page = client.get("/admin/posts/add")
    post_token = extract_csrf_token(post_page.get_data(as_text=True))
    invalid_category_post = client.post(
        "/admin/posts/add",
        data={
            "_csrf_token": post_token,
            "title": post_title,
            "excerpt": "x",
            "content": "<p>content</p>",
            "category_id": "abc",
            "is_published": "on",
        },
        follow_redirects=False,
    )
    assert invalid_category_post.status_code < 500
    assert invalid_category_post.status_code == 200

    with app.app_context():
        not_created = Post.query.filter_by(title=post_title).first()
        assert not_created is None


def test_rich_text_bleach_sanitization(client, app):
    admin_login(client)
    with app.app_context():
        category = Category.query.first()
        assert category is not None
        category_id = category.id

    post_title = f"Sanitize {uuid.uuid4().hex[:8]}"
    post_page = client.get("/admin/posts/add")
    csrf_token = extract_csrf_token(post_page.get_data(as_text=True))
    assert csrf_token

    response = client.post(
        "/admin/posts/add",
        data={
            "_csrf_token": csrf_token,
            "title": post_title,
            "excerpt": "security test",
            "content": '<p>Safe</p><script>alert(1)</script><a href="javascript:alert(2)" onclick="alert(3)">Click</a>',
            "category_id": str(category_id),
            "is_published": "on",
        },
        follow_redirects=False,
    )
    assert response.status_code in (302, 303)

    with app.app_context():
        created = Post.query.filter_by(title=post_title).first()
        assert created is not None
        lower_content = created.content.lower()
        assert "<script" not in lower_content
        assert "javascript:" not in lower_content
        assert "onclick=" not in lower_content


def test_admin_login_rate_limit_blocks_after_threshold(client):
    # 5 failures allowed, 6th should be blocked.
    for _ in range(5):
        page = client.get("/admin/login")
        csrf_token = extract_csrf_token(page.get_data(as_text=True))
        response = client.post(
            "/admin/login",
            data={"_csrf_token": csrf_token, "username": "admin", "password": "wrong-password"},
            follow_redirects=False,
        )
        assert response.status_code == 200

    blocked_page = client.get("/admin/login")
    blocked_token = extract_csrf_token(blocked_page.get_data(as_text=True))
    blocked = client.post(
        "/admin/login",
        data={"_csrf_token": blocked_token, "username": "admin", "password": "wrong-password"},
        follow_redirects=False,
    )
    assert blocked.status_code == 429


def test_admin_login_rate_limit_not_bypassable_with_spoofed_xff(client):
    # Multiple spoofed X-Forwarded-For values from the same origin should still count.
    for i in range(5):
        page = client.get("/admin/login")
        csrf_token = extract_csrf_token(page.get_data(as_text=True))
        response = client.post(
            "/admin/login",
            data={"_csrf_token": csrf_token, "username": "admin", "password": "wrong-password"},
            headers={"X-Forwarded-For": f"203.0.113.{i + 1}"},
            follow_redirects=False,
        )
        assert response.status_code == 200

    blocked_page = client.get("/admin/login")
    blocked_token = extract_csrf_token(blocked_page.get_data(as_text=True))
    blocked = client.post(
        "/admin/login",
        data={"_csrf_token": blocked_token, "username": "admin", "password": "wrong-password"},
        headers={"X-Forwarded-For": "198.51.100.77"},
        follow_redirects=False,
    )
    assert blocked.status_code == 429


def test_admin_login_rate_limit_not_bypassable_with_trusted_proxy_xff(tmp_path, monkeypatch):
    proxied_app = build_test_app(tmp_path, monkeypatch, {"TRUST_PROXY_HEADERS": True})
    proxied_client = proxied_app.test_client()

    # ProxyFix trusts one proxy hop, so the right-most entry is used as client IP.
    for i in range(5):
        page = proxied_client.get("/admin/login")
        csrf_token = extract_csrf_token(page.get_data(as_text=True))
        response = proxied_client.post(
            "/admin/login",
            data={"_csrf_token": csrf_token, "username": "admin", "password": "wrong-password"},
            headers={"X-Forwarded-For": f"203.0.113.{i + 1}, 198.51.100.20"},
            follow_redirects=False,
        )
        assert response.status_code == 200

    blocked_page = proxied_client.get("/admin/login")
    blocked_token = extract_csrf_token(blocked_page.get_data(as_text=True))
    blocked = proxied_client.post(
        "/admin/login",
        data={"_csrf_token": blocked_token, "username": "admin", "password": "wrong-password"},
        headers={"X-Forwarded-For": "198.18.0.33, 198.51.100.20"},
        follow_redirects=False,
    )
    assert blocked.status_code == 429


def test_csrf_failure_redirect_rejects_external_referrer(client):
    response = client.post(
        "/contact",
        data={"name": "No Token", "email": "notoken@example.com", "message": "Should fail", "_csrf_token": "bad-token"},
        headers={"Referer": "https://evil.example/phish"},
        follow_redirects=False,
    )
    assert response.status_code in (302, 303)
    location = response.headers.get("Location") or ""
    assert location.startswith("/")
    assert "evil.example" not in location


def test_role_tier_editor_cannot_open_settings_or_users(client, app):
    admin_login(client)
    with app.app_context():
        editor = User(username=f"editor-{uuid.uuid4().hex[:6]}", email=f"editor-{uuid.uuid4().hex[:6]}@example.com", role=ROLE_EDITOR)
        editor.set_password("EditorPass!123")
        db.session.add(editor)
        db.session.commit()
        editor_username = editor.username

    dashboard = client.get("/admin/")
    csrf_token = extract_csrf_token(dashboard.get_data(as_text=True))
    assert csrf_token
    client.post("/admin/logout", data={"_csrf_token": csrf_token}, follow_redirects=False)

    admin_login_as(client, editor_username, "EditorPass!123")
    assert client.get("/admin/posts", follow_redirects=False).status_code == 200
    denied_settings = client.get("/admin/settings", follow_redirects=False)
    denied_users = client.get("/admin/users", follow_redirects=False)
    assert denied_settings.status_code in (302, 303)
    assert denied_users.status_code in (302, 303)
    assert denied_settings.headers.get("Location", "").endswith("/admin/")
    assert denied_users.headers.get("Location", "").endswith("/admin/")


def test_scheduled_publish_promotes_approved_post(client, app):
    with app.app_context():
        category = Category.query.first()
        assert category is not None
        post = Post(
            title=f"Scheduled publish {uuid.uuid4().hex[:8]}",
            slug=f"scheduled-publish-{uuid.uuid4().hex[:8]}",
            excerpt="Scheduled excerpt",
            content="<p>Scheduled content.</p>",
            category_id=category.id,
            workflow_status=WORKFLOW_APPROVED,
            scheduled_publish_at=utc_now_naive() - timedelta(minutes=2),
            is_published=False,
        )
        db.session.add(post)
        db.session.commit()
        created_id = post.id

    client.get("/")

    with app.app_context():
        refreshed = db.session.get(Post, created_id)
        assert refreshed is not None
        assert refreshed.workflow_status == WORKFLOW_PUBLISHED
        assert refreshed.is_published is True
        assert refreshed.scheduled_publish_at is None
        assert refreshed.published_at is not None


def test_draft_service_is_hidden_from_public_routes(client, app):
    with app.app_context():
        service = Service(
            title=f"Hidden Service {uuid.uuid4().hex[:6]}",
            slug=f"hidden-service-{uuid.uuid4().hex[:6]}",
            description="Should not be visible publicly.",
            service_type="professional",
            workflow_status=WORKFLOW_DRAFT,
            is_featured=True,
        )
        db.session.add(service)
        db.session.commit()
        hidden_slug = service.slug
        hidden_title = service.title

    services_page = client.get("/services")
    assert services_page.status_code == 200
    assert hidden_title not in services_page.get_data(as_text=True)
    assert client.get(f"/services/{hidden_slug}").status_code == 404
