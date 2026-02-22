import re
import uuid

import pytest

try:
    from app.routes import admin as admin_routes
    from app.routes import main as main_routes
    from app import create_app
    from app.models import (
        Category,
        ContactSubmission,
        Post,
        Service,
        SupportClient,
        SupportTicket,
        AuthRateLimitBucket,
        SecurityEvent,
        db,
    )
except ModuleNotFoundError:  # pragma: no cover - fallback for direct app/ cwd test runs
    import routes.admin as admin_routes
    import routes.main as main_routes
    from __init__ import create_app
    from models import (
        Category,
        ContactSubmission,
        Post,
        Service,
        SupportClient,
        SupportTicket,
        AuthRateLimitBucket,
        SecurityEvent,
        db,
    )

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
    login_page = client.get("/admin/login")
    csrf_token = extract_csrf_token(login_page.get_data(as_text=True))
    assert csrf_token

    response = client.post(
        "/admin/login",
        data={
            "_csrf_token": csrf_token,
            "username": "admin",
            "password": "admin123",
        },
        follow_redirects=False,
    )
    assert response.status_code in (302, 303)


def test_public_pages_and_security_headers(client):
    response = client.get("/")
    assert response.status_code == 200
    assert "Content-Security-Policy" in response.headers
    csp = response.headers.get("Content-Security-Policy", "")
    assert "script-src 'self' 'nonce-" in csp
    assert "script-src 'self' 'unsafe-inline'" not in csp
    assert "style-src 'self' 'nonce-" in csp
    assert "style-src 'self' 'unsafe-inline'" not in csp
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


def test_hsts_header_on_https_requests(client):
    response = client.get("/", base_url="https://example.com")
    assert response.status_code == 200
    assert response.headers.get("Strict-Transport-Security") == "max-age=31536000; includeSubDomains; preload"


def test_hsts_header_on_trusted_forwarded_proto(tmp_path, monkeypatch):
    proxied_app = build_test_app(tmp_path, monkeypatch, {"TRUST_PROXY_HEADERS": True})
    proxied_client = proxied_app.test_client()
    response = proxied_client.get("/", base_url="http://example.com", headers={"X-Forwarded-Proto": "https"})
    assert response.status_code == 200
    assert response.headers.get("Strict-Transport-Security") == "max-age=31536000; includeSubDomains; preload"


def test_health_endpoint_reports_ok(client):
    response = client.get("/healthz")
    assert response.status_code == 200
    payload = response.get_json()
    assert payload["status"] == "ok"


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
