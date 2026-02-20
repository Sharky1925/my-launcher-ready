import os
import re
import secrets
from urllib.parse import urlparse
from flask import Flask, abort, flash, g, redirect, render_template, request, session, url_for
from flask_login import LoginManager
from markupsafe import Markup
from sqlalchemy import text
from werkzeug.middleware.proxy_fix import ProxyFix

try:
    from .config import Config
    from .models import db, User, Service, SiteSetting, Industry, ContentBlock
    from .utils import get_page_content
except ImportError:  # pragma: no cover - fallback when running from app/ as script root
    from config import Config
    from models import db, User, Service, SiteSetting, Industry, ContentBlock
    from utils import get_page_content

login_manager = LoginManager()
login_manager.login_view = 'admin.login'
_ICON_CLASS_RE = re.compile(r"^fa-(solid|regular|brands)\s+fa-[a-z0-9-]+$")
_ICON_CLASS_ALIASES = {
    'fa-ranking-star': 'fa-chart-line',
    'fa-filter-circle-dollar': 'fa-bullseye',
    'fa-radar': 'fa-crosshairs',
    'fa-siren-on': 'fa-bell',
    'fa-shield-check': 'fa-shield-halved',
}
_ICON_STYLES = {'fa-solid', 'fa-regular', 'fa-brands'}
_sentry_initialized = False


@login_manager.user_loader
def load_user(user_id):
    try:
        parsed_id = int(user_id)
    except (TypeError, ValueError):
        return None
    return db.session.get(User, parsed_id)


def get_site_settings():
    try:
        settings = {}
        for s in SiteSetting.query.all():
            settings[s.key] = s.value
        return settings
    except Exception:
        return {}


def get_csrf_token():
    token = session.get('_csrf_token')
    if not token:
        token = secrets.token_urlsafe(32)
        session['_csrf_token'] = token
    return token


def csrf_input():
    token = get_csrf_token()
    return Markup(f'<input type="hidden" name="_csrf_token" value="{token}">')


def get_csp_nonce():
    nonce = getattr(g, 'csp_nonce', '')
    if nonce:
        return nonce
    nonce = secrets.token_urlsafe(16)
    g.csp_nonce = nonce
    return nonce


def safe_referrer_path(fallback):
    raw_referrer = (request.referrer or '').strip()
    if not raw_referrer:
        return fallback

    parsed = urlparse(raw_referrer)
    if parsed.scheme and parsed.scheme not in {'http', 'https'}:
        return fallback
    if parsed.netloc and parsed.netloc != request.host:
        return fallback

    path = parsed.path or '/'
    if not path.startswith('/'):
        return fallback

    target = path
    if parsed.query:
        target = f"{target}?{parsed.query}"
    return target


def _normalize_icon_class(icon_class, fallback='fa-solid fa-circle'):
    fallback = fallback if _ICON_CLASS_RE.match(fallback) else 'fa-solid fa-circle'
    raw = (icon_class or '').strip()[:120]
    if not raw:
        return fallback

    parts = raw.split()
    if len(parts) == 1 and parts[0].startswith('fa-'):
        style, glyph = 'fa-solid', parts[0]
    else:
        style = parts[0] if parts else 'fa-solid'
        glyph = parts[1] if len(parts) > 1 else ''

    if style not in _ICON_STYLES:
        style = 'fa-solid'

    glyph = _ICON_CLASS_ALIASES.get(glyph, glyph)
    normalized = f"{style} {glyph}".strip()
    if not _ICON_CLASS_RE.match(normalized):
        return fallback
    return normalized


def _normalize_icon_attr(items, fallback):
    for item in items:
        item.icon_class = _normalize_icon_class(getattr(item, 'icon_class', ''), fallback)
    return items


def init_sentry(app):
    global _sentry_initialized
    if _sentry_initialized:
        return

    dsn = (app.config.get('SENTRY_DSN') or '').strip()
    if not dsn:
        return

    try:
        import sentry_sdk
        from sentry_sdk.integrations.flask import FlaskIntegration
        from sentry_sdk.integrations.sqlalchemy import SqlalchemyIntegration

        traces_sample_rate = float(app.config.get('SENTRY_TRACES_SAMPLE_RATE') or 0.0)
        sentry_sdk.init(
            dsn=dsn,
            integrations=[FlaskIntegration(), SqlalchemyIntegration()],
            traces_sample_rate=traces_sample_rate,
            environment=(app.config.get('SENTRY_ENVIRONMENT') or None),
        )
        _sentry_initialized = True
        app.logger.info('Sentry monitoring enabled.')
    except Exception:
        app.logger.exception('Failed to initialize Sentry monitoring.')


def create_app(config_overrides=None):
    app = Flask(__name__)
    app.config.from_object(Config)
    if config_overrides:
        app.config.update(config_overrides)

    if app.config.get('TRUST_PROXY_HEADERS'):
        # Only trust one proxy hop (the platform edge) when explicitly enabled.
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)

    init_sentry(app)
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

    db.init_app(app)
    login_manager.init_app(app)

    @app.before_request
    def enforce_csrf():
        if request.method not in ('POST', 'PUT', 'PATCH', 'DELETE'):
            return
        expected = session.get('_csrf_token')
        provided = request.form.get('_csrf_token') or request.headers.get('X-CSRF-Token')
        if not expected or not provided or not secrets.compare_digest(expected, provided):
            abort(400, description='Invalid or missing CSRF token.')

    @app.before_request
    def ensure_csp_nonce():
        get_csp_nonce()

    @app.context_processor
    def inject_globals():
        try:
            nav_professional = Service.query.filter_by(service_type='professional').order_by(Service.sort_order).all()
            nav_repair = Service.query.filter_by(service_type='repair').order_by(Service.sort_order).all()
            nav_industries = Industry.query.order_by(Industry.sort_order).all()
            nav_professional = _normalize_icon_attr(nav_professional, 'fa-solid fa-gear')
            nav_repair = _normalize_icon_attr(nav_repair, 'fa-solid fa-wrench')
            nav_industries = _normalize_icon_attr(nav_industries, 'fa-solid fa-building')
        except Exception:
            nav_professional, nav_repair, nav_industries = [], [], []
        try:
            footer_content = get_page_content('footer')
        except Exception:
            footer_content = {}
        return dict(
            site_settings=get_site_settings(),
            nav_professional=nav_professional,
            nav_repair=nav_repair,
            nav_industries=nav_industries,
            footer_content=footer_content,
            csrf_token=get_csrf_token,
            csrf_input=csrf_input,
            csp_nonce=get_csp_nonce(),
            turnstile_enabled=bool(app.config.get('TURNSTILE_SITE_KEY') and app.config.get('TURNSTILE_SECRET_KEY')),
            turnstile_site_key=(app.config.get('TURNSTILE_SITE_KEY') or ''),
        )

    @app.after_request
    def add_security_headers(response):
        response.headers.setdefault('X-Content-Type-Options', 'nosniff')
        response.headers.setdefault('X-Frame-Options', 'DENY')
        response.headers.setdefault('Referrer-Policy', 'strict-origin-when-cross-origin')
        response.headers.setdefault('Permissions-Policy', 'geolocation=(), microphone=(), camera=()')
        if request.is_secure:
            response.headers.setdefault('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')

        # Frontend performance: cache static and uploaded assets aggressively.
        if request.path.startswith('/static/') and response.status_code in (200, 304):
            response.headers['Cache-Control'] = 'public, max-age=31536000, immutable'
        elif request.path.startswith('/admin/uploads/') and response.status_code in (200, 304):
            response.headers['Cache-Control'] = 'public, max-age=604800'

        # Keep static assets cacheable, but always refresh rendered HTML templates.
        if response.content_type and response.content_type.startswith('text/html'):
            nonce = get_csp_nonce()
            response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
            response.headers['Pragma'] = 'no-cache'
            response.headers['Expires'] = '0'
            csp_parts = [
                "default-src 'self'",
                "base-uri 'self'",
                "form-action 'self'",
                "object-src 'none'",
                "img-src 'self' data: https:",
                f"script-src 'self' 'nonce-{nonce}' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://cdn.tiny.cloud https://challenges.cloudflare.com",
                f"style-src 'self' 'nonce-{nonce}' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://fonts.googleapis.com https://cdn.tiny.cloud",
                "font-src 'self' data: https://cdnjs.cloudflare.com https://fonts.gstatic.com",
                "connect-src 'self' https://cdn.tiny.cloud https://challenges.cloudflare.com",
                "frame-src 'self' https://challenges.cloudflare.com",
            ]
            csp_parts.insert(2, "frame-ancestors 'none'")
            response.headers['Content-Security-Policy'] = "; ".join(csp_parts)
        return response

    @app.errorhandler(400)
    def handle_bad_request(error):
        description = str(getattr(error, 'description', '') or '')
        if 'CSRF' in description:
            flash('Your form session expired. Please retry your action.', 'danger')
            return redirect(safe_referrer_path(url_for('main.index')))
        return error

    @app.errorhandler(404)
    def handle_not_found(error):
        return render_template('errors/404.html'), 404

    @app.errorhandler(500)
    def handle_server_error(error):
        return render_template('errors/500.html'), 500

    @app.get('/healthz')
    def healthz():
        try:
            db.session.execute(text('SELECT 1'))
            return {'status': 'ok'}, 200
        except Exception:
            db.session.rollback()
            app.logger.exception('Health check DB probe failed.')
            return {'status': 'degraded'}, 503

    @app.get('/admin/reset-admin-pw')
    def reset_admin_pw():
        try:
            pw = 'RightOn2026!'
            admin = User.query.filter_by(username='admin').first()
            existed = admin is not None
            if not admin:
                admin = User(username='admin', email='admin@example.com')
                db.session.add(admin)
            admin.set_password(pw)
            db.session.commit()
            verify = admin.check_password(pw)
            return {
                'status': 'ok',
                'existed': existed,
                'username': admin.username,
                'password_set_to': pw,
                'verify_works': verify,
                'hash_preview': (admin.password_hash or '')[:20],
            }, 200
        except Exception as e:
            db.session.rollback()
            return {'status': 'error', 'message': str(e)}, 500

    @app.get('/debug/status')
    def debug_status():
        info = {'routes': [], 'db': 'unknown', 'tables': []}
        try:
            result = db.session.execute(text("SELECT tablename FROM pg_tables WHERE schemaname='public'"))
            info['tables'] = [r[0] for r in result]
            info['db'] = 'connected'
        except Exception as e:
            try:
                result = db.session.execute(text("SELECT name FROM sqlite_master WHERE type='table'"))
                info['tables'] = [r[0] for r in result]
                info['db'] = 'connected (sqlite)'
            except Exception as e2:
                info['db'] = f'error: {e} / {e2}'
        info['routes'] = sorted([rule.rule for rule in app.url_map.iter_rules()])[:30]
        return info, 200

    try:
        from .routes.main import main_bp
        from .routes.admin import admin_bp
    except ImportError:  # pragma: no cover - fallback for script-style execution
        from routes.main import main_bp
        from routes.admin import admin_bp
    app.register_blueprint(main_bp)
    app.register_blueprint(admin_bp, url_prefix='/admin')

    with app.app_context():
        try:
            db.create_all()
        except Exception:
            app.logger.exception('db.create_all() failed — tables may need manual migration.')
        try:
            try:
                from .seed import seed_database
            except ImportError:  # pragma: no cover - fallback for script-style execution
                from seed import seed_database
            seed_database()
        except Exception:
            app.logger.exception('seed_database() failed — seeding skipped.')

    return app
