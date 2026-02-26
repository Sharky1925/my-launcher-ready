import os
import tempfile
from urllib.parse import urlparse

basedir = os.path.abspath(os.path.dirname(__file__))


def _is_vercel_runtime():
    return bool(os.environ.get('VERCEL') or os.environ.get('VERCEL_ENV'))


def _is_managed_runtime():
    return bool(
        os.environ.get('RAILWAY_ENVIRONMENT')
        or os.environ.get('RAILWAY_PROJECT_ID')
        or os.environ.get('RENDER')
        or os.environ.get('RENDER_SERVICE_ID')
        or _is_vercel_runtime()
    )


def _is_production_runtime():
    flask_env = (os.environ.get('FLASK_ENV') or '').strip().lower()
    railway_env = (os.environ.get('RAILWAY_ENVIRONMENT') or '').strip().lower()
    render_env = (os.environ.get('RENDER_ENV') or '').strip().lower()
    vercel_env = (os.environ.get('VERCEL_ENV') or '').strip().lower()
    return flask_env == 'production' or railway_env == 'production' or render_env == 'production' or vercel_env == 'production'


def _as_bool(value, default=False):
    if value is None:
        return default
    return str(value).strip().lower() in {'1', 'true', 'yes', 'on'}


def _as_int(value, default):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _as_float(value, default):
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _database_url():
    raw = (os.environ.get('DATABASE_URL') or '').strip()
    if raw.startswith('postgres://'):
        raw = raw.replace('postgres://', 'postgresql://', 1)
    if raw:
        return raw
    if _is_vercel_runtime():
        return 'sqlite:////tmp/site.db'
    return 'sqlite:///' + os.path.join(basedir, 'site.db')


def _database_engine_options(database_url):
    if not database_url.startswith('sqlite'):
        options = {
            'pool_pre_ping': True,
            'pool_recycle': 300,
        }
        parsed = urlparse(database_url)
        if parsed.scheme.startswith('postgresql'):
            connect_timeout_seconds = max(1, _as_int(os.environ.get('DB_CONNECT_TIMEOUT_SECONDS'), 5))
            statement_timeout_ms = max(1000, _as_int(os.environ.get('DB_STATEMENT_TIMEOUT_MS'), 8000))
            idle_tx_timeout_ms = max(1000, _as_int(os.environ.get('DB_IDLE_IN_TX_TIMEOUT_MS'), 15000))
            pg_options = [
                f'-c statement_timeout={statement_timeout_ms}',
                f'-c idle_in_transaction_session_timeout={idle_tx_timeout_ms}',
            ]
            options['connect_args'] = {
                'connect_timeout': connect_timeout_seconds,
                'options': ' '.join(pg_options),
            }
        return options
    return {}


class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or ''
    SQLALCHEMY_DATABASE_URI = _database_url()
    SQLALCHEMY_ENGINE_OPTIONS = _database_engine_options(SQLALCHEMY_DATABASE_URI)
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    UPLOAD_FOLDER = (os.environ.get('UPLOAD_FOLDER') or '').strip() or (
        os.path.join(tempfile.gettempdir(), 'uploads') if _is_vercel_runtime() else os.path.join(basedir, 'uploads')
    )
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max upload
    MAX_UPLOAD_IMAGE_PIXELS = _as_int(os.environ.get('MAX_UPLOAD_IMAGE_PIXELS'), 40_000_000)
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp', 'pdf', 'ico'}
    ALLOWED_UPLOAD_MIME_TYPES = {
        'image/png',
        'image/jpeg',
        'image/gif',
        'image/webp',
        'image/x-icon',
        'image/vnd.microsoft.icon',
        'application/pdf',
    }
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    SESSION_COOKIE_SECURE = _as_bool(
        os.environ.get('SESSION_COOKIE_SECURE'),
        ((os.environ.get('PREFERRED_URL_SCHEME') or '').lower() == 'https') or _is_production_runtime(),
    )
    REMEMBER_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_SAMESITE = 'Lax'
    REMEMBER_COOKIE_SECURE = SESSION_COOKIE_SECURE
    TRUST_PROXY_HEADERS = _as_bool(os.environ.get('TRUST_PROXY_HEADERS'), _is_managed_runtime())
    PREFERRED_URL_SCHEME = os.environ.get('PREFERRED_URL_SCHEME') or ('https' if SESSION_COOKIE_SECURE else 'http')
    APP_BASE_URL = (os.environ.get('APP_BASE_URL') or '').rstrip('/')
    ASSET_VERSION = (os.environ.get('ASSET_VERSION') or '').strip()
    HSTS_ENABLED = _as_bool(os.environ.get('HSTS_ENABLED'), True)
    HSTS_MAX_AGE = _as_int(os.environ.get('HSTS_MAX_AGE'), 31536000)
    HSTS_INCLUDE_SUBDOMAINS = _as_bool(os.environ.get('HSTS_INCLUDE_SUBDOMAINS'), True)
    HSTS_PRELOAD = _as_bool(os.environ.get('HSTS_PRELOAD'), False)
    FORCE_HTTPS = _as_bool(os.environ.get('FORCE_HTTPS'), _is_production_runtime())
    _force_https_exempt = [p.strip() for p in os.environ.get('FORCE_HTTPS_EXEMPT_PATHS', '/healthz,/readyz').split(',')]
    FORCE_HTTPS_EXEMPT_PATHS = tuple(
        f'/{path}' if path and not path.startswith('/') else path
        for path in _force_https_exempt
        if path
    )
    HEADLESS_SYNC_ENABLED = _as_bool(os.environ.get('HEADLESS_SYNC_ENABLED'), True)
    HEADLESS_SYNC_TOKEN = (os.environ.get('HEADLESS_SYNC_TOKEN') or '').strip()
    HEADLESS_SYNC_MAX_ITEMS = max(1, _as_int(os.environ.get('HEADLESS_SYNC_MAX_ITEMS'), 250))
    HEADLESS_DELIVERY_REQUIRE_TOKEN = _as_bool(os.environ.get('HEADLESS_DELIVERY_REQUIRE_TOKEN'), False)
    HEADLESS_DELIVERY_TOKEN = (os.environ.get('HEADLESS_DELIVERY_TOKEN') or '').strip()
    HEADLESS_DELIVERY_DEFAULT_LIMIT = max(1, _as_int(os.environ.get('HEADLESS_DELIVERY_DEFAULT_LIMIT'), 24))
    HEADLESS_DELIVERY_MAX_LIMIT = max(1, _as_int(os.environ.get('HEADLESS_DELIVERY_MAX_LIMIT'), 100))
    CSRF_EXEMPT_ENDPOINTS = ('main.headless_sync_upsert',)
    _trusted_hosts = [h.strip() for h in os.environ.get('TRUSTED_HOSTS', '').split(',') if h.strip()]
    TRUSTED_HOSTS = _trusted_hosts or None

    SMTP_HOST = (os.environ.get('SMTP_HOST') or '').strip()
    SMTP_PORT = _as_int(os.environ.get('SMTP_PORT'), 587)
    SMTP_USERNAME = (os.environ.get('SMTP_USERNAME') or '').strip()
    SMTP_PASSWORD = os.environ.get('SMTP_PASSWORD') or ''
    SMTP_USE_TLS = _as_bool(os.environ.get('SMTP_USE_TLS'), True)
    SMTP_USE_SSL = _as_bool(os.environ.get('SMTP_USE_SSL'), False)
    MAIL_FROM = (os.environ.get('MAIL_FROM') or SMTP_USERNAME or 'no-reply@localhost').strip()
    CONTACT_NOTIFICATION_EMAILS = os.environ.get('CONTACT_NOTIFICATION_EMAILS') or ''
    TICKET_NOTIFICATION_EMAILS = os.environ.get('TICKET_NOTIFICATION_EMAILS') or ''

    MAILGUN_API_KEY = (os.environ.get('MAILGUN_API_KEY') or '').strip()
    MAILGUN_DOMAIN = (os.environ.get('MAILGUN_DOMAIN') or '').strip()

    TURNSTILE_SITE_KEY = (os.environ.get('TURNSTILE_SITE_KEY') or '').strip()
    TURNSTILE_SECRET_KEY = (os.environ.get('TURNSTILE_SECRET_KEY') or '').strip()
    TURNSTILE_ENFORCED = _as_bool(os.environ.get('TURNSTILE_ENFORCED'), True)

    CONTACT_FORM_LIMIT = _as_int(os.environ.get('CONTACT_FORM_LIMIT'), 12)
    CONTACT_FORM_WINDOW_SECONDS = _as_int(os.environ.get('CONTACT_FORM_WINDOW_SECONDS'), 3600)
    QUOTE_FORM_LIMIT = _as_int(os.environ.get('QUOTE_FORM_LIMIT'), 8)
    QUOTE_FORM_WINDOW_SECONDS = _as_int(os.environ.get('QUOTE_FORM_WINDOW_SECONDS'), 3600)
    TICKET_VERIFICATION_TOKEN_TTL_SECONDS = _as_int(os.environ.get('TICKET_VERIFICATION_TOKEN_TTL_SECONDS'), 604800)

    SENTRY_DSN = (os.environ.get('SENTRY_DSN') or '').strip()
    SENTRY_ENVIRONMENT = (os.environ.get('SENTRY_ENVIRONMENT') or '').strip()
    SENTRY_TRACES_SAMPLE_RATE = _as_float(os.environ.get('SENTRY_TRACES_SAMPLE_RATE'), 0.0)
    LOG_JSON = _as_bool(os.environ.get('LOG_JSON'), True)
    LOG_LEVEL = (os.environ.get('LOG_LEVEL') or 'INFO').strip().upper()
