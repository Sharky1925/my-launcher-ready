import os

basedir = os.path.abspath(os.path.dirname(__file__))


def _is_vercel_runtime():
    return bool(os.environ.get('VERCEL') or os.environ.get('VERCEL_ENV'))


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


class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or ''
    SQLALCHEMY_DATABASE_URI = _database_url()
    SQLALCHEMY_ENGINE_OPTIONS = {} if SQLALCHEMY_DATABASE_URI.startswith('sqlite') else {
        'pool_pre_ping': True,
        'pool_recycle': 300,
    }
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    UPLOAD_FOLDER = (os.environ.get('UPLOAD_FOLDER') or '').strip() or (
        '/tmp/uploads' if _is_vercel_runtime() else os.path.join(basedir, 'uploads')
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
        (os.environ.get('PREFERRED_URL_SCHEME') or '').lower() == 'https',
    )
    REMEMBER_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_SAMESITE = 'Lax'
    REMEMBER_COOKIE_SECURE = SESSION_COOKIE_SECURE
    TRUST_PROXY_HEADERS = _as_bool(os.environ.get('TRUST_PROXY_HEADERS'), False)
    PREFERRED_URL_SCHEME = os.environ.get('PREFERRED_URL_SCHEME') or ('https' if SESSION_COOKIE_SECURE else 'http')
    APP_BASE_URL = (os.environ.get('APP_BASE_URL') or '').rstrip('/')
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

    SENTRY_DSN = (os.environ.get('SENTRY_DSN') or '').strip()
    SENTRY_ENVIRONMENT = (os.environ.get('SENTRY_ENVIRONMENT') or '').strip()
    SENTRY_TRACES_SAMPLE_RATE = _as_float(os.environ.get('SENTRY_TRACES_SAMPLE_RATE'), 0.0)
