from datetime import timedelta
import json
import os
import re
import uuid
import bleach
from sqlalchemy import func, or_
from flask import Blueprint, render_template, request, redirect, url_for, flash, current_app, send_from_directory, session, abort
from flask_login import login_user, logout_user, login_required, current_user
from PIL import Image, UnidentifiedImageError
from sqlalchemy.exc import IntegrityError
from werkzeug.utils import secure_filename
from werkzeug.security import check_password_hash, generate_password_hash
from slugify import slugify
try:
    from ..models import (
        db,
        User,
        Service,
        TeamMember,
        Testimonial,
        Category,
        Post,
        Media,
        ContactSubmission,
        SiteSetting,
        SupportClient,
        SupportTicket,
        AuthRateLimitBucket,
        SecurityEvent,
        Industry,
        ContentBlock,
    )
    from ..utils import utc_now_naive, clean_text, escape_like, is_valid_email, get_request_ip
    from ..content_schemas import CONTENT_SCHEMAS
except ImportError:  # pragma: no cover - fallback when running from app/ cwd
    from models import (
        db,
        User,
        Service,
        TeamMember,
        Testimonial,
        Category,
        Post,
        Media,
        ContactSubmission,
        SiteSetting,
        SupportClient,
        SupportTicket,
        AuthRateLimitBucket,
        SecurityEvent,
        Industry,
        ContentBlock,
    )
    from utils import utc_now_naive, clean_text, escape_like, is_valid_email, get_request_ip
    from content_schemas import CONTENT_SCHEMAS

admin_bp = Blueprint('admin', __name__, template_folder='../templates/admin')
ADMIN_LOGIN_LIMIT = 5
ADMIN_LOGIN_WINDOW_SECONDS = 300
IMAGE_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp', 'ico'}
ADMIN_PASSWORD_MIN_LENGTH = 10
AUTH_DUMMY_HASH = generate_password_hash('RightOnRepair::dummy-auth-check')
QUOTE_INTAKE_EMAIL = 'quote-intake@rightonrepair.local'
QUOTE_SUBJECT_PREFIX = 'quote request:'
QUOTE_DETAILS_PREFIX = 'quote intake submission'
ALLOWED_RICH_TEXT_TAGS = [
    'p', 'br', 'strong', 'em', 'b', 'i', 'u', 'blockquote', 'code', 'pre',
    'ul', 'ol', 'li', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
    'a', 'img', 'table', 'thead', 'tbody', 'tr', 'th', 'td', 'hr', 'div', 'span'
]
ALLOWED_RICH_TEXT_ATTRIBUTES = {
    '*': ['class'],
    'a': ['href', 'title', 'target', 'rel'],
    'img': ['src', 'alt', 'title', 'width', 'height'],
}
ALLOWED_RICH_TEXT_PROTOCOLS = ['http', 'https', 'mailto']


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in current_app.config['ALLOWED_EXTENSIONS']


def _safe_upload_path(stored_name):
    upload_root = os.path.abspath(current_app.config['UPLOAD_FOLDER'])
    raw_name = (stored_name or '').strip()
    safe_name = secure_filename(raw_name)
    if not safe_name or safe_name != raw_name:
        return None, None
    full_path = os.path.abspath(os.path.join(upload_root, safe_name))
    try:
        if os.path.commonpath([upload_root, full_path]) != upload_root:
            return None, None
    except ValueError:
        return None, None
    return safe_name, full_path


def parse_int(value, default=0, min_value=None, max_value=None):
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    if min_value is not None and parsed < min_value:
        return min_value
    if max_value is not None and parsed > max_value:
        return max_value
    return parsed


def parse_positive_int(value):
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    if parsed <= 0:
        return None
    return parsed


def is_strong_password(value):
    password = value or ''
    return (
        len(password) >= ADMIN_PASSWORD_MIN_LENGTH
        and any(c.isupper() for c in password)
        and any(c.islower() for c in password)
        and any(c.isdigit() for c in password)
        and any(not c.isalnum() for c in password)
    )


def is_valid_url(value):
    return not value or value.startswith('https://') or value.startswith('http://')


def sanitize_html(value, max_length=100000):
    html = (value or '').strip()
    cleaned = bleach.clean(
        html,
        tags=ALLOWED_RICH_TEXT_TAGS,
        attributes=ALLOWED_RICH_TEXT_ATTRIBUTES,
        protocols=ALLOWED_RICH_TEXT_PROTOCOLS,
        strip=True,
    )
    return cleaned[:max_length]


def quote_ticket_filter_expression():
    return or_(
        func.lower(SupportTicket.subject).like(f'{QUOTE_SUBJECT_PREFIX}%'),
        func.lower(SupportTicket.details).like(f'{QUOTE_DETAILS_PREFIX}%'),
        func.lower(SupportClient.email) == QUOTE_INTAKE_EMAIL,
    )


def is_quote_ticket(ticket):
    if not ticket:
        return False
    subject = (ticket.subject or '').strip().lower()
    details = (ticket.details or '').strip().lower()
    client = getattr(ticket, 'client', None)
    client_email = (getattr(client, 'email', '') or '').strip().lower()
    return (
        subject.startswith(QUOTE_SUBJECT_PREFIX)
        or details.startswith(QUOTE_DETAILS_PREFIX)
        or client_email == QUOTE_INTAKE_EMAIL
    )


def get_login_bucket():
    ip = get_request_ip()
    now = utc_now_naive()
    bucket = AuthRateLimitBucket.query.filter_by(scope='admin_login', ip=ip).first()
    if not bucket:
        bucket = AuthRateLimitBucket(
            scope='admin_login',
            ip=ip,
            count=0,
            reset_at=now + timedelta(seconds=ADMIN_LOGIN_WINDOW_SECONDS),
        )
        db.session.add(bucket)
        db.session.commit()
        return bucket
    if bucket.reset_at <= now:
        bucket.count = 0
        bucket.reset_at = now + timedelta(seconds=ADMIN_LOGIN_WINDOW_SECONDS)
        db.session.commit()
    return bucket


def is_admin_login_rate_limited():
    bucket = get_login_bucket()
    if bucket.count < ADMIN_LOGIN_LIMIT:
        return False, 0
    seconds = max(1, int((bucket.reset_at - utc_now_naive()).total_seconds()))
    return True, seconds


def register_admin_login_failure():
    bucket = get_login_bucket()
    bucket.count += 1
    db.session.commit()
    return bucket.count


def clear_admin_login_failures():
    ip = get_request_ip()
    bucket = AuthRateLimitBucket.query.filter_by(scope='admin_login', ip=ip).first()
    if bucket:
        db.session.delete(bucket)
        db.session.commit()


def validate_uploaded_file(file):
    if not file or not file.filename:
        return False

    filename = secure_filename(file.filename)
    if not filename or len(filename) > 180 or not allowed_file(filename):
        return False

    extension = filename.rsplit('.', 1)[1].lower()
    mime_type = (file.mimetype or '').split(';', 1)[0].lower()
    allowed_mimes = current_app.config.get('ALLOWED_UPLOAD_MIME_TYPES', set())
    extension_allowed_mimes = {
        'png': {'image/png'},
        'jpg': {'image/jpeg'},
        'jpeg': {'image/jpeg'},
        'gif': {'image/gif'},
        'webp': {'image/webp'},
        'ico': {'image/x-icon', 'image/vnd.microsoft.icon'},
        'pdf': {'application/pdf'},
    }
    if (
        mime_type not in allowed_mimes
        or extension not in extension_allowed_mimes
        or mime_type not in extension_allowed_mimes[extension]
    ):
        return False

    file.stream.seek(0)
    if extension == 'pdf':
        signature = file.stream.read(5)
        file.stream.seek(0)
        return signature == b'%PDF-'

    if extension in IMAGE_EXTENSIONS:
        max_pixels = max(1, int(current_app.config.get('MAX_UPLOAD_IMAGE_PIXELS', 40_000_000)))
        try:
            with Image.open(file.stream) as image:
                width, height = image.size
                if width < 1 or height < 1 or (width * height) > max_pixels:
                    return False
                image.verify()
            return True
        except (UnidentifiedImageError, OSError, Image.DecompressionBombError):
            return False
        finally:
            file.stream.seek(0)

    file.stream.seek(0)
    return False


def save_upload(file):
    if validate_uploaded_file(file):
        filename = secure_filename(file.filename)
        if not filename:
            return None
        unique_name = f"{uuid.uuid4().hex[:16]}_{filename}"
        full_path = os.path.join(current_app.config['UPLOAD_FOLDER'], unique_name)
        file.save(full_path)
        file_size = os.path.getsize(full_path)
        media = Media(filename=filename, file_path=unique_name, file_size=file_size, mime_type=(file.mimetype or ''))
        db.session.add(media)
        db.session.commit()
        return unique_name
    return None


@admin_bp.route('/uploads/<filename>')
def uploaded_file(filename):
    safe_filename, full_path = _safe_upload_path(filename)
    if not safe_filename or not full_path or not os.path.exists(full_path):
        abort(404)
    response = send_from_directory(current_app.config['UPLOAD_FOLDER'], safe_filename, conditional=True, etag=True)
    extension = safe_filename.rsplit('.', 1)[1].lower() if '.' in safe_filename else ''
    if extension not in IMAGE_EXTENSIONS:
        response.headers['Content-Disposition'] = f'attachment; filename="{safe_filename}"'
    return response


# Auth
@admin_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('admin.dashboard'))
    if request.method == 'POST':
        limited, seconds = is_admin_login_rate_limited()
        if limited:
            flash(f'Too many login attempts. Try again in {seconds} seconds.', 'danger')
            return render_template('admin/login.html'), 429

        username = clean_text(request.form.get('username'), 80)
        password = request.form.get('password', '')
        user = User.query.filter_by(username=username).first()
        password_ok = False
        if user:
            password_ok = user.check_password(password)
        else:
            # Keep response timing closer for unknown usernames.
            check_password_hash(AUTH_DUMMY_HASH, password or '')
        if user and password_ok:
            clear_admin_login_failures()
            session.clear()
            login_user(user)
            return redirect(url_for('admin.dashboard'))

        attempts = register_admin_login_failure()
        remaining = max(0, ADMIN_LOGIN_LIMIT - attempts)
        if remaining == 0:
            flash('Too many failed attempts. Please wait 5 minutes and try again.', 'danger')
        else:
            flash(f'Invalid credentials. {remaining} attempt(s) remaining before temporary lock.', 'danger')
    return render_template('admin/login.html')


@admin_bp.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('admin.login'))


# Dashboard
@admin_bp.route('/')
@login_required
def dashboard():
    now = utc_now_naive()
    last_24h = now - timedelta(hours=24)
    last_7d = now - timedelta(days=7)
    stale_cutoff = now - timedelta(days=14)
    open_ticket_statuses = ['open', 'in_progress', 'waiting_customer']
    quote_filter = quote_ticket_filter_expression()

    site_settings = {s.key: s.value for s in SiteSetting.query.all()}
    missing_setting_keys = [
        key for key in ('company_name', 'email', 'meta_title', 'meta_description')
        if not (site_settings.get(key) or '').strip()
    ]

    published_posts_count = Post.query.filter_by(is_published=True).count()
    draft_posts_count = Post.query.filter_by(is_published=False).count()
    contacts_24h = ContactSubmission.query.filter(ContactSubmission.created_at >= last_24h).count()
    tickets_24h = SupportTicket.query.filter(SupportTicket.created_at >= last_24h).count()
    support_waiting_count = SupportTicket.query.filter(SupportTicket.status == 'waiting_customer').count()
    critical_open_tickets = SupportTicket.query.filter(
        SupportTicket.status.in_(open_ticket_statuses),
        SupportTicket.priority.in_(['high', 'critical']),
    ).count()
    quote_open_count = SupportTicket.query.join(
        SupportClient,
        SupportTicket.client_id == SupportClient.id,
    ).filter(
        quote_filter,
        SupportTicket.status.in_(open_ticket_statuses),
    ).count()
    support_open_count = SupportTicket.query.join(
        SupportClient,
        SupportTicket.client_id == SupportClient.id,
    ).filter(
        ~quote_filter,
        SupportTicket.status.in_(open_ticket_statuses),
    ).count()
    resolved_7d_count = SupportTicket.query.filter(
        SupportTicket.status == 'resolved',
        SupportTicket.updated_at >= last_7d,
    ).count()

    services_missing_profile = Service.query.filter(
        or_(
            Service.profile_json.is_(None),
            func.trim(Service.profile_json) == '',
        )
    ).count()
    services_missing_image = Service.query.filter(
        or_(
            Service.image.is_(None),
            func.trim(Service.image) == '',
        )
    ).count()
    industries_incomplete = Industry.query.filter(
        or_(
            Industry.hero_description.is_(None),
            func.trim(Industry.hero_description) == '',
            Industry.challenges.is_(None),
            func.trim(Industry.challenges) == '',
            Industry.solutions.is_(None),
            func.trim(Industry.solutions) == '',
        )
    ).count()
    published_posts_missing_excerpt = Post.query.filter(
        Post.is_published.is_(True),
        or_(Post.excerpt.is_(None), func.trim(Post.excerpt) == ''),
    ).count()
    stale_drafts = Post.query.filter(
        Post.is_published.is_(False),
        Post.updated_at <= stale_cutoff,
    ).order_by(Post.updated_at.asc()).limit(6).all()

    status_rows = db.session.query(
        SupportTicket.status,
        func.count(SupportTicket.id),
    ).group_by(SupportTicket.status).all()
    status_map = {status: count for status, count in status_rows}
    ticket_status = [
        {'key': 'open', 'label': 'Open', 'count': status_map.get('open', 0)},
        {'key': 'in_progress', 'label': 'In Progress', 'count': status_map.get('in_progress', 0)},
        {'key': 'waiting_customer', 'label': 'Waiting Client', 'count': status_map.get('waiting_customer', 0)},
        {'key': 'resolved', 'label': 'Resolved', 'count': status_map.get('resolved', 0)},
        {'key': 'closed', 'label': 'Closed', 'count': status_map.get('closed', 0)},
    ]
    max_status_count = max(1, *(item['count'] for item in ticket_status))
    for item in ticket_status:
        item['pct'] = int(round((item['count'] / max_status_count) * 100)) if item['count'] else 0

    service_title_map = {slug: title for slug, title in Service.query.with_entities(Service.slug, Service.title).all()}
    popular_service_rows = db.session.query(
        SupportTicket.service_slug,
        func.count(SupportTicket.id).label('count'),
    ).filter(
        SupportTicket.service_slug.isnot(None),
        func.trim(SupportTicket.service_slug) != '',
    ).group_by(
        SupportTicket.service_slug,
    ).order_by(
        func.count(SupportTicket.id).desc(),
    ).limit(6).all()
    popular_services = []
    for slug, count in popular_service_rows:
        normalized_slug = (slug or '').strip()
        if not normalized_slug:
            continue
        popular_services.append({
            'slug': normalized_slug,
            'title': service_title_map.get(normalized_slug, normalized_slug.replace('-', ' ').title()),
            'count': count,
        })

    stats = {
        'services': Service.query.count(),
        'industries': Industry.query.count(),
        'team': TeamMember.query.count(),
        'posts': Post.query.count(),
        'published_posts': published_posts_count,
        'draft_posts': draft_posts_count,
        'stale_drafts': len(stale_drafts),
        'content_blocks': ContentBlock.query.count(),
        'contacts': ContactSubmission.query.filter_by(is_read=False).count(),
        'contacts_24h': contacts_24h,
        'testimonials': Testimonial.query.count(),
        'media': Media.query.count(),
        'support_tickets': SupportTicket.query.filter(SupportTicket.status.in_(open_ticket_statuses)).count(),
        'support_clients': SupportClient.query.count(),
        'support_open': support_open_count,
        'quote_open': quote_open_count,
        'critical_open_tickets': critical_open_tickets,
        'support_waiting': support_waiting_count,
        'resolved_7d': resolved_7d_count,
        'tickets_24h': tickets_24h,
        'security_events_24h': SecurityEvent.query.filter(
            SecurityEvent.created_at >= last_24h,
            SecurityEvent.event_type.in_(['turnstile_failed', 'rate_limited']),
        ).count(),
        'security_turnstile_24h': SecurityEvent.query.filter(
            SecurityEvent.created_at >= last_24h,
            SecurityEvent.event_type == 'turnstile_failed',
        ).count(),
        'security_rate_limited_24h': SecurityEvent.query.filter(
            SecurityEvent.created_at >= last_24h,
            SecurityEvent.event_type == 'rate_limited',
        ).count(),
        'active_admin_buckets': AuthRateLimitBucket.query.filter(
            AuthRateLimitBucket.scope == 'admin_login',
            AuthRateLimitBucket.count > 0,
            AuthRateLimitBucket.reset_at > now,
        ).count(),
        'services_missing_profile': services_missing_profile,
        'services_missing_image': services_missing_image,
        'industries_incomplete': industries_incomplete,
        'published_posts_missing_excerpt': published_posts_missing_excerpt,
        'missing_setting_keys': len(missing_setting_keys),
    }

    response_backlog = stats['contacts'] + stats['support_waiting'] + stats['critical_open_tickets']
    content_issues = stats['services_missing_profile'] + stats['industries_incomplete']
    seo_issues = stats['published_posts_missing_excerpt'] + stats['missing_setting_keys']
    security_issues = stats['security_events_24h'] + stats['active_admin_buckets']
    health_penalty = (content_issues * 4) + (seo_issues * 3) + (response_backlog * 2) + (security_issues * 2)
    health_score = max(10, min(100, 100 - health_penalty))

    health_checks = [
        {
            'label': 'Content Structure',
            'issues': content_issues,
            'href': url_for('admin.services'),
            'description': 'Service profiles and industry challenge/solution completeness.',
        },
        {
            'label': 'SEO Readiness',
            'issues': seo_issues,
            'href': url_for('admin.posts'),
            'description': 'Published excerpts plus global metadata settings coverage.',
        },
        {
            'label': 'Response Backlog',
            'issues': response_backlog,
            'href': url_for('admin.support_tickets'),
            'description': 'Unread leads, waiting-client tickets, and urgent open support items.',
        },
        {
            'label': 'Security Watchlist',
            'issues': security_issues,
            'href': url_for('admin.security_events'),
            'description': 'Rate-limiting and Turnstile failures in the last 24 hours.',
        },
    ]
    for item in health_checks:
        issues = item['issues']
        if issues == 0:
            item['state'] = 'good'
        elif issues <= 3:
            item['state'] = 'warn'
        else:
            item['state'] = 'critical'

    urgent_tickets = SupportTicket.query.filter(
        SupportTicket.status.in_(open_ticket_statuses),
        SupportTicket.priority.in_(['high', 'critical']),
    ).order_by(SupportTicket.updated_at.desc()).limit(6).all()
    unread_contacts = ContactSubmission.query.filter_by(is_read=False).order_by(ContactSubmission.created_at.desc()).limit(6).all()
    recent_contacts = ContactSubmission.query.order_by(ContactSubmission.created_at.desc()).limit(6).all()
    recent_tickets = SupportTicket.query.order_by(SupportTicket.updated_at.desc()).limit(6).all()
    recent_posts = Post.query.order_by(Post.updated_at.desc()).limit(6).all()
    recent_security = SecurityEvent.query.order_by(SecurityEvent.created_at.desc()).limit(6).all()

    search_query = clean_text(request.args.get('q', ''), 120).lower().strip()
    search_results = {
        'services': [],
        'industries': [],
        'posts': [],
        'contacts': [],
        'tickets': [],
    }
    if search_query:
        safe_search = escape_like(search_query)
        like_pattern = f'%{safe_search}%'
        search_results['services'] = Service.query.filter(
            or_(
                func.lower(Service.title).like(like_pattern),
                func.lower(Service.slug).like(like_pattern),
                func.lower(Service.description).like(like_pattern),
            )
        ).order_by(Service.sort_order.asc(), Service.id.asc()).limit(6).all()
        search_results['industries'] = Industry.query.filter(
            or_(
                func.lower(Industry.title).like(like_pattern),
                func.lower(Industry.slug).like(like_pattern),
                func.lower(Industry.description).like(like_pattern),
            )
        ).order_by(Industry.sort_order.asc(), Industry.id.asc()).limit(6).all()
        search_results['posts'] = Post.query.filter(
            or_(
                func.lower(Post.title).like(like_pattern),
                func.lower(Post.slug).like(like_pattern),
                func.lower(Post.excerpt).like(like_pattern),
            )
        ).order_by(Post.updated_at.desc()).limit(6).all()
        search_results['contacts'] = ContactSubmission.query.filter(
            or_(
                func.lower(ContactSubmission.name).like(like_pattern),
                func.lower(ContactSubmission.email).like(like_pattern),
                func.lower(ContactSubmission.subject).like(like_pattern),
            )
        ).order_by(ContactSubmission.created_at.desc()).limit(6).all()
        search_results['tickets'] = SupportTicket.query.join(
            SupportClient,
            SupportTicket.client_id == SupportClient.id,
        ).filter(
            or_(
                func.lower(SupportTicket.ticket_number).like(like_pattern),
                func.lower(SupportTicket.subject).like(like_pattern),
                func.lower(SupportClient.full_name).like(like_pattern),
                func.lower(SupportClient.email).like(like_pattern),
            )
        ).order_by(SupportTicket.updated_at.desc()).limit(6).all()

    search_total = sum(len(results) for results in search_results.values())

    activity_feed = []
    for item in recent_contacts:
        activity_feed.append({
            'at': item.created_at,
            'icon': 'fa-solid fa-envelope',
            'tone': 'info',
            'title': item.subject or f'Contact from {item.name}',
            'meta': f'{item.name} · {item.email}',
            'href': url_for('admin.contact_view', id=item.id),
        })
    for item in recent_tickets:
        ticket_type = 'Quote' if is_quote_ticket(item) else 'Support'
        activity_feed.append({
            'at': item.updated_at,
            'icon': 'fa-solid fa-ticket',
            'tone': 'primary',
            'title': f'{ticket_type} ticket {item.ticket_number}',
            'meta': f'{item.subject} · {item.status.replace("_", " ").title()}',
            'href': url_for('admin.support_ticket_view', id=item.id),
        })
    for item in recent_posts:
        activity_feed.append({
            'at': item.updated_at,
            'icon': 'fa-solid fa-newspaper',
            'tone': 'success',
            'title': f'Post updated: {item.title}',
            'meta': 'Published' if item.is_published else 'Draft',
            'href': url_for('admin.post_edit', id=item.id),
        })
    for item in recent_security:
        activity_feed.append({
            'at': item.created_at,
            'icon': 'fa-solid fa-shield-halved',
            'tone': 'warning',
            'title': item.event_type.replace('_', ' ').title(),
            'meta': f'{item.scope} · {item.ip}',
            'href': url_for('admin.security_events'),
        })
    activity_feed.sort(key=lambda event: event['at'] or now, reverse=True)
    activity_feed = activity_feed[:12]

    return render_template(
        'admin/dashboard.html',
        stats=stats,
        health_score=health_score,
        health_checks=health_checks,
        missing_setting_keys=missing_setting_keys,
        ticket_status=ticket_status,
        popular_services=popular_services,
        urgent_tickets=urgent_tickets,
        unread_contacts=unread_contacts,
        stale_drafts=stale_drafts,
        recent_posts=recent_posts,
        recent_security=recent_security,
        activity_feed=activity_feed,
        search_query=search_query,
        search_results=search_results,
        search_total=search_total,
        recent_contacts=recent_contacts,
        recent_tickets=recent_tickets,
        is_quote_ticket=is_quote_ticket,
    )


# Services CRUD
@admin_bp.route('/services')
@login_required
def services():
    items = Service.query.order_by(Service.sort_order).all()
    return render_template('admin/services.html', items=items)


@admin_bp.route('/services/add', methods=['GET', 'POST'])
@login_required
def service_add():
    if request.method == 'POST':
        title = clean_text(request.form.get('title'), 200)
        description = clean_text(request.form.get('description'), 10000)
        icon_class = clean_text(request.form.get('icon_class', 'fa-solid fa-gear'), 100)
        service_type = clean_text(request.form.get('service_type', 'professional'), 20)
        service_type = service_type if service_type in {'professional', 'repair'} else 'professional'
        sort_order = parse_int(request.form.get('sort_order', 0), default=0, min_value=-100000, max_value=100000)

        if not title or not description:
            flash('Title and description are required.', 'danger')
            return render_template('admin/service_form.html', item=None)

        slug = slugify(title)
        if not slug:
            flash('Unable to generate a valid slug from title.', 'danger')
            return render_template('admin/service_form.html', item=None)
        if Service.query.filter_by(slug=slug).first():
            flash('A service with that title already exists.', 'danger')
            return render_template('admin/service_form.html', item=None)

        profile_json_raw = request.form.get('profile_json', '').strip()
        if profile_json_raw:
            try:
                json.loads(profile_json_raw)
            except (json.JSONDecodeError, TypeError):
                flash('Invalid JSON in service profile.', 'danger')
                return render_template('admin/service_form.html', item=None)

        image = save_upload(request.files.get('image')) if request.files.get('image') else None
        item = Service(
            title=title,
            slug=slug,
            description=description,
            icon_class=icon_class,
            image=image,
            service_type=service_type,
            is_featured='is_featured' in request.form,
            sort_order=sort_order,
            profile_json=profile_json_raw or None,
        )
        db.session.add(item)
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            flash('Unable to save service due to duplicate data.', 'danger')
            return render_template('admin/service_form.html', item=None)
        flash('Service added.', 'success')
        return redirect(url_for('admin.services'))
    return render_template('admin/service_form.html', item=None)


@admin_bp.route('/services/<int:id>/edit', methods=['GET', 'POST'])
@login_required
def service_edit(id):
    item = Service.query.get_or_404(id)
    if request.method == 'POST':
        title = clean_text(request.form.get('title'), 200)
        description = clean_text(request.form.get('description'), 10000)
        icon_class = clean_text(request.form.get('icon_class', 'fa-solid fa-gear'), 100)
        service_type = clean_text(request.form.get('service_type', 'professional'), 20)
        service_type = service_type if service_type in {'professional', 'repair'} else 'professional'
        sort_order = parse_int(request.form.get('sort_order', 0), default=0, min_value=-100000, max_value=100000)

        if not title or not description:
            flash('Title and description are required.', 'danger')
            return render_template('admin/service_form.html', item=item)

        slug = slugify(title)
        if not slug:
            flash('Unable to generate a valid slug from title.', 'danger')
            return render_template('admin/service_form.html', item=item)
        slug_exists = Service.query.filter(Service.slug == slug, Service.id != item.id).first()
        if slug_exists:
            flash('Another service already uses this title/slug.', 'danger')
            return render_template('admin/service_form.html', item=item)

        profile_json_raw = request.form.get('profile_json', '').strip()
        if profile_json_raw:
            try:
                json.loads(profile_json_raw)
            except (json.JSONDecodeError, TypeError):
                flash('Invalid JSON in service profile.', 'danger')
                return render_template('admin/service_form.html', item=item)

        item.title = title
        item.slug = slug
        item.description = description
        item.icon_class = icon_class
        item.service_type = service_type
        item.is_featured = 'is_featured' in request.form
        item.sort_order = sort_order
        item.profile_json = profile_json_raw or None
        if request.files.get('image') and request.files['image'].filename:
            uploaded_image = save_upload(request.files['image'])
            if not uploaded_image:
                flash('Invalid image upload.', 'danger')
                return render_template('admin/service_form.html', item=item)
            item.image = uploaded_image
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            flash('Unable to update service due to duplicate data.', 'danger')
            return render_template('admin/service_form.html', item=item)
        flash('Service updated.', 'success')
        return redirect(url_for('admin.services'))
    return render_template('admin/service_form.html', item=item)


@admin_bp.route('/services/<int:id>/delete', methods=['POST'])
@login_required
def service_delete(id):
    db.session.delete(Service.query.get_or_404(id))
    db.session.commit()
    flash('Service deleted.', 'success')
    return redirect(url_for('admin.services'))


# Team CRUD
@admin_bp.route('/team')
@login_required
def team():
    items = TeamMember.query.order_by(TeamMember.sort_order).all()
    return render_template('admin/team.html', items=items)


@admin_bp.route('/team/add', methods=['GET', 'POST'])
@login_required
def team_add():
    if request.method == 'POST':
        name = clean_text(request.form.get('name'), 200)
        position = clean_text(request.form.get('position'), 200)
        bio = clean_text(request.form.get('bio', ''), 4000)
        linkedin = clean_text(request.form.get('linkedin', ''), 300)
        sort_order = parse_int(request.form.get('sort_order', 0), default=0, min_value=-100000, max_value=100000)

        if not name or not position:
            flash('Name and position are required.', 'danger')
            return render_template('admin/team_form.html', item=None)

        photo = save_upload(request.files.get('photo')) if request.files.get('photo') else None
        item = TeamMember(
            name=name,
            position=position,
            bio=bio,
            photo=photo,
            linkedin=linkedin,
            sort_order=sort_order
        )
        db.session.add(item)
        db.session.commit()
        flash('Team member added.', 'success')
        return redirect(url_for('admin.team'))
    return render_template('admin/team_form.html', item=None)


@admin_bp.route('/team/<int:id>/edit', methods=['GET', 'POST'])
@login_required
def team_edit(id):
    item = TeamMember.query.get_or_404(id)
    if request.method == 'POST':
        name = clean_text(request.form.get('name'), 200)
        position = clean_text(request.form.get('position'), 200)
        bio = clean_text(request.form.get('bio', ''), 4000)
        linkedin = clean_text(request.form.get('linkedin', ''), 300)
        sort_order = parse_int(request.form.get('sort_order', 0), default=0, min_value=-100000, max_value=100000)

        if not name or not position:
            flash('Name and position are required.', 'danger')
            return render_template('admin/team_form.html', item=item)

        item.name = name
        item.position = position
        item.bio = bio
        item.linkedin = linkedin
        item.sort_order = sort_order
        if request.files.get('photo') and request.files['photo'].filename:
            uploaded_photo = save_upload(request.files['photo'])
            if not uploaded_photo:
                flash('Invalid photo upload.', 'danger')
                return render_template('admin/team_form.html', item=item)
            item.photo = uploaded_photo
        db.session.commit()
        flash('Team member updated.', 'success')
        return redirect(url_for('admin.team'))
    return render_template('admin/team_form.html', item=item)


@admin_bp.route('/team/<int:id>/delete', methods=['POST'])
@login_required
def team_delete(id):
    db.session.delete(TeamMember.query.get_or_404(id))
    db.session.commit()
    flash('Team member deleted.', 'success')
    return redirect(url_for('admin.team'))


# Testimonials CRUD
@admin_bp.route('/testimonials')
@login_required
def testimonials():
    items = Testimonial.query.order_by(Testimonial.created_at.desc()).all()
    return render_template('admin/testimonials.html', items=items)


@admin_bp.route('/testimonials/add', methods=['GET', 'POST'])
@login_required
def testimonial_add():
    if request.method == 'POST':
        client_name = clean_text(request.form.get('client_name'), 200)
        company = clean_text(request.form.get('company', ''), 200)
        content = clean_text(request.form.get('content'), 4000)
        rating = parse_int(request.form.get('rating', 5), default=5, min_value=1, max_value=5)

        if not client_name or not content:
            flash('Client name and testimonial content are required.', 'danger')
            return render_template('admin/testimonial_form.html', item=None)

        item = Testimonial(
            client_name=client_name,
            company=company,
            content=content,
            rating=rating,
            is_featured='is_featured' in request.form
        )
        db.session.add(item)
        db.session.commit()
        flash('Testimonial added.', 'success')
        return redirect(url_for('admin.testimonials'))
    return render_template('admin/testimonial_form.html', item=None)


@admin_bp.route('/testimonials/<int:id>/edit', methods=['GET', 'POST'])
@login_required
def testimonial_edit(id):
    item = Testimonial.query.get_or_404(id)
    if request.method == 'POST':
        client_name = clean_text(request.form.get('client_name'), 200)
        company = clean_text(request.form.get('company', ''), 200)
        content = clean_text(request.form.get('content'), 4000)
        rating = parse_int(request.form.get('rating', 5), default=5, min_value=1, max_value=5)

        if not client_name or not content:
            flash('Client name and testimonial content are required.', 'danger')
            return render_template('admin/testimonial_form.html', item=item)

        item.client_name = client_name
        item.company = company
        item.content = content
        item.rating = rating
        item.is_featured = 'is_featured' in request.form
        db.session.commit()
        flash('Testimonial updated.', 'success')
        return redirect(url_for('admin.testimonials'))
    return render_template('admin/testimonial_form.html', item=item)


@admin_bp.route('/testimonials/<int:id>/delete', methods=['POST'])
@login_required
def testimonial_delete(id):
    db.session.delete(Testimonial.query.get_or_404(id))
    db.session.commit()
    flash('Testimonial deleted.', 'success')
    return redirect(url_for('admin.testimonials'))


# Categories
@admin_bp.route('/categories')
@login_required
def categories():
    items = Category.query.all()
    return render_template('admin/categories.html', items=items)


@admin_bp.route('/categories/add', methods=['POST'])
@login_required
def category_add():
    name = clean_text(request.form.get('name'), 100)
    if not name:
        flash('Category name is required.', 'danger')
        return redirect(url_for('admin.categories'))

    slug = slugify(name)
    if not slug:
        flash('Unable to generate a valid category slug.', 'danger')
        return redirect(url_for('admin.categories'))
    if Category.query.filter_by(slug=slug).first():
        flash('Category already exists.', 'danger')
        return redirect(url_for('admin.categories'))

    db.session.add(Category(name=name, slug=slug))
    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        flash('Unable to add category due to duplicate data.', 'danger')
        return redirect(url_for('admin.categories'))
    flash('Category added.', 'success')
    return redirect(url_for('admin.categories'))


@admin_bp.route('/categories/<int:id>/delete', methods=['POST'])
@login_required
def category_delete(id):
    cat = Category.query.get_or_404(id)
    if cat.posts:
        flash('Cannot delete category with posts.', 'danger')
    else:
        db.session.delete(cat)
        db.session.commit()
        flash('Category deleted.', 'success')
    return redirect(url_for('admin.categories'))


# Posts CRUD
@admin_bp.route('/posts')
@login_required
def posts():
    items = Post.query.order_by(Post.created_at.desc()).all()
    return render_template('admin/posts.html', items=items)


@admin_bp.route('/posts/add', methods=['GET', 'POST'])
@login_required
def post_add():
    if request.method == 'POST':
        title = clean_text(request.form.get('title'), 300)
        excerpt = clean_text(request.form.get('excerpt', ''), 2000)
        content = sanitize_html(request.form.get('content', ''), 100000)
        raw_category_id = request.form.get('category_id')
        category_id = parse_positive_int(raw_category_id) if raw_category_id else None
        if raw_category_id and category_id is None:
            flash('Invalid category value.', 'danger')
            cats = Category.query.all()
            return render_template('admin/post_form.html', item=None, categories=cats)
        if category_id and not db.session.get(Category, category_id):
            flash('Selected category does not exist.', 'danger')
            cats = Category.query.all()
            return render_template('admin/post_form.html', item=None, categories=cats)

        if not title or not content:
            flash('Title and content are required.', 'danger')
            cats = Category.query.all()
            return render_template('admin/post_form.html', item=None, categories=cats)

        slug = slugify(title)
        if not slug:
            flash('Unable to generate a valid post slug.', 'danger')
            cats = Category.query.all()
            return render_template('admin/post_form.html', item=None, categories=cats)
        if Post.query.filter_by(slug=slug).first():
            flash('A post with that title already exists.', 'danger')
            cats = Category.query.all()
            return render_template('admin/post_form.html', item=None, categories=cats)

        image = save_upload(request.files.get('featured_image')) if request.files.get('featured_image') else None
        item = Post(
            title=title,
            slug=slug,
            excerpt=excerpt,
            content=content,
            featured_image=image,
            category_id=category_id,
            is_published='is_published' in request.form
        )
        db.session.add(item)
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            flash('Unable to create post due to duplicate data.', 'danger')
            cats = Category.query.all()
            return render_template('admin/post_form.html', item=None, categories=cats)
        flash('Post created.', 'success')
        return redirect(url_for('admin.posts'))
    cats = Category.query.all()
    return render_template('admin/post_form.html', item=None, categories=cats)


@admin_bp.route('/posts/<int:id>/edit', methods=['GET', 'POST'])
@login_required
def post_edit(id):
    item = Post.query.get_or_404(id)
    if request.method == 'POST':
        title = clean_text(request.form.get('title'), 300)
        excerpt = clean_text(request.form.get('excerpt', ''), 2000)
        content = sanitize_html(request.form.get('content', ''), 100000)
        raw_category_id = request.form.get('category_id')
        category_id = parse_positive_int(raw_category_id) if raw_category_id else None
        if raw_category_id and category_id is None:
            flash('Invalid category value.', 'danger')
            cats = Category.query.all()
            return render_template('admin/post_form.html', item=item, categories=cats)
        if category_id and not db.session.get(Category, category_id):
            flash('Selected category does not exist.', 'danger')
            cats = Category.query.all()
            return render_template('admin/post_form.html', item=item, categories=cats)

        if not title or not content:
            flash('Title and content are required.', 'danger')
            cats = Category.query.all()
            return render_template('admin/post_form.html', item=item, categories=cats)

        slug = slugify(title)
        if not slug:
            flash('Unable to generate a valid post slug.', 'danger')
            cats = Category.query.all()
            return render_template('admin/post_form.html', item=item, categories=cats)
        slug_exists = Post.query.filter(Post.slug == slug, Post.id != item.id).first()
        if slug_exists:
            flash('Another post already uses this title/slug.', 'danger')
            cats = Category.query.all()
            return render_template('admin/post_form.html', item=item, categories=cats)

        item.title = title
        item.slug = slug
        item.excerpt = excerpt
        item.content = content
        item.category_id = category_id
        item.is_published = 'is_published' in request.form
        if request.files.get('featured_image') and request.files['featured_image'].filename:
            uploaded_image = save_upload(request.files['featured_image'])
            if not uploaded_image:
                flash('Invalid featured image upload.', 'danger')
                cats = Category.query.all()
                return render_template('admin/post_form.html', item=item, categories=cats)
            item.featured_image = uploaded_image
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            flash('Unable to update post due to duplicate data.', 'danger')
            cats = Category.query.all()
            return render_template('admin/post_form.html', item=item, categories=cats)
        flash('Post updated.', 'success')
        return redirect(url_for('admin.posts'))
    cats = Category.query.all()
    return render_template('admin/post_form.html', item=item, categories=cats)


@admin_bp.route('/posts/<int:id>/delete', methods=['POST'])
@login_required
def post_delete(id):
    db.session.delete(Post.query.get_or_404(id))
    db.session.commit()
    flash('Post deleted.', 'success')
    return redirect(url_for('admin.posts'))


# Media
@admin_bp.route('/media')
@login_required
def media():
    items = Media.query.order_by(Media.created_at.desc()).all()
    return render_template('admin/media.html', items=items)


@admin_bp.route('/media/upload', methods=['POST'])
@login_required
def media_upload():
    file = request.files.get('file')
    if file:
        result = save_upload(file)
        if result:
            flash('File uploaded.', 'success')
        else:
            flash('Invalid file type or unsafe file content.', 'danger')
    else:
        flash('Please choose a file to upload.', 'danger')
    return redirect(url_for('admin.media'))


@admin_bp.route('/media/<int:id>/delete', methods=['POST'])
@login_required
def media_delete(id):
    item = Media.query.get_or_404(id)
    _, filepath = _safe_upload_path(item.file_path)
    if filepath and os.path.exists(filepath):
        os.remove(filepath)
    db.session.delete(item)
    db.session.commit()
    flash('File deleted.', 'success')
    return redirect(url_for('admin.media'))


# Settings
@admin_bp.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    if request.method == 'POST':
        email = clean_text(request.form.get('email', ''), 200)
        if email and not is_valid_email(email):
            flash('Please provide a valid email address for contact settings.', 'danger')
            return redirect(url_for('admin.settings'))

        for social_key in ('facebook', 'twitter', 'linkedin'):
            social_url = clean_text(request.form.get(social_key, ''), 300)
            if social_url and not is_valid_url(social_url):
                flash(f'{social_key.capitalize()} URL must start with http:// or https://.', 'danger')
                return redirect(url_for('admin.settings'))

        keys = ['company_name', 'tagline', 'phone', 'email', 'address',
                'facebook', 'twitter', 'linkedin', 'meta_title', 'meta_description', 'footer_text']
        length_limits = {
            'company_name': 200,
            'tagline': 300,
            'phone': 80,
            'email': 200,
            'address': 400,
            'facebook': 300,
            'twitter': 300,
            'linkedin': 300,
            'meta_title': 300,
            'meta_description': 500,
            'footer_text': 300,
        }
        for key in keys:
            value = clean_text(request.form.get(key, ''), length_limits.get(key, 400))
            setting = SiteSetting.query.filter_by(key=key).first()
            if setting:
                setting.value = value
            else:
                db.session.add(SiteSetting(key=key, value=value))
        db.session.commit()
        flash('Settings saved.', 'success')
        return redirect(url_for('admin.settings'))
    settings_dict = {s.key: s.value for s in SiteSetting.query.all()}
    return render_template('admin/settings.html', settings=settings_dict)


# Admin Users
@admin_bp.route('/users')
@login_required
def users():
    items = User.query.order_by(User.created_at).all()
    return render_template('admin/users.html', items=items)


@admin_bp.route('/users/add', methods=['GET', 'POST'])
@login_required
def user_add():
    if request.method == 'POST':
        username = clean_text(request.form.get('username', ''), 80)
        email = clean_text(request.form.get('email', ''), 120)
        password = request.form.get('password', '')
        if not username or not email or not password:
            flash('Username, email, and password are required.', 'danger')
            return render_template('admin/user_form.html', user=None)
        if not is_strong_password(password):
            flash(
                f'Password must be at least {ADMIN_PASSWORD_MIN_LENGTH} characters and include uppercase, lowercase, a digit, and a special character.',
                'danger',
            )
            return render_template('admin/user_form.html', user=None)
        if not is_valid_email(email):
            flash('Please provide a valid email address.', 'danger')
            return render_template('admin/user_form.html', user=None)
        existing = User.query.filter((User.username == username) | (User.email == email)).first()
        if existing:
            flash('Username or email already exists.', 'danger')
            return render_template('admin/user_form.html', user=None)
        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        flash(f'Admin user "{username}" created.', 'success')
        return redirect(url_for('admin.users'))
    return render_template('admin/user_form.html', user=None)


@admin_bp.route('/users/<int:id>/edit', methods=['GET', 'POST'])
@login_required
def user_edit(id):
    user = db.session.get(User, id)
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('admin.users'))
    if request.method == 'POST':
        email = clean_text(request.form.get('email', ''), 120)
        password = request.form.get('password', '')
        if email and not is_valid_email(email):
            flash('Please provide a valid email address.', 'danger')
            return render_template('admin/user_form.html', user=user)
        if email:
            dup = User.query.filter(User.email == email, User.id != user.id).first()
            if dup:
                flash('Email already in use by another user.', 'danger')
                return render_template('admin/user_form.html', user=user)
            user.email = email
        if password:
            if not is_strong_password(password):
                flash(
                    f'Password must be at least {ADMIN_PASSWORD_MIN_LENGTH} characters and include uppercase, lowercase, a digit, and a special character.',
                    'danger',
                )
                return render_template('admin/user_form.html', user=user)
            user.set_password(password)
        db.session.commit()
        flash(f'User "{user.username}" updated.', 'success')
        return redirect(url_for('admin.users'))
    return render_template('admin/user_form.html', user=user)


@admin_bp.route('/users/<int:id>/delete', methods=['POST'])
@login_required
def user_delete(id):
    user = db.session.get(User, id)
    if not user:
        flash('User not found.', 'danger')
    elif user.id == current_user.id:
        flash('You cannot delete your own account.', 'danger')
    elif User.query.count() <= 1:
        flash('Cannot delete the last admin user.', 'danger')
    else:
        db.session.delete(user)
        db.session.commit()
        flash(f'User "{user.username}" deleted.', 'success')
    return redirect(url_for('admin.users'))


# Contacts
@admin_bp.route('/contacts')
@login_required
def contacts():
    items = ContactSubmission.query.order_by(ContactSubmission.created_at.desc()).all()
    return render_template('admin/contacts.html', items=items)


@admin_bp.route('/contacts/<int:id>')
@login_required
def contact_view(id):
    item = ContactSubmission.query.get_or_404(id)
    if not item.is_read:
        item.is_read = True
        db.session.commit()
    return render_template('admin/contact_view.html', item=item)


@admin_bp.route('/contacts/<int:id>/delete', methods=['POST'])
@login_required
def contact_delete(id):
    db.session.delete(ContactSubmission.query.get_or_404(id))
    db.session.commit()
    flash('Contact deleted.', 'success')
    return redirect(url_for('admin.contacts'))


# Support tickets
@admin_bp.route('/support-tickets')
@login_required
def support_tickets():
    status_filter = request.args.get('status', '').strip().lower()
    type_filter = request.args.get('type', 'all').strip().lower()
    if type_filter not in {'all', 'support', 'quote'}:
        type_filter = 'all'

    query = SupportTicket.query.join(SupportClient, SupportTicket.client_id == SupportClient.id)
    quote_filter = quote_ticket_filter_expression()
    if type_filter == 'quote':
        query = query.filter(quote_filter)
    elif type_filter == 'support':
        query = query.filter(~quote_filter)
    if status_filter:
        query = query.filter(SupportTicket.status == status_filter)
    items = query.order_by(SupportTicket.updated_at.desc(), SupportTicket.created_at.desc()).all()
    return render_template(
        'admin/support_tickets.html',
        items=items,
        status_filter=status_filter,
        type_filter=type_filter,
        is_quote_ticket=is_quote_ticket,
    )


@admin_bp.route('/security-events')
@login_required
def security_events():
    event_type_filter = clean_text(request.args.get('event_type', 'all'), 40).lower()
    scope_filter = clean_text(request.args.get('scope', 'all'), 80).lower()
    search = clean_text(request.args.get('q', ''), 120).lower()
    page = parse_int(request.args.get('page', 1), default=1, min_value=1, max_value=100000)

    valid_event_types = {'all', 'turnstile_failed', 'rate_limited'}
    valid_scopes = {'all', 'contact_form', 'quote_form', 'personal_quote_form'}

    if event_type_filter not in valid_event_types:
        event_type_filter = 'all'
    if scope_filter not in valid_scopes:
        scope_filter = 'all'

    query = SecurityEvent.query
    if event_type_filter != 'all':
        query = query.filter(SecurityEvent.event_type == event_type_filter)
    if scope_filter != 'all':
        query = query.filter(SecurityEvent.scope == scope_filter)
    if search:
        safe_search = escape_like(search)
        query = query.filter(
            or_(
                func.lower(SecurityEvent.ip).like(f'%{safe_search}%'),
                func.lower(SecurityEvent.path).like(f'%{safe_search}%'),
                func.lower(SecurityEvent.details).like(f'%{safe_search}%'),
            )
        )

    items = query.order_by(SecurityEvent.created_at.desc()).paginate(page=page, per_page=50, error_out=False)
    last_24h = utc_now_naive() - timedelta(hours=24)
    stats = {
        'last_24h': SecurityEvent.query.filter(SecurityEvent.created_at >= last_24h).count(),
        'turnstile_failed_24h': SecurityEvent.query.filter(
            SecurityEvent.created_at >= last_24h,
            SecurityEvent.event_type == 'turnstile_failed',
        ).count(),
        'rate_limited_24h': SecurityEvent.query.filter(
            SecurityEvent.created_at >= last_24h,
            SecurityEvent.event_type == 'rate_limited',
        ).count(),
    }
    return render_template(
        'admin/security_events.html',
        items=items,
        stats=stats,
        event_type_filter=event_type_filter,
        scope_filter=scope_filter,
        search=search,
    )


@admin_bp.route('/support-tickets/<int:id>', methods=['GET', 'POST'])
@login_required
def support_ticket_view(id):
    item = SupportTicket.query.get_or_404(id)
    if request.method == 'POST':
        allowed_status = {'open', 'in_progress', 'waiting_customer', 'resolved', 'closed'}
        allowed_priority = {'low', 'normal', 'high', 'critical'}
        next_status = clean_text(request.form.get('status', item.status), 30)
        next_priority = clean_text(request.form.get('priority', item.priority), 20)
        if next_status in allowed_status:
            item.status = next_status
        if next_priority in allowed_priority:
            item.priority = next_priority
        item.internal_notes = clean_text(request.form.get('internal_notes', ''), 4000)
        db.session.commit()
        flash('Support ticket updated.', 'success')
        return redirect(url_for('admin.support_ticket_view', id=item.id))
    return render_template('admin/support_ticket_view.html', item=item, is_quote_ticket=is_quote_ticket(item))


# Industry CRUD
@admin_bp.route('/industries')
@login_required
def industries():
    items = Industry.query.order_by(Industry.sort_order).all()
    return render_template('admin/industries.html', items=items)


@admin_bp.route('/industries/add', methods=['GET', 'POST'])
@login_required
def industry_add():
    if request.method == 'POST':
        title = clean_text(request.form.get('title'), 200)
        description = clean_text(request.form.get('description'), 10000)
        icon_class = clean_text(request.form.get('icon_class', 'fa-solid fa-building'), 100)
        hero_description = clean_text(request.form.get('hero_description', ''), 10000)
        challenges = clean_text(request.form.get('challenges', ''), 5000)
        solutions = clean_text(request.form.get('solutions', ''), 5000)
        stats = clean_text(request.form.get('stats', ''), 5000)
        sort_order = parse_int(request.form.get('sort_order', 0), default=0, min_value=-100000, max_value=100000)

        if not title or not description:
            flash('Title and description are required.', 'danger')
            return render_template('admin/industry_form.html', item=None)

        slug = slugify(title)
        if not slug:
            flash('Unable to generate a valid slug from title.', 'danger')
            return render_template('admin/industry_form.html', item=None)
        if Industry.query.filter_by(slug=slug).first():
            flash('An industry with that title already exists.', 'danger')
            return render_template('admin/industry_form.html', item=None)

        item = Industry(
            title=title, slug=slug, description=description,
            icon_class=icon_class, hero_description=hero_description,
            challenges=challenges, solutions=solutions,
            stats=stats, sort_order=sort_order,
        )
        db.session.add(item)
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            flash('Unable to save industry due to duplicate data.', 'danger')
            return render_template('admin/industry_form.html', item=None)
        flash('Industry added.', 'success')
        return redirect(url_for('admin.industries'))
    return render_template('admin/industry_form.html', item=None)


@admin_bp.route('/industries/<int:id>/edit', methods=['GET', 'POST'])
@login_required
def industry_edit(id):
    item = Industry.query.get_or_404(id)
    if request.method == 'POST':
        title = clean_text(request.form.get('title'), 200)
        description = clean_text(request.form.get('description'), 10000)
        icon_class = clean_text(request.form.get('icon_class', 'fa-solid fa-building'), 100)
        hero_description = clean_text(request.form.get('hero_description', ''), 10000)
        challenges = clean_text(request.form.get('challenges', ''), 5000)
        solutions = clean_text(request.form.get('solutions', ''), 5000)
        stats = clean_text(request.form.get('stats', ''), 5000)
        sort_order = parse_int(request.form.get('sort_order', 0), default=0, min_value=-100000, max_value=100000)

        if not title or not description:
            flash('Title and description are required.', 'danger')
            return render_template('admin/industry_form.html', item=item)

        slug = slugify(title)
        if not slug:
            flash('Unable to generate a valid slug from title.', 'danger')
            return render_template('admin/industry_form.html', item=item)
        slug_exists = Industry.query.filter(Industry.slug == slug, Industry.id != item.id).first()
        if slug_exists:
            flash('Another industry already uses this title/slug.', 'danger')
            return render_template('admin/industry_form.html', item=item)

        item.title = title
        item.slug = slug
        item.description = description
        item.icon_class = icon_class
        item.hero_description = hero_description
        item.challenges = challenges
        item.solutions = solutions
        item.stats = stats
        item.sort_order = sort_order
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            flash('Unable to update industry due to duplicate data.', 'danger')
            return render_template('admin/industry_form.html', item=item)
        flash('Industry updated.', 'success')
        return redirect(url_for('admin.industries'))
    return render_template('admin/industry_form.html', item=item)


@admin_bp.route('/industries/<int:id>/delete', methods=['POST'])
@login_required
def industry_delete(id):
    db.session.delete(Industry.query.get_or_404(id))
    db.session.commit()
    flash('Industry deleted.', 'success')
    return redirect(url_for('admin.industries'))


# Category Edit
@admin_bp.route('/categories/<int:id>/edit', methods=['GET', 'POST'])
@login_required
def category_edit(id):
    cat = Category.query.get_or_404(id)
    if request.method == 'POST':
        name = clean_text(request.form.get('name'), 100)
        if not name:
            flash('Category name is required.', 'danger')
            return render_template('admin/category_form.html', item=cat)

        slug = slugify(name)
        if not slug:
            flash('Unable to generate a valid category slug.', 'danger')
            return render_template('admin/category_form.html', item=cat)
        slug_exists = Category.query.filter(Category.slug == slug, Category.id != cat.id).first()
        if slug_exists:
            flash('Another category already uses this name/slug.', 'danger')
            return render_template('admin/category_form.html', item=cat)

        cat.name = name
        cat.slug = slug
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            flash('Unable to update category due to duplicate data.', 'danger')
            return render_template('admin/category_form.html', item=cat)
        flash('Category updated.', 'success')
        return redirect(url_for('admin.categories'))
    return render_template('admin/category_form.html', item=cat)


# Content Block Management
@admin_bp.route('/content')
@login_required
def content_list():
    pages = {}
    for (page, section), schema in CONTENT_SCHEMAS.items():
        if page not in pages:
            pages[page] = []
        pages[page].append({'section': section, 'label': schema['label']})
    return render_template('admin/content_list.html', pages=pages)


@admin_bp.route('/content/<page>/<section>', methods=['GET', 'POST'])
@login_required
def content_edit(page, section):
    schema = CONTENT_SCHEMAS.get((page, section))
    if not schema:
        flash('Unknown content section.', 'danger')
        return redirect(url_for('admin.content_list'))

    block = ContentBlock.query.filter_by(page=page, section=section).first()
    current_data = {}
    if block:
        try:
            current_data = json.loads(block.content)
        except (json.JSONDecodeError, TypeError):
            current_data = {}

    if request.method == 'POST':
        new_data = {}
        for field in schema['fields']:
            key = field['key']
            raw_value = request.form.get(key, '')
            if field['type'] == 'lines':
                new_data[key] = [line.strip() for line in raw_value.split('\n') if line.strip()]
            elif field['type'] == 'json':
                try:
                    new_data[key] = json.loads(raw_value)
                except (json.JSONDecodeError, TypeError):
                    flash(f'Invalid JSON for field "{field["label"]}".', 'danger')
                    return render_template('admin/content_edit.html', schema=schema, page=page, section=section, current_data=current_data)
            else:
                new_data[key] = raw_value.strip()

        if not block:
            block = ContentBlock(page=page, section=section)
            db.session.add(block)
        block.content = json.dumps(new_data, ensure_ascii=False)
        db.session.commit()
        flash('Content updated.', 'success')
        return redirect(url_for('admin.content_edit', page=page, section=section))

    return render_template('admin/content_edit.html', schema=schema, page=page, section=section, current_data=current_data)
