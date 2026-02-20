from datetime import timedelta
import json
import os
import re
import uuid
import bleach
from sqlalchemy import func, or_
from flask import Blueprint, render_template, request, redirect, url_for, flash, current_app, send_from_directory, session
from flask_login import login_user, logout_user, login_required, current_user
from PIL import Image, UnidentifiedImageError
from sqlalchemy.exc import IntegrityError
from werkzeug.utils import secure_filename
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
    if not filename or not allowed_file(filename):
        return False

    extension = filename.rsplit('.', 1)[1].lower()
    mime_type = (file.mimetype or '').split(';', 1)[0].lower()
    allowed_mimes = current_app.config.get('ALLOWED_UPLOAD_MIME_TYPES', set())
    if mime_type not in allowed_mimes:
        return False

    file.stream.seek(0)
    if extension == 'pdf':
        signature = file.stream.read(5)
        file.stream.seek(0)
        return signature == b'%PDF-'

    if extension in IMAGE_EXTENSIONS:
        try:
            image = Image.open(file.stream)
            image.verify()
            file.stream.seek(0)
            return True
        except (UnidentifiedImageError, OSError):
            file.stream.seek(0)
            return False

    file.stream.seek(0)
    return False


def save_upload(file):
    if validate_uploaded_file(file):
        filename = secure_filename(file.filename)
        unique_name = f"{uuid.uuid4().hex[:8]}_{filename}"
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
    return send_from_directory(current_app.config['UPLOAD_FOLDER'], filename)


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
        if user and user.check_password(password):
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
    last_24h = utc_now_naive() - timedelta(hours=24)
    stats = {
        'services': Service.query.count(),
        'team': TeamMember.query.count(),
        'posts': Post.query.count(),
        'contacts': ContactSubmission.query.filter_by(is_read=False).count(),
        'testimonials': Testimonial.query.count(),
        'media': Media.query.count(),
        'support_tickets': SupportTicket.query.filter(SupportTicket.status.in_(['open', 'in_progress', 'waiting_customer'])).count(),
        'support_clients': SupportClient.query.count(),
        'security_events_24h': SecurityEvent.query.filter(
            SecurityEvent.created_at >= last_24h,
            SecurityEvent.event_type.in_(['turnstile_failed', 'rate_limited']),
        ).count(),
    }
    recent_contacts = ContactSubmission.query.order_by(ContactSubmission.created_at.desc()).limit(5).all()
    recent_tickets = SupportTicket.query.order_by(SupportTicket.updated_at.desc()).limit(5).all()
    return render_template(
        'admin/dashboard.html',
        stats=stats,
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
    filepath = os.path.join(current_app.config['UPLOAD_FOLDER'], item.file_path)
    if os.path.exists(filepath):
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
    valid_scopes = {'all', 'contact_form', 'quote_form'}

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
