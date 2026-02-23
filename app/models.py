from datetime import datetime, timezone
import json
import re
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

WORKFLOW_DRAFT = 'draft'
WORKFLOW_REVIEW = 'review'
WORKFLOW_APPROVED = 'approved'
WORKFLOW_PUBLISHED = 'published'
WORKFLOW_STATUSES = (
    WORKFLOW_DRAFT,
    WORKFLOW_REVIEW,
    WORKFLOW_APPROVED,
    WORKFLOW_PUBLISHED,
)
WORKFLOW_STATUS_LABELS = {
    WORKFLOW_DRAFT: 'Draft',
    WORKFLOW_REVIEW: 'In Review',
    WORKFLOW_APPROVED: 'Approved',
    WORKFLOW_PUBLISHED: 'Published',
}

ROLE_OWNER = 'owner'
ROLE_ADMIN = 'admin'
ROLE_PUBLISHER = 'publisher'
ROLE_REVIEWER = 'reviewer'
ROLE_EDITOR = 'editor'
ROLE_SUPPORT = 'support'
USER_ROLE_CHOICES = (
    ROLE_OWNER,
    ROLE_ADMIN,
    ROLE_PUBLISHER,
    ROLE_REVIEWER,
    ROLE_EDITOR,
    ROLE_SUPPORT,
)
USER_ROLE_LABELS = {
    ROLE_OWNER: 'Owner',
    ROLE_ADMIN: 'Admin',
    ROLE_PUBLISHER: 'Publisher',
    ROLE_REVIEWER: 'Reviewer',
    ROLE_EDITOR: 'Editor',
    ROLE_SUPPORT: 'Support',
}
ROLE_DEFAULT = ROLE_ADMIN
ROLE_PERMISSIONS = {
    ROLE_OWNER: {
        'dashboard:view',
        'content:manage',
        'workflow:review',
        'workflow:publish',
        'support:manage',
        'security:view',
        'settings:manage',
        'users:manage',
        'acp:studio:view',
        'acp:pages:manage',
        'acp:dashboards:manage',
        'acp:registry:manage',
        'acp:metrics:manage',
        'acp:content:manage',
        'acp:theme:manage',
        'acp:mcp:manage',
        'acp:publish',
        'acp:audit:view',
        'acp:mcp:audit:view',
        'acp:environments:manage',
    },
    ROLE_ADMIN: {
        'dashboard:view',
        'content:manage',
        'workflow:review',
        'workflow:publish',
        'support:manage',
        'security:view',
        'settings:manage',
        'users:manage',
        'acp:studio:view',
        'acp:pages:manage',
        'acp:dashboards:manage',
        'acp:registry:manage',
        'acp:metrics:manage',
        'acp:content:manage',
        'acp:theme:manage',
        'acp:mcp:manage',
        'acp:publish',
        'acp:audit:view',
        'acp:mcp:audit:view',
        'acp:environments:manage',
    },
    ROLE_PUBLISHER: {
        'dashboard:view',
        'content:manage',
        'workflow:review',
        'workflow:publish',
        'acp:studio:view',
        'acp:pages:manage',
        'acp:dashboards:manage',
        'acp:content:manage',
        'acp:theme:manage',
        'acp:publish',
    },
    ROLE_REVIEWER: {
        'dashboard:view',
        'content:manage',
        'workflow:review',
        'acp:studio:view',
        'acp:pages:manage',
        'acp:dashboards:manage',
        'acp:content:manage',
        'acp:theme:manage',
    },
    ROLE_EDITOR: {
        'dashboard:view',
        'content:manage',
        'acp:studio:view',
        'acp:pages:manage',
        'acp:content:manage',
        'acp:theme:manage',
    },
    ROLE_SUPPORT: {
        'dashboard:view',
        'support:manage',
        'acp:studio:view',
    },
}


def utc_now_naive():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def normalize_workflow_status(value, default=WORKFLOW_DRAFT):
    candidate = (value or '').strip().lower()
    if candidate in WORKFLOW_STATUSES:
        return candidate
    return default


def normalize_user_role(value, default=ROLE_DEFAULT):
    candidate = (value or '').strip().lower()
    if candidate in USER_ROLE_CHOICES:
        return candidate
    return default


SUPPORT_TICKET_STATUS_OPEN = 'open'
SUPPORT_TICKET_STATUS_IN_PROGRESS = 'in_progress'
SUPPORT_TICKET_STATUS_WAITING_CUSTOMER = 'waiting_customer'
SUPPORT_TICKET_STATUS_RESOLVED = 'resolved'
SUPPORT_TICKET_STATUS_CLOSED = 'closed'
SUPPORT_TICKET_STATUSES = (
    SUPPORT_TICKET_STATUS_OPEN,
    SUPPORT_TICKET_STATUS_IN_PROGRESS,
    SUPPORT_TICKET_STATUS_WAITING_CUSTOMER,
    SUPPORT_TICKET_STATUS_RESOLVED,
    SUPPORT_TICKET_STATUS_CLOSED,
)
SUPPORT_TICKET_STATUS_LABELS = {
    SUPPORT_TICKET_STATUS_OPEN: 'Open',
    SUPPORT_TICKET_STATUS_IN_PROGRESS: 'In Progress',
    SUPPORT_TICKET_STATUS_WAITING_CUSTOMER: 'Waiting on Client',
    SUPPORT_TICKET_STATUS_RESOLVED: 'Done',
    SUPPORT_TICKET_STATUS_CLOSED: 'Closed',
}
SUPPORT_TICKET_STAGE_PENDING = 'pending'
SUPPORT_TICKET_STAGE_DONE = 'done'
SUPPORT_TICKET_STAGE_CLOSED = 'closed'
SUPPORT_TICKET_STAGE_LABELS = {
    SUPPORT_TICKET_STAGE_PENDING: 'Pending',
    SUPPORT_TICKET_STAGE_DONE: 'Done',
    SUPPORT_TICKET_STAGE_CLOSED: 'Closed',
}
SUPPORT_TICKET_PENDING_STATUSES = {
    SUPPORT_TICKET_STATUS_OPEN,
    SUPPORT_TICKET_STATUS_IN_PROGRESS,
    SUPPORT_TICKET_STATUS_WAITING_CUSTOMER,
}
SUPPORT_TICKET_STAGE_TO_STATUS = {
    SUPPORT_TICKET_STAGE_PENDING: SUPPORT_TICKET_STATUS_IN_PROGRESS,
    SUPPORT_TICKET_STAGE_DONE: SUPPORT_TICKET_STATUS_RESOLVED,
    SUPPORT_TICKET_STAGE_CLOSED: SUPPORT_TICKET_STATUS_CLOSED,
}
SUPPORT_TICKET_EVENT_CREATED = 'created'
SUPPORT_TICKET_EVENT_REVIEW_ACTION = 'review_action'
SUPPORT_TICKET_EVENT_ADMIN_UPDATE = 'admin_update'
SUPPORT_TICKET_NUMBER_SANITIZER_RE = re.compile(r'[^A-Z0-9-]+')


def normalize_support_ticket_status(value, default=SUPPORT_TICKET_STATUS_OPEN):
    candidate = (value or '').strip().lower()
    alias_map = {
        'pending': SUPPORT_TICKET_STAGE_TO_STATUS[SUPPORT_TICKET_STAGE_PENDING],
        'in-progress': SUPPORT_TICKET_STATUS_IN_PROGRESS,
        'waiting': SUPPORT_TICKET_STATUS_WAITING_CUSTOMER,
        'waiting-on-client': SUPPORT_TICKET_STATUS_WAITING_CUSTOMER,
        'done': SUPPORT_TICKET_STAGE_TO_STATUS[SUPPORT_TICKET_STAGE_DONE],
        'complete': SUPPORT_TICKET_STAGE_TO_STATUS[SUPPORT_TICKET_STAGE_DONE],
        'completed': SUPPORT_TICKET_STAGE_TO_STATUS[SUPPORT_TICKET_STAGE_DONE],
        'close': SUPPORT_TICKET_STAGE_TO_STATUS[SUPPORT_TICKET_STAGE_CLOSED],
    }
    normalized = alias_map.get(candidate, candidate)
    if normalized in SUPPORT_TICKET_STATUSES:
        return normalized
    return default


def support_ticket_stage_for_status(status):
    normalized = normalize_support_ticket_status(status, default=SUPPORT_TICKET_STATUS_OPEN)
    if normalized in SUPPORT_TICKET_PENDING_STATUSES:
        return SUPPORT_TICKET_STAGE_PENDING
    if normalized == SUPPORT_TICKET_STATUS_RESOLVED:
        return SUPPORT_TICKET_STAGE_DONE
    return SUPPORT_TICKET_STAGE_CLOSED


def normalize_support_ticket_stage(value, default=SUPPORT_TICKET_STAGE_PENDING):
    candidate = (value or '').strip().lower()
    if candidate in SUPPORT_TICKET_STAGE_TO_STATUS:
        return candidate
    return default


def normalize_ticket_number(value):
    candidate = (value or '').strip().upper()[:40]
    return SUPPORT_TICKET_NUMBER_SANITIZER_RE.sub('', candidate)


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(30), nullable=False, default=ROLE_DEFAULT, index=True)
    created_at = db.Column(db.DateTime, default=utc_now_naive)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    @property
    def role_key(self):
        return normalize_user_role(self.role, default=ROLE_DEFAULT)

    @property
    def role_label(self):
        return USER_ROLE_LABELS.get(self.role_key, USER_ROLE_LABELS[ROLE_DEFAULT])

    def has_permission(self, permission):
        return permission in ROLE_PERMISSIONS.get(self.role_key, ROLE_PERMISSIONS[ROLE_DEFAULT])

    def can_assign_role(self, role):
        target = normalize_user_role(role, default=ROLE_DEFAULT)
        if self.role_key == ROLE_OWNER:
            return target in USER_ROLE_CHOICES
        if self.role_key != ROLE_ADMIN:
            return False
        return target in USER_ROLE_CHOICES and target != ROLE_OWNER


class Service(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    slug = db.Column(db.String(200), unique=True, nullable=False)
    description = db.Column(db.Text, nullable=False)
    icon_class = db.Column(db.String(100), default='fa-solid fa-gear')
    image = db.Column(db.String(300))
    service_type = db.Column(db.String(20), default='professional', index=True)  # 'professional' or 'repair'
    is_featured = db.Column(db.Boolean, default=False, index=True)
    sort_order = db.Column(db.Integer, default=0)
    profile_json = db.Column(db.Text)
    workflow_status = db.Column(db.String(20), nullable=False, default=WORKFLOW_DRAFT, index=True)
    scheduled_publish_at = db.Column(db.DateTime, index=True)
    reviewed_at = db.Column(db.DateTime)
    approved_at = db.Column(db.DateTime)
    published_at = db.Column(db.DateTime, index=True)
    created_at = db.Column(db.DateTime, default=utc_now_naive)
    updated_at = db.Column(db.DateTime, default=utc_now_naive, onupdate=utc_now_naive)


class TeamMember(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    position = db.Column(db.String(200), nullable=False)
    bio = db.Column(db.Text)
    photo = db.Column(db.String(300))
    linkedin = db.Column(db.String(300))
    sort_order = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=utc_now_naive)


class Testimonial(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    client_name = db.Column(db.String(200), nullable=False)
    company = db.Column(db.String(200))
    content = db.Column(db.Text, nullable=False)
    rating = db.Column(db.Integer, default=5)
    is_featured = db.Column(db.Boolean, default=False, index=True)
    created_at = db.Column(db.DateTime, default=utc_now_naive)


class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    slug = db.Column(db.String(100), unique=True, nullable=False)
    posts = db.relationship('Post', backref='category', lazy=True)


class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(300), nullable=False)
    slug = db.Column(db.String(300), unique=True, nullable=False)
    excerpt = db.Column(db.Text)
    content = db.Column(db.Text, nullable=False)
    featured_image = db.Column(db.String(300))
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'))
    is_published = db.Column(db.Boolean, default=False, index=True)
    workflow_status = db.Column(db.String(20), nullable=False, default=WORKFLOW_DRAFT, index=True)
    scheduled_publish_at = db.Column(db.DateTime, index=True)
    reviewed_at = db.Column(db.DateTime)
    approved_at = db.Column(db.DateTime)
    published_at = db.Column(db.DateTime, index=True)
    created_at = db.Column(db.DateTime, default=utc_now_naive)
    updated_at = db.Column(db.DateTime, default=utc_now_naive, onupdate=utc_now_naive)


class Media(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(300), nullable=False)
    file_path = db.Column(db.String(500), nullable=False)
    file_size = db.Column(db.Integer)
    mime_type = db.Column(db.String(100))
    alt_text = db.Column(db.String(300))
    created_at = db.Column(db.DateTime, default=utc_now_naive)


class ContactSubmission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(200), nullable=False)
    phone = db.Column(db.String(50))
    subject = db.Column(db.String(300))
    message = db.Column(db.Text, nullable=False)
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=utc_now_naive)


class SupportClient(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(200), unique=True, nullable=False, index=True)
    company = db.Column(db.String(200))
    phone = db.Column(db.String(50))
    password_hash = db.Column(db.String(256), nullable=False)
    created_at = db.Column(db.DateTime, default=utc_now_naive)
    last_login_at = db.Column(db.DateTime)
    tickets = db.relationship('SupportTicket', backref='client', lazy=True, cascade='all, delete-orphan')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class SupportTicket(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ticket_number = db.Column(db.String(24), unique=True, nullable=False, index=True)
    client_id = db.Column(db.Integer, db.ForeignKey('support_client.id'), nullable=False, index=True)
    subject = db.Column(db.String(300), nullable=False)
    service_slug = db.Column(db.String(200))
    priority = db.Column(db.String(20), default='normal', nullable=False)  # low, normal, high, critical
    status = db.Column(db.String(30), default=SUPPORT_TICKET_STATUS_OPEN, nullable=False)  # open, in_progress, waiting_customer, resolved, closed
    details = db.Column(db.Text, nullable=False)
    internal_notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=utc_now_naive)
    updated_at = db.Column(db.DateTime, default=utc_now_naive, onupdate=utc_now_naive)
    events = db.relationship(
        'SupportTicketEvent',
        backref='ticket',
        lazy=True,
        cascade='all, delete-orphan',
        order_by='SupportTicketEvent.created_at.desc()',
    )


class SupportTicketEvent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ticket_id = db.Column(db.Integer, db.ForeignKey('support_ticket.id'), nullable=False, index=True)
    event_type = db.Column(db.String(40), nullable=False, index=True)  # created, review_action, admin_update
    message = db.Column(db.Text)
    actor_type = db.Column(db.String(30), nullable=False, default='system', index=True)  # system, admin, client, quote_form
    actor_name = db.Column(db.String(200), nullable=False, default='System')
    actor_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), index=True)
    actor_client_id = db.Column(db.Integer, db.ForeignKey('support_client.id'), index=True)
    status_from = db.Column(db.String(30))
    status_to = db.Column(db.String(30))
    stage_from = db.Column(db.String(20))
    stage_to = db.Column(db.String(20))
    metadata_json = db.Column(db.Text, nullable=False, default='{}')
    created_at = db.Column(db.DateTime, default=utc_now_naive, index=True)

    __table_args__ = (
        db.Index('ix_support_ticket_event_ticket_created', 'ticket_id', 'created_at'),
    )


def create_support_ticket_event(
    ticket,
    event_type,
    message='',
    *,
    actor_type='system',
    actor_name='System',
    actor_user_id=None,
    actor_client_id=None,
    status_from='',
    status_to='',
    stage_from='',
    stage_to='',
    metadata=None,
):
    if ticket is None:
        return None
    if not ticket.id:
        db.session.flush()

    normalized_status_from = normalize_support_ticket_status(status_from, default='') if status_from else ''
    normalized_status_to = normalize_support_ticket_status(status_to, default='') if status_to else ''
    normalized_stage_from = normalize_support_ticket_stage(stage_from, default='') if stage_from else ''
    normalized_stage_to = normalize_support_ticket_stage(stage_to, default='') if stage_to else ''

    if not normalized_stage_from and normalized_status_from:
        normalized_stage_from = support_ticket_stage_for_status(normalized_status_from)
    if not normalized_stage_to and normalized_status_to:
        normalized_stage_to = support_ticket_stage_for_status(normalized_status_to)

    safe_metadata = metadata if isinstance(metadata, dict) else {}
    event = SupportTicketEvent(
        ticket_id=ticket.id,
        event_type=((event_type or 'updated').strip().lower()[:40] or 'updated'),
        message=(message or '').strip()[:1000],
        actor_type=((actor_type or 'system').strip().lower()[:30] or 'system'),
        actor_name=(actor_name or 'System').strip()[:200] or 'System',
        actor_user_id=actor_user_id,
        actor_client_id=actor_client_id,
        status_from=normalized_status_from or None,
        status_to=normalized_status_to or None,
        stage_from=normalized_stage_from or None,
        stage_to=normalized_stage_to or None,
        metadata_json=json.dumps(safe_metadata, ensure_ascii=False),
    )
    db.session.add(event)
    return event


class Industry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    slug = db.Column(db.String(200), unique=True, nullable=False)
    description = db.Column(db.Text, nullable=False)
    icon_class = db.Column(db.String(100), default='fa-solid fa-building')
    hero_description = db.Column(db.Text)
    challenges = db.Column(db.Text)  # pipe-separated: "challenge1|challenge2|challenge3"
    solutions = db.Column(db.Text)   # pipe-separated: "solution1|solution2|solution3"
    stats = db.Column(db.Text)       # pipe-separated: "label1:value1|label2:value2"
    sort_order = db.Column(db.Integer, default=0)
    workflow_status = db.Column(db.String(20), nullable=False, default=WORKFLOW_DRAFT, index=True)
    scheduled_publish_at = db.Column(db.DateTime, index=True)
    reviewed_at = db.Column(db.DateTime)
    approved_at = db.Column(db.DateTime)
    published_at = db.Column(db.DateTime, index=True)
    created_at = db.Column(db.DateTime, default=utc_now_naive)
    updated_at = db.Column(db.DateTime, default=utc_now_naive, onupdate=utc_now_naive)


class ContentBlock(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    page = db.Column(db.String(50), nullable=False)
    section = db.Column(db.String(80), nullable=False)
    content = db.Column(db.Text, nullable=False, default='{}')
    updated_at = db.Column(db.DateTime, default=utc_now_naive, onupdate=utc_now_naive)

    __table_args__ = (
        db.UniqueConstraint('page', 'section', name='uq_content_block_page_section'),
        db.Index('ix_content_block_page', 'page'),
    )


class SiteSetting(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(100), unique=True, nullable=False)
    value = db.Column(db.Text, default='')


class AuthRateLimitBucket(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scope = db.Column(db.String(80), nullable=False, index=True)
    ip = db.Column(db.String(64), nullable=False, index=True)
    count = db.Column(db.Integer, nullable=False, default=0)
    reset_at = db.Column(db.DateTime, nullable=False)
    updated_at = db.Column(db.DateTime, default=utc_now_naive, onupdate=utc_now_naive)

    __table_args__ = (
        db.UniqueConstraint('scope', 'ip', name='uq_auth_rate_limit_scope_ip'),
        db.Index('ix_auth_rate_limit_scope_reset_at', 'scope', 'reset_at'),
    )


class SecurityEvent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    event_type = db.Column(db.String(40), nullable=False, index=True)  # turnstile_failed, rate_limited
    scope = db.Column(db.String(80), nullable=False, index=True)       # contact_form, quote_form, etc.
    ip = db.Column(db.String(64), nullable=False, index=True)
    path = db.Column(db.String(255), nullable=False)
    method = db.Column(db.String(10), nullable=False)
    user_agent = db.Column(db.String(300))
    details = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=utc_now_naive, index=True)

    __table_args__ = (
        db.Index('ix_security_event_scope_created_at', 'scope', 'created_at'),
        db.Index('ix_security_event_type_created_at', 'event_type', 'created_at'),
    )


class AcpPageDocument(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    slug = db.Column(db.String(200), unique=True, nullable=False, index=True)
    title = db.Column(db.String(220), nullable=False)
    template_id = db.Column(db.String(120), nullable=False, default='default-page')
    locale = db.Column(db.String(20), nullable=False, default='en-US')
    status = db.Column(db.String(20), nullable=False, default=WORKFLOW_DRAFT, index=True)
    seo_json = db.Column(db.Text, nullable=False, default='{}')
    blocks_tree = db.Column(db.Text, nullable=False, default='{}')
    theme_override_json = db.Column(db.Text, nullable=False, default='{}')
    scheduled_publish_at = db.Column(db.DateTime, index=True)
    published_at = db.Column(db.DateTime, index=True)
    created_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), index=True)
    updated_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), index=True)
    created_at = db.Column(db.DateTime, default=utc_now_naive, index=True)
    updated_at = db.Column(db.DateTime, default=utc_now_naive, onupdate=utc_now_naive, index=True)

    __table_args__ = (
        db.Index('ix_acp_page_document_status_slug', 'status', 'slug'),
    )


class AcpPageVersion(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    page_id = db.Column(db.Integer, db.ForeignKey('acp_page_document.id'), nullable=False, index=True)
    version_number = db.Column(db.Integer, nullable=False)
    snapshot_json = db.Column(db.Text, nullable=False, default='{}')
    change_note = db.Column(db.String(260))
    created_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), index=True)
    created_at = db.Column(db.DateTime, default=utc_now_naive, index=True)

    page = db.relationship('AcpPageDocument', backref=db.backref('versions', lazy=True, order_by='AcpPageVersion.version_number.desc()'))

    __table_args__ = (
        db.UniqueConstraint('page_id', 'version_number', name='uq_acp_page_version_page_number'),
        db.Index('ix_acp_page_version_page_created', 'page_id', 'created_at'),
    )


class AcpPageRouteBinding(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    route_rule = db.Column(db.String(240), unique=True, nullable=False, index=True)
    endpoint = db.Column(db.String(180), nullable=False, index=True)
    methods_json = db.Column(db.Text, nullable=False, default='[]')
    page_slug = db.Column(db.String(200), index=True)
    page_id = db.Column(db.Integer, db.ForeignKey('acp_page_document.id'), index=True)
    sync_status = db.Column(db.String(40), nullable=False, default='missing_page_document', index=True)
    issue_detail = db.Column(db.String(320))
    is_dynamic = db.Column(db.Boolean, nullable=False, default=False, index=True)
    is_active = db.Column(db.Boolean, nullable=False, default=True, index=True)
    last_seen_at = db.Column(db.DateTime, default=utc_now_naive, index=True)
    created_at = db.Column(db.DateTime, default=utc_now_naive, index=True)
    updated_at = db.Column(db.DateTime, default=utc_now_naive, onupdate=utc_now_naive, index=True)

    page = db.relationship('AcpPageDocument', backref=db.backref('route_bindings', lazy=True))

    __table_args__ = (
        db.Index('ix_acp_page_route_binding_status_seen', 'sync_status', 'last_seen_at'),
        db.Index('ix_acp_page_route_binding_page', 'page_slug', 'page_id'),
    )


class AcpDashboardDocument(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    dashboard_id = db.Column(db.String(120), unique=True, nullable=False, index=True)
    title = db.Column(db.String(220), nullable=False)
    route = db.Column(db.String(220), unique=True, nullable=False, index=True)
    layout_type = db.Column(db.String(24), nullable=False, default='grid')
    status = db.Column(db.String(20), nullable=False, default=WORKFLOW_DRAFT, index=True)
    layout_config_json = db.Column(db.Text, nullable=False, default='{}')
    widgets_json = db.Column(db.Text, nullable=False, default='[]')
    global_filters_json = db.Column(db.Text, nullable=False, default='[]')
    role_visibility_json = db.Column(db.Text, nullable=False, default='{}')
    scheduled_publish_at = db.Column(db.DateTime, index=True)
    published_at = db.Column(db.DateTime, index=True)
    created_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), index=True)
    updated_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), index=True)
    created_at = db.Column(db.DateTime, default=utc_now_naive, index=True)
    updated_at = db.Column(db.DateTime, default=utc_now_naive, onupdate=utc_now_naive, index=True)

    __table_args__ = (
        db.Index('ix_acp_dashboard_document_status_route', 'status', 'route'),
    )


class AcpDashboardVersion(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    dashboard_document_id = db.Column(
        db.Integer,
        db.ForeignKey('acp_dashboard_document.id'),
        nullable=False,
        index=True,
    )
    version_number = db.Column(db.Integer, nullable=False)
    snapshot_json = db.Column(db.Text, nullable=False, default='{}')
    change_note = db.Column(db.String(260))
    created_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), index=True)
    created_at = db.Column(db.DateTime, default=utc_now_naive, index=True)

    dashboard = db.relationship(
        'AcpDashboardDocument',
        backref=db.backref('versions', lazy=True, order_by='AcpDashboardVersion.version_number.desc()'),
    )

    __table_args__ = (
        db.UniqueConstraint(
            'dashboard_document_id',
            'version_number',
            name='uq_acp_dashboard_version_doc_number',
        ),
        db.Index('ix_acp_dashboard_version_doc_created', 'dashboard_document_id', 'created_at'),
    )


class AcpComponentDefinition(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(120), unique=True, nullable=False, index=True)
    name = db.Column(db.String(160), nullable=False)
    category = db.Column(db.String(80), nullable=False, default='layout')
    prop_schema_json = db.Column(db.Text, nullable=False, default='{}')
    default_props_json = db.Column(db.Text, nullable=False, default='{}')
    allowed_children_json = db.Column(db.Text, nullable=False, default='[]')
    restrictions_json = db.Column(db.Text, nullable=False, default='{}')
    is_enabled = db.Column(db.Boolean, nullable=False, default=True, index=True)
    created_at = db.Column(db.DateTime, default=utc_now_naive, index=True)
    updated_at = db.Column(db.DateTime, default=utc_now_naive, onupdate=utc_now_naive, index=True)


class AcpWidgetDefinition(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(120), unique=True, nullable=False, index=True)
    name = db.Column(db.String(160), nullable=False)
    category = db.Column(db.String(80), nullable=False, default='kpi')
    config_schema_json = db.Column(db.Text, nullable=False, default='{}')
    data_contract_json = db.Column(db.Text, nullable=False, default='{}')
    allowed_filters_json = db.Column(db.Text, nullable=False, default='[]')
    permissions_required_json = db.Column(db.Text, nullable=False, default='[]')
    is_enabled = db.Column(db.Boolean, nullable=False, default=True, index=True)
    created_at = db.Column(db.DateTime, default=utc_now_naive, index=True)
    updated_at = db.Column(db.DateTime, default=utc_now_naive, onupdate=utc_now_naive, index=True)


class AcpMetricDefinition(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(120), unique=True, nullable=False, index=True)
    name = db.Column(db.String(160), nullable=False)
    description = db.Column(db.Text)
    dataset_key = db.Column(db.String(120), nullable=False, default='internal')
    query_template = db.Column(db.Text, nullable=False, default='')
    formula = db.Column(db.Text, nullable=False, default='')
    dimensions_json = db.Column(db.Text, nullable=False, default='[]')
    allowed_roles_json = db.Column(db.Text, nullable=False, default='[]')
    default_aggregation = db.Column(db.String(40), nullable=False, default='count')
    is_enabled = db.Column(db.Boolean, nullable=False, default=True, index=True)
    created_at = db.Column(db.DateTime, default=utc_now_naive, index=True)
    updated_at = db.Column(db.DateTime, default=utc_now_naive, onupdate=utc_now_naive, index=True)


class AcpContentType(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(120), unique=True, nullable=False, index=True)
    name = db.Column(db.String(180), nullable=False)
    description = db.Column(db.Text)
    schema_json = db.Column(db.Text, nullable=False, default='{}')
    is_enabled = db.Column(db.Boolean, nullable=False, default=True, index=True)
    created_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), index=True)
    updated_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), index=True)
    created_at = db.Column(db.DateTime, default=utc_now_naive, index=True)
    updated_at = db.Column(db.DateTime, default=utc_now_naive, onupdate=utc_now_naive, index=True)


class AcpContentTypeVersion(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content_type_id = db.Column(db.Integer, db.ForeignKey('acp_content_type.id'), nullable=False, index=True)
    version_number = db.Column(db.Integer, nullable=False)
    snapshot_json = db.Column(db.Text, nullable=False, default='{}')
    change_note = db.Column(db.String(260))
    created_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), index=True)
    created_at = db.Column(db.DateTime, default=utc_now_naive, index=True)

    content_type = db.relationship(
        'AcpContentType',
        backref=db.backref('versions', lazy=True, order_by='AcpContentTypeVersion.version_number.desc()'),
    )

    __table_args__ = (
        db.UniqueConstraint('content_type_id', 'version_number', name='uq_acp_content_type_version_type_number'),
        db.Index('ix_acp_content_type_version_type_created', 'content_type_id', 'created_at'),
    )


class AcpContentEntry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content_type_id = db.Column(db.Integer, db.ForeignKey('acp_content_type.id'), nullable=False, index=True)
    entry_key = db.Column(db.String(140), nullable=False, index=True)
    title = db.Column(db.String(220), nullable=False, default='')
    locale = db.Column(db.String(20), nullable=False, default='en-US')
    status = db.Column(db.String(20), nullable=False, default=WORKFLOW_DRAFT, index=True)
    data_json = db.Column(db.Text, nullable=False, default='{}')
    scheduled_publish_at = db.Column(db.DateTime, index=True)
    published_at = db.Column(db.DateTime, index=True)
    created_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), index=True)
    updated_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), index=True)
    created_at = db.Column(db.DateTime, default=utc_now_naive, index=True)
    updated_at = db.Column(db.DateTime, default=utc_now_naive, onupdate=utc_now_naive, index=True)

    content_type = db.relationship('AcpContentType', backref=db.backref('entries', lazy=True))

    __table_args__ = (
        db.UniqueConstraint('content_type_id', 'entry_key', 'locale', name='uq_acp_content_entry_type_key_locale'),
        db.Index('ix_acp_content_entry_status_key', 'status', 'entry_key'),
    )


class AcpContentEntryVersion(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content_entry_id = db.Column(db.Integer, db.ForeignKey('acp_content_entry.id'), nullable=False, index=True)
    version_number = db.Column(db.Integer, nullable=False)
    snapshot_json = db.Column(db.Text, nullable=False, default='{}')
    change_note = db.Column(db.String(260))
    created_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), index=True)
    created_at = db.Column(db.DateTime, default=utc_now_naive, index=True)

    content_entry = db.relationship(
        'AcpContentEntry',
        backref=db.backref('versions', lazy=True, order_by='AcpContentEntryVersion.version_number.desc()'),
    )

    __table_args__ = (
        db.UniqueConstraint('content_entry_id', 'version_number', name='uq_acp_content_entry_version_entry_number'),
        db.Index('ix_acp_content_entry_version_entry_created', 'content_entry_id', 'created_at'),
    )


class AcpThemeTokenSet(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(80), unique=True, nullable=False, index=True)
    name = db.Column(db.String(180), nullable=False)
    status = db.Column(db.String(20), nullable=False, default=WORKFLOW_DRAFT, index=True)
    tokens_json = db.Column(db.Text, nullable=False, default='{}')
    scheduled_publish_at = db.Column(db.DateTime, index=True)
    published_at = db.Column(db.DateTime, index=True)
    created_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), index=True)
    updated_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), index=True)
    created_at = db.Column(db.DateTime, default=utc_now_naive, index=True)
    updated_at = db.Column(db.DateTime, default=utc_now_naive, onupdate=utc_now_naive, index=True)

    __table_args__ = (
        db.Index('ix_acp_theme_token_set_status_key', 'status', 'key'),
    )


class AcpThemeTokenVersion(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    token_set_id = db.Column(db.Integer, db.ForeignKey('acp_theme_token_set.id'), nullable=False, index=True)
    version_number = db.Column(db.Integer, nullable=False)
    snapshot_json = db.Column(db.Text, nullable=False, default='{}')
    change_note = db.Column(db.String(260))
    created_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), index=True)
    created_at = db.Column(db.DateTime, default=utc_now_naive, index=True)

    token_set = db.relationship(
        'AcpThemeTokenSet',
        backref=db.backref('versions', lazy=True, order_by='AcpThemeTokenVersion.version_number.desc()'),
    )

    __table_args__ = (
        db.UniqueConstraint('token_set_id', 'version_number', name='uq_acp_theme_token_version_set_number'),
        db.Index('ix_acp_theme_token_version_set_created', 'token_set_id', 'created_at'),
    )


class AcpMcpServer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(120), unique=True, nullable=False, index=True)
    name = db.Column(db.String(180), nullable=False)
    server_url = db.Column(db.String(500), nullable=False)
    transport = db.Column(db.String(40), nullable=False, default='http')
    auth_mode = db.Column(db.String(40), nullable=False, default='oauth')
    environment = db.Column(db.String(40), nullable=False, default='production', index=True)
    allowed_tools_json = db.Column(db.Text, nullable=False, default='[]')
    require_approval = db.Column(db.String(24), nullable=False, default='always')
    is_enabled = db.Column(db.Boolean, nullable=False, default=True, index=True)
    notes = db.Column(db.String(400))
    created_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), index=True)
    updated_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), index=True)
    created_at = db.Column(db.DateTime, default=utc_now_naive, index=True)
    updated_at = db.Column(db.DateTime, default=utc_now_naive, onupdate=utc_now_naive, index=True)


class AcpMcpAuditEvent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    server_id = db.Column(db.Integer, db.ForeignKey('acp_mcp_server.id'), index=True)
    action = db.Column(db.String(40), nullable=False, index=True)  # approval_requested|approved|rejected|tool_call
    tool_name = db.Column(db.String(160), index=True)
    status = db.Column(db.String(30), nullable=False, default='ok', index=True)  # ok|error|blocked
    request_json = db.Column(db.Text)
    response_json = db.Column(db.Text)
    actor_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), index=True)
    created_at = db.Column(db.DateTime, default=utc_now_naive, index=True)

    server = db.relationship('AcpMcpServer', backref=db.backref('audit_events', lazy=True))

    __table_args__ = (
        db.Index('ix_acp_mcp_audit_server_created', 'server_id', 'created_at'),
    )


class AcpEnvironment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(40), unique=True, nullable=False, index=True)
    label = db.Column(db.String(80), nullable=False)
    is_default = db.Column(db.Boolean, nullable=False, default=False)
    is_protected = db.Column(db.Boolean, nullable=False, default=False)
    created_at = db.Column(db.DateTime, default=utc_now_naive, index=True)


class AcpPromotionEvent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    source_environment = db.Column(db.String(40), nullable=False, index=True)
    target_environment = db.Column(db.String(40), nullable=False, index=True)
    resource_type = db.Column(db.String(40), nullable=False, index=True)  # page|dashboard
    resource_id = db.Column(db.Integer, nullable=False, index=True)
    version_number = db.Column(db.Integer, nullable=False)
    status = db.Column(db.String(20), nullable=False, default='completed', index=True)
    notes = db.Column(db.String(300))
    promoted_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), index=True)
    created_at = db.Column(db.DateTime, default=utc_now_naive, index=True)


class AcpAuditEvent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    domain = db.Column(db.String(50), nullable=False, index=True)  # pages|dashboards|registry|metrics
    action = db.Column(db.String(50), nullable=False, index=True)  # create|update|publish|rollback
    entity_type = db.Column(db.String(60), nullable=False, index=True)
    entity_id = db.Column(db.String(120), nullable=False, index=True)
    before_json = db.Column(db.Text)
    after_json = db.Column(db.Text)
    actor_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), index=True)
    actor_username = db.Column(db.String(120), nullable=False)
    actor_ip = db.Column(db.String(64))
    actor_user_agent = db.Column(db.String(320))
    environment = db.Column(db.String(40), nullable=False, default='production', index=True)
    created_at = db.Column(db.DateTime, default=utc_now_naive, index=True)

    __table_args__ = (
        db.Index('ix_acp_audit_domain_created', 'domain', 'created_at'),
        db.Index('ix_acp_audit_entity_created', 'entity_type', 'entity_id', 'created_at'),
    )


def run_scheduled_publication_cycle(now=None):
    now = now or utc_now_naive()
    total_published = 0
    for model in (Post, Service, Industry):
        due_items = model.query.filter(
            model.workflow_status == WORKFLOW_APPROVED,
            model.scheduled_publish_at.isnot(None),
            model.scheduled_publish_at <= now,
        ).all()
        if not due_items:
            continue
        for item in due_items:
            item.workflow_status = WORKFLOW_PUBLISHED
            item.reviewed_at = item.reviewed_at or now
            item.approved_at = item.approved_at or now
            item.published_at = now
            item.scheduled_publish_at = None
            if hasattr(item, 'is_published'):
                item.is_published = True
            if hasattr(item, 'updated_at'):
                item.updated_at = now
        total_published += len(due_items)
    for model in (AcpPageDocument, AcpDashboardDocument):
        due_items = model.query.filter(
            model.status == WORKFLOW_APPROVED,
            model.scheduled_publish_at.isnot(None),
            model.scheduled_publish_at <= now,
        ).all()
        if not due_items:
            continue
        for item in due_items:
            item.status = WORKFLOW_PUBLISHED
            item.published_at = now
            item.scheduled_publish_at = None
            item.updated_at = now
        total_published += len(due_items)
    for model in (AcpContentEntry, AcpThemeTokenSet):
        due_items = model.query.filter(
            model.status == WORKFLOW_APPROVED,
            model.scheduled_publish_at.isnot(None),
            model.scheduled_publish_at <= now,
        ).all()
        if not due_items:
            continue
        for item in due_items:
            item.status = WORKFLOW_PUBLISHED
            item.published_at = now
            item.scheduled_publish_at = None
            item.updated_at = now
        total_published += len(due_items)
    if total_published:
        db.session.commit()
    return total_published
