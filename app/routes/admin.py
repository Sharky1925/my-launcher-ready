from datetime import datetime, timedelta
import json
import os
import re
import uuid
from urllib.parse import urlparse
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError
import bleach
from sqlalchemy import func, or_
from flask import Blueprint, render_template, request, redirect, url_for, flash, current_app, send_from_directory, session, abort, jsonify
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
        CmsPage,
        CmsArticle,
        Media,
        ContactSubmission,
        SiteSetting,
        SupportClient,
        SupportTicket,
        SupportTicketEvent,
        AuthRateLimitBucket,
        SecurityEvent,
        Industry,
        ContentBlock,
        PostVersion,
        ServiceVersion,
        IndustryVersion,
        MenuItem,
        PageView,
        NotificationPreference,
        AcpPageDocument,
        AcpPageVersion,
        AcpPageRouteBinding,
        AcpDashboardDocument,
        AcpDashboardVersion,
        AcpComponentDefinition,
        AcpWidgetDefinition,
        AcpMetricDefinition,
        AcpContentType,
        AcpContentTypeVersion,
        AcpContentEntry,
        AcpContentEntryVersion,
        AcpThemeTokenSet,
        AcpThemeTokenVersion,
        AcpMcpServer,
        AcpMcpAuditEvent,
        AcpMcpOperation,
        AcpEnvironment,
        AcpPromotionEvent,
        AcpAuditEvent,
        LEAD_STATUSES,
        LEAD_STATUS_LABELS,
        LEAD_STATUS_NEW,
        WORKFLOW_DRAFT,
        WORKFLOW_REVIEW,
        WORKFLOW_APPROVED,
        WORKFLOW_PUBLISHED,
        WORKFLOW_STATUSES,
        WORKFLOW_STATUS_LABELS,
        ROLE_OWNER,
        ROLE_ADMIN,
        ROLE_PUBLISHER,
        ROLE_REVIEWER,
        ROLE_EDITOR,
        ROLE_SUPPORT,
        USER_ROLE_CHOICES,
        USER_ROLE_LABELS,
        SUPPORT_TICKET_STATUS_OPEN,
        SUPPORT_TICKET_STATUS_IN_PROGRESS,
        SUPPORT_TICKET_STATUS_WAITING_CUSTOMER,
        SUPPORT_TICKET_STATUS_RESOLVED,
        SUPPORT_TICKET_STATUS_CLOSED,
        SUPPORT_TICKET_STATUSES,
        SUPPORT_TICKET_STATUS_LABELS,
        SUPPORT_TICKET_STAGE_PENDING,
        SUPPORT_TICKET_STAGE_DONE,
        SUPPORT_TICKET_STAGE_CLOSED,
        SUPPORT_TICKET_STAGE_LABELS,
        SUPPORT_TICKET_EVENT_CREATED,
        SUPPORT_TICKET_EVENT_REVIEW_ACTION,
        SUPPORT_TICKET_EVENT_ADMIN_UPDATE,
        normalize_support_ticket_status,
        normalize_support_ticket_stage,
        support_ticket_stage_for_status,
        normalize_ticket_number,
        create_support_ticket_event,
        normalize_workflow_status,
        normalize_user_role,
        MCP_OPERATION_STATUS_PENDING_APPROVAL,
        MCP_OPERATION_STATUS_QUEUED,
        MCP_OPERATION_STATUS_RUNNING,
        MCP_OPERATION_STATUS_SUCCEEDED,
        MCP_OPERATION_STATUS_FAILED,
        MCP_OPERATION_STATUS_BLOCKED,
        MCP_OPERATION_STATUS_REJECTED,
        MCP_APPROVAL_STATUS_PENDING,
        MCP_APPROVAL_STATUS_APPROVED,
        MCP_APPROVAL_STATUS_REJECTED,
        MCP_APPROVAL_STATUS_NOT_REQUIRED,
    )
    from ..utils import utc_now_naive, clean_text, escape_like, is_valid_email, get_request_ip
    from ..forms import HAS_FLASK_WTF, CmsPageForm, CmsArticleForm
    from ..content_schemas import CONTENT_SCHEMAS
    from ..page_sync import run_page_route_sync
    from ..service_seo_overrides import SERVICE_RESEARCH_OVERRIDES
    from .main import SERVICE_PROFILES
except ImportError:  # pragma: no cover - fallback when running from app/ cwd
    from models import (
        db,
        User,
        Service,
        TeamMember,
        Testimonial,
        Category,
        Post,
        CmsPage,
        CmsArticle,
        Media,
        ContactSubmission,
        SiteSetting,
        SupportClient,
        SupportTicket,
        SupportTicketEvent,
        AuthRateLimitBucket,
        SecurityEvent,
        Industry,
        ContentBlock,
        PostVersion,
        ServiceVersion,
        IndustryVersion,
        MenuItem,
        PageView,
        NotificationPreference,
        AcpPageDocument,
        AcpPageVersion,
        AcpPageRouteBinding,
        AcpDashboardDocument,
        AcpDashboardVersion,
        AcpComponentDefinition,
        AcpWidgetDefinition,
        AcpMetricDefinition,
        AcpContentType,
        AcpContentTypeVersion,
        AcpContentEntry,
        AcpContentEntryVersion,
        AcpThemeTokenSet,
        AcpThemeTokenVersion,
        AcpMcpServer,
        AcpMcpAuditEvent,
        AcpMcpOperation,
        AcpEnvironment,
        AcpPromotionEvent,
        AcpAuditEvent,
        LEAD_STATUSES,
        LEAD_STATUS_LABELS,
        LEAD_STATUS_NEW,
        WORKFLOW_DRAFT,
        WORKFLOW_REVIEW,
        WORKFLOW_APPROVED,
        WORKFLOW_PUBLISHED,
        WORKFLOW_STATUSES,
        WORKFLOW_STATUS_LABELS,
        ROLE_OWNER,
        ROLE_ADMIN,
        ROLE_PUBLISHER,
        ROLE_REVIEWER,
        ROLE_EDITOR,
        ROLE_SUPPORT,
        USER_ROLE_CHOICES,
        USER_ROLE_LABELS,
        SUPPORT_TICKET_STATUS_OPEN,
        SUPPORT_TICKET_STATUS_IN_PROGRESS,
        SUPPORT_TICKET_STATUS_WAITING_CUSTOMER,
        SUPPORT_TICKET_STATUS_RESOLVED,
        SUPPORT_TICKET_STATUS_CLOSED,
        SUPPORT_TICKET_STATUSES,
        SUPPORT_TICKET_STATUS_LABELS,
        SUPPORT_TICKET_STAGE_PENDING,
        SUPPORT_TICKET_STAGE_DONE,
        SUPPORT_TICKET_STAGE_CLOSED,
        SUPPORT_TICKET_STAGE_LABELS,
        SUPPORT_TICKET_EVENT_CREATED,
        SUPPORT_TICKET_EVENT_REVIEW_ACTION,
        SUPPORT_TICKET_EVENT_ADMIN_UPDATE,
        normalize_support_ticket_status,
        normalize_support_ticket_stage,
        support_ticket_stage_for_status,
        normalize_ticket_number,
        create_support_ticket_event,
        normalize_workflow_status,
        normalize_user_role,
        MCP_OPERATION_STATUS_PENDING_APPROVAL,
        MCP_OPERATION_STATUS_QUEUED,
        MCP_OPERATION_STATUS_RUNNING,
        MCP_OPERATION_STATUS_SUCCEEDED,
        MCP_OPERATION_STATUS_FAILED,
        MCP_OPERATION_STATUS_BLOCKED,
        MCP_OPERATION_STATUS_REJECTED,
        MCP_APPROVAL_STATUS_PENDING,
        MCP_APPROVAL_STATUS_APPROVED,
        MCP_APPROVAL_STATUS_REJECTED,
        MCP_APPROVAL_STATUS_NOT_REQUIRED,
    )
    from utils import utc_now_naive, clean_text, escape_like, is_valid_email, get_request_ip
    from forms import HAS_FLASK_WTF, CmsPageForm, CmsArticleForm
    from content_schemas import CONTENT_SCHEMAS
    from page_sync import run_page_route_sync
    from service_seo_overrides import SERVICE_RESEARCH_OVERRIDES
    from routes.main import SERVICE_PROFILES

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
ROLE_OPTIONS = [ROLE_OWNER, ROLE_ADMIN, ROLE_PUBLISHER, ROLE_REVIEWER, ROLE_EDITOR, ROLE_SUPPORT]
WORKFLOW_INPUT_DATE_FORMAT = '%Y-%m-%dT%H:%M'
WORKFLOW_STATUS_BADGES = {
    WORKFLOW_DRAFT: 'bg-warning text-dark',
    WORKFLOW_REVIEW: 'bg-info text-dark',
    WORKFLOW_APPROVED: 'bg-primary',
    WORKFLOW_PUBLISHED: 'bg-success',
}
SUPPORT_TICKET_STAGE_BADGES = {
    SUPPORT_TICKET_STAGE_PENDING: 'bg-warning text-dark',
    SUPPORT_TICKET_STAGE_DONE: 'bg-success',
    SUPPORT_TICKET_STAGE_CLOSED: 'bg-secondary',
}
SUPPORT_TICKET_EVENT_LABELS = {
    SUPPORT_TICKET_EVENT_CREATED: 'Created',
    SUPPORT_TICKET_EVENT_REVIEW_ACTION: 'Review Action',
    SUPPORT_TICKET_EVENT_ADMIN_UPDATE: 'Admin Update',
}
SUPPORT_TICKET_EVENT_BADGES = {
    SUPPORT_TICKET_EVENT_CREATED: 'bg-primary',
    SUPPORT_TICKET_EVENT_REVIEW_ACTION: 'bg-info text-dark',
    SUPPORT_TICKET_EVENT_ADMIN_UPDATE: 'bg-secondary',
}
SERVICE_PROFILE_FALLBACK_SLUGS = {
    str(slug).strip().lower()
    for slug in (set(SERVICE_RESEARCH_OVERRIDES.keys()) | set(SERVICE_PROFILES.keys()))
    if str(slug).strip()
}
MCP_REQUEST_TIMEOUT_SECONDS = 12
MCP_MAX_ATTEMPTS_DEFAULT = 3
MCP_MAX_ATTEMPTS_LIMIT = 6
MCP_RETRY_BACKOFF_SECONDS = (10, 30, 120, 300, 900)
MCP_MUTATING_TOOL_MARKERS = ('create', 'update', 'delete', 'write', 'publish', 'approve', 'set', 'run', 'execute')
ADMIN_PERMISSION_MAP = {
    'admin.control_center': 'dashboard:view',
    'admin.dashboard': 'dashboard:view',
    'admin.services': 'content:manage',
    'admin.service_add': 'content:manage',
    'admin.service_edit': 'content:manage',
    'admin.service_delete': 'content:manage',
    'admin.team': 'content:manage',
    'admin.team_add': 'content:manage',
    'admin.team_edit': 'content:manage',
    'admin.team_delete': 'content:manage',
    'admin.testimonials': 'content:manage',
    'admin.testimonial_add': 'content:manage',
    'admin.testimonial_edit': 'content:manage',
    'admin.testimonial_delete': 'content:manage',
    'admin.categories': 'content:manage',
    'admin.category_add': 'content:manage',
    'admin.category_edit': 'content:manage',
    'admin.category_delete': 'content:manage',
    'admin.posts': 'content:manage',
    'admin.post_add': 'content:manage',
    'admin.post_edit': 'content:manage',
    'admin.post_delete': 'content:manage',
    'admin.cms_pages': 'content:manage',
    'admin.cms_page_add': 'content:manage',
    'admin.cms_page_edit': 'content:manage',
    'admin.cms_page_delete': 'content:manage',
    'admin.cms_articles': 'content:manage',
    'admin.cms_article_add': 'content:manage',
    'admin.cms_article_edit': 'content:manage',
    'admin.cms_article_delete': 'content:manage',
    'admin.media': 'content:manage',
    'admin.media_upload': 'content:manage',
    'admin.media_delete': 'content:manage',
    'admin.industries': 'content:manage',
    'admin.industry_add': 'content:manage',
    'admin.industry_edit': 'content:manage',
    'admin.industry_delete': 'content:manage',
    'admin.content_list': 'content:manage',
    'admin.content_edit': 'content:manage',
    'admin.acp_studio': 'acp:studio:view',
    'admin.acp_pages': 'acp:pages:manage',
    'admin.acp_page_add': 'acp:pages:manage',
    'admin.acp_page_edit': 'acp:pages:manage',
    'admin.acp_page_snapshot': 'acp:pages:manage',
    'admin.acp_page_publish': 'acp:publish',
    'admin.acp_sync_status': 'acp:pages:manage',
    'admin.acp_sync_resync': 'acp:pages:manage',
    'admin.acp_dashboards': 'acp:dashboards:manage',
    'admin.acp_dashboard_add': 'acp:dashboards:manage',
    'admin.acp_dashboard_edit': 'acp:dashboards:manage',
    'admin.acp_dashboard_preview': 'acp:studio:view',
    'admin.acp_dashboard_snapshot': 'acp:dashboards:manage',
    'admin.acp_dashboard_publish': 'acp:publish',
    'admin.acp_content_types': 'acp:content:manage',
    'admin.acp_content_type_add': 'acp:content:manage',
    'admin.acp_content_type_edit': 'acp:content:manage',
    'admin.acp_content_entries': 'acp:content:manage',
    'admin.acp_content_entry_add': 'acp:content:manage',
    'admin.acp_content_entry_edit': 'acp:content:manage',
    'admin.acp_theme_tokens': 'acp:theme:manage',
    'admin.acp_theme_token_add': 'acp:theme:manage',
    'admin.acp_theme_token_edit': 'acp:theme:manage',
    'admin.acp_mcp_servers': 'acp:mcp:manage',
    'admin.acp_mcp_server_add': 'acp:mcp:manage',
    'admin.acp_mcp_server_edit': 'acp:mcp:manage',
    'admin.acp_mcp_operations': 'acp:mcp:manage',
    'admin.acp_mcp_operation_create': 'acp:mcp:manage',
    'admin.acp_mcp_operation_run': 'acp:mcp:manage',
    'admin.acp_mcp_operation_retry': 'acp:mcp:manage',
    'admin.acp_mcp_operation_approve': 'acp:mcp:manage',
    'admin.acp_mcp_operation_reject': 'acp:mcp:manage',
    'admin.acp_mcp_process_queue': 'acp:mcp:manage',
    'admin.acp_mcp_audit': 'acp:mcp:audit:view',
    'admin.acp_admin_mcp_operations_api': 'acp:mcp:audit:view',
    'admin.acp_registry': 'acp:registry:manage',
    'admin.acp_metrics': 'acp:metrics:manage',
    'admin.acp_audit': 'acp:audit:view',
    'admin.acp_promote': 'acp:environments:manage',
    'admin.acp_admin_page_api': 'acp:studio:view',
    'admin.acp_admin_dashboard_api': 'acp:studio:view',
    'admin.acp_admin_content_type_api': 'acp:content:manage',
    'admin.acp_admin_content_entry_api': 'acp:content:manage',
    'admin.acp_admin_theme_token_api': 'acp:theme:manage',
    'admin.acp_admin_mcp_server_api': 'acp:mcp:manage',
    'admin.contacts': 'support:manage',
    'admin.contact_view': 'support:manage',
    'admin.contact_delete': 'support:manage',
    'admin.support_tickets': 'support:manage',
    'admin.support_ticket_view': 'support:manage',
    'admin.support_ticket_review': 'support:manage',
    'admin.security_events': 'security:view',
    'admin.appearance': 'acp:theme:manage',
    'admin.settings': 'settings:manage',
    'admin.headless_hub': 'settings:manage',
    'admin.users': 'users:manage',
    'admin.user_add': 'users:manage',
    'admin.user_edit': 'users:manage',
    'admin.user_delete': 'users:manage',
    # New CMS enhancement routes
    'admin.post_restore': 'content:manage',
    'admin.service_restore': 'content:manage',
    'admin.industry_restore': 'content:manage',
    'admin.post_clone': 'content:manage',
    'admin.service_clone': 'content:manage',
    'admin.industry_clone': 'content:manage',
    'admin.post_trash_restore': 'content:manage',
    'admin.service_trash_restore': 'content:manage',
    'admin.industry_trash_restore': 'content:manage',
    'admin.testimonial_trash_restore': 'content:manage',
    'admin.team_trash_restore': 'content:manage',
    'admin.posts_bulk': 'content:manage',
    'admin.services_bulk': 'content:manage',
    'admin.industries_bulk': 'content:manage',
    'admin.testimonials_bulk': 'content:manage',
    'admin.team_bulk': 'content:manage',
    'admin.contacts_bulk': 'support:manage',
    'admin.media_picker_api': 'content:manage',
    'admin.media_edit': 'content:manage',
    'admin.post_autosave': 'content:manage',
    'admin.service_autosave': 'content:manage',
    'admin.industry_autosave': 'content:manage',
    'admin.contact_status_update': 'support:manage',
    'admin.contacts_export': 'support:manage',
    'admin.menu_editor': 'content:manage',
    'admin.menu_item_edit': 'content:manage',
    'admin.menu_item_delete': 'content:manage',
    'admin.menu_reorder': 'content:manage',
    'admin.admin_search_api': 'dashboard:view',
    'admin.analytics_top_pages_api': 'dashboard:view',
}


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


def parse_datetime_local(value):
    raw = (value or '').strip()
    if not raw:
        return None
    for fmt in ('%Y-%m-%dT%H:%M', '%Y-%m-%d %H:%M', '%Y-%m-%dT%H:%M:%S'):
        try:
            return datetime.strptime(raw, fmt)
        except ValueError:
            continue
    return None


def is_valid_https_url(value):
    raw = (value or '').strip()
    if not raw:
        return False
    parsed = urlparse(raw)
    if parsed.scheme not in {'http', 'https'}:
        return False
    if not parsed.netloc:
        return False
    return True


def format_datetime_local(value):
    if not value:
        return ''
    return value.strftime(WORKFLOW_INPUT_DATE_FORMAT)


def get_workflow_status_options(user):
    options = [WORKFLOW_DRAFT, WORKFLOW_REVIEW]
    if getattr(user, 'has_permission', None) and user.has_permission('workflow:review'):
        options.append(WORKFLOW_APPROVED)
    if getattr(user, 'has_permission', None) and user.has_permission('workflow:publish'):
        options.append(WORKFLOW_PUBLISHED)
    deduped = []
    for status in options:
        if status not in deduped:
            deduped.append(status)
    return deduped


def get_assignable_roles(user):
    if not getattr(user, 'is_authenticated', False):
        return [ROLE_EDITOR]
    if getattr(user, 'role_key', '') == ROLE_OWNER:
        return ROLE_OPTIONS
    if getattr(user, 'role_key', '') == ROLE_ADMIN:
        return [role for role in ROLE_OPTIONS if role != ROLE_OWNER]
    return [getattr(user, 'role_key', ROLE_EDITOR)]


def workflow_status_label(status):
    normalized = normalize_workflow_status(status, default=WORKFLOW_DRAFT)
    return WORKFLOW_STATUS_LABELS.get(normalized, WORKFLOW_STATUS_LABELS[WORKFLOW_DRAFT])


def workflow_status_badge(status):
    normalized = normalize_workflow_status(status, default=WORKFLOW_DRAFT)
    return WORKFLOW_STATUS_BADGES.get(normalized, WORKFLOW_STATUS_BADGES[WORKFLOW_DRAFT])


def has_permission(user, permission):
    if not permission:
        return True
    if not getattr(user, 'is_authenticated', False):
        return False
    checker = getattr(user, 'has_permission', None)
    if callable(checker):
        return bool(checker(permission))
    return False


def is_allowed_workflow_transition(user, target_status):
    status = normalize_workflow_status(target_status, default=WORKFLOW_DRAFT)
    if status in {WORKFLOW_DRAFT, WORKFLOW_REVIEW}:
        return has_permission(user, 'content:manage')
    if status == WORKFLOW_APPROVED:
        return has_permission(user, 'workflow:review')
    if status == WORKFLOW_PUBLISHED:
        return has_permission(user, 'workflow:publish')
    return False


def apply_workflow_form_fields(item, form, user, default_status=WORKFLOW_DRAFT):
    requested_status = normalize_workflow_status(form.get('workflow_status'), default=default_status)
    # Backward-compatible fallback for legacy tests/forms using the old checkbox only.
    if not (form.get('workflow_status') or '').strip() and 'is_published' in form:
        requested_status = WORKFLOW_PUBLISHED if form.get('is_published') else WORKFLOW_DRAFT

    schedule_raw = (form.get('scheduled_publish_at') or '').strip()
    scheduled_publish_at = None
    if schedule_raw:
        scheduled_publish_at = parse_datetime_local(schedule_raw)
        if not scheduled_publish_at:
            return False, 'Invalid scheduled publish date/time. Use the date picker format.'
        if not has_permission(user, 'workflow:publish'):
            return False, 'Your role cannot schedule publishing.'

    if not is_allowed_workflow_transition(user, requested_status):
        return False, 'Your role cannot set this workflow status.'

    now = utc_now_naive()
    if requested_status == WORKFLOW_PUBLISHED and scheduled_publish_at and scheduled_publish_at > now:
        requested_status = WORKFLOW_APPROVED
    if requested_status == WORKFLOW_APPROVED and scheduled_publish_at and scheduled_publish_at <= now:
        requested_status = WORKFLOW_PUBLISHED

    if scheduled_publish_at and requested_status not in {WORKFLOW_APPROVED, WORKFLOW_PUBLISHED}:
        return False, 'Scheduled publishing requires status Approved or Published.'

    item.workflow_status = requested_status
    if requested_status in {WORKFLOW_REVIEW, WORKFLOW_APPROVED, WORKFLOW_PUBLISHED}:
        item.reviewed_at = item.reviewed_at or now
    if requested_status in {WORKFLOW_APPROVED, WORKFLOW_PUBLISHED}:
        item.approved_at = item.approved_at or now
    if requested_status == WORKFLOW_PUBLISHED:
        item.published_at = now
        item.scheduled_publish_at = None
    else:
        item.scheduled_publish_at = scheduled_publish_at
    if hasattr(item, 'is_published'):
        item.is_published = requested_status == WORKFLOW_PUBLISHED
    if hasattr(item, 'updated_at'):
        item.updated_at = now
    return True, None


def support_ticket_status_label(status):
    normalized = normalize_support_ticket_status(status, default=SUPPORT_TICKET_STATUS_OPEN)
    return SUPPORT_TICKET_STATUS_LABELS.get(normalized, SUPPORT_TICKET_STATUS_LABELS[SUPPORT_TICKET_STATUS_OPEN])


def support_ticket_stage_label(stage):
    normalized = normalize_support_ticket_stage(stage, default=SUPPORT_TICKET_STAGE_PENDING)
    return SUPPORT_TICKET_STAGE_LABELS.get(normalized, SUPPORT_TICKET_STAGE_LABELS[SUPPORT_TICKET_STAGE_PENDING])


def support_ticket_stage_badge(stage):
    normalized = normalize_support_ticket_stage(stage, default=SUPPORT_TICKET_STAGE_PENDING)
    return SUPPORT_TICKET_STAGE_BADGES.get(normalized, SUPPORT_TICKET_STAGE_BADGES[SUPPORT_TICKET_STAGE_PENDING])


def support_ticket_stage_for_item(item):
    return support_ticket_stage_for_status(getattr(item, 'status', SUPPORT_TICKET_STATUS_OPEN))


def support_ticket_status_badge(status):
    stage = support_ticket_stage_for_status(status)
    return support_ticket_stage_badge(stage)


def support_ticket_event_label(event_type):
    normalized = (event_type or '').strip().lower()
    return SUPPORT_TICKET_EVENT_LABELS.get(normalized, 'Update')


def support_ticket_event_badge(event_type):
    normalized = (event_type or '').strip().lower()
    return SUPPORT_TICKET_EVENT_BADGES.get(normalized, 'bg-dark')


def _append_internal_note(existing, extra):
    cleaned = clean_text(extra, 4000)
    if not cleaned:
        return existing
    timestamp = utc_now_naive().strftime('%Y-%m-%d %H:%M UTC')
    note_line = f"[{timestamp}] {cleaned}"
    current = (existing or '').strip()
    if not current:
        return note_line
    return f"{current}\n{note_line}"


def apply_ticket_review_action(item, action, review_note=''):
    normalized_action = normalize_support_ticket_stage(action, default=SUPPORT_TICKET_STAGE_PENDING)
    target_status = {
        SUPPORT_TICKET_STAGE_PENDING: SUPPORT_TICKET_STATUS_IN_PROGRESS,
        SUPPORT_TICKET_STAGE_DONE: SUPPORT_TICKET_STATUS_RESOLVED,
        SUPPORT_TICKET_STAGE_CLOSED: SUPPORT_TICKET_STATUS_CLOSED,
    }[normalized_action]
    item.status = target_status
    item.internal_notes = _append_internal_note(item.internal_notes, review_note)
    item.updated_at = utc_now_naive()
    return normalized_action, target_status


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


def _safe_json_loads(raw_value, fallback):
    if raw_value is None:
        return fallback
    if isinstance(raw_value, (dict, list)):
        return raw_value
    value = str(raw_value).strip()
    if not value:
        return fallback
    try:
        parsed = json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return fallback
    return parsed


def _safe_json_dumps(value, fallback):
    payload = value if value is not None else fallback
    try:
        return json.dumps(payload, ensure_ascii=False)
    except (TypeError, ValueError):
        return json.dumps(fallback, ensure_ascii=False)


def _current_environment_name():
    return (
        (current_app.config.get('RAILWAY_ENVIRONMENT') or '').strip()
        or (os.environ.get('RAILWAY_ENVIRONMENT') or '').strip()
        or (os.environ.get('FLASK_ENV') or '').strip()
        or 'production'
    )


def _serialize_acp_page(page):
    return {
        'id': page.id,
        'slug': page.slug,
        'title': page.title,
        'template_id': page.template_id,
        'locale': page.locale,
        'status': page.status,
        'seo': _safe_json_loads(page.seo_json, {}),
        'blocks_tree': _safe_json_loads(page.blocks_tree, {}),
        'theme_override': _safe_json_loads(page.theme_override_json, {}),
        'scheduled_publish_at': page.scheduled_publish_at.isoformat() if page.scheduled_publish_at else None,
        'published_at': page.published_at.isoformat() if page.published_at else None,
        'updated_at': page.updated_at.isoformat() if page.updated_at else None,
    }


def _serialize_acp_dashboard(dashboard):
    return {
        'id': dashboard.id,
        'dashboard_id': dashboard.dashboard_id,
        'title': dashboard.title,
        'route': dashboard.route,
        'layout_type': dashboard.layout_type,
        'status': dashboard.status,
        'layout_config': _safe_json_loads(dashboard.layout_config_json, {}),
        'widgets': _safe_json_loads(dashboard.widgets_json, []),
        'global_filters': _safe_json_loads(dashboard.global_filters_json, []),
        'role_visibility_rules': _safe_json_loads(dashboard.role_visibility_json, {}),
        'scheduled_publish_at': dashboard.scheduled_publish_at.isoformat() if dashboard.scheduled_publish_at else None,
        'published_at': dashboard.published_at.isoformat() if dashboard.published_at else None,
        'updated_at': dashboard.updated_at.isoformat() if dashboard.updated_at else None,
    }


def _serialize_acp_content_type(content_type):
    return {
        'id': content_type.id,
        'key': content_type.key,
        'name': content_type.name,
        'description': content_type.description,
        'schema': _safe_json_loads(content_type.schema_json, {}),
        'is_enabled': bool(content_type.is_enabled),
        'updated_at': content_type.updated_at.isoformat() if content_type.updated_at else None,
    }


def _serialize_acp_content_entry(entry):
    content_type = getattr(entry, 'content_type', None)
    return {
        'id': entry.id,
        'content_type_id': entry.content_type_id,
        'content_type_key': getattr(content_type, 'key', ''),
        'content_type_name': getattr(content_type, 'name', ''),
        'entry_key': entry.entry_key,
        'title': entry.title,
        'locale': entry.locale,
        'status': entry.status,
        'data': _safe_json_loads(entry.data_json, {}),
        'scheduled_publish_at': entry.scheduled_publish_at.isoformat() if entry.scheduled_publish_at else None,
        'published_at': entry.published_at.isoformat() if entry.published_at else None,
        'updated_at': entry.updated_at.isoformat() if entry.updated_at else None,
    }


def _serialize_acp_theme_token_set(item):
    return {
        'id': item.id,
        'key': item.key,
        'name': item.name,
        'status': item.status,
        'tokens': _safe_json_loads(item.tokens_json, {}),
        'scheduled_publish_at': item.scheduled_publish_at.isoformat() if item.scheduled_publish_at else None,
        'published_at': item.published_at.isoformat() if item.published_at else None,
        'updated_at': item.updated_at.isoformat() if item.updated_at else None,
    }


def _serialize_acp_mcp_server(item):
    return {
        'id': item.id,
        'key': item.key,
        'name': item.name,
        'server_url': item.server_url,
        'transport': item.transport,
        'auth_mode': item.auth_mode,
        'environment': item.environment,
        'allowed_tools': _safe_json_loads(item.allowed_tools_json, []),
        'require_approval': item.require_approval,
        'is_enabled': bool(item.is_enabled),
        'notes': item.notes,
        'updated_at': item.updated_at.isoformat() if item.updated_at else None,
    }


def _serialize_acp_mcp_operation(item):
    if not item:
        return {}
    return {
        'id': item.id,
        'request_id': item.request_id,
        'server_id': item.server_id,
        'server_key': item.server.key if item.server else None,
        'server_name': item.server.name if item.server else None,
        'tool_name': item.tool_name,
        'arguments': _safe_json_loads(item.arguments_json, {}),
        'response': _safe_json_loads(item.response_json, {}),
        'status': item.status,
        'approval_status': item.approval_status,
        'requires_approval': bool(item.requires_approval),
        'attempt_count': item.attempt_count,
        'max_attempts': item.max_attempts,
        'error_message': item.error_message,
        'requested_by_id': item.requested_by_id,
        'approved_by_id': item.approved_by_id,
        'approved_at': item.approved_at.isoformat() if item.approved_at else None,
        'last_attempt_at': item.last_attempt_at.isoformat() if item.last_attempt_at else None,
        'next_attempt_at': item.next_attempt_at.isoformat() if item.next_attempt_at else None,
        'updated_at': item.updated_at.isoformat() if item.updated_at else None,
        'created_at': item.created_at.isoformat() if item.created_at else None,
    }


def _normalize_mcp_tool_name(value):
    cleaned = clean_text(value, 160).lower()
    if not cleaned:
        return ''
    return re.sub(r'[^a-z0-9._:-]+', '', cleaned)


def _safe_mcp_arguments(raw_value):
    parsed = _safe_json_loads(raw_value, None)
    if isinstance(parsed, dict):
        return parsed
    return None


def _mcp_allowed_tools(server):
    tools = _safe_json_loads(getattr(server, 'allowed_tools_json', '[]'), [])
    if not isinstance(tools, list):
        return []
    normalized = []
    for tool in tools:
        cleaned = _normalize_mcp_tool_name(tool)
        if cleaned and cleaned not in normalized:
            normalized.append(cleaned)
    return normalized


def _is_mcp_tool_mutating(tool_name):
    normalized = _normalize_mcp_tool_name(tool_name)
    return any(marker in normalized for marker in MCP_MUTATING_TOOL_MARKERS)


def _mcp_requires_approval(server, tool_name):
    mode = clean_text(getattr(server, 'require_approval', ''), 24).lower() or 'always'
    if mode == 'always':
        return True
    if mode == 'never':
        return False
    # Selective mode: require manual review for potentially mutating tool calls.
    return _is_mcp_tool_mutating(tool_name)


def _mcp_next_backoff_delay_seconds(attempt_count):
    idx = max(0, min(int(attempt_count or 1) - 1, len(MCP_RETRY_BACKOFF_SECONDS) - 1))
    return MCP_RETRY_BACKOFF_SECONDS[idx]


def _create_mcp_audit_event(server, action, tool_name, status, request_payload, response_payload):
    event = AcpMcpAuditEvent(
        server_id=getattr(server, 'id', None),
        action=clean_text(action, 40) or 'tool_call',
        tool_name=_normalize_mcp_tool_name(tool_name) or None,
        status=clean_text(status, 30) or 'ok',
        request_json=_safe_json_dumps(request_payload, {}),
        response_json=_safe_json_dumps(response_payload, {}),
        actor_user_id=getattr(current_user, 'id', None),
    )
    db.session.add(event)


def _invoke_mcp_http(server, tool_name, arguments, request_id):
    payload = {
        'jsonrpc': '2.0',
        'id': request_id,
        'method': 'tools/call',
        'params': {
            'name': _normalize_mcp_tool_name(tool_name),
            'arguments': arguments,
        },
    }
    body = json.dumps(payload, ensure_ascii=False).encode('utf-8')
    req = Request(
        url=server.server_url,
        method='POST',
        headers={
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'User-Agent': 'RightOnRepair-MCP/1.0',
        },
        data=body,
    )
    with urlopen(req, timeout=MCP_REQUEST_TIMEOUT_SECONDS) as resp:
        raw = resp.read().decode('utf-8', errors='replace')
        status_code = getattr(resp, 'status', 200)
    parsed = _safe_json_loads(raw, None)
    if isinstance(parsed, dict):
        if parsed.get('error'):
            raise RuntimeError(clean_text(parsed['error'].get('message'), 300) or 'MCP error response')
        return {
            'http_status': status_code,
            'result': parsed.get('result'),
            'raw': parsed,
        }
    return {
        'http_status': status_code,
        'result': raw,
        'raw': {'raw': raw},
    }


def _execute_mcp_operation(operation):
    now = utc_now_naive()
    server = operation.server
    if not server or not server.is_enabled:
        operation.status = MCP_OPERATION_STATUS_BLOCKED
        operation.error_message = 'Server is disabled or missing.'
        operation.updated_at = now
        _create_mcp_audit_event(server, 'tool_call', operation.tool_name, 'blocked', _serialize_acp_mcp_operation(operation), {'error': operation.error_message})
        return False
    if operation.status == MCP_OPERATION_STATUS_PENDING_APPROVAL:
        operation.error_message = 'Waiting for approval.'
        operation.updated_at = now
        return False
    if operation.approval_status == MCP_APPROVAL_STATUS_REJECTED:
        operation.status = MCP_OPERATION_STATUS_REJECTED
        operation.error_message = 'Operation was rejected.'
        operation.updated_at = now
        return False
    if operation.requires_approval and operation.approval_status != MCP_APPROVAL_STATUS_APPROVED:
        operation.status = MCP_OPERATION_STATUS_PENDING_APPROVAL
        operation.error_message = 'Approval required before execution.'
        operation.updated_at = now
        return False
    if operation.attempt_count >= max(1, int(operation.max_attempts or MCP_MAX_ATTEMPTS_DEFAULT)):
        operation.status = MCP_OPERATION_STATUS_FAILED
        operation.error_message = operation.error_message or 'Maximum attempts reached.'
        operation.updated_at = now
        return False

    operation.status = MCP_OPERATION_STATUS_RUNNING
    operation.attempt_count = int(operation.attempt_count or 0) + 1
    operation.last_attempt_at = now
    operation.updated_at = now
    db.session.flush()

    args_payload = _safe_json_loads(operation.arguments_json, {})
    try:
        response_payload = _invoke_mcp_http(server, operation.tool_name, args_payload, operation.request_id)
        operation.status = MCP_OPERATION_STATUS_SUCCEEDED
        operation.response_json = _safe_json_dumps(response_payload, {})
        operation.error_message = None
        operation.next_attempt_at = None
        operation.updated_at = utc_now_naive()
        _create_mcp_audit_event(
            server,
            'tool_call',
            operation.tool_name,
            'ok',
            {'request_id': operation.request_id, 'arguments': args_payload},
            response_payload,
        )
        return True
    except (HTTPError, URLError, TimeoutError, OSError, ValueError, RuntimeError) as exc:
        remaining = max(0, int(operation.max_attempts or MCP_MAX_ATTEMPTS_DEFAULT) - int(operation.attempt_count or 0))
        message = clean_text(str(exc), 700) or 'MCP request failed.'
        if remaining > 0:
            operation.status = MCP_OPERATION_STATUS_QUEUED
            operation.next_attempt_at = utc_now_naive() + timedelta(seconds=_mcp_next_backoff_delay_seconds(operation.attempt_count))
        else:
            operation.status = MCP_OPERATION_STATUS_FAILED
            operation.next_attempt_at = None
        operation.error_message = message
        operation.updated_at = utc_now_naive()
        _create_mcp_audit_event(
            server,
            'tool_call',
            operation.tool_name,
            'error',
            {'request_id': operation.request_id, 'attempt': operation.attempt_count, 'arguments': args_payload},
            {'error': message, 'remaining_attempts': remaining},
        )
        return False


def _process_due_mcp_operations(limit=10):
    now = utc_now_naive()
    items = (
        AcpMcpOperation.query
        .filter(
            AcpMcpOperation.status == MCP_OPERATION_STATUS_QUEUED,
            or_(
                AcpMcpOperation.next_attempt_at.is_(None),
                AcpMcpOperation.next_attempt_at <= now,
            ),
        )
        .order_by(AcpMcpOperation.next_attempt_at.asc(), AcpMcpOperation.created_at.asc())
        .limit(max(1, min(int(limit or 10), 50)))
        .all()
    )
    results = {'processed': 0, 'succeeded': 0, 'failed': 0}
    for item in items:
        ok = _execute_mcp_operation(item)
        results['processed'] += 1
        if ok:
            results['succeeded'] += 1
        elif item.status in {MCP_OPERATION_STATUS_FAILED, MCP_OPERATION_STATUS_BLOCKED, MCP_OPERATION_STATUS_REJECTED}:
            results['failed'] += 1
    return results


def _create_acp_audit_event(domain, action, entity_type, entity_id, before_state, after_state):
    actor_username = getattr(current_user, 'username', 'system')
    event = AcpAuditEvent(
        domain=domain,
        action=action,
        entity_type=entity_type,
        entity_id=str(entity_id),
        before_json=_safe_json_dumps(before_state, {}),
        after_json=_safe_json_dumps(after_state, {}),
        actor_user_id=getattr(current_user, 'id', None),
        actor_username=actor_username,
        actor_ip=get_request_ip(),
        actor_user_agent=(request.headers.get('User-Agent') or '')[:300],
        environment=_current_environment_name(),
    )
    db.session.add(event)


def _next_page_version_number(page_id):
    latest = db.session.query(func.max(AcpPageVersion.version_number)).filter_by(page_id=page_id).scalar()
    return int(latest or 0) + 1


def _next_dashboard_version_number(dashboard_document_id):
    latest = db.session.query(func.max(AcpDashboardVersion.version_number)).filter_by(
        dashboard_document_id=dashboard_document_id
    ).scalar()
    return int(latest or 0) + 1


def _next_content_type_version_number(content_type_id):
    latest = db.session.query(func.max(AcpContentTypeVersion.version_number)).filter_by(
        content_type_id=content_type_id
    ).scalar()
    return int(latest or 0) + 1


def _next_content_entry_version_number(content_entry_id):
    latest = db.session.query(func.max(AcpContentEntryVersion.version_number)).filter_by(
        content_entry_id=content_entry_id
    ).scalar()
    return int(latest or 0) + 1


def _next_theme_token_version_number(token_set_id):
    latest = db.session.query(func.max(AcpThemeTokenVersion.version_number)).filter_by(
        token_set_id=token_set_id
    ).scalar()
    return int(latest or 0) + 1


def _create_page_version(page, note=''):
    snapshot = _serialize_acp_page(page)
    version = AcpPageVersion(
        page_id=page.id,
        version_number=_next_page_version_number(page.id),
        snapshot_json=_safe_json_dumps(snapshot, {}),
        change_note=clean_text(note, 260) or None,
        created_by_id=getattr(current_user, 'id', None),
    )
    db.session.add(version)
    return version


def _create_dashboard_version(dashboard, note=''):
    snapshot = _serialize_acp_dashboard(dashboard)
    version = AcpDashboardVersion(
        dashboard_document_id=dashboard.id,
        version_number=_next_dashboard_version_number(dashboard.id),
        snapshot_json=_safe_json_dumps(snapshot, {}),
        change_note=clean_text(note, 260) or None,
        created_by_id=getattr(current_user, 'id', None),
    )
    db.session.add(version)
    return version


def _create_content_type_version(item, note=''):
    snapshot = _serialize_acp_content_type(item)
    version = AcpContentTypeVersion(
        content_type_id=item.id,
        version_number=_next_content_type_version_number(item.id),
        snapshot_json=_safe_json_dumps(snapshot, {}),
        change_note=clean_text(note, 260) or None,
        created_by_id=getattr(current_user, 'id', None),
    )
    db.session.add(version)
    return version


def _create_content_entry_version(item, note=''):
    snapshot = _serialize_acp_content_entry(item)
    version = AcpContentEntryVersion(
        content_entry_id=item.id,
        version_number=_next_content_entry_version_number(item.id),
        snapshot_json=_safe_json_dumps(snapshot, {}),
        change_note=clean_text(note, 260) or None,
        created_by_id=getattr(current_user, 'id', None),
    )
    db.session.add(version)
    return version


def _create_theme_token_version(item, note=''):
    snapshot = _serialize_acp_theme_token_set(item)
    version = AcpThemeTokenVersion(
        token_set_id=item.id,
        version_number=_next_theme_token_version_number(item.id),
        snapshot_json=_safe_json_dumps(snapshot, {}),
        change_note=clean_text(note, 260) or None,
        created_by_id=getattr(current_user, 'id', None),
    )
    db.session.add(version)
    return version


def _build_component_registry_payload(enabled_only=True):
    query = AcpComponentDefinition.query
    if enabled_only:
        query = query.filter_by(is_enabled=True)
    items = query.order_by(AcpComponentDefinition.category.asc(), AcpComponentDefinition.key.asc()).all()
    payload = []
    for item in items:
        payload.append(
            {
                'key': item.key,
                'name': item.name,
                'category': item.category,
                'prop_schema': _safe_json_loads(item.prop_schema_json, {}) or {},
                'default_props': _safe_json_loads(item.default_props_json, {}) or {},
                'allowed_children': _safe_json_loads(item.allowed_children_json, []) or [],
                'restrictions': _safe_json_loads(item.restrictions_json, {}) or {},
            }
        )
    return payload


def _build_widget_registry_payload(enabled_only=True):
    query = AcpWidgetDefinition.query
    if enabled_only:
        query = query.filter_by(is_enabled=True)
    items = query.order_by(AcpWidgetDefinition.category.asc(), AcpWidgetDefinition.key.asc()).all()
    payload = []
    for item in items:
        payload.append(
            {
                'key': item.key,
                'name': item.name,
                'category': item.category,
                'config_schema': _safe_json_loads(item.config_schema_json, {}) or {},
                'data_contract': _safe_json_loads(item.data_contract_json, {}) or {},
                'allowed_filters': _safe_json_loads(item.allowed_filters_json, []) or [],
                'permissions_required': _safe_json_loads(item.permissions_required_json, []) or [],
            }
        )
    return payload


def _normalize_component_type(component_type):
    raw = clean_text(component_type, 120)
    alias_map = {
        'Container': 'layout.container',
        'Hero': 'marketing.hero',
        'ServiceCards': 'content.serviceCards',
    }
    return alias_map.get(raw, raw)


def _normalize_blocks_tree_payload(blocks_payload):
    root = blocks_payload if isinstance(blocks_payload, dict) else {}
    root_type = _normalize_component_type(root.get('type') or 'layout.container') or 'layout.container'
    root_props = root.get('props') if isinstance(root.get('props'), dict) else {}
    root_children = root.get('children') if isinstance(root.get('children'), list) else []
    normalized_children = []
    for child in root_children:
        if not isinstance(child, dict):
            continue
        child_type = _normalize_component_type(child.get('type') or '')
        if not child_type:
            continue
        child_props = child.get('props') if isinstance(child.get('props'), dict) else {}
        normalized_children.append(
            {
                'type': child_type,
                'props': child_props,
            }
        )
    return {
        'type': root_type,
        'props': root_props,
        'children': normalized_children,
    }


def _validate_blocks_tree_against_registry(blocks_payload):
    normalized = _normalize_blocks_tree_payload(blocks_payload)
    registry_keys = {item['key'] for item in _build_component_registry_payload(enabled_only=True)}
    if registry_keys:
        if normalized['type'] not in registry_keys:
            return False, normalized, f'Root block type "{normalized["type"]}" is not registered.'
        for child in normalized.get('children', []):
            if child.get('type') not in registry_keys:
                return False, normalized, f'Child block type "{child.get("type")}" is not registered.'
    return True, normalized, None


def _filter_widgets_for_role(widgets, role_rules, role_key):
    role_rule = role_rules.get(role_key) if isinstance(role_rules, dict) else {}
    role_rule = role_rule if isinstance(role_rule, dict) else {}
    hidden_widgets = role_rule.get('hiddenWidgets')
    hidden = {str(v) for v in hidden_widgets} if isinstance(hidden_widgets, list) else set()
    allowed_widgets = role_rule.get('allowedWidgets')
    allowed = {str(v) for v in allowed_widgets} if isinstance(allowed_widgets, list) else set()
    show_all = bool(role_rule.get('showAll'))

    visible_widgets = []
    for widget in widgets if isinstance(widgets, list) else []:
        if not isinstance(widget, dict):
            continue
        widget_id = str(widget.get('id') or '')
        widget_type = str(widget.get('type') or '')
        if hidden and (widget_id in hidden or widget_type in hidden):
            continue
        widget_roles = widget.get('visibilityRoles')
        if isinstance(widget_roles, list) and widget_roles:
            normalized_roles = {str(role) for role in widget_roles}
            if role_key not in normalized_roles:
                continue
        if not show_all and allowed:
            if widget_id not in allowed and widget_type not in allowed:
                continue
        visible_widgets.append(widget)
    return visible_widgets, role_rule


def _apply_acp_workflow(document, requested_status, scheduled_raw):
    status = normalize_workflow_status(requested_status, default=WORKFLOW_DRAFT)
    if not is_allowed_workflow_transition(current_user, status):
        return False, 'Your role cannot set this workflow status.'

    scheduled_publish_at = None
    if (scheduled_raw or '').strip():
        scheduled_publish_at = parse_datetime_local(scheduled_raw)
        if not scheduled_publish_at:
            return False, 'Invalid scheduled publish date/time. Use the date picker format.'
        if not has_permission(current_user, 'acp:publish'):
            return False, 'Your role cannot schedule publishing.'

    now = utc_now_naive()
    if status == WORKFLOW_PUBLISHED and scheduled_publish_at and scheduled_publish_at > now:
        status = WORKFLOW_APPROVED
    if status == WORKFLOW_APPROVED and scheduled_publish_at and scheduled_publish_at <= now:
        status = WORKFLOW_PUBLISHED

    if scheduled_publish_at and status not in {WORKFLOW_APPROVED, WORKFLOW_PUBLISHED}:
        return False, 'Scheduled publishing requires Approved or Published status.'

    document.status = status
    if status == WORKFLOW_PUBLISHED:
        document.published_at = now
        document.scheduled_publish_at = None
    else:
        document.scheduled_publish_at = scheduled_publish_at
    document.updated_at = now
    return True, None


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


@admin_bp.before_request
def enforce_role_permissions():
    endpoint = request.endpoint or ''
    if endpoint == 'admin.login':
        return
    if not current_user.is_authenticated:
        return
    required_permission = ADMIN_PERMISSION_MAP.get(endpoint)
    if not required_permission:
        return
    if has_permission(current_user, required_permission):
        return
    flash('Your role does not have access to that area.', 'danger')
    return redirect(url_for('admin.dashboard'))


@admin_bp.app_context_processor
def inject_admin_template_helpers():
    return {
        'workflow_status_label': workflow_status_label,
        'workflow_status_badge': workflow_status_badge,
        'workflow_status_labels': WORKFLOW_STATUS_LABELS,
        'role_labels': USER_ROLE_LABELS,
        'format_datetime_local': format_datetime_local,
        'support_ticket_status_label': support_ticket_status_label,
        'support_ticket_stage_label': support_ticket_stage_label,
        'support_ticket_stage_badge': support_ticket_stage_badge,
        'support_ticket_stage_for_status': support_ticket_stage_for_status,
        'support_ticket_status_badge': support_ticket_status_badge,
        'support_ticket_event_label': support_ticket_event_label,
        'support_ticket_event_badge': support_ticket_event_badge,
        'support_ticket_stage_labels': SUPPORT_TICKET_STAGE_LABELS,
        'support_ticket_status_labels': SUPPORT_TICKET_STATUS_LABELS,
    }


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
    session.clear()
    return redirect(url_for('admin.login'))


@admin_bp.route('/control-center')
@login_required
def control_center():
    now = utc_now_naive()
    last_24h = now - timedelta(hours=24)
    open_ticket_statuses = [
        SUPPORT_TICKET_STATUS_OPEN,
        SUPPORT_TICKET_STATUS_IN_PROGRESS,
        SUPPORT_TICKET_STATUS_WAITING_CUSTOMER,
    ]

    page_count = AcpPageDocument.query.count()
    dashboard_count = AcpDashboardDocument.query.count()
    published_page_count = AcpPageDocument.query.filter_by(status=WORKFLOW_PUBLISHED).count()
    published_dashboard_count = AcpDashboardDocument.query.filter_by(status=WORKFLOW_PUBLISHED).count()
    content_type_count = AcpContentType.query.filter_by(is_enabled=True).count()
    content_entry_count = AcpContentEntry.query.count()
    theme_token_count = AcpThemeTokenSet.query.count()
    registry_component_count = AcpComponentDefinition.query.filter_by(is_enabled=True).count()
    registry_widget_count = AcpWidgetDefinition.query.filter_by(is_enabled=True).count()
    metric_count = AcpMetricDefinition.query.filter_by(is_enabled=True).count()
    mcp_server_count = AcpMcpServer.query.count()
    mcp_operation_queue_count = AcpMcpOperation.query.filter(
        AcpMcpOperation.status.in_([
            MCP_OPERATION_STATUS_PENDING_APPROVAL,
            MCP_OPERATION_STATUS_QUEUED,
            MCP_OPERATION_STATUS_RUNNING,
        ])
    ).count()
    services_count = Service.query.count()
    industries_count = Industry.query.count()
    media_count = Media.query.count()
    content_block_count = ContentBlock.query.count()

    ticket_open_count = SupportTicket.query.filter(SupportTicket.status.in_(open_ticket_statuses)).count()
    contacts_unread_count = ContactSubmission.query.filter_by(is_read=False).count()
    security_24h_count = SecurityEvent.query.filter(SecurityEvent.created_at >= last_24h).count()
    users_count = User.query.count()

    website_modules = [
        {
            'title': 'Visual Pages',
            'description': 'Edit page routes, layout blocks, hero sections, and per-page SEO.',
            'icon': 'fa-solid fa-layer-group',
            'href': url_for('admin.acp_pages'),
            'permission': 'acp:pages:manage',
            'metric': f'{page_count} pages',
        },
        {
            'title': 'Theme, Fonts, Icons, Motion',
            'description': 'Manage color tokens, typography scale, spacing, icon presets, and animation defaults.',
            'icon': 'fa-solid fa-palette',
            'href': url_for('admin.acp_theme_tokens'),
            'permission': 'acp:theme:manage',
            'metric': f'{theme_token_count} token sets',
        },
        {
            'title': 'Content Models & Entries',
            'description': 'Configure structured data models and editable website content entries.',
            'icon': 'fa-solid fa-table-list',
            'href': url_for('admin.acp_content_types'),
            'permission': 'acp:content:manage',
            'metric': f'{content_type_count} types / {content_entry_count} entries',
        },
        {
            'title': 'Services, Industries, Media',
            'description': 'Update service pages, industry pages, imagery, and website-facing business content.',
            'icon': 'fa-solid fa-briefcase',
            'href': url_for('admin.services'),
            'permission': 'content:manage',
            'metric': f'{services_count} services / {industries_count} industries / {media_count} assets',
        },
        {
            'title': 'Headless API Hub',
            'description': 'Control delivery API authentication, token policy, and pagination limits.',
            'icon': 'fa-solid fa-cloud-arrow-down',
            'href': url_for('admin.headless_hub'),
            'permission': 'settings:manage',
            'metric': 'Security + API controls',
        },
        {
            'title': 'Component & Widget Registry',
            'description': 'Control allowed building blocks, input schemas, and design guardrails.',
            'icon': 'fa-solid fa-puzzle-piece',
            'href': url_for('admin.acp_registry'),
            'permission': 'acp:registry:manage',
            'metric': f'{registry_component_count} components / {registry_widget_count} widgets',
        },
        {
            'title': 'Route Sync & Editability',
            'description': 'Audit web routes against CMS page records and fix out-of-sync pages.',
            'icon': 'fa-solid fa-arrows-rotate',
            'href': url_for('admin.acp_sync_status'),
            'permission': 'acp:pages:manage',
            'metric': 'Sync monitor',
        },
    ]

    operations_modules = [
        {
            'title': 'Operations Dashboard',
            'description': 'Monitor KPIs, queue health, service workload, and recent platform activity.',
            'icon': 'fa-solid fa-gauge-high',
            'href': url_for('admin.dashboard'),
            'permission': 'dashboard:view',
            'metric': 'Live KPIs',
        },
        {
            'title': 'Dashboard Studio',
            'description': 'Build role-based internal dashboards with widgets, filters, and visibility rules.',
            'icon': 'fa-solid fa-chart-line',
            'href': url_for('admin.acp_dashboards'),
            'permission': 'acp:dashboards:manage',
            'metric': f'{dashboard_count} dashboards',
        },
        {
            'title': 'Support Tickets',
            'description': 'Review client tickets, set pending/done/closed status, and manage ticket timeline.',
            'icon': 'fa-solid fa-ticket',
            'href': url_for('admin.support_tickets'),
            'permission': 'support:manage',
            'metric': f'{ticket_open_count} open',
        },
        {
            'title': 'MCP Operations',
            'description': 'Approve, execute, retry, and monitor MCP tool calls across connected servers.',
            'icon': 'fa-solid fa-bolt',
            'href': url_for('admin.acp_mcp_operations'),
            'permission': 'acp:mcp:manage',
            'metric': f'{mcp_operation_queue_count} active in queue',
        },
        {
            'title': 'Contact Inbox',
            'description': 'Manage contact submissions, quote leads, and inbound requests from the website.',
            'icon': 'fa-solid fa-envelope',
            'href': url_for('admin.contacts'),
            'permission': 'support:manage',
            'metric': f'{contacts_unread_count} unread',
        },
        {
            'title': 'Security & Access',
            'description': 'Review security events, role access, and operational risk indicators.',
            'icon': 'fa-solid fa-shield-halved',
            'href': url_for('admin.security_events'),
            'permission': 'security:view',
            'metric': f'{security_24h_count} events (24h)',
        },
        {
            'title': 'Admin Users & Settings',
            'description': 'Manage admin accounts, role tiers, global settings, and business profile details.',
            'icon': 'fa-solid fa-user-shield',
            'href': url_for('admin.users'),
            'permission': 'users:manage',
            'metric': f'{users_count} users',
        },
    ]

    visible_website_modules = [item for item in website_modules if has_permission(current_user, item['permission'])]
    visible_operations_modules = [item for item in operations_modules if has_permission(current_user, item['permission'])]

    quick_actions = []
    if has_permission(current_user, 'acp:pages:manage'):
        quick_actions.append({'label': 'New Visual Page', 'href': url_for('admin.acp_page_add'), 'icon': 'fa-solid fa-layer-group'})
    if has_permission(current_user, 'acp:dashboards:manage'):
        quick_actions.append({'label': 'New Dashboard', 'href': url_for('admin.acp_dashboard_add'), 'icon': 'fa-solid fa-chart-line'})
    if has_permission(current_user, 'acp:content:manage'):
        quick_actions.append({'label': 'New Content Type', 'href': url_for('admin.acp_content_type_add'), 'icon': 'fa-solid fa-table-list'})
    if has_permission(current_user, 'settings:manage'):
        quick_actions.append({'label': 'Headless Hub', 'href': url_for('admin.headless_hub'), 'icon': 'fa-solid fa-cloud-arrow-down'})
    if has_permission(current_user, 'support:manage'):
        quick_actions.append({'label': 'Open Ticket Queue', 'href': url_for('admin.support_tickets'), 'icon': 'fa-solid fa-ticket'})
    if has_permission(current_user, 'acp:mcp:manage'):
        quick_actions.append({'label': 'MCP Servers', 'href': url_for('admin.acp_mcp_servers'), 'icon': 'fa-solid fa-plug-circle-bolt'})
        quick_actions.append({'label': 'MCP Operations', 'href': url_for('admin.acp_mcp_operations'), 'icon': 'fa-solid fa-bolt'})

    return render_template(
        'admin/control_center.html',
        website_modules=visible_website_modules,
        operations_modules=visible_operations_modules,
        quick_actions=quick_actions,
        section_stats={
            'website_total': len(visible_website_modules),
            'operations_total': len(visible_operations_modules),
            'published_pages': published_page_count,
            'published_dashboards': published_dashboard_count,
            'metrics': metric_count,
            'mcp_servers': mcp_server_count,
            'mcp_operations': mcp_operation_queue_count,
            'content_blocks': content_block_count,
        },
    )


# Dashboard
@admin_bp.route('/')
@login_required
def dashboard():
    now = utc_now_naive()
    last_24h = now - timedelta(hours=24)
    last_7d = now - timedelta(days=7)
    stale_cutoff = now - timedelta(days=14)
    open_ticket_statuses = [
        SUPPORT_TICKET_STATUS_OPEN,
        SUPPORT_TICKET_STATUS_IN_PROGRESS,
        SUPPORT_TICKET_STATUS_WAITING_CUSTOMER,
    ]
    quote_filter = quote_ticket_filter_expression()

    site_settings = {s.key: s.value for s in SiteSetting.query.all()}
    missing_setting_keys = [
        key for key in ('company_name', 'email', 'meta_title', 'meta_description')
        if not (site_settings.get(key) or '').strip()
    ]

    published_posts_count = Post.query.filter_by(workflow_status=WORKFLOW_PUBLISHED).count()
    draft_posts_count = Post.query.filter(Post.workflow_status != WORKFLOW_PUBLISHED).count()
    contacts_24h = ContactSubmission.query.filter(ContactSubmission.created_at >= last_24h).count()
    tickets_24h = SupportTicket.query.filter(SupportTicket.created_at >= last_24h).count()
    support_waiting_count = SupportTicket.query.filter(SupportTicket.status == SUPPORT_TICKET_STATUS_WAITING_CUSTOMER).count()
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
        SupportTicket.status == SUPPORT_TICKET_STATUS_RESOLVED,
        SupportTicket.updated_at >= last_7d,
    ).count()

    service_profile_rows = Service.query.with_entities(Service.slug, Service.profile_json).all()
    services_missing_profile = 0
    for slug, profile_json in service_profile_rows:
        if (profile_json or '').strip():
            continue
        normalized_slug = (slug or '').strip().lower()
        # Treat known profile registries as valid fallback content, even without per-row JSON.
        if normalized_slug and normalized_slug in SERVICE_PROFILE_FALLBACK_SLUGS:
            continue
        services_missing_profile += 1
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
        Post.workflow_status == WORKFLOW_PUBLISHED,
        or_(Post.excerpt.is_(None), func.trim(Post.excerpt) == ''),
    ).count()
    stale_drafts = Post.query.filter(
        Post.workflow_status.in_([WORKFLOW_DRAFT, WORKFLOW_REVIEW, WORKFLOW_APPROVED]),
        Post.updated_at <= stale_cutoff,
    ).order_by(Post.updated_at.asc()).limit(6).all()

    status_rows = db.session.query(
        SupportTicket.status,
        func.count(SupportTicket.id),
    ).group_by(SupportTicket.status).all()
    status_map = {status: count for status, count in status_rows}
    ticket_status = [
        {'key': SUPPORT_TICKET_STATUS_OPEN, 'label': support_ticket_status_label(SUPPORT_TICKET_STATUS_OPEN), 'count': status_map.get(SUPPORT_TICKET_STATUS_OPEN, 0)},
        {'key': SUPPORT_TICKET_STATUS_IN_PROGRESS, 'label': support_ticket_status_label(SUPPORT_TICKET_STATUS_IN_PROGRESS), 'count': status_map.get(SUPPORT_TICKET_STATUS_IN_PROGRESS, 0)},
        {'key': SUPPORT_TICKET_STATUS_WAITING_CUSTOMER, 'label': support_ticket_status_label(SUPPORT_TICKET_STATUS_WAITING_CUSTOMER), 'count': status_map.get(SUPPORT_TICKET_STATUS_WAITING_CUSTOMER, 0)},
        {'key': SUPPORT_TICKET_STATUS_RESOLVED, 'label': support_ticket_status_label(SUPPORT_TICKET_STATUS_RESOLVED), 'count': status_map.get(SUPPORT_TICKET_STATUS_RESOLVED, 0)},
        {'key': SUPPORT_TICKET_STATUS_CLOSED, 'label': support_ticket_status_label(SUPPORT_TICKET_STATUS_CLOSED), 'count': status_map.get(SUPPORT_TICKET_STATUS_CLOSED, 0)},
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
            'description': 'Service profile coverage (custom or fallback registry) and industry challenge/solution completeness.',
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

    ticket_lookup_query_raw = clean_text(request.args.get('ticket_number', ''), 40)
    ticket_lookup_query = normalize_ticket_number(ticket_lookup_query_raw)
    ticket_lookup_result = None
    if ticket_lookup_query:
        ticket_lookup_result = SupportTicket.query.filter_by(ticket_number=ticket_lookup_query).first()

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
            'meta': workflow_status_label(item.workflow_status),
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
        ticket_lookup_query=ticket_lookup_query,
        ticket_lookup_result=ticket_lookup_result,
        is_quote_ticket=is_quote_ticket,
        workflow_status_label=workflow_status_label,
        workflow_status_badge=workflow_status_badge,
    )


# Services CRUD
@admin_bp.route('/services')
@login_required
def services():
    if request.args.get('trash'):
        items = Service.query.filter(Service.is_trashed == True).order_by(Service.sort_order, Service.id).all()
    else:
        items = Service.query.filter(db.or_(Service.is_trashed == False, Service.is_trashed == None)).order_by(Service.sort_order, Service.id).all()
    return render_template('admin/services.html', items=items)


@admin_bp.route('/services/add', methods=['GET', 'POST'])
@login_required
def service_add():
    workflow_options = get_workflow_status_options(current_user)
    if request.method == 'POST':
        title = clean_text(request.form.get('title'), 200)
        description = clean_text(request.form.get('description'), 10000)
        icon_class = clean_text(request.form.get('icon_class', 'fa-solid fa-gear'), 100)
        service_type = clean_text(request.form.get('service_type', 'professional'), 20)
        service_type = service_type if service_type in {'professional', 'repair'} else 'professional'
        sort_order = parse_int(request.form.get('sort_order', 0), default=0, min_value=-100000, max_value=100000)

        if not title or not description:
            flash('Title and description are required.', 'danger')
            return render_template('admin/service_form.html', item=None, workflow_options=workflow_options)

        slug = slugify(title)
        if not slug:
            flash('Unable to generate a valid slug from title.', 'danger')
            return render_template('admin/service_form.html', item=None, workflow_options=workflow_options)
        if Service.query.filter_by(slug=slug).first():
            flash('A service with that title already exists.', 'danger')
            return render_template('admin/service_form.html', item=None, workflow_options=workflow_options)

        profile_json_raw = request.form.get('profile_json', '').strip()
        if profile_json_raw:
            try:
                json.loads(profile_json_raw)
            except (json.JSONDecodeError, TypeError):
                flash('Invalid JSON in service profile.', 'danger')
                return render_template('admin/service_form.html', item=None, workflow_options=workflow_options)

        image = save_upload(request.files.get('image')) if request.files.get('image') else None
        seo_title = clean_text(request.form.get('seo_title', ''), 200)
        seo_description = clean_text(request.form.get('seo_description', ''), 500)
        og_image_val = clean_text(request.form.get('og_image', ''), 500)
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
            seo_title=seo_title or None,
            seo_description=seo_description or None,
            og_image=og_image_val or None,
        )
        ok, workflow_error = apply_workflow_form_fields(
            item,
            request.form,
            current_user,
            default_status=WORKFLOW_DRAFT,
        )
        if not ok:
            flash(workflow_error, 'danger')
            return render_template('admin/service_form.html', item=None, workflow_options=workflow_options)
        db.session.add(item)
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            flash('Unable to save service due to duplicate data.', 'danger')
            return render_template('admin/service_form.html', item=None, workflow_options=workflow_options)
        flash('Service added.', 'success')
        return redirect(url_for('admin.services'))
    return render_template('admin/service_form.html', item=None, workflow_options=workflow_options)


@admin_bp.route('/services/<int:id>/edit', methods=['GET', 'POST'])
@login_required
def service_edit(id):
    item = db.get_or_404(Service, id)
    workflow_options = get_workflow_status_options(current_user)
    if request.method == 'POST':
        title = clean_text(request.form.get('title'), 200)
        description = clean_text(request.form.get('description'), 10000)
        icon_class = clean_text(request.form.get('icon_class', 'fa-solid fa-gear'), 100)
        service_type = clean_text(request.form.get('service_type', 'professional'), 20)
        service_type = service_type if service_type in {'professional', 'repair'} else 'professional'
        sort_order = parse_int(request.form.get('sort_order', 0), default=0, min_value=-100000, max_value=100000)

        if not title or not description:
            flash('Title and description are required.', 'danger')
            return render_template('admin/service_form.html', item=item, workflow_options=workflow_options)

        slug = slugify(title)
        if not slug:
            flash('Unable to generate a valid slug from title.', 'danger')
            return render_template('admin/service_form.html', item=item, workflow_options=workflow_options)
        slug_exists = Service.query.filter(Service.slug == slug, Service.id != item.id).first()
        if slug_exists:
            flash('Another service already uses this title/slug.', 'danger')
            return render_template('admin/service_form.html', item=item, workflow_options=workflow_options)

        profile_json_raw = request.form.get('profile_json', '').strip()
        if profile_json_raw:
            try:
                json.loads(profile_json_raw)
            except (json.JSONDecodeError, TypeError):
                flash('Invalid JSON in service profile.', 'danger')
                return render_template('admin/service_form.html', item=item, workflow_options=workflow_options)

        seo_title = clean_text(request.form.get('seo_title', ''), 200)
        seo_description = clean_text(request.form.get('seo_description', ''), 500)
        og_image_val = clean_text(request.form.get('og_image', ''), 500)
        change_note = clean_text(request.form.get('change_note', ''), 260)
        item.title = title
        item.slug = slug
        item.description = description
        item.icon_class = icon_class
        item.service_type = service_type
        item.is_featured = 'is_featured' in request.form
        item.sort_order = sort_order
        item.profile_json = profile_json_raw or None
        item.seo_title = seo_title or None
        item.seo_description = seo_description or None
        item.og_image = og_image_val or None
        ok, workflow_error = apply_workflow_form_fields(
            item,
            request.form,
            current_user,
            default_status=normalize_workflow_status(item.workflow_status, default=WORKFLOW_DRAFT),
        )
        if not ok:
            flash(workflow_error, 'danger')
            return render_template('admin/service_form.html', item=item, workflow_options=workflow_options)
        if request.files.get('image') and request.files['image'].filename:
            uploaded_image = save_upload(request.files['image'])
            if not uploaded_image:
                flash('Invalid image upload.', 'danger')
                return render_template('admin/service_form.html', item=item, workflow_options=workflow_options)
            item.image = uploaded_image
        try:
            db.session.flush()
            _create_service_version(item, change_note, current_user)
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            flash('Unable to update service due to duplicate data.', 'danger')
            return render_template('admin/service_form.html', item=item, workflow_options=workflow_options)
        flash('Service updated.', 'success')
        return redirect(url_for('admin.services'))
    versions = ServiceVersion.query.filter_by(service_id=item.id).order_by(ServiceVersion.version_number.desc()).limit(20).all() if item else []
    return render_template('admin/service_form.html', item=item, workflow_options=workflow_options, versions=versions)


@admin_bp.route('/services/<int:id>/delete', methods=['POST'])
@login_required
def service_delete(id):
    item = db.get_or_404(Service, id)
    if item.is_trashed:
        db.session.delete(item)
        flash('Service permanently deleted.', 'success')
    else:
        item.is_trashed = True
        item.trashed_at = utc_now_naive()
        flash('Service moved to trash.', 'success')
    db.session.commit()
    return redirect(url_for('admin.services'))


# Team CRUD
@admin_bp.route('/team')
@login_required
def team():
    if request.args.get('trash'):
        items = TeamMember.query.filter(TeamMember.is_trashed == True).order_by(TeamMember.sort_order).all()
    else:
        items = TeamMember.query.filter(db.or_(TeamMember.is_trashed == False, TeamMember.is_trashed == None)).order_by(TeamMember.sort_order).all()
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
    item = db.get_or_404(TeamMember, id)
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
    item = db.get_or_404(TeamMember, id)
    if item.is_trashed:
        db.session.delete(item)
        flash('Team member permanently deleted.', 'success')
    else:
        item.is_trashed = True
        item.trashed_at = utc_now_naive()
        flash('Team member moved to trash.', 'success')
    db.session.commit()
    return redirect(url_for('admin.team'))


# Testimonials CRUD
@admin_bp.route('/testimonials')
@login_required
def testimonials():
    if request.args.get('trash'):
        items = Testimonial.query.filter(Testimonial.is_trashed == True).order_by(Testimonial.created_at.desc()).all()
    else:
        items = Testimonial.query.filter(db.or_(Testimonial.is_trashed == False, Testimonial.is_trashed == None)).order_by(Testimonial.created_at.desc()).all()
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
    item = db.get_or_404(Testimonial, id)
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
    item = db.get_or_404(Testimonial, id)
    if item.is_trashed:
        db.session.delete(item)
        flash('Testimonial permanently deleted.', 'success')
    else:
        item.is_trashed = True
        item.trashed_at = utc_now_naive()
        flash('Testimonial moved to trash.', 'success')
    db.session.commit()
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
    cat = db.get_or_404(Category, id)
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
    if request.args.get('trash'):
        items = Post.query.filter(Post.is_trashed == True).order_by(Post.updated_at.desc(), Post.created_at.desc()).all()
    else:
        items = Post.query.filter(db.or_(Post.is_trashed == False, Post.is_trashed == None)).order_by(Post.updated_at.desc(), Post.created_at.desc()).all()
    return render_template('admin/posts.html', items=items)


@admin_bp.route('/posts/add', methods=['GET', 'POST'])
@login_required
def post_add():
    workflow_options = get_workflow_status_options(current_user)
    if request.method == 'POST':
        title = clean_text(request.form.get('title'), 300)
        excerpt = clean_text(request.form.get('excerpt', ''), 2000)
        content = sanitize_html(request.form.get('content', ''), 100000)
        raw_category_id = request.form.get('category_id')
        category_id = parse_positive_int(raw_category_id) if raw_category_id else None
        if raw_category_id and category_id is None:
            flash('Invalid category value.', 'danger')
            cats = Category.query.all()
            return render_template('admin/post_form.html', item=None, categories=cats, workflow_options=workflow_options)
        if category_id and not db.session.get(Category, category_id):
            flash('Selected category does not exist.', 'danger')
            cats = Category.query.all()
            return render_template('admin/post_form.html', item=None, categories=cats, workflow_options=workflow_options)

        if not title or not content:
            flash('Title and content are required.', 'danger')
            cats = Category.query.all()
            return render_template('admin/post_form.html', item=None, categories=cats, workflow_options=workflow_options)

        slug = slugify(title)
        if not slug:
            flash('Unable to generate a valid post slug.', 'danger')
            cats = Category.query.all()
            return render_template('admin/post_form.html', item=None, categories=cats, workflow_options=workflow_options)
        if Post.query.filter_by(slug=slug).first():
            flash('A post with that title already exists.', 'danger')
            cats = Category.query.all()
            return render_template('admin/post_form.html', item=None, categories=cats, workflow_options=workflow_options)

        image = save_upload(request.files.get('featured_image')) if request.files.get('featured_image') else None
        seo_title = clean_text(request.form.get('seo_title', ''), 200)
        seo_description = clean_text(request.form.get('seo_description', ''), 500)
        og_image_val = clean_text(request.form.get('og_image', ''), 500)
        item = Post(
            title=title,
            slug=slug,
            excerpt=excerpt,
            content=content,
            featured_image=image,
            category_id=category_id,
            seo_title=seo_title or None,
            seo_description=seo_description or None,
            og_image=og_image_val or None,
        )
        ok, workflow_error = apply_workflow_form_fields(
            item,
            request.form,
            current_user,
            default_status=WORKFLOW_DRAFT,
        )
        if not ok:
            flash(workflow_error, 'danger')
            cats = Category.query.all()
            return render_template('admin/post_form.html', item=None, categories=cats, workflow_options=workflow_options)
        db.session.add(item)
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            flash('Unable to create post due to duplicate data.', 'danger')
            cats = Category.query.all()
            return render_template('admin/post_form.html', item=None, categories=cats, workflow_options=workflow_options)
        flash('Post created.', 'success')
        return redirect(url_for('admin.posts'))
    cats = Category.query.all()
    return render_template('admin/post_form.html', item=None, categories=cats, workflow_options=workflow_options)


@admin_bp.route('/posts/<int:id>/edit', methods=['GET', 'POST'])
@login_required
def post_edit(id):
    item = db.get_or_404(Post, id)
    workflow_options = get_workflow_status_options(current_user)
    if request.method == 'POST':
        title = clean_text(request.form.get('title'), 300)
        excerpt = clean_text(request.form.get('excerpt', ''), 2000)
        content = sanitize_html(request.form.get('content', ''), 100000)
        raw_category_id = request.form.get('category_id')
        category_id = parse_positive_int(raw_category_id) if raw_category_id else None
        if raw_category_id and category_id is None:
            flash('Invalid category value.', 'danger')
            cats = Category.query.all()
            return render_template('admin/post_form.html', item=item, categories=cats, workflow_options=workflow_options)
        if category_id and not db.session.get(Category, category_id):
            flash('Selected category does not exist.', 'danger')
            cats = Category.query.all()
            return render_template('admin/post_form.html', item=item, categories=cats, workflow_options=workflow_options)

        if not title or not content:
            flash('Title and content are required.', 'danger')
            cats = Category.query.all()
            return render_template('admin/post_form.html', item=item, categories=cats, workflow_options=workflow_options)

        slug = slugify(title)
        if not slug:
            flash('Unable to generate a valid post slug.', 'danger')
            cats = Category.query.all()
            return render_template('admin/post_form.html', item=item, categories=cats, workflow_options=workflow_options)
        slug_exists = Post.query.filter(Post.slug == slug, Post.id != item.id).first()
        if slug_exists:
            flash('Another post already uses this title/slug.', 'danger')
            cats = Category.query.all()
            return render_template('admin/post_form.html', item=item, categories=cats, workflow_options=workflow_options)

        seo_title = clean_text(request.form.get('seo_title', ''), 200)
        seo_description = clean_text(request.form.get('seo_description', ''), 500)
        og_image_val = clean_text(request.form.get('og_image', ''), 500)
        change_note = clean_text(request.form.get('change_note', ''), 260)
        item.title = title
        item.slug = slug
        item.excerpt = excerpt
        item.content = content
        item.category_id = category_id
        item.seo_title = seo_title or None
        item.seo_description = seo_description or None
        item.og_image = og_image_val or None
        ok, workflow_error = apply_workflow_form_fields(
            item,
            request.form,
            current_user,
            default_status=normalize_workflow_status(item.workflow_status, default=WORKFLOW_DRAFT),
        )
        if not ok:
            flash(workflow_error, 'danger')
            cats = Category.query.all()
            return render_template('admin/post_form.html', item=item, categories=cats, workflow_options=workflow_options)
        if request.files.get('featured_image') and request.files['featured_image'].filename:
            uploaded_image = save_upload(request.files['featured_image'])
            if not uploaded_image:
                flash('Invalid featured image upload.', 'danger')
                cats = Category.query.all()
                return render_template('admin/post_form.html', item=item, categories=cats, workflow_options=workflow_options)
            item.featured_image = uploaded_image
        try:
            db.session.flush()
            _create_post_version(item, change_note, current_user)
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            flash('Unable to update post due to duplicate data.', 'danger')
            cats = Category.query.all()
            return render_template('admin/post_form.html', item=item, categories=cats, workflow_options=workflow_options)
        flash('Post updated.', 'success')
        return redirect(url_for('admin.posts'))
    cats = Category.query.all()
    versions = PostVersion.query.filter_by(post_id=item.id).order_by(PostVersion.version_number.desc()).limit(20).all() if item else []
    return render_template('admin/post_form.html', item=item, categories=cats, workflow_options=workflow_options, versions=versions)


@admin_bp.route('/posts/<int:id>/delete', methods=['POST'])
@login_required
def post_delete(id):
    item = db.get_or_404(Post, id)
    if item.is_trashed:
        db.session.delete(item)
        flash('Post permanently deleted.', 'success')
    else:
        item.is_trashed = True
        item.trashed_at = utc_now_naive()
        flash('Post moved to trash.', 'success')
    db.session.commit()
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
    item = db.get_or_404(Media, id)
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
                'facebook', 'twitter', 'linkedin', 'meta_title', 'meta_description', 'footer_text',
                'custom_head_code', 'custom_footer_code', 'zip_code']
        length_limits = {
            'company_name': 200,
            'tagline': 300,
            'phone': 80,
            'email': 200,
            'address': 400,
            'zip_code': 20,
            'facebook': 300,
            'twitter': 300,
            'linkedin': 300,
            'meta_title': 300,
            'meta_description': 500,
            'footer_text': 300,
            'custom_head_code': 10000,
            'custom_footer_code': 10000,
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


def _save_site_setting(key, value):
    """Create or update a SiteSetting record."""
    setting = SiteSetting.query.filter_by(key=key).first()
    if setting:
        setting.value = value
    else:
        db.session.add(SiteSetting(key=key, value=value))


def _coerce_bool_setting(value, default=False):
    if value is None:
        return default
    return str(value).strip().lower() in {'1', 'true', 'yes', 'on'}


@admin_bp.route('/headless', methods=['GET', 'POST'])
@login_required
def headless_hub():
    config_default_limit = parse_positive_int(current_app.config.get('HEADLESS_DELIVERY_DEFAULT_LIMIT')) or 24
    config_max_limit = parse_positive_int(current_app.config.get('HEADLESS_DELIVERY_MAX_LIMIT')) or 100
    if config_max_limit < config_default_limit:
        config_max_limit = config_default_limit

    if request.method == 'POST':
        default_limit = parse_positive_int(request.form.get('headless_delivery_default_limit'))
        max_limit = parse_positive_int(request.form.get('headless_delivery_max_limit'))
        if default_limit is None:
            flash('Default API page size must be a positive number.', 'danger')
            return redirect(url_for('admin.headless_hub'))
        if max_limit is None:
            flash('Maximum API page size must be a positive number.', 'danger')
            return redirect(url_for('admin.headless_hub'))
        if max_limit < default_limit:
            flash('Maximum API page size must be greater than or equal to default page size.', 'danger')
            return redirect(url_for('admin.headless_hub'))

        require_token = request.form.get('headless_delivery_require_token') == '1'
        token_value = clean_text(request.form.get('headless_delivery_token', ''), 260)
        clear_token = request.form.get('clear_headless_delivery_token') == '1'

        _save_site_setting('headless_delivery_require_token', '1' if require_token else '0')
        _save_site_setting('headless_delivery_default_limit', str(default_limit))
        _save_site_setting('headless_delivery_max_limit', str(max_limit))
        if clear_token:
            _save_site_setting('headless_delivery_token', '')
        elif token_value:
            _save_site_setting('headless_delivery_token', token_value)
        db.session.commit()
        flash('Headless CMS settings saved.', 'success')
        return redirect(url_for('admin.headless_hub'))

    settings_dict = {s.key: s.value for s in SiteSetting.query.all()}
    require_token = _coerce_bool_setting(
        settings_dict.get('headless_delivery_require_token'),
        bool(current_app.config.get('HEADLESS_DELIVERY_REQUIRE_TOKEN', False)),
    )
    site_delivery_token = (settings_dict.get('headless_delivery_token') or '').strip()
    env_delivery_token = (current_app.config.get('HEADLESS_DELIVERY_TOKEN') or '').strip()
    effective_delivery_token = site_delivery_token or env_delivery_token

    default_limit = parse_positive_int(settings_dict.get('headless_delivery_default_limit')) or config_default_limit
    max_limit = parse_positive_int(settings_dict.get('headless_delivery_max_limit')) or config_max_limit
    if max_limit < default_limit:
        max_limit = default_limit

    sync_enabled = bool(current_app.config.get('HEADLESS_SYNC_ENABLED', True))
    sync_token_configured = bool((current_app.config.get('HEADLESS_SYNC_TOKEN') or '').strip())
    sync_max_items = parse_positive_int(current_app.config.get('HEADLESS_SYNC_MAX_ITEMS')) or 250

    public_base_url = (current_app.config.get('APP_BASE_URL') or '').strip().rstrip('/')
    if not public_base_url:
        public_base_url = request.url_root.rstrip('/')

    endpoints = [
        {'label': 'Delivery API Index', 'path': '/api/delivery'},
        {'label': 'ACP Visual Pages', 'path': '/api/delivery/pages/<slug>'},
        {'label': 'ACP Dashboards', 'path': '/api/delivery/dashboards/<dashboard_id>'},
        {'label': 'ACP Content Entries', 'path': '/api/delivery/content/<content_type_key>/<entry_key>'},
        {'label': 'ACP Theme Tokens', 'path': '/api/delivery/theme/<token_set_key>'},
        {'label': 'CMS Pages', 'path': '/api/delivery/cms/pages'},
        {'label': 'CMS Articles', 'path': '/api/delivery/cms/articles'},
        {'label': 'Services', 'path': '/api/delivery/services'},
        {'label': 'Industries', 'path': '/api/delivery/industries'},
        {'label': 'Posts', 'path': '/api/delivery/posts'},
    ]
    for item in endpoints:
        item['url'] = f"{public_base_url}{item['path']}"

    counts = {
        'cms_pages_published': CmsPage.query.filter_by(is_published=True).count(),
        'cms_articles_published': CmsArticle.query.filter_by(is_published=True).count(),
        'services_published': Service.query.filter_by(workflow_status=WORKFLOW_PUBLISHED).filter(
            db.or_(Service.is_trashed == False, Service.is_trashed == None)
        ).count(),
        'industries_published': Industry.query.filter_by(workflow_status=WORKFLOW_PUBLISHED).filter(
            db.or_(Industry.is_trashed == False, Industry.is_trashed == None)
        ).count(),
        'posts_published': Post.query.filter_by(workflow_status=WORKFLOW_PUBLISHED).filter(
            db.or_(Post.is_trashed == False, Post.is_trashed == None)
        ).count(),
        'acp_pages_published': AcpPageDocument.query.filter_by(status=WORKFLOW_PUBLISHED).count(),
        'acp_dashboards_published': AcpDashboardDocument.query.filter_by(status=WORKFLOW_PUBLISHED).count(),
    }

    quick_links = []
    if has_permission(current_user, 'content:manage'):
        quick_links.extend([
            {'label': 'CMS Pages', 'href': url_for('admin.cms_pages')},
            {'label': 'CMS Articles', 'href': url_for('admin.cms_articles')},
            {'label': 'Services', 'href': url_for('admin.services')},
            {'label': 'Industries', 'href': url_for('admin.industries')},
            {'label': 'Posts', 'href': url_for('admin.posts')},
        ])
    if has_permission(current_user, 'acp:pages:manage'):
        quick_links.append({'label': 'ACP Pages', 'href': url_for('admin.acp_pages')})
    if has_permission(current_user, 'acp:dashboards:manage'):
        quick_links.append({'label': 'ACP Dashboards', 'href': url_for('admin.acp_dashboards')})
    if has_permission(current_user, 'acp:content:manage'):
        quick_links.append({'label': 'ACP Content Entries', 'href': url_for('admin.acp_content_entries')})

    return render_template(
        'admin/headless_hub.html',
        settings=settings_dict,
        require_token=require_token,
        default_limit=default_limit,
        max_limit=max_limit,
        config_default_limit=config_default_limit,
        config_max_limit=config_max_limit,
        site_delivery_token=site_delivery_token,
        env_delivery_token=env_delivery_token,
        effective_delivery_token=effective_delivery_token,
        sync_enabled=sync_enabled,
        sync_token_configured=sync_token_configured,
        sync_max_items=sync_max_items,
        endpoints=endpoints,
        counts=counts,
        quick_links=quick_links,
        delivery_auth_warning=require_token and not bool(effective_delivery_token),
    )


@admin_bp.route('/appearance', methods=['GET', 'POST'])
@login_required
def appearance():
    from ..appearance_config import (
        FONT_NAMES, APPEARANCE_COLOR_VARS, SHADOW_PRESETS, SPEED_PRESETS,
        EASING_PRESETS, tokens_to_visual_config, visual_config_to_tokens,
        build_google_fonts_url, APPEARANCE_DEFAULTS,
    )

    item = AcpThemeTokenSet.query.filter_by(key='default').first()
    theme_mode_setting = SiteSetting.query.filter_by(key='theme_mode').first()
    current_theme_mode = (theme_mode_setting.value if theme_mode_setting else 'dark') or 'dark'

    if request.method == 'POST':
        use_raw_json = request.form.get('use_raw_json') == '1'
        change_note = clean_text(request.form.get('change_note'), 260)
        new_theme_mode = request.form.get('theme_mode', 'dark').strip().lower()
        if new_theme_mode not in ('dark', 'light'):
            new_theme_mode = 'dark'

        if use_raw_json:
            raw_json = request.form.get('tokens_json', '{}')
            tokens_payload = _safe_json_loads(raw_json, None)
            if not isinstance(tokens_payload, dict):
                flash('Tokens JSON must be a valid JSON object.', 'danger')
                visual_config = tokens_to_visual_config(
                    _safe_json_loads(item.tokens_json, {}) if item else APPEARANCE_DEFAULTS
                )
                versions = []
                if item:
                    versions = AcpThemeTokenVersion.query.filter_by(
                        token_set_id=item.id
                    ).order_by(AcpThemeTokenVersion.version_number.desc()).limit(12).all()
                return render_template(
                    'admin/appearance.html',
                    item=item, visual_config=visual_config, theme_mode=new_theme_mode,
                    font_names=FONT_NAMES, color_vars=APPEARANCE_COLOR_VARS,
                    shadow_presets=list(SHADOW_PRESETS.keys()),
                    speed_presets=list(SPEED_PRESETS.keys()),
                    easing_presets=list(EASING_PRESETS.keys()),
                    workflow_options=get_workflow_status_options(current_user),
                    versions=versions,
                    raw_json=raw_json,
                )
        else:
            tokens_payload, errors = visual_config_to_tokens(request.form, new_theme_mode)
            if errors:
                for err in errors:
                    flash(err, 'danger')
                visual_config = tokens_to_visual_config(tokens_payload)
                versions = []
                if item:
                    versions = AcpThemeTokenVersion.query.filter_by(
                        token_set_id=item.id
                    ).order_by(AcpThemeTokenVersion.version_number.desc()).limit(12).all()
                return render_template(
                    'admin/appearance.html',
                    item=item, visual_config=visual_config, theme_mode=new_theme_mode,
                    font_names=FONT_NAMES, color_vars=APPEARANCE_COLOR_VARS,
                    shadow_presets=list(SHADOW_PRESETS.keys()),
                    speed_presets=list(SPEED_PRESETS.keys()),
                    easing_presets=list(EASING_PRESETS.keys()),
                    workflow_options=get_workflow_status_options(current_user),
                    versions=versions,
                    raw_json=_safe_json_dumps(tokens_payload, {}),
                )

        # Save theme_mode and google_fonts_url to SiteSettings
        _save_site_setting('theme_mode', new_theme_mode)

        # Build Google Fonts URL from font selections
        body_font = request.form.get('body_font', 'Manrope')
        heading_font = request.form.get('heading_font', 'Sora')
        slogan_font = request.form.get('slogan_font', 'Orbitron')
        fonts_url = build_google_fonts_url(body_font, heading_font, slogan_font)
        _save_site_setting('google_fonts_url', fonts_url)

        tokens_json_str = _safe_json_dumps(tokens_payload, {})

        if item:
            before_state = _serialize_acp_theme_token_set(item)
            item.tokens_json = tokens_json_str
            item.updated_by_id = current_user.id
            ok, workflow_error = _apply_acp_workflow(
                item,
                request.form.get('workflow_status') or item.status,
                request.form.get('scheduled_publish_at'),
            )
            if not ok:
                flash(workflow_error, 'danger')
                visual_config = tokens_to_visual_config(tokens_payload)
                versions = AcpThemeTokenVersion.query.filter_by(
                    token_set_id=item.id
                ).order_by(AcpThemeTokenVersion.version_number.desc()).limit(12).all()
                return render_template(
                    'admin/appearance.html',
                    item=item, visual_config=visual_config, theme_mode=new_theme_mode,
                    font_names=FONT_NAMES, color_vars=APPEARANCE_COLOR_VARS,
                    shadow_presets=list(SHADOW_PRESETS.keys()),
                    speed_presets=list(SPEED_PRESETS.keys()),
                    easing_presets=list(EASING_PRESETS.keys()),
                    workflow_options=get_workflow_status_options(current_user),
                    versions=versions,
                    raw_json=tokens_json_str,
                )
            _create_theme_token_version(item, note=change_note or 'Appearance updated')
            _create_acp_audit_event('theme', 'update', 'acp_theme_token_set', item.key, before_state, _serialize_acp_theme_token_set(item))
        else:
            item = AcpThemeTokenSet(
                key='default',
                name='Default Theme',
                tokens_json=tokens_json_str,
                created_by_id=current_user.id,
                updated_by_id=current_user.id,
            )
            ok, workflow_error = _apply_acp_workflow(
                item,
                request.form.get('workflow_status'),
                request.form.get('scheduled_publish_at'),
            )
            if not ok:
                flash(workflow_error, 'danger')
                visual_config = tokens_to_visual_config(tokens_payload)
                return render_template(
                    'admin/appearance.html',
                    item=None, visual_config=visual_config, theme_mode=new_theme_mode,
                    font_names=FONT_NAMES, color_vars=APPEARANCE_COLOR_VARS,
                    shadow_presets=list(SHADOW_PRESETS.keys()),
                    speed_presets=list(SPEED_PRESETS.keys()),
                    easing_presets=list(EASING_PRESETS.keys()),
                    workflow_options=get_workflow_status_options(current_user),
                    versions=[],
                    raw_json=tokens_json_str,
                )
            db.session.add(item)
            db.session.flush()
            _create_theme_token_version(item, note=change_note or 'Initial appearance')
            _create_acp_audit_event('theme', 'create', 'acp_theme_token_set', item.key, {}, _serialize_acp_theme_token_set(item))

        db.session.commit()
        flash('Site appearance saved.', 'success')
        return redirect(url_for('admin.appearance'))

    # GET
    tokens_dict = _safe_json_loads(item.tokens_json, {}) if item else APPEARANCE_DEFAULTS
    visual_config = tokens_to_visual_config(tokens_dict)
    versions = []
    if item:
        versions = AcpThemeTokenVersion.query.filter_by(
            token_set_id=item.id
        ).order_by(AcpThemeTokenVersion.version_number.desc()).limit(12).all()
    return render_template(
        'admin/appearance.html',
        item=item,
        visual_config=visual_config,
        theme_mode=current_theme_mode,
        font_names=FONT_NAMES,
        color_vars=APPEARANCE_COLOR_VARS,
        shadow_presets=list(SHADOW_PRESETS.keys()),
        speed_presets=list(SPEED_PRESETS.keys()),
        easing_presets=list(EASING_PRESETS.keys()),
        workflow_options=get_workflow_status_options(current_user),
        versions=versions,
        raw_json=_safe_json_dumps(tokens_dict, {}),
    )


# Admin Users
@admin_bp.route('/users')
@login_required
def users():
    items = User.query.order_by(User.created_at).all()
    return render_template('admin/users.html', items=items)


@admin_bp.route('/users/add', methods=['GET', 'POST'])
@login_required
def user_add():
    assignable_roles = get_assignable_roles(current_user)
    default_role = ROLE_ADMIN if ROLE_ADMIN in assignable_roles else assignable_roles[0]
    if request.method == 'POST':
        username = clean_text(request.form.get('username', ''), 80)
        email = clean_text(request.form.get('email', ''), 120)
        password = request.form.get('password', '')
        role = normalize_user_role(request.form.get('role', default_role), default=default_role)
        if role not in assignable_roles:
            flash('You do not have permission to assign that role.', 'danger')
            return render_template('admin/user_form.html', user=None, assignable_roles=assignable_roles, default_role=default_role)
        if not username or not email or not password:
            flash('Username, email, and password are required.', 'danger')
            return render_template('admin/user_form.html', user=None, assignable_roles=assignable_roles, default_role=default_role)
        if not is_strong_password(password):
            flash(
                f'Password must be at least {ADMIN_PASSWORD_MIN_LENGTH} characters and include uppercase, lowercase, a digit, and a special character.',
                'danger',
            )
            return render_template('admin/user_form.html', user=None, assignable_roles=assignable_roles, default_role=default_role)
        if not is_valid_email(email):
            flash('Please provide a valid email address.', 'danger')
            return render_template('admin/user_form.html', user=None, assignable_roles=assignable_roles, default_role=default_role)
        existing = User.query.filter((User.username == username) | (User.email == email)).first()
        if existing:
            flash('Username or email already exists.', 'danger')
            return render_template('admin/user_form.html', user=None, assignable_roles=assignable_roles, default_role=default_role)
        user = User(username=username, email=email, role=role)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        flash(f'Admin user "{username}" created.', 'success')
        return redirect(url_for('admin.users'))
    return render_template('admin/user_form.html', user=None, assignable_roles=assignable_roles, default_role=default_role)


@admin_bp.route('/users/<int:id>/edit', methods=['GET', 'POST'])
@login_required
def user_edit(id):
    user = db.session.get(User, id)
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('admin.users'))
    assignable_roles = get_assignable_roles(current_user)
    if user.role_key not in assignable_roles:
        assignable_roles = [user.role_key] + assignable_roles
    if request.method == 'POST':
        email = clean_text(request.form.get('email', ''), 120)
        password = request.form.get('password', '')
        requested_role = normalize_user_role(request.form.get('role', user.role_key), default=user.role_key)
        if requested_role not in assignable_roles:
            flash('You do not have permission to assign that role.', 'danger')
            return render_template('admin/user_form.html', user=user, assignable_roles=assignable_roles, default_role=user.role_key)
        if user.role_key == ROLE_OWNER and requested_role != ROLE_OWNER:
            owner_count = User.query.filter_by(role=ROLE_OWNER).count()
            if owner_count <= 1:
                flash('Cannot remove the final owner role from the last owner account.', 'danger')
                return render_template('admin/user_form.html', user=user, assignable_roles=assignable_roles, default_role=user.role_key)
        if email and not is_valid_email(email):
            flash('Please provide a valid email address.', 'danger')
            return render_template('admin/user_form.html', user=user, assignable_roles=assignable_roles, default_role=user.role_key)
        if email:
            dup = User.query.filter(User.email == email, User.id != user.id).first()
            if dup:
                flash('Email already in use by another user.', 'danger')
                return render_template('admin/user_form.html', user=user, assignable_roles=assignable_roles, default_role=user.role_key)
            user.email = email
        user.role = requested_role
        if password:
            if not is_strong_password(password):
                flash(
                    f'Password must be at least {ADMIN_PASSWORD_MIN_LENGTH} characters and include uppercase, lowercase, a digit, and a special character.',
                    'danger',
                )
                return render_template('admin/user_form.html', user=user, assignable_roles=assignable_roles, default_role=user.role_key)
            user.set_password(password)
        db.session.commit()
        flash(f'User "{user.username}" updated.', 'success')
        return redirect(url_for('admin.users'))
    return render_template('admin/user_form.html', user=user, assignable_roles=assignable_roles, default_role=user.role_key)


@admin_bp.route('/users/<int:id>/delete', methods=['POST'])
@login_required
def user_delete(id):
    user = db.session.get(User, id)
    if not user:
        flash('User not found.', 'danger')
    elif user.id == current_user.id:
        flash('You cannot delete your own account.', 'danger')
    elif user.role_key == ROLE_OWNER and User.query.filter_by(role=ROLE_OWNER).count() <= 1:
        flash('Cannot delete the last owner account.', 'danger')
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
    query = ContactSubmission.query
    status_filter = request.args.get('status', '').strip()
    if status_filter and status_filter in LEAD_STATUSES:
        query = query.filter(ContactSubmission.lead_status == status_filter)
    items = query.order_by(ContactSubmission.created_at.desc()).all()
    return render_template('admin/contacts.html', items=items,
                           lead_statuses=LEAD_STATUS_LABELS,
                           lead_status_labels=LEAD_STATUS_LABELS)


@admin_bp.route('/contacts/<int:id>')
@login_required
def contact_view(id):
    item = db.get_or_404(ContactSubmission, id)
    if not item.is_read:
        item.is_read = True
        db.session.commit()
    return render_template('admin/contact_view.html', item=item,
                           lead_status_labels=LEAD_STATUS_LABELS)


@admin_bp.route('/contacts/<int:id>/delete', methods=['POST'])
@login_required
def contact_delete(id):
    db.session.delete(db.get_or_404(ContactSubmission, id))
    db.session.commit()
    flash('Contact deleted.', 'success')
    return redirect(url_for('admin.contacts'))


# Support tickets
@admin_bp.route('/support-tickets')
@login_required
def support_tickets():
    status_filter_raw = request.args.get('status', '').strip().lower()
    status_filter = normalize_support_ticket_status(status_filter_raw, default='') if status_filter_raw else ''
    stage_filter = normalize_support_ticket_stage(request.args.get('stage', ''), default='') if request.args.get('stage', '').strip() else ''
    type_filter = request.args.get('type', 'all').strip().lower()
    search_query = clean_text(request.args.get('q', ''), 120).strip()
    normalized_ticket_query = normalize_ticket_number(search_query)
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
    if stage_filter:
        if stage_filter == SUPPORT_TICKET_STAGE_PENDING:
            query = query.filter(SupportTicket.status.in_([
                SUPPORT_TICKET_STATUS_OPEN,
                SUPPORT_TICKET_STATUS_IN_PROGRESS,
                SUPPORT_TICKET_STATUS_WAITING_CUSTOMER,
            ]))
        elif stage_filter == SUPPORT_TICKET_STAGE_DONE:
            query = query.filter(SupportTicket.status == SUPPORT_TICKET_STATUS_RESOLVED)
        elif stage_filter == SUPPORT_TICKET_STAGE_CLOSED:
            query = query.filter(SupportTicket.status == SUPPORT_TICKET_STATUS_CLOSED)
    if search_query:
        safe_search = escape_like(search_query.lower())
        like_pattern = f'%{safe_search}%'
        search_filters = [
            func.lower(SupportTicket.subject).like(like_pattern),
            func.lower(SupportClient.full_name).like(like_pattern),
            func.lower(SupportClient.email).like(like_pattern),
        ]
        if normalized_ticket_query:
            safe_ticket = escape_like(normalized_ticket_query)
            search_filters.append(func.upper(SupportTicket.ticket_number).like(f'%{safe_ticket}%'))
        query = query.filter(or_(*search_filters))
    items = query.order_by(SupportTicket.updated_at.desc(), SupportTicket.created_at.desc()).all()
    return render_template(
        'admin/support_tickets.html',
        items=items,
        status_filter=status_filter,
        stage_filter=stage_filter,
        type_filter=type_filter,
        search_query=search_query,
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
    item = db.get_or_404(SupportTicket, id)
    if request.method == 'POST':
        previous_status = item.status
        previous_priority = item.priority
        previous_notes = item.internal_notes or ''
        allowed_priority = {'low', 'normal', 'high', 'critical'}
        requested_status = clean_text(request.form.get('status', item.status), 30)
        next_priority = clean_text(request.form.get('priority', item.priority), 20)
        next_status = normalize_support_ticket_status(requested_status, default=item.status)
        if next_status in SUPPORT_TICKET_STATUSES:
            item.status = next_status
        if next_priority in allowed_priority:
            item.priority = next_priority
        review_note = request.form.get('review_note', '')
        clean_review_note = clean_text(review_note, 4000)
        item.internal_notes = _append_internal_note(
            request.form.get('internal_notes', ''),
            review_note,
        )
        item.updated_at = utc_now_naive()
        if (
            previous_status != item.status
            or previous_priority != item.priority
            or previous_notes.strip() != (item.internal_notes or '').strip()
        ):
            change_summary = []
            if previous_status != item.status:
                change_summary.append(
                    f"Status: {support_ticket_status_label(previous_status)} -> {support_ticket_status_label(item.status)}"
                )
            if previous_priority != item.priority:
                change_summary.append(f"Priority: {previous_priority.title()} -> {item.priority.title()}")
            if clean_review_note:
                change_summary.append('Review note added')
            create_support_ticket_event(
                item,
                SUPPORT_TICKET_EVENT_ADMIN_UPDATE,
                '; '.join(change_summary) if change_summary else 'Ticket updated from admin view.',
                actor_type='admin',
                actor_name=current_user.username,
                actor_user_id=current_user.id,
                status_from=previous_status,
                status_to=item.status,
                metadata={
                    'priority_from': previous_priority,
                    'priority_to': item.priority,
                    'review_note_added': bool(clean_review_note),
                },
            )
        db.session.commit()
        flash('Support ticket updated.', 'success')
        return redirect(url_for('admin.support_ticket_view', id=item.id))
    ticket_events = (
        SupportTicketEvent.query
        .filter(SupportTicketEvent.ticket_id == item.id)
        .order_by(SupportTicketEvent.created_at.desc(), SupportTicketEvent.id.desc())
        .all()
    )
    return render_template(
        'admin/support_ticket_view.html',
        item=item,
        is_quote_ticket=is_quote_ticket(item),
        current_ticket_stage=support_ticket_stage_for_item(item),
        ticket_events=ticket_events,
    )


@admin_bp.route('/support-tickets/<int:id>/review', methods=['POST'])
@login_required
def support_ticket_review(id):
    item = db.get_or_404(SupportTicket, id)
    previous_status = item.status
    review_action = clean_text(request.form.get('review_action', ''), 20)
    review_note = request.form.get('review_note', '')
    clean_review_note = clean_text(review_note, 4000)
    stage_key, _ = apply_ticket_review_action(item, review_action, review_note=review_note)
    summary = f"Marked as {support_ticket_stage_label(stage_key)}."
    if clean_review_note:
        summary = f"{summary} Review note added."
    create_support_ticket_event(
        item,
        SUPPORT_TICKET_EVENT_REVIEW_ACTION,
        summary,
        actor_type='admin',
        actor_name=current_user.username,
        actor_user_id=current_user.id,
        status_from=previous_status,
        status_to=item.status,
        stage_from=support_ticket_stage_for_status(previous_status),
        stage_to=stage_key,
        metadata={
            'action': stage_key,
            'review_note_added': bool(clean_review_note),
        },
    )
    db.session.commit()
    flash(f'Ticket marked as {support_ticket_stage_label(stage_key)}.', 'success')
    return redirect(url_for('admin.support_ticket_view', id=item.id))


# Industry CRUD
@admin_bp.route('/industries')
@login_required
def industries():
    if request.args.get('trash'):
        items = Industry.query.filter(Industry.is_trashed == True).order_by(Industry.sort_order, Industry.id).all()
    else:
        items = Industry.query.filter(db.or_(Industry.is_trashed == False, Industry.is_trashed == None)).order_by(Industry.sort_order, Industry.id).all()
    return render_template('admin/industries.html', items=items)


@admin_bp.route('/industries/add', methods=['GET', 'POST'])
@login_required
def industry_add():
    workflow_options = get_workflow_status_options(current_user)
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
            return render_template('admin/industry_form.html', item=None, workflow_options=workflow_options)

        slug = slugify(title)
        if not slug:
            flash('Unable to generate a valid slug from title.', 'danger')
            return render_template('admin/industry_form.html', item=None, workflow_options=workflow_options)
        if Industry.query.filter_by(slug=slug).first():
            flash('An industry with that title already exists.', 'danger')
            return render_template('admin/industry_form.html', item=None, workflow_options=workflow_options)

        seo_title = clean_text(request.form.get('seo_title', ''), 200)
        seo_description = clean_text(request.form.get('seo_description', ''), 500)
        og_image_val = clean_text(request.form.get('og_image', ''), 500)
        item = Industry(
            title=title, slug=slug, description=description,
            icon_class=icon_class, hero_description=hero_description,
            challenges=challenges, solutions=solutions,
            stats=stats, sort_order=sort_order,
            seo_title=seo_title or None,
            seo_description=seo_description or None,
            og_image=og_image_val or None,
        )
        ok, workflow_error = apply_workflow_form_fields(
            item,
            request.form,
            current_user,
            default_status=WORKFLOW_DRAFT,
        )
        if not ok:
            flash(workflow_error, 'danger')
            return render_template('admin/industry_form.html', item=None, workflow_options=workflow_options)
        db.session.add(item)
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            flash('Unable to save industry due to duplicate data.', 'danger')
            return render_template('admin/industry_form.html', item=None, workflow_options=workflow_options)
        flash('Industry added.', 'success')
        return redirect(url_for('admin.industries'))
    return render_template('admin/industry_form.html', item=None, workflow_options=workflow_options)


@admin_bp.route('/industries/<int:id>/edit', methods=['GET', 'POST'])
@login_required
def industry_edit(id):
    item = db.get_or_404(Industry, id)
    workflow_options = get_workflow_status_options(current_user)
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
            return render_template('admin/industry_form.html', item=item, workflow_options=workflow_options)

        slug = slugify(title)
        if not slug:
            flash('Unable to generate a valid slug from title.', 'danger')
            return render_template('admin/industry_form.html', item=item, workflow_options=workflow_options)
        slug_exists = Industry.query.filter(Industry.slug == slug, Industry.id != item.id).first()
        if slug_exists:
            flash('Another industry already uses this title/slug.', 'danger')
            return render_template('admin/industry_form.html', item=item, workflow_options=workflow_options)

        seo_title = clean_text(request.form.get('seo_title', ''), 200)
        seo_description = clean_text(request.form.get('seo_description', ''), 500)
        og_image_val = clean_text(request.form.get('og_image', ''), 500)
        change_note = clean_text(request.form.get('change_note', ''), 260)
        item.title = title
        item.slug = slug
        item.description = description
        item.icon_class = icon_class
        item.hero_description = hero_description
        item.challenges = challenges
        item.solutions = solutions
        item.stats = stats
        item.sort_order = sort_order
        item.seo_title = seo_title or None
        item.seo_description = seo_description or None
        item.og_image = og_image_val or None
        ok, workflow_error = apply_workflow_form_fields(
            item,
            request.form,
            current_user,
            default_status=normalize_workflow_status(item.workflow_status, default=WORKFLOW_DRAFT),
        )
        if not ok:
            flash(workflow_error, 'danger')
            return render_template('admin/industry_form.html', item=item, workflow_options=workflow_options)
        try:
            db.session.flush()
            _create_industry_version(item, change_note, current_user)
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            flash('Unable to update industry due to duplicate data.', 'danger')
            return render_template('admin/industry_form.html', item=item, workflow_options=workflow_options)
        flash('Industry updated.', 'success')
        return redirect(url_for('admin.industries'))
    versions = IndustryVersion.query.filter_by(industry_id=item.id).order_by(IndustryVersion.version_number.desc()).limit(20).all() if item else []
    return render_template('admin/industry_form.html', item=item, workflow_options=workflow_options, versions=versions)


@admin_bp.route('/industries/<int:id>/delete', methods=['POST'])
@login_required
def industry_delete(id):
    item = db.get_or_404(Industry, id)
    if item.is_trashed:
        db.session.delete(item)
        flash('Industry permanently deleted.', 'success')
    else:
        item.is_trashed = True
        item.trashed_at = utc_now_naive()
        flash('Industry moved to trash.', 'success')
    db.session.commit()
    return redirect(url_for('admin.industries'))


# Category Edit
@admin_bp.route('/categories/<int:id>/edit', methods=['GET', 'POST'])
@login_required
def category_edit(id):
    cat = db.get_or_404(Category, id)
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


# ACP / Visual CMS + Dashboard Studio (thin-slice)
@admin_bp.route('/acp/studio')
@login_required
def acp_studio():
    page_count = AcpPageDocument.query.count()
    dashboard_count = AcpDashboardDocument.query.count()
    content_type_count = AcpContentType.query.filter_by(is_enabled=True).count()
    content_entry_count = AcpContentEntry.query.count()
    theme_token_count = AcpThemeTokenSet.query.count()
    mcp_server_count = AcpMcpServer.query.count()
    mcp_operation_count = AcpMcpOperation.query.count()
    mcp_pending_approval_count = AcpMcpOperation.query.filter_by(status=MCP_OPERATION_STATUS_PENDING_APPROVAL).count()
    mcp_queue_count = AcpMcpOperation.query.filter_by(status=MCP_OPERATION_STATUS_QUEUED).count()
    component_count = AcpComponentDefinition.query.filter_by(is_enabled=True).count()
    widget_count = AcpWidgetDefinition.query.filter_by(is_enabled=True).count()
    metric_count = AcpMetricDefinition.query.filter_by(is_enabled=True).count()
    route_binding_count = AcpPageRouteBinding.query.count()
    out_of_sync_routes = AcpPageRouteBinding.query.filter(
        AcpPageRouteBinding.is_active.is_(True),
        AcpPageRouteBinding.sync_status != 'synced',
    ).count()
    audit_count = AcpAuditEvent.query.count()
    version_count = AcpPageVersion.query.count() + AcpDashboardVersion.query.count()
    environments = AcpEnvironment.query.order_by(AcpEnvironment.id.asc()).all()
    recent_audit = AcpAuditEvent.query.order_by(AcpAuditEvent.created_at.desc()).limit(12).all()
    published_pages = AcpPageDocument.query.filter_by(status=WORKFLOW_PUBLISHED).count()
    published_dashboards = AcpDashboardDocument.query.filter_by(status=WORKFLOW_PUBLISHED).count()
    return render_template(
        'admin/acp/studio.html',
        stats={
            'pages': page_count,
            'dashboards': dashboard_count,
            'content_types': content_type_count,
            'content_entries': content_entry_count,
            'theme_tokens': theme_token_count,
            'mcp_servers': mcp_server_count,
            'mcp_operations': mcp_operation_count,
            'mcp_pending_approval': mcp_pending_approval_count,
            'mcp_queue': mcp_queue_count,
            'components': component_count,
            'widgets': widget_count,
            'metrics': metric_count,
            'route_bindings': route_binding_count,
            'out_of_sync_routes': out_of_sync_routes,
            'audit_events': audit_count,
            'versions': version_count,
            'published_pages': published_pages,
            'published_dashboards': published_dashboards,
        },
        environments=environments,
        recent_audit=recent_audit,
    )


@admin_bp.route('/acp/pages')
@login_required
def acp_pages():
    q = clean_text(request.args.get('q', ''), 120)
    query = AcpPageDocument.query
    if q:
        like = f"%{escape_like(q.lower())}%"
        query = query.filter(or_(
            func.lower(AcpPageDocument.title).like(like),
            func.lower(AcpPageDocument.slug).like(like),
            func.lower(AcpPageDocument.template_id).like(like),
        ))
    items = query.order_by(
        AcpPageDocument.updated_at.desc(),
        AcpPageDocument.id.desc(),
    ).all()
    return render_template(
        'admin/acp/pages.html',
        items=items,
        q=q,
        workflow_options=get_workflow_status_options(current_user),
    )


@admin_bp.route('/acp/sync-status')
@login_required
def acp_sync_status():
    report = run_page_route_sync(
        current_app._get_current_object(),
        auto_register=False,
        persist=False,
    )
    stored_bindings = (
        AcpPageRouteBinding.query
        .order_by(
            AcpPageRouteBinding.is_active.desc(),
            AcpPageRouteBinding.updated_at.desc(),
            AcpPageRouteBinding.route_rule.asc(),
        )
        .limit(120)
        .all()
    )
    return render_template(
        'admin/acp/sync_status.html',
        report=report,
        stored_bindings=stored_bindings,
    )


@admin_bp.route('/acp/sync-status/resync', methods=['POST'])
@login_required
def acp_sync_resync():
    action = clean_text(request.form.get('action', 'scan'), 30).lower()
    auto_register = action == 'autoregister'
    if action not in {'scan', 'autoregister'}:
        action = 'scan'
        auto_register = False
    try:
        report = run_page_route_sync(
            current_app._get_current_object(),
            auto_register=auto_register,
            persist=True,
        )
        _create_acp_audit_event(
            'pages',
            'sync',
            'acp_page_route_binding',
            'route-sync',
            {'action': action},
            {
                'totals': report.get('totals', {}),
                'auto_registered_pages': report.get('auto_registered_pages', []),
            },
        )
        db.session.commit()
    except Exception:
        db.session.rollback()
        current_app.logger.exception('ACP route sync failed.')
        flash('Route sync failed. Check logs and retry.', 'danger')
        return redirect(url_for('admin.acp_sync_status'))

    totals = report.get('totals', {})
    if auto_register:
        flash(
            (
                f"Route sync completed. Synced {totals.get('synced', 0)} route(s), "
                f"auto-registered {totals.get('auto_registered_pages', 0)} page document(s)."
            ),
            'success',
        )
    else:
        flash(
            (
                f"Route sync completed. Synced {totals.get('synced', 0)} route(s), "
                f"missing {totals.get('missing_page_document', 0)} page document(s)."
            ),
            'success',
        )
    return redirect(url_for('admin.acp_sync_status'))


@admin_bp.route('/acp/pages/new', methods=['GET', 'POST'])
@login_required
def acp_page_add():
    component_registry = _build_component_registry_payload(enabled_only=True)
    if request.method == 'POST':
        title = clean_text(request.form.get('title'), 220)
        slug = clean_text(request.form.get('slug'), 220) or slugify(title)
        template_id = clean_text(request.form.get('template_id'), 120) or 'default-page'
        locale = clean_text(request.form.get('locale'), 20) or 'en-US'
        seo_json = request.form.get('seo_json', '{}')
        blocks_tree = request.form.get('blocks_tree', '{}')
        theme_override_json = request.form.get('theme_override_json', '{}')
        change_note = clean_text(request.form.get('change_note'), 260)

        if not title or not slug:
            flash('Title and slug are required.', 'danger')
            return render_template('admin/acp/page_form.html', item=None, workflow_options=get_workflow_status_options(current_user), component_registry=component_registry)
        if AcpPageDocument.query.filter_by(slug=slug).first():
            flash('A page with this slug already exists.', 'danger')
            return render_template('admin/acp/page_form.html', item=None, workflow_options=get_workflow_status_options(current_user), component_registry=component_registry)

        seo_payload = _safe_json_loads(seo_json, None)
        blocks_payload = _safe_json_loads(blocks_tree, None)
        theme_payload = _safe_json_loads(theme_override_json, None)
        if seo_payload is None or blocks_payload is None or theme_payload is None:
            flash('Invalid JSON payload. Fix SEO, blocks tree, or theme override JSON.', 'danger')
            return render_template('admin/acp/page_form.html', item=None, workflow_options=get_workflow_status_options(current_user), component_registry=component_registry)
        blocks_ok, normalized_blocks, blocks_error = _validate_blocks_tree_against_registry(blocks_payload)
        if not blocks_ok:
            flash(blocks_error, 'danger')
            return render_template('admin/acp/page_form.html', item=None, workflow_options=get_workflow_status_options(current_user), component_registry=component_registry)

        item = AcpPageDocument(
            title=title,
            slug=slug,
            template_id=template_id,
            locale=locale,
            seo_json=_safe_json_dumps(seo_payload, {}),
            blocks_tree=_safe_json_dumps(normalized_blocks, {}),
            theme_override_json=_safe_json_dumps(theme_payload, {}),
            created_by_id=current_user.id,
            updated_by_id=current_user.id,
        )
        ok, workflow_error = _apply_acp_workflow(
            item,
            request.form.get('workflow_status'),
            request.form.get('scheduled_publish_at'),
        )
        if not ok:
            flash(workflow_error, 'danger')
            return render_template('admin/acp/page_form.html', item=None, workflow_options=get_workflow_status_options(current_user), component_registry=component_registry)

        db.session.add(item)
        db.session.flush()
        _create_page_version(item, note=change_note or 'Initial ACP page draft')
        _create_acp_audit_event('pages', 'create', 'acp_page_document', item.slug, {}, _serialize_acp_page(item))
        db.session.commit()
        flash('ACP page created.', 'success')
        return redirect(url_for('admin.acp_page_edit', id=item.id))

    return render_template(
        'admin/acp/page_form.html',
        item=None,
        workflow_options=get_workflow_status_options(current_user),
        component_registry=component_registry,
    )


@admin_bp.route('/acp/pages/<int:id>/edit', methods=['GET', 'POST'])
@login_required
def acp_page_edit(id):
    item = db.get_or_404(AcpPageDocument, id)
    component_registry = _build_component_registry_payload(enabled_only=True)
    if request.method == 'POST':
        before_state = _serialize_acp_page(item)
        title = clean_text(request.form.get('title'), 220)
        slug = clean_text(request.form.get('slug'), 220) or slugify(title)
        template_id = clean_text(request.form.get('template_id'), 120) or 'default-page'
        locale = clean_text(request.form.get('locale'), 20) or 'en-US'
        seo_json = request.form.get('seo_json', '{}')
        blocks_tree = request.form.get('blocks_tree', '{}')
        theme_override_json = request.form.get('theme_override_json', '{}')
        change_note = clean_text(request.form.get('change_note'), 260)

        if not title or not slug:
            flash('Title and slug are required.', 'danger')
            return render_template('admin/acp/page_form.html', item=item, workflow_options=get_workflow_status_options(current_user), component_registry=component_registry)
        duplicate = AcpPageDocument.query.filter(AcpPageDocument.slug == slug, AcpPageDocument.id != item.id).first()
        if duplicate:
            flash('Another page already uses this slug.', 'danger')
            return render_template('admin/acp/page_form.html', item=item, workflow_options=get_workflow_status_options(current_user), component_registry=component_registry)

        seo_payload = _safe_json_loads(seo_json, None)
        blocks_payload = _safe_json_loads(blocks_tree, None)
        theme_payload = _safe_json_loads(theme_override_json, None)
        if seo_payload is None or blocks_payload is None or theme_payload is None:
            flash('Invalid JSON payload. Fix SEO, blocks tree, or theme override JSON.', 'danger')
            return render_template('admin/acp/page_form.html', item=item, workflow_options=get_workflow_status_options(current_user), component_registry=component_registry)
        blocks_ok, normalized_blocks, blocks_error = _validate_blocks_tree_against_registry(blocks_payload)
        if not blocks_ok:
            flash(blocks_error, 'danger')
            return render_template('admin/acp/page_form.html', item=item, workflow_options=get_workflow_status_options(current_user), component_registry=component_registry)

        item.title = title
        item.slug = slug
        item.template_id = template_id
        item.locale = locale
        item.seo_json = _safe_json_dumps(seo_payload, {})
        item.blocks_tree = _safe_json_dumps(normalized_blocks, {})
        item.theme_override_json = _safe_json_dumps(theme_payload, {})
        item.updated_by_id = current_user.id

        ok, workflow_error = _apply_acp_workflow(
            item,
            request.form.get('workflow_status') or item.status,
            request.form.get('scheduled_publish_at'),
        )
        if not ok:
            flash(workflow_error, 'danger')
            return render_template('admin/acp/page_form.html', item=item, workflow_options=get_workflow_status_options(current_user), component_registry=component_registry)

        _create_page_version(item, note=change_note or 'Content updated')
        _create_acp_audit_event('pages', 'update', 'acp_page_document', item.slug, before_state, _serialize_acp_page(item))
        db.session.commit()
        flash('ACP page updated.', 'success')
        return redirect(url_for('admin.acp_page_edit', id=item.id))

    versions = AcpPageVersion.query.filter_by(page_id=item.id).order_by(AcpPageVersion.version_number.desc()).limit(12).all()
    return render_template(
        'admin/acp/page_form.html',
        item=item,
        versions=versions,
        workflow_options=get_workflow_status_options(current_user),
        component_registry=component_registry,
    )


@admin_bp.route('/acp/pages/<int:id>/snapshot', methods=['POST'])
@login_required
def acp_page_snapshot(id):
    item = db.get_or_404(AcpPageDocument, id)
    note = clean_text(request.form.get('change_note'), 260) or 'Manual snapshot'
    _create_page_version(item, note=note)
    _create_acp_audit_event('pages', 'snapshot', 'acp_page_document', item.slug, _serialize_acp_page(item), _serialize_acp_page(item))
    db.session.commit()
    flash('Page snapshot created.', 'success')
    return redirect(url_for('admin.acp_page_edit', id=item.id))


@admin_bp.route('/acp/pages/<int:id>/publish', methods=['POST'])
@login_required
def acp_page_publish(id):
    item = db.get_or_404(AcpPageDocument, id)
    before_state = _serialize_acp_page(item)
    requested_status = request.form.get('workflow_status') or WORKFLOW_PUBLISHED
    ok, workflow_error = _apply_acp_workflow(item, requested_status, request.form.get('scheduled_publish_at'))
    if not ok:
        flash(workflow_error, 'danger')
        return redirect(url_for('admin.acp_page_edit', id=item.id))
    _create_page_version(item, note=clean_text(request.form.get('change_note'), 260) or 'Publishing update')
    _create_acp_audit_event('pages', 'publish', 'acp_page_document', item.slug, before_state, _serialize_acp_page(item))
    db.session.commit()
    flash('Page workflow status updated.', 'success')
    return redirect(url_for('admin.acp_page_edit', id=item.id))


@admin_bp.route('/acp/dashboards')
@login_required
def acp_dashboards():
    q = clean_text(request.args.get('q', ''), 120)
    query = AcpDashboardDocument.query
    if q:
        like = f"%{escape_like(q.lower())}%"
        query = query.filter(or_(
            func.lower(AcpDashboardDocument.title).like(like),
            func.lower(AcpDashboardDocument.dashboard_id).like(like),
            func.lower(AcpDashboardDocument.route).like(like),
        ))
    items = query.order_by(AcpDashboardDocument.updated_at.desc(), AcpDashboardDocument.id.desc()).all()
    return render_template(
        'admin/acp/dashboards.html',
        items=items,
        q=q,
        workflow_options=get_workflow_status_options(current_user),
    )


@admin_bp.route('/acp/dashboards/new', methods=['GET', 'POST'])
@login_required
def acp_dashboard_add():
    widget_registry = _build_widget_registry_payload(enabled_only=True)
    if request.method == 'POST':
        title = clean_text(request.form.get('title'), 220)
        dashboard_id = clean_text(request.form.get('dashboard_id'), 120) or slugify(title)
        route = clean_text(request.form.get('route'), 220)
        if route and not route.startswith('/'):
            route = f'/{route}'
        layout_type = clean_text(request.form.get('layout_type'), 24) or 'grid'
        layout_config_json = request.form.get('layout_config_json', '{}')
        widgets_json = request.form.get('widgets_json', '[]')
        global_filters_json = request.form.get('global_filters_json', '[]')
        role_visibility_json = request.form.get('role_visibility_json', '{}')
        change_note = clean_text(request.form.get('change_note'), 260)

        if not title or not dashboard_id or not route:
            flash('Title, dashboard ID, and route are required.', 'danger')
            return render_template('admin/acp/dashboard_form.html', item=None, workflow_options=get_workflow_status_options(current_user), widget_registry=widget_registry, role_options=USER_ROLE_CHOICES)
        if AcpDashboardDocument.query.filter_by(dashboard_id=dashboard_id).first():
            flash('A dashboard with this ID already exists.', 'danger')
            return render_template('admin/acp/dashboard_form.html', item=None, workflow_options=get_workflow_status_options(current_user), widget_registry=widget_registry, role_options=USER_ROLE_CHOICES)
        if AcpDashboardDocument.query.filter_by(route=route).first():
            flash('A dashboard with this route already exists.', 'danger')
            return render_template('admin/acp/dashboard_form.html', item=None, workflow_options=get_workflow_status_options(current_user), widget_registry=widget_registry, role_options=USER_ROLE_CHOICES)

        layout_payload = _safe_json_loads(layout_config_json, None)
        widgets_payload = _safe_json_loads(widgets_json, None)
        filters_payload = _safe_json_loads(global_filters_json, None)
        visibility_payload = _safe_json_loads(role_visibility_json, None)
        if layout_payload is None or widgets_payload is None or filters_payload is None or visibility_payload is None:
            flash('Invalid JSON payload in dashboard configuration.', 'danger')
            return render_template('admin/acp/dashboard_form.html', item=None, workflow_options=get_workflow_status_options(current_user), widget_registry=widget_registry, role_options=USER_ROLE_CHOICES)

        item = AcpDashboardDocument(
            title=title,
            dashboard_id=dashboard_id,
            route=route,
            layout_type=layout_type,
            layout_config_json=_safe_json_dumps(layout_payload, {}),
            widgets_json=_safe_json_dumps(widgets_payload, []),
            global_filters_json=_safe_json_dumps(filters_payload, []),
            role_visibility_json=_safe_json_dumps(visibility_payload, {}),
            created_by_id=current_user.id,
            updated_by_id=current_user.id,
        )
        ok, workflow_error = _apply_acp_workflow(
            item,
            request.form.get('workflow_status'),
            request.form.get('scheduled_publish_at'),
        )
        if not ok:
            flash(workflow_error, 'danger')
            return render_template('admin/acp/dashboard_form.html', item=None, workflow_options=get_workflow_status_options(current_user), widget_registry=widget_registry, role_options=USER_ROLE_CHOICES)

        db.session.add(item)
        db.session.flush()
        _create_dashboard_version(item, note=change_note or 'Initial dashboard draft')
        _create_acp_audit_event('dashboards', 'create', 'acp_dashboard_document', item.dashboard_id, {}, _serialize_acp_dashboard(item))
        db.session.commit()
        flash('ACP dashboard created.', 'success')
        return redirect(url_for('admin.acp_dashboard_edit', id=item.id))

    return render_template(
        'admin/acp/dashboard_form.html',
        item=None,
        workflow_options=get_workflow_status_options(current_user),
        widget_registry=widget_registry,
        role_options=USER_ROLE_CHOICES,
    )


@admin_bp.route('/acp/dashboards/<int:id>/edit', methods=['GET', 'POST'])
@login_required
def acp_dashboard_edit(id):
    item = db.get_or_404(AcpDashboardDocument, id)
    widget_registry = _build_widget_registry_payload(enabled_only=True)
    if request.method == 'POST':
        before_state = _serialize_acp_dashboard(item)
        title = clean_text(request.form.get('title'), 220)
        dashboard_id = clean_text(request.form.get('dashboard_id'), 120) or slugify(title)
        route = clean_text(request.form.get('route'), 220)
        if route and not route.startswith('/'):
            route = f'/{route}'
        layout_type = clean_text(request.form.get('layout_type'), 24) or 'grid'
        layout_config_json = request.form.get('layout_config_json', '{}')
        widgets_json = request.form.get('widgets_json', '[]')
        global_filters_json = request.form.get('global_filters_json', '[]')
        role_visibility_json = request.form.get('role_visibility_json', '{}')
        change_note = clean_text(request.form.get('change_note'), 260)

        if not title or not dashboard_id or not route:
            flash('Title, dashboard ID, and route are required.', 'danger')
            return render_template('admin/acp/dashboard_form.html', item=item, workflow_options=get_workflow_status_options(current_user), widget_registry=widget_registry, role_options=USER_ROLE_CHOICES)
        duplicate_dashboard = AcpDashboardDocument.query.filter(
            AcpDashboardDocument.dashboard_id == dashboard_id,
            AcpDashboardDocument.id != item.id,
        ).first()
        if duplicate_dashboard:
            flash('Another dashboard already uses this dashboard ID.', 'danger')
            return render_template('admin/acp/dashboard_form.html', item=item, workflow_options=get_workflow_status_options(current_user), widget_registry=widget_registry, role_options=USER_ROLE_CHOICES)
        duplicate_route = AcpDashboardDocument.query.filter(
            AcpDashboardDocument.route == route,
            AcpDashboardDocument.id != item.id,
        ).first()
        if duplicate_route:
            flash('Another dashboard already uses this route.', 'danger')
            return render_template('admin/acp/dashboard_form.html', item=item, workflow_options=get_workflow_status_options(current_user), widget_registry=widget_registry, role_options=USER_ROLE_CHOICES)

        layout_payload = _safe_json_loads(layout_config_json, None)
        widgets_payload = _safe_json_loads(widgets_json, None)
        filters_payload = _safe_json_loads(global_filters_json, None)
        visibility_payload = _safe_json_loads(role_visibility_json, None)
        if layout_payload is None or widgets_payload is None or filters_payload is None or visibility_payload is None:
            flash('Invalid JSON payload in dashboard configuration.', 'danger')
            return render_template('admin/acp/dashboard_form.html', item=item, workflow_options=get_workflow_status_options(current_user), widget_registry=widget_registry, role_options=USER_ROLE_CHOICES)

        item.title = title
        item.dashboard_id = dashboard_id
        item.route = route
        item.layout_type = layout_type
        item.layout_config_json = _safe_json_dumps(layout_payload, {})
        item.widgets_json = _safe_json_dumps(widgets_payload, [])
        item.global_filters_json = _safe_json_dumps(filters_payload, [])
        item.role_visibility_json = _safe_json_dumps(visibility_payload, {})
        item.updated_by_id = current_user.id
        ok, workflow_error = _apply_acp_workflow(
            item,
            request.form.get('workflow_status') or item.status,
            request.form.get('scheduled_publish_at'),
        )
        if not ok:
            flash(workflow_error, 'danger')
            return render_template('admin/acp/dashboard_form.html', item=item, workflow_options=get_workflow_status_options(current_user), widget_registry=widget_registry, role_options=USER_ROLE_CHOICES)

        _create_dashboard_version(item, note=change_note or 'Dashboard updated')
        _create_acp_audit_event('dashboards', 'update', 'acp_dashboard_document', item.dashboard_id, before_state, _serialize_acp_dashboard(item))
        db.session.commit()
        flash('ACP dashboard updated.', 'success')
        return redirect(url_for('admin.acp_dashboard_edit', id=item.id))

    versions = AcpDashboardVersion.query.filter_by(
        dashboard_document_id=item.id
    ).order_by(AcpDashboardVersion.version_number.desc()).limit(12).all()
    return render_template(
        'admin/acp/dashboard_form.html',
        item=item,
        versions=versions,
        workflow_options=get_workflow_status_options(current_user),
        widget_registry=widget_registry,
        role_options=USER_ROLE_CHOICES,
    )


@admin_bp.route('/acp/dashboards/<int:id>/preview')
@login_required
def acp_dashboard_preview(id):
    item = db.get_or_404(AcpDashboardDocument, id)
    requested_role = normalize_user_role(
        request.args.get('role', getattr(current_user, 'role_key', ROLE_EDITOR)),
        default=getattr(current_user, 'role_key', ROLE_EDITOR),
    )
    dashboard_payload = _serialize_acp_dashboard(item)
    widgets = dashboard_payload.get('widgets', [])
    role_rules = dashboard_payload.get('role_visibility_rules', {})
    visible_widgets, applied_rule = _filter_widgets_for_role(widgets, role_rules, requested_role)
    hidden_count = max(0, len(widgets) - len(visible_widgets))
    return render_template(
        'admin/acp/dashboard_preview.html',
        item=item,
        role=requested_role,
        role_options=USER_ROLE_CHOICES,
        visible_widgets=visible_widgets,
        hidden_count=hidden_count,
        role_rule=applied_rule,
        layout_config=dashboard_payload.get('layout_config', {}),
        global_filters=dashboard_payload.get('global_filters', []),
        role_rules=role_rules,
    )


@admin_bp.route('/acp/dashboards/<int:id>/snapshot', methods=['POST'])
@login_required
def acp_dashboard_snapshot(id):
    item = db.get_or_404(AcpDashboardDocument, id)
    note = clean_text(request.form.get('change_note'), 260) or 'Manual snapshot'
    _create_dashboard_version(item, note=note)
    _create_acp_audit_event('dashboards', 'snapshot', 'acp_dashboard_document', item.dashboard_id, _serialize_acp_dashboard(item), _serialize_acp_dashboard(item))
    db.session.commit()
    flash('Dashboard snapshot created.', 'success')
    return redirect(url_for('admin.acp_dashboard_edit', id=item.id))


@admin_bp.route('/acp/dashboards/<int:id>/publish', methods=['POST'])
@login_required
def acp_dashboard_publish(id):
    item = db.get_or_404(AcpDashboardDocument, id)
    before_state = _serialize_acp_dashboard(item)
    requested_status = request.form.get('workflow_status') or WORKFLOW_PUBLISHED
    ok, workflow_error = _apply_acp_workflow(item, requested_status, request.form.get('scheduled_publish_at'))
    if not ok:
        flash(workflow_error, 'danger')
        return redirect(url_for('admin.acp_dashboard_edit', id=item.id))
    _create_dashboard_version(item, note=clean_text(request.form.get('change_note'), 260) or 'Publishing update')
    _create_acp_audit_event('dashboards', 'publish', 'acp_dashboard_document', item.dashboard_id, before_state, _serialize_acp_dashboard(item))
    db.session.commit()
    flash('Dashboard workflow status updated.', 'success')
    return redirect(url_for('admin.acp_dashboard_edit', id=item.id))


@admin_bp.route('/acp/content-types')
@login_required
def acp_content_types():
    q = clean_text(request.args.get('q', ''), 120)
    query = AcpContentType.query
    if q:
        like = f"%{escape_like(q.lower())}%"
        query = query.filter(or_(
            func.lower(AcpContentType.name).like(like),
            func.lower(AcpContentType.key).like(like),
        ))
    items = query.order_by(AcpContentType.updated_at.desc(), AcpContentType.id.desc()).all()
    return render_template('admin/acp/content_types.html', items=items, q=q)


@admin_bp.route('/acp/content-types/new', methods=['GET', 'POST'])
@login_required
def acp_content_type_add():
    if request.method == 'POST':
        name = clean_text(request.form.get('name'), 180)
        key = clean_text(request.form.get('key'), 120) or slugify(name)
        description = clean_text(request.form.get('description'), 800)
        schema_json = request.form.get('schema_json', '{}')
        change_note = clean_text(request.form.get('change_note'), 260)
        is_enabled = bool(request.form.get('is_enabled'))

        if not name or not key:
            flash('Name and key are required.', 'danger')
            return render_template('admin/acp/content_type_form.html', item=None)
        if AcpContentType.query.filter_by(key=key).first():
            flash('A content type with this key already exists.', 'danger')
            return render_template('admin/acp/content_type_form.html', item=None)
        schema_payload = _safe_json_loads(schema_json, None)
        if not isinstance(schema_payload, dict):
            flash('Schema JSON must be a valid JSON object.', 'danger')
            return render_template('admin/acp/content_type_form.html', item=None)

        item = AcpContentType(
            key=key,
            name=name,
            description=description or None,
            schema_json=_safe_json_dumps(schema_payload, {}),
            is_enabled=is_enabled,
            created_by_id=current_user.id,
            updated_by_id=current_user.id,
        )
        db.session.add(item)
        db.session.flush()
        _create_content_type_version(item, note=change_note or 'Initial content type definition')
        _create_acp_audit_event(
            'content_models',
            'create',
            'acp_content_type',
            item.key,
            {},
            _serialize_acp_content_type(item),
        )
        db.session.commit()
        flash('Content type created.', 'success')
        return redirect(url_for('admin.acp_content_type_edit', id=item.id))

    return render_template('admin/acp/content_type_form.html', item=None)


@admin_bp.route('/acp/content-types/<int:id>/edit', methods=['GET', 'POST'])
@login_required
def acp_content_type_edit(id):
    item = db.get_or_404(AcpContentType, id)
    if request.method == 'POST':
        before_state = _serialize_acp_content_type(item)
        name = clean_text(request.form.get('name'), 180)
        key = clean_text(request.form.get('key'), 120) or slugify(name)
        description = clean_text(request.form.get('description'), 800)
        schema_json = request.form.get('schema_json', '{}')
        change_note = clean_text(request.form.get('change_note'), 260)
        is_enabled = bool(request.form.get('is_enabled'))

        if not name or not key:
            flash('Name and key are required.', 'danger')
            return render_template('admin/acp/content_type_form.html', item=item)
        duplicate = AcpContentType.query.filter(
            AcpContentType.key == key,
            AcpContentType.id != item.id,
        ).first()
        if duplicate:
            flash('Another content type already uses this key.', 'danger')
            return render_template('admin/acp/content_type_form.html', item=item)
        schema_payload = _safe_json_loads(schema_json, None)
        if not isinstance(schema_payload, dict):
            flash('Schema JSON must be a valid JSON object.', 'danger')
            return render_template('admin/acp/content_type_form.html', item=item)

        item.name = name
        item.key = key
        item.description = description or None
        item.schema_json = _safe_json_dumps(schema_payload, {})
        item.is_enabled = is_enabled
        item.updated_by_id = current_user.id
        item.updated_at = utc_now_naive()
        _create_content_type_version(item, note=change_note or 'Content type updated')
        _create_acp_audit_event(
            'content_models',
            'update',
            'acp_content_type',
            item.key,
            before_state,
            _serialize_acp_content_type(item),
        )
        db.session.commit()
        flash('Content type updated.', 'success')
        return redirect(url_for('admin.acp_content_type_edit', id=item.id))

    versions = AcpContentTypeVersion.query.filter_by(
        content_type_id=item.id
    ).order_by(AcpContentTypeVersion.version_number.desc()).limit(12).all()
    return render_template('admin/acp/content_type_form.html', item=item, versions=versions)


@admin_bp.route('/acp/content-entries')
@login_required
def acp_content_entries():
    q = clean_text(request.args.get('q', ''), 120)
    content_type_id = parse_positive_int(request.args.get('content_type_id'))
    query = AcpContentEntry.query.join(AcpContentType)
    if content_type_id:
        query = query.filter(AcpContentEntry.content_type_id == content_type_id)
    if q:
        like = f"%{escape_like(q.lower())}%"
        query = query.filter(or_(
            func.lower(AcpContentEntry.title).like(like),
            func.lower(AcpContentEntry.entry_key).like(like),
            func.lower(AcpContentType.key).like(like),
            func.lower(AcpContentType.name).like(like),
        ))
    items = query.order_by(AcpContentEntry.updated_at.desc(), AcpContentEntry.id.desc()).all()
    content_types = AcpContentType.query.order_by(AcpContentType.name.asc()).all()
    return render_template(
        'admin/acp/content_entries.html',
        items=items,
        q=q,
        content_types=content_types,
        selected_content_type_id=content_type_id,
        workflow_options=get_workflow_status_options(current_user),
    )


@admin_bp.route('/acp/content-entries/new', methods=['GET', 'POST'])
@login_required
def acp_content_entry_add():
    content_types = AcpContentType.query.filter_by(is_enabled=True).order_by(AcpContentType.name.asc()).all()
    if request.method == 'POST':
        content_type_id = parse_positive_int(request.form.get('content_type_id'))
        content_type = db.session.get(AcpContentType, content_type_id) if content_type_id else None
        title = clean_text(request.form.get('title'), 220)
        entry_key = clean_text(request.form.get('entry_key'), 140) or slugify(title)
        locale = clean_text(request.form.get('locale'), 20) or 'en-US'
        data_json = request.form.get('data_json', '{}')
        change_note = clean_text(request.form.get('change_note'), 260)
        if not content_type:
            flash('Select a valid content type.', 'danger')
            return render_template(
                'admin/acp/content_entry_form.html',
                item=None,
                content_types=content_types,
                workflow_options=get_workflow_status_options(current_user),
            )
        if not title or not entry_key:
            flash('Title and entry key are required.', 'danger')
            return render_template(
                'admin/acp/content_entry_form.html',
                item=None,
                content_types=content_types,
                workflow_options=get_workflow_status_options(current_user),
            )
        duplicate = AcpContentEntry.query.filter_by(
            content_type_id=content_type.id,
            entry_key=entry_key,
            locale=locale,
        ).first()
        if duplicate:
            flash('An entry with this key and locale already exists for this content type.', 'danger')
            return render_template(
                'admin/acp/content_entry_form.html',
                item=None,
                content_types=content_types,
                workflow_options=get_workflow_status_options(current_user),
            )
        data_payload = _safe_json_loads(data_json, None)
        if data_payload is None:
            flash('Data JSON must be valid JSON.', 'danger')
            return render_template(
                'admin/acp/content_entry_form.html',
                item=None,
                content_types=content_types,
                workflow_options=get_workflow_status_options(current_user),
            )

        item = AcpContentEntry(
            content_type_id=content_type.id,
            entry_key=entry_key,
            title=title,
            locale=locale,
            data_json=_safe_json_dumps(data_payload, {}),
            created_by_id=current_user.id,
            updated_by_id=current_user.id,
        )
        ok, workflow_error = _apply_acp_workflow(
            item,
            request.form.get('workflow_status'),
            request.form.get('scheduled_publish_at'),
        )
        if not ok:
            flash(workflow_error, 'danger')
            return render_template(
                'admin/acp/content_entry_form.html',
                item=None,
                content_types=content_types,
                workflow_options=get_workflow_status_options(current_user),
            )

        db.session.add(item)
        db.session.flush()
        _create_content_entry_version(item, note=change_note or 'Initial content entry')
        _create_acp_audit_event(
            'content_entries',
            'create',
            'acp_content_entry',
            f'{content_type.key}:{item.entry_key}:{item.locale}',
            {},
            _serialize_acp_content_entry(item),
        )
        db.session.commit()
        flash('Content entry created.', 'success')
        return redirect(url_for('admin.acp_content_entry_edit', id=item.id))

    return render_template(
        'admin/acp/content_entry_form.html',
        item=None,
        content_types=content_types,
        workflow_options=get_workflow_status_options(current_user),
    )


@admin_bp.route('/acp/content-entries/<int:id>/edit', methods=['GET', 'POST'])
@login_required
def acp_content_entry_edit(id):
    item = db.get_or_404(AcpContentEntry, id)
    content_types = AcpContentType.query.filter_by(is_enabled=True).order_by(AcpContentType.name.asc()).all()
    if request.method == 'POST':
        before_state = _serialize_acp_content_entry(item)
        content_type_id = parse_positive_int(request.form.get('content_type_id'))
        content_type = db.session.get(AcpContentType, content_type_id) if content_type_id else None
        title = clean_text(request.form.get('title'), 220)
        entry_key = clean_text(request.form.get('entry_key'), 140) or slugify(title)
        locale = clean_text(request.form.get('locale'), 20) or 'en-US'
        data_json = request.form.get('data_json', '{}')
        change_note = clean_text(request.form.get('change_note'), 260)

        if not content_type:
            flash('Select a valid content type.', 'danger')
            return render_template(
                'admin/acp/content_entry_form.html',
                item=item,
                content_types=content_types,
                workflow_options=get_workflow_status_options(current_user),
            )
        if not title or not entry_key:
            flash('Title and entry key are required.', 'danger')
            return render_template(
                'admin/acp/content_entry_form.html',
                item=item,
                content_types=content_types,
                workflow_options=get_workflow_status_options(current_user),
            )
        duplicate = AcpContentEntry.query.filter(
            AcpContentEntry.content_type_id == content_type.id,
            AcpContentEntry.entry_key == entry_key,
            AcpContentEntry.locale == locale,
            AcpContentEntry.id != item.id,
        ).first()
        if duplicate:
            flash('Another entry with this key and locale already exists for this content type.', 'danger')
            return render_template(
                'admin/acp/content_entry_form.html',
                item=item,
                content_types=content_types,
                workflow_options=get_workflow_status_options(current_user),
            )
        data_payload = _safe_json_loads(data_json, None)
        if data_payload is None:
            flash('Data JSON must be valid JSON.', 'danger')
            return render_template(
                'admin/acp/content_entry_form.html',
                item=item,
                content_types=content_types,
                workflow_options=get_workflow_status_options(current_user),
            )

        item.content_type_id = content_type.id
        item.entry_key = entry_key
        item.title = title
        item.locale = locale
        item.data_json = _safe_json_dumps(data_payload, {})
        item.updated_by_id = current_user.id
        ok, workflow_error = _apply_acp_workflow(
            item,
            request.form.get('workflow_status') or item.status,
            request.form.get('scheduled_publish_at'),
        )
        if not ok:
            flash(workflow_error, 'danger')
            return render_template(
                'admin/acp/content_entry_form.html',
                item=item,
                content_types=content_types,
                workflow_options=get_workflow_status_options(current_user),
            )

        _create_content_entry_version(item, note=change_note or 'Content entry updated')
        _create_acp_audit_event(
            'content_entries',
            'update',
            'acp_content_entry',
            f'{content_type.key}:{item.entry_key}:{item.locale}',
            before_state,
            _serialize_acp_content_entry(item),
        )
        db.session.commit()
        flash('Content entry updated.', 'success')
        return redirect(url_for('admin.acp_content_entry_edit', id=item.id))

    versions = AcpContentEntryVersion.query.filter_by(
        content_entry_id=item.id
    ).order_by(AcpContentEntryVersion.version_number.desc()).limit(12).all()
    return render_template(
        'admin/acp/content_entry_form.html',
        item=item,
        versions=versions,
        content_types=content_types,
        workflow_options=get_workflow_status_options(current_user),
    )


@admin_bp.route('/acp/theme')
@login_required
def acp_theme_tokens():
    q = clean_text(request.args.get('q', ''), 120)
    query = AcpThemeTokenSet.query
    if q:
        like = f"%{escape_like(q.lower())}%"
        query = query.filter(or_(
            func.lower(AcpThemeTokenSet.name).like(like),
            func.lower(AcpThemeTokenSet.key).like(like),
        ))
    items = query.order_by(AcpThemeTokenSet.updated_at.desc(), AcpThemeTokenSet.id.desc()).all()
    return render_template(
        'admin/acp/theme_tokens.html',
        items=items,
        q=q,
        workflow_options=get_workflow_status_options(current_user),
    )


@admin_bp.route('/acp/theme/new', methods=['GET', 'POST'])
@login_required
def acp_theme_token_add():
    if request.method == 'POST':
        key = clean_text(request.form.get('key'), 80) or slugify(clean_text(request.form.get('name'), 180))
        name = clean_text(request.form.get('name'), 180)
        tokens_json = request.form.get('tokens_json', '{}')
        change_note = clean_text(request.form.get('change_note'), 260)
        if not key or not name:
            flash('Name and key are required.', 'danger')
            return render_template('admin/acp/theme_token_form.html', item=None, workflow_options=get_workflow_status_options(current_user))
        if AcpThemeTokenSet.query.filter_by(key=key).first():
            flash('A theme token set with this key already exists.', 'danger')
            return render_template('admin/acp/theme_token_form.html', item=None, workflow_options=get_workflow_status_options(current_user))
        tokens_payload = _safe_json_loads(tokens_json, None)
        if not isinstance(tokens_payload, dict):
            flash('Tokens JSON must be a valid JSON object.', 'danger')
            return render_template('admin/acp/theme_token_form.html', item=None, workflow_options=get_workflow_status_options(current_user))

        item = AcpThemeTokenSet(
            key=key,
            name=name,
            tokens_json=_safe_json_dumps(tokens_payload, {}),
            created_by_id=current_user.id,
            updated_by_id=current_user.id,
        )
        ok, workflow_error = _apply_acp_workflow(
            item,
            request.form.get('workflow_status'),
            request.form.get('scheduled_publish_at'),
        )
        if not ok:
            flash(workflow_error, 'danger')
            return render_template('admin/acp/theme_token_form.html', item=None, workflow_options=get_workflow_status_options(current_user))

        db.session.add(item)
        db.session.flush()
        _create_theme_token_version(item, note=change_note or 'Initial token set')
        _create_acp_audit_event('theme', 'create', 'acp_theme_token_set', item.key, {}, _serialize_acp_theme_token_set(item))
        db.session.commit()
        flash('Theme token set created.', 'success')
        return redirect(url_for('admin.acp_theme_token_edit', id=item.id))

    return render_template('admin/acp/theme_token_form.html', item=None, workflow_options=get_workflow_status_options(current_user))


@admin_bp.route('/acp/theme/<int:id>/edit', methods=['GET', 'POST'])
@login_required
def acp_theme_token_edit(id):
    item = db.get_or_404(AcpThemeTokenSet, id)
    if request.method == 'POST':
        before_state = _serialize_acp_theme_token_set(item)
        key = clean_text(request.form.get('key'), 80) or slugify(clean_text(request.form.get('name'), 180))
        name = clean_text(request.form.get('name'), 180)
        tokens_json = request.form.get('tokens_json', '{}')
        change_note = clean_text(request.form.get('change_note'), 260)
        if not key or not name:
            flash('Name and key are required.', 'danger')
            return render_template('admin/acp/theme_token_form.html', item=item, workflow_options=get_workflow_status_options(current_user))
        duplicate = AcpThemeTokenSet.query.filter(
            AcpThemeTokenSet.key == key,
            AcpThemeTokenSet.id != item.id,
        ).first()
        if duplicate:
            flash('Another token set already uses this key.', 'danger')
            return render_template('admin/acp/theme_token_form.html', item=item, workflow_options=get_workflow_status_options(current_user))
        tokens_payload = _safe_json_loads(tokens_json, None)
        if not isinstance(tokens_payload, dict):
            flash('Tokens JSON must be a valid JSON object.', 'danger')
            return render_template('admin/acp/theme_token_form.html', item=item, workflow_options=get_workflow_status_options(current_user))

        item.key = key
        item.name = name
        item.tokens_json = _safe_json_dumps(tokens_payload, {})
        item.updated_by_id = current_user.id
        ok, workflow_error = _apply_acp_workflow(
            item,
            request.form.get('workflow_status') or item.status,
            request.form.get('scheduled_publish_at'),
        )
        if not ok:
            flash(workflow_error, 'danger')
            return render_template('admin/acp/theme_token_form.html', item=item, workflow_options=get_workflow_status_options(current_user))

        _create_theme_token_version(item, note=change_note or 'Token set updated')
        _create_acp_audit_event('theme', 'update', 'acp_theme_token_set', item.key, before_state, _serialize_acp_theme_token_set(item))
        db.session.commit()
        flash('Theme token set updated.', 'success')
        return redirect(url_for('admin.acp_theme_token_edit', id=item.id))

    versions = AcpThemeTokenVersion.query.filter_by(
        token_set_id=item.id
    ).order_by(AcpThemeTokenVersion.version_number.desc()).limit(12).all()
    return render_template(
        'admin/acp/theme_token_form.html',
        item=item,
        versions=versions,
        workflow_options=get_workflow_status_options(current_user),
    )


@admin_bp.route('/acp/mcp/servers')
@login_required
def acp_mcp_servers():
    q = clean_text(request.args.get('q', ''), 120)
    query = AcpMcpServer.query
    if q:
        like = f"%{escape_like(q.lower())}%"
        query = query.filter(or_(
            func.lower(AcpMcpServer.name).like(like),
            func.lower(AcpMcpServer.key).like(like),
            func.lower(AcpMcpServer.server_url).like(like),
        ))
    items = query.order_by(AcpMcpServer.updated_at.desc(), AcpMcpServer.id.desc()).all()
    return render_template('admin/acp/mcp_servers.html', items=items, q=q)


@admin_bp.route('/acp/mcp/servers/new', methods=['GET', 'POST'])
@login_required
def acp_mcp_server_add():
    if request.method == 'POST':
        name = clean_text(request.form.get('name'), 180)
        key = clean_text(request.form.get('key'), 120) or slugify(name)
        server_url = clean_text(request.form.get('server_url'), 500)
        transport = clean_text(request.form.get('transport'), 40) or 'http'
        auth_mode = clean_text(request.form.get('auth_mode'), 40) or 'oauth'
        environment = clean_text(request.form.get('environment'), 40) or 'production'
        allowed_tools_json = request.form.get('allowed_tools_json', '[]')
        require_approval = clean_text(request.form.get('require_approval'), 24) or 'always'
        notes = clean_text(request.form.get('notes'), 400)
        is_enabled = bool(request.form.get('is_enabled'))

        if not name or not key or not server_url:
            flash('Name, key, and server URL are required.', 'danger')
            return render_template('admin/acp/mcp_server_form.html', item=None)
        if not is_valid_https_url(server_url):
            flash('Server URL must be a valid http(s) URL.', 'danger')
            return render_template('admin/acp/mcp_server_form.html', item=None)
        if AcpMcpServer.query.filter_by(key=key).first():
            flash('An MCP server with this key already exists.', 'danger')
            return render_template('admin/acp/mcp_server_form.html', item=None)
        allowed_tools_payload = _safe_json_loads(allowed_tools_json, None)
        if not isinstance(allowed_tools_payload, list):
            flash('Allowed tools JSON must be a valid JSON array.', 'danger')
            return render_template('admin/acp/mcp_server_form.html', item=None)
        if require_approval not in {'always', 'never', 'selective'}:
            flash('Require approval must be always, never, or selective.', 'danger')
            return render_template('admin/acp/mcp_server_form.html', item=None)

        item = AcpMcpServer(
            name=name,
            key=key,
            server_url=server_url,
            transport=transport,
            auth_mode=auth_mode,
            environment=environment,
            allowed_tools_json=_safe_json_dumps(allowed_tools_payload, []),
            require_approval=require_approval,
            notes=notes or None,
            is_enabled=is_enabled,
            created_by_id=current_user.id,
            updated_by_id=current_user.id,
        )
        db.session.add(item)
        _create_acp_audit_event('mcp', 'create', 'acp_mcp_server', item.key, {}, _serialize_acp_mcp_server(item))
        db.session.commit()
        flash('MCP server created.', 'success')
        return redirect(url_for('admin.acp_mcp_server_edit', id=item.id))

    return render_template('admin/acp/mcp_server_form.html', item=None)


@admin_bp.route('/acp/mcp/servers/<int:id>/edit', methods=['GET', 'POST'])
@login_required
def acp_mcp_server_edit(id):
    item = db.get_or_404(AcpMcpServer, id)
    if request.method == 'POST':
        before_state = _serialize_acp_mcp_server(item)
        name = clean_text(request.form.get('name'), 180)
        key = clean_text(request.form.get('key'), 120) or slugify(name)
        server_url = clean_text(request.form.get('server_url'), 500)
        transport = clean_text(request.form.get('transport'), 40) or 'http'
        auth_mode = clean_text(request.form.get('auth_mode'), 40) or 'oauth'
        environment = clean_text(request.form.get('environment'), 40) or 'production'
        allowed_tools_json = request.form.get('allowed_tools_json', '[]')
        require_approval = clean_text(request.form.get('require_approval'), 24) or 'always'
        notes = clean_text(request.form.get('notes'), 400)
        is_enabled = bool(request.form.get('is_enabled'))

        if not name or not key or not server_url:
            flash('Name, key, and server URL are required.', 'danger')
            return render_template('admin/acp/mcp_server_form.html', item=item)
        if not is_valid_https_url(server_url):
            flash('Server URL must be a valid http(s) URL.', 'danger')
            return render_template('admin/acp/mcp_server_form.html', item=item)
        duplicate = AcpMcpServer.query.filter(
            AcpMcpServer.key == key,
            AcpMcpServer.id != item.id,
        ).first()
        if duplicate:
            flash('Another MCP server already uses this key.', 'danger')
            return render_template('admin/acp/mcp_server_form.html', item=item)
        allowed_tools_payload = _safe_json_loads(allowed_tools_json, None)
        if not isinstance(allowed_tools_payload, list):
            flash('Allowed tools JSON must be a valid JSON array.', 'danger')
            return render_template('admin/acp/mcp_server_form.html', item=item)
        if require_approval not in {'always', 'never', 'selective'}:
            flash('Require approval must be always, never, or selective.', 'danger')
            return render_template('admin/acp/mcp_server_form.html', item=item)

        item.name = name
        item.key = key
        item.server_url = server_url
        item.transport = transport
        item.auth_mode = auth_mode
        item.environment = environment
        item.allowed_tools_json = _safe_json_dumps(allowed_tools_payload, [])
        item.require_approval = require_approval
        item.notes = notes or None
        item.is_enabled = is_enabled
        item.updated_by_id = current_user.id
        item.updated_at = utc_now_naive()
        _create_acp_audit_event('mcp', 'update', 'acp_mcp_server', item.key, before_state, _serialize_acp_mcp_server(item))
        db.session.commit()
        flash('MCP server updated.', 'success')
        return redirect(url_for('admin.acp_mcp_server_edit', id=item.id))

    return render_template('admin/acp/mcp_server_form.html', item=item)


@admin_bp.route('/acp/mcp/operations')
@login_required
def acp_mcp_operations():
    server_id = parse_positive_int(request.args.get('server_id'))
    status = clean_text(request.args.get('status', ''), 40).lower()
    tool_query = _normalize_mcp_tool_name(request.args.get('tool_name'))
    query = AcpMcpOperation.query
    if server_id:
        query = query.filter(AcpMcpOperation.server_id == server_id)
    if status:
        query = query.filter(AcpMcpOperation.status == status)
    if tool_query:
        like = f"%{escape_like(tool_query)}%"
        query = query.filter(func.lower(AcpMcpOperation.tool_name).like(like))
    items = query.order_by(AcpMcpOperation.created_at.desc(), AcpMcpOperation.id.desc()).limit(250).all()
    servers = AcpMcpServer.query.order_by(AcpMcpServer.name.asc()).all()
    summary = {
        'pending_approval': AcpMcpOperation.query.filter_by(status=MCP_OPERATION_STATUS_PENDING_APPROVAL).count(),
        'queued': AcpMcpOperation.query.filter_by(status=MCP_OPERATION_STATUS_QUEUED).count(),
        'running': AcpMcpOperation.query.filter_by(status=MCP_OPERATION_STATUS_RUNNING).count(),
        'failed': AcpMcpOperation.query.filter_by(status=MCP_OPERATION_STATUS_FAILED).count(),
        'succeeded_24h': AcpMcpOperation.query.filter(
            AcpMcpOperation.status == MCP_OPERATION_STATUS_SUCCEEDED,
            AcpMcpOperation.updated_at >= (utc_now_naive() - timedelta(hours=24)),
        ).count(),
    }
    return render_template(
        'admin/acp/mcp_operations.html',
        items=items,
        servers=servers,
        selected_server_id=server_id,
        status=status,
        tool_name=tool_query,
        summary=summary,
        status_options=[
            MCP_OPERATION_STATUS_PENDING_APPROVAL,
            MCP_OPERATION_STATUS_QUEUED,
            MCP_OPERATION_STATUS_RUNNING,
            MCP_OPERATION_STATUS_SUCCEEDED,
            MCP_OPERATION_STATUS_FAILED,
            MCP_OPERATION_STATUS_BLOCKED,
            MCP_OPERATION_STATUS_REJECTED,
        ],
    )


@admin_bp.route('/acp/mcp/operations/create', methods=['POST'])
@login_required
def acp_mcp_operation_create():
    server_id = parse_positive_int(request.form.get('server_id'))
    tool_name = _normalize_mcp_tool_name(request.form.get('tool_name'))
    arguments_raw = request.form.get('arguments_json', '{}')
    arguments = _safe_mcp_arguments(arguments_raw)
    max_attempts = parse_int(request.form.get('max_attempts'), default=MCP_MAX_ATTEMPTS_DEFAULT, min_value=1, max_value=MCP_MAX_ATTEMPTS_LIMIT)
    execute_now = bool(request.form.get('execute_now'))

    server = db.session.get(AcpMcpServer, server_id) if server_id else None
    if not server:
        flash('Select a valid MCP server.', 'danger')
        return redirect(url_for('admin.acp_mcp_operations'))
    if not tool_name:
        flash('Tool name is required.', 'danger')
        return redirect(url_for('admin.acp_mcp_operations', server_id=server.id))
    if arguments is None:
        flash('Arguments JSON must be a valid JSON object.', 'danger')
        return redirect(url_for('admin.acp_mcp_operations', server_id=server.id))

    allowed_tools = _mcp_allowed_tools(server)
    allowed = (not allowed_tools) or (tool_name in allowed_tools)
    requires_approval = _mcp_requires_approval(server, tool_name)
    if not allowed:
        status = MCP_OPERATION_STATUS_BLOCKED
        approval_status = MCP_APPROVAL_STATUS_NOT_REQUIRED
        error_message = 'Tool not allowed by server policy.'
    elif requires_approval:
        status = MCP_OPERATION_STATUS_PENDING_APPROVAL
        approval_status = MCP_APPROVAL_STATUS_PENDING
        error_message = 'Approval required before execution.'
    else:
        status = MCP_OPERATION_STATUS_QUEUED
        approval_status = MCP_APPROVAL_STATUS_NOT_REQUIRED
        error_message = None

    item = AcpMcpOperation(
        server_id=server.id,
        request_id=str(uuid.uuid4()),
        tool_name=tool_name,
        arguments_json=_safe_json_dumps(arguments, {}),
        status=status,
        approval_status=approval_status,
        requires_approval=requires_approval,
        attempt_count=0,
        max_attempts=max_attempts,
        error_message=error_message,
        requested_by_id=current_user.id,
        next_attempt_at=utc_now_naive() if status == MCP_OPERATION_STATUS_QUEUED else None,
    )
    db.session.add(item)
    db.session.flush()

    if not allowed:
        _create_mcp_audit_event(server, 'policy_block', tool_name, 'blocked', _serialize_acp_mcp_operation(item), {'reason': error_message})
    elif requires_approval:
        _create_mcp_audit_event(server, 'approval_requested', tool_name, 'blocked', _serialize_acp_mcp_operation(item), {'reason': 'Manual approval required'})
    else:
        _create_mcp_audit_event(server, 'queued', tool_name, 'ok', _serialize_acp_mcp_operation(item), {'queued': True})
        if execute_now:
            _execute_mcp_operation(item)

    db.session.commit()
    if item.status == MCP_OPERATION_STATUS_PENDING_APPROVAL:
        flash('MCP operation queued for approval.', 'warning')
    elif item.status == MCP_OPERATION_STATUS_BLOCKED:
        flash('MCP operation blocked by policy. Review allowed tools.', 'danger')
    elif item.status == MCP_OPERATION_STATUS_SUCCEEDED:
        flash('MCP operation executed successfully.', 'success')
    elif item.status == MCP_OPERATION_STATUS_QUEUED:
        flash('MCP operation queued.', 'success')
    else:
        flash(f'MCP operation status: {item.status}.', 'info')
    return redirect(url_for('admin.acp_mcp_operations', server_id=server.id))


@admin_bp.route('/acp/mcp/operations/process', methods=['POST'])
@login_required
def acp_mcp_process_queue():
    limit = parse_int(request.form.get('limit'), default=10, min_value=1, max_value=50)
    results = _process_due_mcp_operations(limit=limit)
    db.session.commit()
    flash(
        f"Processed {results['processed']} queued operations ({results['succeeded']} succeeded, {results['failed']} failed).",
        'info',
    )
    return redirect(url_for('admin.acp_mcp_operations'))


@admin_bp.route('/acp/mcp/operations/<int:id>/approve', methods=['POST'])
@login_required
def acp_mcp_operation_approve(id):
    item = db.get_or_404(AcpMcpOperation, id)
    if not item.requires_approval:
        flash('This operation does not require approval.', 'info')
        return redirect(url_for('admin.acp_mcp_operations'))
    item.approval_status = MCP_APPROVAL_STATUS_APPROVED
    item.approved_by_id = current_user.id
    item.approved_at = utc_now_naive()
    item.status = MCP_OPERATION_STATUS_QUEUED
    item.next_attempt_at = utc_now_naive()
    item.error_message = None
    _create_mcp_audit_event(item.server, 'approved', item.tool_name, 'ok', _serialize_acp_mcp_operation(item), {'approved': True})
    if bool(request.form.get('execute_now')):
        _execute_mcp_operation(item)
    db.session.commit()
    flash('MCP operation approved.', 'success')
    return redirect(url_for('admin.acp_mcp_operations', server_id=item.server_id))


@admin_bp.route('/acp/mcp/operations/<int:id>/reject', methods=['POST'])
@login_required
def acp_mcp_operation_reject(id):
    item = db.get_or_404(AcpMcpOperation, id)
    item.approval_status = MCP_APPROVAL_STATUS_REJECTED
    item.status = MCP_OPERATION_STATUS_REJECTED
    item.next_attempt_at = None
    item.error_message = 'Rejected by admin.'
    item.approved_by_id = current_user.id
    item.approved_at = utc_now_naive()
    _create_mcp_audit_event(item.server, 'rejected', item.tool_name, 'blocked', _serialize_acp_mcp_operation(item), {'approved': False})
    db.session.commit()
    flash('MCP operation rejected.', 'warning')
    return redirect(url_for('admin.acp_mcp_operations', server_id=item.server_id))


@admin_bp.route('/acp/mcp/operations/<int:id>/run', methods=['POST'])
@login_required
def acp_mcp_operation_run(id):
    item = db.get_or_404(AcpMcpOperation, id)
    if item.status == MCP_OPERATION_STATUS_REJECTED:
        flash('Rejected operations cannot run until retried.', 'danger')
        return redirect(url_for('admin.acp_mcp_operations', server_id=item.server_id))
    if item.requires_approval and item.approval_status != MCP_APPROVAL_STATUS_APPROVED:
        flash('Approve this operation before running.', 'danger')
        return redirect(url_for('admin.acp_mcp_operations', server_id=item.server_id))
    item.status = MCP_OPERATION_STATUS_QUEUED
    item.next_attempt_at = utc_now_naive()
    _execute_mcp_operation(item)
    db.session.commit()
    if item.status == MCP_OPERATION_STATUS_SUCCEEDED:
        flash('Operation executed successfully.', 'success')
    elif item.status == MCP_OPERATION_STATUS_QUEUED:
        flash('Operation failed and was re-queued for retry.', 'warning')
    else:
        flash(f'Operation status: {item.status}.', 'warning')
    return redirect(url_for('admin.acp_mcp_operations', server_id=item.server_id))


@admin_bp.route('/acp/mcp/operations/<int:id>/retry', methods=['POST'])
@login_required
def acp_mcp_operation_retry(id):
    item = db.get_or_404(AcpMcpOperation, id)
    if item.status == MCP_OPERATION_STATUS_REJECTED:
        item.approval_status = MCP_APPROVAL_STATUS_PENDING if item.requires_approval else MCP_APPROVAL_STATUS_NOT_REQUIRED
        item.status = MCP_OPERATION_STATUS_PENDING_APPROVAL if item.requires_approval else MCP_OPERATION_STATUS_QUEUED
    else:
        item.status = MCP_OPERATION_STATUS_QUEUED
    item.error_message = None
    item.next_attempt_at = utc_now_naive()
    if item.attempt_count >= item.max_attempts:
        item.attempt_count = 0
    _create_mcp_audit_event(item.server, 'retry', item.tool_name, 'ok', _serialize_acp_mcp_operation(item), {'retry': True})
    if bool(request.form.get('execute_now')) and item.status == MCP_OPERATION_STATUS_QUEUED:
        _execute_mcp_operation(item)
    db.session.commit()
    flash('Operation reset for retry.', 'success')
    return redirect(url_for('admin.acp_mcp_operations', server_id=item.server_id))


@admin_bp.route('/acp/mcp/audit')
@login_required
def acp_mcp_audit():
    server_id = parse_positive_int(request.args.get('server_id'))
    status = clean_text(request.args.get('status', ''), 30)
    query = AcpMcpAuditEvent.query
    if server_id:
        query = query.filter(AcpMcpAuditEvent.server_id == server_id)
    if status:
        query = query.filter(AcpMcpAuditEvent.status == status)
    items = query.order_by(AcpMcpAuditEvent.created_at.desc()).limit(200).all()
    servers = AcpMcpServer.query.order_by(AcpMcpServer.name.asc()).all()
    return render_template(
        'admin/acp/mcp_audit.html',
        items=items,
        servers=servers,
        selected_server_id=server_id,
        status=status,
    )


@admin_bp.route('/acp/registry')
@login_required
def acp_registry():
    components = AcpComponentDefinition.query.order_by(AcpComponentDefinition.category.asc(), AcpComponentDefinition.key.asc()).all()
    widgets = AcpWidgetDefinition.query.order_by(AcpWidgetDefinition.category.asc(), AcpWidgetDefinition.key.asc()).all()
    return render_template('admin/acp/registry.html', components=components, widgets=widgets)


@admin_bp.route('/acp/metrics')
@login_required
def acp_metrics():
    metrics = AcpMetricDefinition.query.order_by(AcpMetricDefinition.key.asc()).all()
    return render_template('admin/acp/metrics.html', metrics=metrics)


@admin_bp.route('/acp/audit')
@login_required
def acp_audit():
    domain = clean_text(request.args.get('domain', ''), 50)
    action = clean_text(request.args.get('action', ''), 50)
    environment = clean_text(request.args.get('environment', ''), 40)
    query = AcpAuditEvent.query
    if domain:
        query = query.filter(AcpAuditEvent.domain == domain)
    if action:
        query = query.filter(AcpAuditEvent.action == action)
    if environment:
        query = query.filter(AcpAuditEvent.environment == environment)
    items = query.order_by(AcpAuditEvent.created_at.desc()).limit(200).all()
    return render_template('admin/acp/audit.html', items=items, domain=domain, action=action, environment=environment)


@admin_bp.route('/acp/promote', methods=['POST'])
@login_required
def acp_promote():
    resource_type = clean_text(request.form.get('resource_type'), 40)
    resource_id = parse_positive_int(request.form.get('resource_id'))
    target_environment = clean_text(request.form.get('target_environment'), 40)
    source_environment = clean_text(request.form.get('source_environment'), 40) or _current_environment_name()
    version_number = parse_positive_int(request.form.get('version_number')) or 1
    notes = clean_text(request.form.get('notes'), 300)

    if resource_type not in {'page', 'dashboard'} or not resource_id or not target_environment:
        flash('Promotion payload is incomplete.', 'danger')
        return redirect(url_for('admin.acp_studio'))

    event = AcpPromotionEvent(
        source_environment=source_environment,
        target_environment=target_environment,
        resource_type=resource_type,
        resource_id=resource_id,
        version_number=version_number,
        status='completed',
        notes=notes or None,
        promoted_by_id=current_user.id,
    )
    db.session.add(event)
    _create_acp_audit_event(
        'environments',
        'promote',
        f'acp_{resource_type}_document',
        resource_id,
        {'source_environment': source_environment},
        {'target_environment': target_environment, 'version_number': version_number},
    )
    db.session.commit()
    flash('Environment promotion event recorded.', 'success')
    return redirect(url_for('admin.acp_studio'))


@admin_bp.route('/acp/api/pages/<slug>')
@login_required
def acp_admin_page_api(slug):
    item = AcpPageDocument.query.filter_by(slug=slug).first_or_404()
    return jsonify(_serialize_acp_page(item))


@admin_bp.route('/acp/api/dashboards/<dashboard_id>')
@login_required
def acp_admin_dashboard_api(dashboard_id):
    item = AcpDashboardDocument.query.filter_by(dashboard_id=dashboard_id).first_or_404()
    return jsonify(_serialize_acp_dashboard(item))


@admin_bp.route('/acp/api/content-types/<key>')
@login_required
def acp_admin_content_type_api(key):
    item = AcpContentType.query.filter_by(key=clean_text(key, 120)).first_or_404()
    return jsonify(_serialize_acp_content_type(item))


@admin_bp.route('/acp/api/content-entries/<int:id>')
@login_required
def acp_admin_content_entry_api(id):
    item = db.get_or_404(AcpContentEntry, id)
    return jsonify(_serialize_acp_content_entry(item))


@admin_bp.route('/acp/api/theme/<key>')
@login_required
def acp_admin_theme_token_api(key):
    item = AcpThemeTokenSet.query.filter_by(key=clean_text(key, 80)).first_or_404()
    return jsonify(_serialize_acp_theme_token_set(item))


@admin_bp.route('/acp/api/mcp/servers/<key>')
@login_required
def acp_admin_mcp_server_api(key):
    item = AcpMcpServer.query.filter_by(key=clean_text(key, 120)).first_or_404()
    return jsonify(_serialize_acp_mcp_server(item))


@admin_bp.route('/acp/api/mcp/operations')
@login_required
def acp_admin_mcp_operations_api():
    limit = parse_int(request.args.get('limit'), default=30, min_value=1, max_value=100)
    server_id = parse_positive_int(request.args.get('server_id'))
    status = clean_text(request.args.get('status', ''), 40).lower()
    query = AcpMcpOperation.query
    if server_id:
        query = query.filter(AcpMcpOperation.server_id == server_id)
    if status:
        query = query.filter(AcpMcpOperation.status == status)
    items = query.order_by(AcpMcpOperation.created_at.desc(), AcpMcpOperation.id.desc()).limit(limit).all()
    return jsonify({
        'items': [_serialize_acp_mcp_operation(item) for item in items],
        'count': len(items),
    })


# ---------------------------------------------------------------------------
# Version snapshot helpers
# ---------------------------------------------------------------------------

def _create_post_version(post, change_note, user):
    last = PostVersion.query.filter_by(post_id=post.id).order_by(PostVersion.version_number.desc()).first()
    next_num = (last.version_number + 1) if last else 1
    snapshot = {
        'title': post.title, 'slug': post.slug, 'excerpt': post.excerpt,
        'content': post.content, 'featured_image': post.featured_image,
        'category_id': post.category_id, 'workflow_status': post.workflow_status,
        'seo_title': post.seo_title, 'seo_description': post.seo_description, 'og_image': post.og_image,
    }
    db.session.add(PostVersion(
        post_id=post.id, version_number=next_num,
        snapshot_json=json.dumps(snapshot, ensure_ascii=False),
        change_note=change_note or None, created_by_id=user.id,
    ))


def _create_service_version(service, change_note, user):
    last = ServiceVersion.query.filter_by(service_id=service.id).order_by(ServiceVersion.version_number.desc()).first()
    next_num = (last.version_number + 1) if last else 1
    snapshot = {
        'title': service.title, 'slug': service.slug, 'description': service.description,
        'icon_class': service.icon_class, 'image': service.image, 'service_type': service.service_type,
        'is_featured': service.is_featured, 'sort_order': service.sort_order,
        'profile_json': service.profile_json, 'workflow_status': service.workflow_status,
        'seo_title': service.seo_title, 'seo_description': service.seo_description, 'og_image': service.og_image,
    }
    db.session.add(ServiceVersion(
        service_id=service.id, version_number=next_num,
        snapshot_json=json.dumps(snapshot, ensure_ascii=False),
        change_note=change_note or None, created_by_id=user.id,
    ))


def _create_industry_version(industry, change_note, user):
    last = IndustryVersion.query.filter_by(industry_id=industry.id).order_by(IndustryVersion.version_number.desc()).first()
    next_num = (last.version_number + 1) if last else 1
    snapshot = {
        'title': industry.title, 'slug': industry.slug, 'description': industry.description,
        'icon_class': industry.icon_class, 'hero_description': industry.hero_description,
        'challenges': industry.challenges, 'solutions': industry.solutions, 'stats': industry.stats,
        'sort_order': industry.sort_order, 'workflow_status': industry.workflow_status,
        'seo_title': industry.seo_title, 'seo_description': industry.seo_description, 'og_image': industry.og_image,
    }
    db.session.add(IndustryVersion(
        industry_id=industry.id, version_number=next_num,
        snapshot_json=json.dumps(snapshot, ensure_ascii=False),
        change_note=change_note or None, created_by_id=user.id,
    ))


# ---------------------------------------------------------------------------
# Version restore routes
# ---------------------------------------------------------------------------

@admin_bp.route('/posts/version/<int:id>/restore', methods=['POST'])
@login_required
def post_restore(id):
    version = db.get_or_404(PostVersion, id)
    post = db.get_or_404(Post, version.post_id)
    snapshot = json.loads(version.snapshot_json)
    for key in ('title', 'slug', 'excerpt', 'content', 'featured_image', 'category_id',
                'workflow_status', 'seo_title', 'seo_description', 'og_image'):
        if key in snapshot:
            setattr(post, key, snapshot[key])
    _create_post_version(post, f'Restored from v{version.version_number}', current_user)
    db.session.commit()
    flash(f'Post restored to version {version.version_number}.', 'success')
    return redirect(url_for('admin.post_edit', id=post.id))


@admin_bp.route('/services/version/<int:id>/restore', methods=['POST'])
@login_required
def service_restore(id):
    version = db.get_or_404(ServiceVersion, id)
    service = db.get_or_404(Service, version.service_id)
    snapshot = json.loads(version.snapshot_json)
    for key in ('title', 'slug', 'description', 'icon_class', 'image', 'service_type',
                'is_featured', 'sort_order', 'profile_json', 'workflow_status',
                'seo_title', 'seo_description', 'og_image'):
        if key in snapshot:
            setattr(service, key, snapshot[key])
    _create_service_version(service, f'Restored from v{version.version_number}', current_user)
    db.session.commit()
    flash(f'Service restored to version {version.version_number}.', 'success')
    return redirect(url_for('admin.service_edit', id=service.id))


@admin_bp.route('/industries/version/<int:id>/restore', methods=['POST'])
@login_required
def industry_restore(id):
    version = db.get_or_404(IndustryVersion, id)
    industry = db.get_or_404(Industry, version.industry_id)
    snapshot = json.loads(version.snapshot_json)
    for key in ('title', 'slug', 'description', 'icon_class', 'hero_description',
                'challenges', 'solutions', 'stats', 'sort_order', 'workflow_status',
                'seo_title', 'seo_description', 'og_image'):
        if key in snapshot:
            setattr(industry, key, snapshot[key])
    _create_industry_version(industry, f'Restored from v{version.version_number}', current_user)
    db.session.commit()
    flash(f'Industry restored to version {version.version_number}.', 'success')
    return redirect(url_for('admin.industry_edit', id=industry.id))


# ---------------------------------------------------------------------------
# Content clone / duplicate
# ---------------------------------------------------------------------------

@admin_bp.route('/posts/<int:id>/clone', methods=['POST'])
@login_required
def post_clone(id):
    original = db.get_or_404(Post, id)
    clone = Post(
        title=f'{original.title} (Copy)', slug=f'{original.slug}-copy',
        excerpt=original.excerpt, content=original.content,
        featured_image=original.featured_image, category_id=original.category_id,
        seo_title=original.seo_title, seo_description=original.seo_description,
        og_image=original.og_image, workflow_status=WORKFLOW_DRAFT,
    )
    db.session.add(clone)
    try:
        db.session.commit()
        flash('Post duplicated as draft.', 'success')
    except IntegrityError:
        db.session.rollback()
        clone.slug = f'{original.slug}-copy-{int(utc_now_naive().timestamp())}'
        db.session.add(clone)
        db.session.commit()
        flash('Post duplicated as draft.', 'success')
    return redirect(url_for('admin.post_edit', id=clone.id))


@admin_bp.route('/services/<int:id>/clone', methods=['POST'])
@login_required
def service_clone(id):
    original = db.get_or_404(Service, id)
    clone = Service(
        title=f'{original.title} (Copy)', slug=f'{original.slug}-copy',
        description=original.description, icon_class=original.icon_class,
        image=original.image, service_type=original.service_type,
        is_featured=False, sort_order=original.sort_order,
        profile_json=original.profile_json,
        seo_title=original.seo_title, seo_description=original.seo_description,
        og_image=original.og_image, workflow_status=WORKFLOW_DRAFT,
    )
    db.session.add(clone)
    try:
        db.session.commit()
        flash('Service duplicated as draft.', 'success')
    except IntegrityError:
        db.session.rollback()
        clone.slug = f'{original.slug}-copy-{int(utc_now_naive().timestamp())}'
        db.session.add(clone)
        db.session.commit()
        flash('Service duplicated as draft.', 'success')
    return redirect(url_for('admin.service_edit', id=clone.id))


@admin_bp.route('/industries/<int:id>/clone', methods=['POST'])
@login_required
def industry_clone(id):
    original = db.get_or_404(Industry, id)
    clone = Industry(
        title=f'{original.title} (Copy)', slug=f'{original.slug}-copy',
        description=original.description, icon_class=original.icon_class,
        hero_description=original.hero_description,
        challenges=original.challenges, solutions=original.solutions,
        stats=original.stats, sort_order=original.sort_order,
        seo_title=original.seo_title, seo_description=original.seo_description,
        og_image=original.og_image, workflow_status=WORKFLOW_DRAFT,
    )
    db.session.add(clone)
    try:
        db.session.commit()
        flash('Industry duplicated as draft.', 'success')
    except IntegrityError:
        db.session.rollback()
        clone.slug = f'{original.slug}-copy-{int(utc_now_naive().timestamp())}'
        db.session.add(clone)
        db.session.commit()
        flash('Industry duplicated as draft.', 'success')
    return redirect(url_for('admin.industry_edit', id=clone.id))


# ---------------------------------------------------------------------------
# Soft-delete restore routes
# ---------------------------------------------------------------------------

@admin_bp.route('/posts/<int:id>/restore', methods=['POST'])
@login_required
def post_trash_restore(id):
    item = db.get_or_404(Post, id)
    item.is_trashed = False
    item.trashed_at = None
    db.session.commit()
    flash('Post restored from trash.', 'success')
    return redirect(url_for('admin.posts'))


@admin_bp.route('/services/<int:id>/restore', methods=['POST'])
@login_required
def service_trash_restore(id):
    item = db.get_or_404(Service, id)
    item.is_trashed = False
    item.trashed_at = None
    db.session.commit()
    flash('Service restored from trash.', 'success')
    return redirect(url_for('admin.services'))


@admin_bp.route('/industries/<int:id>/restore', methods=['POST'])
@login_required
def industry_trash_restore(id):
    item = db.get_or_404(Industry, id)
    item.is_trashed = False
    item.trashed_at = None
    db.session.commit()
    flash('Industry restored from trash.', 'success')
    return redirect(url_for('admin.industries'))


@admin_bp.route('/testimonials/<int:id>/restore', methods=['POST'])
@login_required
def testimonial_trash_restore(id):
    item = db.get_or_404(Testimonial, id)
    item.is_trashed = False
    item.trashed_at = None
    db.session.commit()
    flash('Testimonial restored from trash.', 'success')
    return redirect(url_for('admin.testimonials'))


@admin_bp.route('/team/<int:id>/restore', methods=['POST'])
@login_required
def team_trash_restore(id):
    item = db.get_or_404(TeamMember, id)
    item.is_trashed = False
    item.trashed_at = None
    db.session.commit()
    flash('Team member restored from trash.', 'success')
    return redirect(url_for('admin.team'))


# ---------------------------------------------------------------------------
# Bulk operations
# ---------------------------------------------------------------------------

def _bulk_action(model, model_name):
    action = clean_text(request.form.get('action', ''), 30)
    ids_raw = clean_text(request.form.get('ids', ''), 2000)
    if not action or not ids_raw:
        flash('No action or items selected.', 'danger')
        return
    ids = [int(x) for x in ids_raw.split(',') if x.strip().isdigit()]
    if not ids:
        flash('No valid items selected.', 'danger')
        return
    items = model.query.filter(model.id.in_(ids)).all()
    count = 0
    for item in items:
        if action == 'publish':
            item.workflow_status = WORKFLOW_PUBLISHED
            item.published_at = item.published_at or utc_now_naive()
            if hasattr(item, 'is_published'):
                item.is_published = True
            count += 1
        elif action == 'draft':
            item.workflow_status = WORKFLOW_DRAFT
            count += 1
        elif action == 'trash' and hasattr(item, 'is_trashed'):
            item.is_trashed = True
            item.trashed_at = utc_now_naive()
            count += 1
        elif action == 'delete':
            db.session.delete(item)
            count += 1
    db.session.commit()
    flash(f'{count} {model_name}(s) updated.', 'success')


@admin_bp.route('/posts/bulk', methods=['POST'])
@login_required
def posts_bulk():
    _bulk_action(Post, 'post')
    return redirect(url_for('admin.posts'))


@admin_bp.route('/services/bulk', methods=['POST'])
@login_required
def services_bulk():
    _bulk_action(Service, 'service')
    return redirect(url_for('admin.services'))


@admin_bp.route('/industries/bulk', methods=['POST'])
@login_required
def industries_bulk():
    _bulk_action(Industry, 'industry')
    return redirect(url_for('admin.industries'))


@admin_bp.route('/testimonials/bulk', methods=['POST'])
@login_required
def testimonials_bulk():
    _bulk_action(Testimonial, 'testimonial')
    return redirect(url_for('admin.testimonials'))


@admin_bp.route('/team/bulk', methods=['POST'])
@login_required
def team_bulk():
    _bulk_action(TeamMember, 'team member')
    return redirect(url_for('admin.team'))


@admin_bp.route('/contacts/bulk', methods=['POST'])
@login_required
def contacts_bulk():
    action = clean_text(request.form.get('action', ''), 30)
    ids_raw = clean_text(request.form.get('ids', ''), 2000)
    ids = [int(x) for x in ids_raw.split(',') if x.strip().isdigit()] if ids_raw else []
    if not ids:
        flash('No items selected.', 'danger')
        return redirect(url_for('admin.contacts'))
    items = ContactSubmission.query.filter(ContactSubmission.id.in_(ids)).all()
    count = 0
    for item in items:
        if action == 'delete':
            db.session.delete(item)
            count += 1
        elif action == 'mark_read':
            item.is_read = True
            count += 1
    db.session.commit()
    flash(f'{count} contact(s) updated.', 'success')
    return redirect(url_for('admin.contacts'))


# ---------------------------------------------------------------------------
# Enhanced media library
# ---------------------------------------------------------------------------

@admin_bp.route('/media/api/picker')
@login_required
def media_picker_api():
    q = clean_text(request.args.get('q', ''), 120)
    mime_filter = clean_text(request.args.get('mime', ''), 60)
    query = Media.query
    if q:
        query = query.filter(or_(
            Media.filename.ilike(f'%{escape_like(q)}%'),
            Media.alt_text.ilike(f'%{escape_like(q)}%'),
        ))
    if mime_filter:
        query = query.filter(Media.mime_type.ilike(f'{escape_like(mime_filter)}%'))
    items = query.order_by(Media.created_at.desc()).limit(60).all()
    return jsonify({'items': [
        {
            'id': m.id, 'filename': m.filename,
            'url': url_for('admin.uploaded_file', filename=m.file_path),
            'mime_type': m.mime_type, 'alt_text': m.alt_text or '',
            'file_size': m.file_size, 'width': m.width, 'height': m.height,
        }
        for m in items
    ]})


@admin_bp.route('/media/<int:id>/edit', methods=['POST'])
@login_required
def media_edit(id):
    item = db.get_or_404(Media, id)
    alt_text = clean_text(request.form.get('alt_text', ''), 300)
    item.alt_text = alt_text
    db.session.commit()
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({'ok': True, 'alt_text': item.alt_text})
    flash('Alt text updated.', 'success')
    return redirect(url_for('admin.media'))


# ---------------------------------------------------------------------------
# Auto-save endpoints
# ---------------------------------------------------------------------------

@admin_bp.route('/posts/<int:id>/autosave', methods=['POST'])
@login_required
def post_autosave(id):
    item = db.get_or_404(Post, id)
    item.title = clean_text(request.form.get('title', item.title), 300)
    item.excerpt = clean_text(request.form.get('excerpt', ''), 2000)
    content_raw = request.form.get('content', '')
    if content_raw:
        item.content = content_raw[:100000]
    db.session.commit()
    return jsonify({'ok': True})


@admin_bp.route('/services/<int:id>/autosave', methods=['POST'])
@login_required
def service_autosave(id):
    item = db.get_or_404(Service, id)
    item.title = clean_text(request.form.get('title', item.title), 200)
    item.description = clean_text(request.form.get('description', ''), 10000)
    db.session.commit()
    return jsonify({'ok': True})


@admin_bp.route('/industries/<int:id>/autosave', methods=['POST'])
@login_required
def industry_autosave(id):
    item = db.get_or_404(Industry, id)
    item.title = clean_text(request.form.get('title', item.title), 200)
    item.description = clean_text(request.form.get('description', ''), 10000)
    db.session.commit()
    return jsonify({'ok': True})


# ---------------------------------------------------------------------------
# Lightweight CMS (Page / Article) routes
# ---------------------------------------------------------------------------

def _flatten_wtf_errors(errors):
    messages = []
    for field_name, field_errors in (errors or {}).items():
        label = str(field_name).replace('_', ' ').strip().title() or 'Field'
        for message in field_errors or ():
            messages.append(f'{label}: {message}')
    return messages


def _cms_slug_from_input(raw_slug, fallback_title, max_length=220):
    base = clean_text(raw_slug or fallback_title, max_length)
    return slugify(base, lowercase=True)[:max_length]


def _cms_page_payload(item=None, form=None):
    if request.method == 'POST':
        if form is not None:
            return {
                'title': clean_text(form.title.data, 200),
                'slug': clean_text(form.slug.data, 200),
                'content': form.content.data or '',
                'is_published': bool(form.is_published.data),
            }
        return {
            'title': clean_text(request.form.get('title', ''), 200),
            'slug': clean_text(request.form.get('slug', ''), 200),
            'content': request.form.get('content', ''),
            'is_published': 'is_published' in request.form,
        }
    if item is None:
        return {'title': '', 'slug': '', 'content': '', 'is_published': True}
    return {
        'title': item.title or '',
        'slug': item.slug or '',
        'content': item.content or '',
        'is_published': bool(item.is_published),
    }


def _cms_article_payload(item=None, form=None):
    if request.method == 'POST':
        if form is not None:
            return {
                'title': clean_text(form.title.data, 220),
                'slug': clean_text(form.slug.data, 220),
                'excerpt': clean_text(form.excerpt.data, 600),
                'content': form.content.data or '',
                'is_published': bool(form.is_published.data),
            }
        return {
            'title': clean_text(request.form.get('title', ''), 220),
            'slug': clean_text(request.form.get('slug', ''), 220),
            'excerpt': clean_text(request.form.get('excerpt', ''), 600),
            'content': request.form.get('content', ''),
            'is_published': 'is_published' in request.form,
        }
    if item is None:
        return {'title': '', 'slug': '', 'excerpt': '', 'content': '', 'is_published': True}
    return {
        'title': item.title or '',
        'slug': item.slug or '',
        'excerpt': item.excerpt or '',
        'content': item.content or '',
        'is_published': bool(item.is_published),
    }


def _validate_cms_page_payload(payload):
    errors = []
    if not (payload.get('title') or '').strip():
        errors.append('Title is required.')
    if not (payload.get('content') or '').strip():
        errors.append('Content is required.')
    return errors


def _validate_cms_article_payload(payload):
    errors = []
    if not (payload.get('title') or '').strip():
        errors.append('Title is required.')
    if not (payload.get('content') or '').strip():
        errors.append('Content is required.')
    return errors


def _find_duplicate_slug(model, slug, item_id=None):
    query = model.query.filter_by(slug=slug)
    if item_id:
        query = query.filter(model.id != item_id)
    return query.first()


def _flash_errors(errors):
    for message in errors:
        flash(message, 'danger')


@admin_bp.route('/pages')
@login_required
def cms_pages():
    items = CmsPage.query.order_by(CmsPage.updated_at.desc(), CmsPage.id.desc()).all()
    return render_template('admin/cms_pages.html', items=items)


@admin_bp.route('/pages/add', methods=['GET', 'POST'])
@login_required
def cms_page_add():
    form = CmsPageForm() if HAS_FLASK_WTF and CmsPageForm else None
    payload = _cms_page_payload(form=form)

    if request.method == 'POST':
        errors = []
        if form is not None and not form.validate_on_submit():
            errors.extend(_flatten_wtf_errors(form.errors))
        errors.extend(_validate_cms_page_payload(payload))

        slug = _cms_slug_from_input(payload.get('slug', ''), payload.get('title', ''), max_length=200)
        if not slug:
            errors.append('Slug could not be generated. Provide a title or slug.')
        elif _find_duplicate_slug(CmsPage, slug):
            errors.append('Slug is already in use by another page.')

        if errors:
            _flash_errors(errors)
            return render_template('admin/cms_page_form.html', item=None, payload=payload)

        item = CmsPage(
            title=payload['title'],
            slug=slug,
            content=sanitize_html(payload['content'], max_length=200000),
            author_id=current_user.id,
            is_published=payload['is_published'],
        )
        db.session.add(item)
        db.session.commit()
        flash('Page created.', 'success')
        return redirect(url_for('admin.cms_pages'))

    return render_template('admin/cms_page_form.html', item=None, payload=payload)


@admin_bp.route('/pages/<int:id>/edit', methods=['GET', 'POST'])
@login_required
def cms_page_edit(id):
    item = db.get_or_404(CmsPage, id)
    form = CmsPageForm(obj=item) if HAS_FLASK_WTF and CmsPageForm else None
    payload = _cms_page_payload(item=item, form=form)

    if request.method == 'POST':
        errors = []
        if form is not None and not form.validate_on_submit():
            errors.extend(_flatten_wtf_errors(form.errors))
        errors.extend(_validate_cms_page_payload(payload))

        slug = _cms_slug_from_input(payload.get('slug', ''), payload.get('title', ''), max_length=200)
        if not slug:
            errors.append('Slug could not be generated. Provide a title or slug.')
        elif _find_duplicate_slug(CmsPage, slug, item.id):
            errors.append('Slug is already in use by another page.')

        if errors:
            _flash_errors(errors)
            return render_template('admin/cms_page_form.html', item=item, payload=payload)

        item.title = payload['title']
        item.slug = slug
        item.content = sanitize_html(payload['content'], max_length=200000)
        item.is_published = payload['is_published']
        item.author_id = item.author_id or current_user.id
        item.updated_at = utc_now_naive()
        db.session.commit()
        flash('Page updated.', 'success')
        return redirect(url_for('admin.cms_pages'))

    return render_template('admin/cms_page_form.html', item=item, payload=payload)


@admin_bp.route('/pages/<int:id>/delete', methods=['POST'])
@login_required
def cms_page_delete(id):
    item = db.get_or_404(CmsPage, id)
    db.session.delete(item)
    db.session.commit()
    flash('Page deleted.', 'success')
    return redirect(url_for('admin.cms_pages'))


@admin_bp.route('/articles')
@login_required
def cms_articles():
    items = CmsArticle.query.order_by(CmsArticle.updated_at.desc(), CmsArticle.id.desc()).all()
    return render_template('admin/cms_articles.html', items=items)


@admin_bp.route('/articles/add', methods=['GET', 'POST'])
@login_required
def cms_article_add():
    form = CmsArticleForm() if HAS_FLASK_WTF and CmsArticleForm else None
    payload = _cms_article_payload(form=form)

    if request.method == 'POST':
        errors = []
        if form is not None and not form.validate_on_submit():
            errors.extend(_flatten_wtf_errors(form.errors))
        errors.extend(_validate_cms_article_payload(payload))

        slug = _cms_slug_from_input(payload.get('slug', ''), payload.get('title', ''), max_length=220)
        if not slug:
            errors.append('Slug could not be generated. Provide a title or slug.')
        elif _find_duplicate_slug(CmsArticle, slug):
            errors.append('Slug is already in use by another article.')

        if errors:
            _flash_errors(errors)
            return render_template('admin/cms_article_form.html', item=None, payload=payload)

        is_published = payload['is_published']
        now = utc_now_naive()
        item = CmsArticle(
            title=payload['title'],
            slug=slug,
            excerpt=payload['excerpt'] or None,
            content=sanitize_html(payload['content'], max_length=200000),
            author_id=current_user.id,
            is_published=is_published,
            published_at=now if is_published else None,
        )
        db.session.add(item)
        db.session.commit()
        flash('Article created.', 'success')
        return redirect(url_for('admin.cms_articles'))

    return render_template('admin/cms_article_form.html', item=None, payload=payload)


@admin_bp.route('/articles/<int:id>/edit', methods=['GET', 'POST'])
@login_required
def cms_article_edit(id):
    item = db.get_or_404(CmsArticle, id)
    form = CmsArticleForm(obj=item) if HAS_FLASK_WTF and CmsArticleForm else None
    payload = _cms_article_payload(item=item, form=form)

    if request.method == 'POST':
        errors = []
        if form is not None and not form.validate_on_submit():
            errors.extend(_flatten_wtf_errors(form.errors))
        errors.extend(_validate_cms_article_payload(payload))

        slug = _cms_slug_from_input(payload.get('slug', ''), payload.get('title', ''), max_length=220)
        if not slug:
            errors.append('Slug could not be generated. Provide a title or slug.')
        elif _find_duplicate_slug(CmsArticle, slug, item.id):
            errors.append('Slug is already in use by another article.')

        if errors:
            _flash_errors(errors)
            return render_template('admin/cms_article_form.html', item=item, payload=payload)

        now = utc_now_naive()
        item.title = payload['title']
        item.slug = slug
        item.excerpt = payload['excerpt'] or None
        item.content = sanitize_html(payload['content'], max_length=200000)
        item.is_published = payload['is_published']
        item.author_id = item.author_id or current_user.id
        item.published_at = (item.published_at or now) if item.is_published else None
        item.updated_at = now
        db.session.commit()
        flash('Article updated.', 'success')
        return redirect(url_for('admin.cms_articles'))

    return render_template('admin/cms_article_form.html', item=item, payload=payload)


@admin_bp.route('/articles/<int:id>/delete', methods=['POST'])
@login_required
def cms_article_delete(id):
    item = db.get_or_404(CmsArticle, id)
    db.session.delete(item)
    db.session.commit()
    flash('Article deleted.', 'success')
    return redirect(url_for('admin.cms_articles'))


# ---------------------------------------------------------------------------
# Lead management
# ---------------------------------------------------------------------------

@admin_bp.route('/contacts/<int:id>/status', methods=['POST'])
@login_required
def contact_status_update(id):
    item = db.get_or_404(ContactSubmission, id)
    new_status = clean_text(request.form.get('lead_status', ''), 30)
    if new_status in LEAD_STATUSES:
        item.lead_status = new_status
    notes = request.form.get('lead_notes', '')
    if notes is not None:
        item.lead_notes = clean_text(notes, 5000)
    db.session.commit()
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({'ok': True})
    flash('Lead status updated.', 'success')
    return redirect(url_for('admin.contact_view', id=id))


@admin_bp.route('/contacts/export')
@login_required
def contacts_export():
    import csv
    import io
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['ID', 'Name', 'Email', 'Phone', 'Subject', 'Lead Status', 'Source Page', 'UTM Source', 'UTM Medium', 'UTM Campaign', 'Date'])
    items = ContactSubmission.query.order_by(ContactSubmission.created_at.desc()).all()
    for item in items:
        writer.writerow([
            item.id, item.name, item.email, item.phone or '', item.subject or '',
            item.lead_status or 'new', item.source_page or '',
            item.utm_source or '', item.utm_medium or '', item.utm_campaign or '',
            item.created_at.strftime('%Y-%m-%d %H:%M') if item.created_at else '',
        ])
    from flask import Response
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment; filename=contacts_export.csv'},
    )


# ---------------------------------------------------------------------------
# Navigation / Menu Editor
# ---------------------------------------------------------------------------

@admin_bp.route('/menu', methods=['GET', 'POST'])
@login_required
def menu_editor():
    if request.method == 'POST':
        location = clean_text(request.form.get('menu_location', 'header'), 30)
        label = clean_text(request.form.get('label', ''), 200)
        link_type = clean_text(request.form.get('link_type', 'custom_url'), 30)
        target_slug = clean_text(request.form.get('target_slug', ''), 200)
        custom_url = clean_text(request.form.get('custom_url', ''), 500)
        icon_class = clean_text(request.form.get('icon_class', ''), 100)
        sort_order = parse_int(request.form.get('sort_order', 0), default=0, min_value=-10000, max_value=10000)
        parent_id_raw = request.form.get('parent_id', '')
        parent_id = parse_positive_int(parent_id_raw) if parent_id_raw else None

        if not label:
            flash('Label is required.', 'danger')
        else:
            item = MenuItem(
                menu_location=location, label=label, link_type=link_type,
                target_slug=target_slug or None, custom_url=custom_url or None,
                icon_class=icon_class or None, sort_order=sort_order,
                parent_id=parent_id, is_visible=True,
            )
            db.session.add(item)
            db.session.commit()
            flash('Menu item added.', 'success')
        return redirect(url_for('admin.menu_editor'))

    location = request.args.get('location', 'header')
    items = MenuItem.query.filter_by(menu_location=location, parent_id=None).order_by(MenuItem.sort_order).all()
    all_items = MenuItem.query.filter_by(menu_location=location).order_by(MenuItem.sort_order).all()
    return render_template('admin/menu_editor.html', items=items, all_items=all_items, location=location)


@admin_bp.route('/menu/<int:id>/edit', methods=['POST'])
@login_required
def menu_item_edit(id):
    item = db.get_or_404(MenuItem, id)
    item.label = clean_text(request.form.get('label', item.label), 200)
    item.link_type = clean_text(request.form.get('link_type', item.link_type), 30)
    item.target_slug = clean_text(request.form.get('target_slug', ''), 200) or None
    item.custom_url = clean_text(request.form.get('custom_url', ''), 500) or None
    item.icon_class = clean_text(request.form.get('icon_class', ''), 100) or None
    item.sort_order = parse_int(request.form.get('sort_order', 0), default=0, min_value=-10000, max_value=10000)
    item.is_visible = 'is_visible' in request.form
    db.session.commit()
    flash('Menu item updated.', 'success')
    return redirect(url_for('admin.menu_editor', location=item.menu_location))


@admin_bp.route('/menu/<int:id>/delete', methods=['POST'])
@login_required
def menu_item_delete(id):
    item = db.get_or_404(MenuItem, id)
    location = item.menu_location
    db.session.delete(item)
    db.session.commit()
    flash('Menu item deleted.', 'success')
    return redirect(url_for('admin.menu_editor', location=location))


@admin_bp.route('/menu/reorder', methods=['POST'])
@login_required
def menu_reorder():
    order_data = request.form.get('order', '')
    if order_data:
        try:
            items_order = json.loads(order_data)
            for entry in items_order:
                item = db.session.get(MenuItem, entry.get('id'))
                if item:
                    item.sort_order = entry.get('sort_order', 0)
            db.session.commit()
        except (json.JSONDecodeError, TypeError):
            pass
    return jsonify({'ok': True})


# ---------------------------------------------------------------------------
# Global search / Command palette
# ---------------------------------------------------------------------------

@admin_bp.route('/api/search')
@login_required
def admin_search_api():
    q = clean_text(request.args.get('q', ''), 120).strip()
    if not q or len(q) < 2:
        return jsonify({'results': []})

    results = []
    like_q = f'%{escape_like(q)}%'

    for post in Post.query.filter(Post.title.ilike(like_q)).limit(5).all():
        results.append({'type': 'post', 'title': post.title, 'url': url_for('admin.post_edit', id=post.id), 'status': post.workflow_status})

    for cms_page in CmsPage.query.filter(CmsPage.title.ilike(like_q)).limit(5).all():
        results.append({'type': 'cms_page', 'title': cms_page.title, 'url': url_for('admin.cms_page_edit', id=cms_page.id), 'status': ('published' if cms_page.is_published else 'draft')})

    for cms_article in CmsArticle.query.filter(CmsArticle.title.ilike(like_q)).limit(5).all():
        results.append({'type': 'cms_article', 'title': cms_article.title, 'url': url_for('admin.cms_article_edit', id=cms_article.id), 'status': ('published' if cms_article.is_published else 'draft')})

    for service in Service.query.filter(Service.title.ilike(like_q)).limit(5).all():
        results.append({'type': 'service', 'title': service.title, 'url': url_for('admin.service_edit', id=service.id), 'status': service.workflow_status})

    for industry in Industry.query.filter(Industry.title.ilike(like_q)).limit(5).all():
        results.append({'type': 'industry', 'title': industry.title, 'url': url_for('admin.industry_edit', id=industry.id), 'status': industry.workflow_status})

    for contact in ContactSubmission.query.filter(or_(
        ContactSubmission.name.ilike(like_q),
        ContactSubmission.email.ilike(like_q),
    )).limit(5).all():
        results.append({'type': 'contact', 'title': f'{contact.name} ({contact.email})', 'url': url_for('admin.contact_view', id=contact.id)})

    for ticket in SupportTicket.query.filter(or_(
        SupportTicket.ticket_number.ilike(like_q),
        SupportTicket.subject.ilike(like_q),
    )).limit(5).all():
        results.append({'type': 'ticket', 'title': f'{ticket.ticket_number}: {ticket.subject}', 'url': url_for('admin.support_ticket_view', id=ticket.id)})

    return jsonify({'results': results})


# ---------------------------------------------------------------------------
# Page view analytics
# ---------------------------------------------------------------------------

@admin_bp.route('/analytics/api/top-pages')
@login_required
def analytics_top_pages_api():
    days = parse_int(request.args.get('days', 7), default=7, min_value=1, max_value=90)
    since = utc_now_naive() - __import__('datetime').timedelta(days=days)
    rows = db.session.query(
        PageView.path,
        func.count(PageView.id).label('views'),
    ).filter(PageView.created_at >= since).group_by(PageView.path).order_by(func.count(PageView.id).desc()).limit(20).all()
    return jsonify({'items': [{'path': r.path, 'views': r.views} for r in rows], 'days': days})
