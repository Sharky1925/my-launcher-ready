from datetime import datetime, timedelta
import json
import os
import re
import uuid
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
        Media,
        ContactSubmission,
        SiteSetting,
        SupportClient,
        SupportTicket,
        AuthRateLimitBucket,
        SecurityEvent,
        Industry,
        ContentBlock,
        AcpPageDocument,
        AcpPageVersion,
        AcpDashboardDocument,
        AcpDashboardVersion,
        AcpComponentDefinition,
        AcpWidgetDefinition,
        AcpMetricDefinition,
        AcpEnvironment,
        AcpPromotionEvent,
        AcpAuditEvent,
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
        normalize_support_ticket_status,
        normalize_support_ticket_stage,
        support_ticket_stage_for_status,
        normalize_workflow_status,
        normalize_user_role,
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
        AcpPageDocument,
        AcpPageVersion,
        AcpDashboardDocument,
        AcpDashboardVersion,
        AcpComponentDefinition,
        AcpWidgetDefinition,
        AcpMetricDefinition,
        AcpEnvironment,
        AcpPromotionEvent,
        AcpAuditEvent,
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
        normalize_support_ticket_status,
        normalize_support_ticket_stage,
        support_ticket_stage_for_status,
        normalize_workflow_status,
        normalize_user_role,
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
ADMIN_PERMISSION_MAP = {
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
    'admin.acp_dashboards': 'acp:dashboards:manage',
    'admin.acp_dashboard_add': 'acp:dashboards:manage',
    'admin.acp_dashboard_edit': 'acp:dashboards:manage',
    'admin.acp_dashboard_preview': 'acp:studio:view',
    'admin.acp_dashboard_snapshot': 'acp:dashboards:manage',
    'admin.acp_dashboard_publish': 'acp:publish',
    'admin.acp_registry': 'acp:registry:manage',
    'admin.acp_metrics': 'acp:metrics:manage',
    'admin.acp_audit': 'acp:audit:view',
    'admin.acp_promote': 'acp:environments:manage',
    'admin.acp_admin_page_api': 'acp:studio:view',
    'admin.acp_admin_dashboard_api': 'acp:studio:view',
    'admin.contacts': 'support:manage',
    'admin.contact_view': 'support:manage',
    'admin.contact_delete': 'support:manage',
    'admin.support_tickets': 'support:manage',
    'admin.support_ticket_view': 'support:manage',
    'admin.support_ticket_review': 'support:manage',
    'admin.security_events': 'security:view',
    'admin.settings': 'settings:manage',
    'admin.users': 'users:manage',
    'admin.user_add': 'users:manage',
    'admin.user_edit': 'users:manage',
    'admin.user_delete': 'users:manage',
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
    return redirect(url_for('admin.login'))


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
        is_quote_ticket=is_quote_ticket,
        workflow_status_label=workflow_status_label,
        workflow_status_badge=workflow_status_badge,
    )


# Services CRUD
@admin_bp.route('/services')
@login_required
def services():
    items = Service.query.order_by(Service.sort_order, Service.id).all()
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
    item = Service.query.get_or_404(id)
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

        item.title = title
        item.slug = slug
        item.description = description
        item.icon_class = icon_class
        item.service_type = service_type
        item.is_featured = 'is_featured' in request.form
        item.sort_order = sort_order
        item.profile_json = profile_json_raw or None
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
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            flash('Unable to update service due to duplicate data.', 'danger')
            return render_template('admin/service_form.html', item=item, workflow_options=workflow_options)
        flash('Service updated.', 'success')
        return redirect(url_for('admin.services'))
    return render_template('admin/service_form.html', item=item, workflow_options=workflow_options)


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
    items = Post.query.order_by(Post.updated_at.desc(), Post.created_at.desc()).all()
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
        item = Post(
            title=title,
            slug=slug,
            excerpt=excerpt,
            content=content,
            featured_image=image,
            category_id=category_id,
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
    item = Post.query.get_or_404(id)
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

        item.title = title
        item.slug = slug
        item.excerpt = excerpt
        item.content = content
        item.category_id = category_id
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
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            flash('Unable to update post due to duplicate data.', 'danger')
            cats = Category.query.all()
            return render_template('admin/post_form.html', item=item, categories=cats, workflow_options=workflow_options)
        flash('Post updated.', 'success')
        return redirect(url_for('admin.posts'))
    cats = Category.query.all()
    return render_template('admin/post_form.html', item=item, categories=cats, workflow_options=workflow_options)


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
    status_filter_raw = request.args.get('status', '').strip().lower()
    status_filter = normalize_support_ticket_status(status_filter_raw, default='') if status_filter_raw else ''
    stage_filter = normalize_support_ticket_stage(request.args.get('stage', ''), default='') if request.args.get('stage', '').strip() else ''
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
    items = query.order_by(SupportTicket.updated_at.desc(), SupportTicket.created_at.desc()).all()
    return render_template(
        'admin/support_tickets.html',
        items=items,
        status_filter=status_filter,
        stage_filter=stage_filter,
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
        allowed_priority = {'low', 'normal', 'high', 'critical'}
        requested_status = clean_text(request.form.get('status', item.status), 30)
        next_priority = clean_text(request.form.get('priority', item.priority), 20)
        next_status = normalize_support_ticket_status(requested_status, default=item.status)
        if next_status in SUPPORT_TICKET_STATUSES:
            item.status = next_status
        if next_priority in allowed_priority:
            item.priority = next_priority
        review_note = request.form.get('review_note', '')
        item.internal_notes = _append_internal_note(
            request.form.get('internal_notes', ''),
            review_note,
        )
        item.updated_at = utc_now_naive()
        db.session.commit()
        flash('Support ticket updated.', 'success')
        return redirect(url_for('admin.support_ticket_view', id=item.id))
    return render_template(
        'admin/support_ticket_view.html',
        item=item,
        is_quote_ticket=is_quote_ticket(item),
        current_ticket_stage=support_ticket_stage_for_item(item),
    )


@admin_bp.route('/support-tickets/<int:id>/review', methods=['POST'])
@login_required
def support_ticket_review(id):
    item = SupportTicket.query.get_or_404(id)
    review_action = clean_text(request.form.get('review_action', ''), 20)
    review_note = request.form.get('review_note', '')
    stage_key, _ = apply_ticket_review_action(item, review_action, review_note=review_note)
    db.session.commit()
    flash(f'Ticket marked as {support_ticket_stage_label(stage_key)}.', 'success')
    return redirect(url_for('admin.support_ticket_view', id=item.id))


# Industry CRUD
@admin_bp.route('/industries')
@login_required
def industries():
    items = Industry.query.order_by(Industry.sort_order, Industry.id).all()
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

        item = Industry(
            title=title, slug=slug, description=description,
            icon_class=icon_class, hero_description=hero_description,
            challenges=challenges, solutions=solutions,
            stats=stats, sort_order=sort_order,
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
    item = Industry.query.get_or_404(id)
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

        item.title = title
        item.slug = slug
        item.description = description
        item.icon_class = icon_class
        item.hero_description = hero_description
        item.challenges = challenges
        item.solutions = solutions
        item.stats = stats
        item.sort_order = sort_order
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
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            flash('Unable to update industry due to duplicate data.', 'danger')
            return render_template('admin/industry_form.html', item=item, workflow_options=workflow_options)
        flash('Industry updated.', 'success')
        return redirect(url_for('admin.industries'))
    return render_template('admin/industry_form.html', item=item, workflow_options=workflow_options)


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


# ACP / Visual CMS + Dashboard Studio (thin-slice)
@admin_bp.route('/acp/studio')
@login_required
def acp_studio():
    page_count = AcpPageDocument.query.count()
    dashboard_count = AcpDashboardDocument.query.count()
    component_count = AcpComponentDefinition.query.filter_by(is_enabled=True).count()
    widget_count = AcpWidgetDefinition.query.filter_by(is_enabled=True).count()
    metric_count = AcpMetricDefinition.query.filter_by(is_enabled=True).count()
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
            'components': component_count,
            'widgets': widget_count,
            'metrics': metric_count,
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
    item = AcpPageDocument.query.get_or_404(id)
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
    item = AcpPageDocument.query.get_or_404(id)
    note = clean_text(request.form.get('change_note'), 260) or 'Manual snapshot'
    _create_page_version(item, note=note)
    _create_acp_audit_event('pages', 'snapshot', 'acp_page_document', item.slug, _serialize_acp_page(item), _serialize_acp_page(item))
    db.session.commit()
    flash('Page snapshot created.', 'success')
    return redirect(url_for('admin.acp_page_edit', id=item.id))


@admin_bp.route('/acp/pages/<int:id>/publish', methods=['POST'])
@login_required
def acp_page_publish(id):
    item = AcpPageDocument.query.get_or_404(id)
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
    item = AcpDashboardDocument.query.get_or_404(id)
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
    item = AcpDashboardDocument.query.get_or_404(id)
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
    item = AcpDashboardDocument.query.get_or_404(id)
    note = clean_text(request.form.get('change_note'), 260) or 'Manual snapshot'
    _create_dashboard_version(item, note=note)
    _create_acp_audit_event('dashboards', 'snapshot', 'acp_dashboard_document', item.dashboard_id, _serialize_acp_dashboard(item), _serialize_acp_dashboard(item))
    db.session.commit()
    flash('Dashboard snapshot created.', 'success')
    return redirect(url_for('admin.acp_dashboard_edit', id=item.id))


@admin_bp.route('/acp/dashboards/<int:id>/publish', methods=['POST'])
@login_required
def acp_dashboard_publish(id):
    item = AcpDashboardDocument.query.get_or_404(id)
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
