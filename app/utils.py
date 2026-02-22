"""Shared utility functions used across route modules."""
import ipaddress
import json
import re
from datetime import datetime, timezone

from flask import request

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def utc_now_naive():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def clean_text(value, max_length=255):
    return (value or '').strip()[:max_length]


def escape_like(value):
    """Escape SQL LIKE wildcard characters."""
    return value.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_')


def is_valid_email(value):
    return bool(EMAIL_RE.match(value or ''))


def normalized_ip(value):
    candidate = (value or '').split(',', 1)[0].strip()
    if not candidate:
        return ''
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return ''


def get_request_ip():
    # request.remote_addr is proxy-aware when ProxyFix is enabled by app config.
    remote_ip = normalized_ip(request.remote_addr)
    return remote_ip or 'unknown'


def get_page_content(page):
    """Load all ContentBlock entries for a page, return dict of section -> parsed JSON."""
    try:
        from .models import ContentBlock
    except ImportError:  # pragma: no cover - fallback when running from app/ cwd
        from models import ContentBlock
    blocks = ContentBlock.query.filter_by(page=page).all()
    result = {}
    for block in blocks:
        try:
            result[block.section] = json.loads(block.content)
        except (json.JSONDecodeError, TypeError):
            result[block.section] = {}
    return result
