import base64
import smtplib
import urllib.error
import urllib.parse
import urllib.request
from email.message import EmailMessage

from flask import current_app, has_request_context, request


def _safe_header_value(value, max_length=240):
    # Prevent header injection by stripping CR/LF and collapsing whitespace.
    cleaned = ' '.join((value or '').replace('\r', ' ').replace('\n', ' ').split())
    return cleaned[:max_length]


def _split_recipients(raw):
    recipients = []
    seen = set()
    for item in (raw or '').split(','):
        cleaned = _safe_header_value(item, max_length=320)
        normalized = cleaned.lower()
        if cleaned and normalized not in seen:
            recipients.append(cleaned)
            seen.add(normalized)
    return recipients


def _ticket_admin_url(ticket_id):
    base = _resolve_base_url()
    if not base:
        return f"/admin/support-tickets/{ticket_id}"
    return f"{base}/admin/support-tickets/{ticket_id}"


def _ticket_status_url(ticket_number):
    base = _resolve_base_url()
    query = urllib.parse.urlencode({'ticket_number': ticket_number})
    if not base:
        return f"/ticket-search?{query}"
    return f"{base}/ticket-search?{query}"


def _ticket_verify_url(ticket_number, token):
    base = _resolve_base_url()
    query = urllib.parse.urlencode({'ticket_number': ticket_number, 'token': token})
    if not base:
        return f"/ticket-search?{query}"
    return f"{base}/ticket-search?{query}"


def _ticket_kind_label(ticket_kind):
    normalized = (ticket_kind or '').strip().lower()
    if normalized == 'quote':
        return 'Quote'
    if normalized == 'contact':
        return 'Contact'
    return 'Support'


def _filter_recipients(recipients, exclude_emails=None):
    if not recipients:
        return []
    excludes = set()
    for item in (exclude_emails or []):
        cleaned = _safe_header_value(item, max_length=320).lower()
        if cleaned:
            excludes.add(cleaned)
    if not excludes:
        return list(recipients)
    return [recipient for recipient in recipients if recipient.lower() not in excludes]


def _resolve_base_url():
    configured = (current_app.config.get('APP_BASE_URL') or '').rstrip('/')
    if configured:
        return configured
    if has_request_context():
        try:
            return (request.host_url or '').rstrip('/')
        except RuntimeError:
            return ''
    return ''


def _send_via_mailgun(subject, body, recipients, mail_from):
    """Send email via Mailgun HTTP API (no SMTP needed)."""
    api_key = (current_app.config.get('MAILGUN_API_KEY') or '').strip()
    domain = (current_app.config.get('MAILGUN_DOMAIN') or '').strip()
    if not api_key or not domain:
        return None  # Not configured, fall through to SMTP

    url = f"https://api.mailgun.net/v3/{domain}/messages"
    data = urllib.parse.urlencode({
        'from': mail_from,
        'to': ', '.join(recipients),
        'subject': subject,
        'text': body,
    }).encode('utf-8')

    auth = base64.b64encode(f"api:{api_key}".encode()).decode()

    req = urllib.request.Request(url, data=data, method='POST')
    req.add_header('Authorization', f'Basic {auth}')

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:  # nosec B310
            current_app.logger.info('Mailgun email sent successfully.')
            return True
    except urllib.error.HTTPError as e:
        error_body = e.read().decode('utf-8', errors='replace')
        current_app.logger.error(f'Mailgun API error {e.code}: {error_body}')
        return False
    except Exception:
        current_app.logger.exception('Mailgun email delivery failed.')
        return False


def _send_via_smtp(subject, body, recipients, mail_from):
    """Send email via SMTP (traditional method)."""
    host = (current_app.config.get('SMTP_HOST') or '').strip()
    if not host:
        current_app.logger.info('SMTP_HOST is not configured; skipping SMTP.')
        return None  # Not configured

    port = int(current_app.config.get('SMTP_PORT') or 587)
    username = current_app.config.get('SMTP_USERNAME') or ''
    password = current_app.config.get('SMTP_PASSWORD') or ''
    use_ssl = bool(current_app.config.get('SMTP_USE_SSL'))
    use_tls = bool(current_app.config.get('SMTP_USE_TLS'))

    message = EmailMessage()
    message['Subject'] = subject
    message['From'] = mail_from
    message['To'] = ', '.join(recipients)
    message.set_content(body)

    try:
        if use_ssl:
            smtp = smtplib.SMTP_SSL(host=host, port=port, timeout=12)
        else:
            smtp = smtplib.SMTP(host=host, port=port, timeout=12)

        with smtp:
            if use_tls and not use_ssl:
                smtp.starttls()
            if username and password:
                smtp.login(username, password)
            smtp.send_message(message)
        return True
    except Exception:
        current_app.logger.exception('SMTP email delivery failed.')
        return False


def _send_email(subject, body, recipients):
    if not recipients:
        return False

    mail_from = _safe_header_value(current_app.config.get('MAIL_FROM') or 'no-reply@localhost', max_length=254)
    safe_subject = _safe_header_value(subject, max_length=240)

    # Try Mailgun first (works on Railway), fall back to SMTP
    result = _send_via_mailgun(safe_subject, body, recipients, mail_from)
    if result is not None:
        return result

    result = _send_via_smtp(safe_subject, body, recipients, mail_from)
    if result is not None:
        return result

    current_app.logger.info('No email provider configured (set MAILGUN_API_KEY+MAILGUN_DOMAIN or SMTP_HOST).')
    return False


def send_contact_notification(submission, exclude_emails=None):
    recipients = _split_recipients(current_app.config.get('CONTACT_NOTIFICATION_EMAILS'))
    recipients = _filter_recipients(recipients, exclude_emails=exclude_emails)
    if not recipients:
        return False

    subject_text = _safe_header_value(submission.subject or 'Website Contact', max_length=180) or 'Website Contact'
    subject = f"[Website] New contact submission: {subject_text}"
    body = "\n".join([
        "A new contact form submission has been received.",
        "",
        f"Name: {submission.name}",
        f"Email: {submission.email}",
        f"Phone: {submission.phone or 'Not provided'}",
        f"Subject: {subject_text}",
        "",
        "Message:",
        submission.message or "",
    ])
    return _send_email(subject, body, recipients)


def send_ticket_notification(ticket, ticket_kind='support', exclude_emails=None):
    recipients = _split_recipients(current_app.config.get('TICKET_NOTIFICATION_EMAILS'))
    recipients = _filter_recipients(recipients, exclude_emails=exclude_emails)
    if not recipients:
        return False

    client = getattr(ticket, 'client', None)
    kind = _ticket_kind_label(ticket_kind)
    subject = f"[Website] New {kind} ticket: {ticket.ticket_number}"
    body = "\n".join([
        f"A new {kind.lower()} ticket has been created.",
        "",
        f"Ticket: {ticket.ticket_number}",
        f"Subject: {ticket.subject}",
        f"Priority: {ticket.priority}",
        f"Status: {ticket.status}",
        f"Client: {getattr(client, 'full_name', 'Unknown')}",
        f"Client Email: {getattr(client, 'email', 'Unknown')}",
        f"Service Slug: {ticket.service_slug or 'Not provided'}",
        "",
        "Details:",
        ticket.details or "",
        "",
        f"Admin URL: {_ticket_admin_url(ticket.id)}",
    ])
    return _send_email(subject, body, recipients)


def send_ticket_verification_email(ticket, recipient_email, token, ticket_kind='support'):
    safe_email = _safe_header_value(recipient_email, max_length=320)
    if not safe_email or not token:
        return False

    kind = _ticket_kind_label(ticket_kind)
    verify_url = _ticket_verify_url(ticket.ticket_number, token)
    status_url = _ticket_status_url(ticket.ticket_number)
    subject = f"[Right On Repair] Verify ticket access: {ticket.ticket_number}"
    body = "\n".join([
        f"Your {kind.lower()} request has been received.",
        "",
        f"Ticket Number: {ticket.ticket_number}",
        f"Subject: {ticket.subject}",
        "",
        "Use this secure link to check ticket status:",
        verify_url,
        "",
        "This link verifies your email automatically and opens the latest status page.",
        f"Direct status page: {status_url}",
        "If you did not submit this request, ignore this email.",
    ])
    return _send_email(subject, body, [safe_email])
