import base64
import smtplib
import urllib.error
import urllib.parse
import urllib.request
from email.message import EmailMessage

from flask import current_app


def _split_recipients(raw):
    return [item.strip() for item in (raw or '').split(',') if item.strip()]


def _ticket_admin_url(ticket_id):
    base = (current_app.config.get('APP_BASE_URL') or '').rstrip('/')
    if not base:
        return f"/admin/support-tickets/{ticket_id}"
    return f"{base}/admin/support-tickets/{ticket_id}"


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
        with urllib.request.urlopen(req, timeout=15) as resp:
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

    mail_from = current_app.config.get('MAIL_FROM') or 'no-reply@localhost'

    # Try Mailgun first (works on Railway), fall back to SMTP
    result = _send_via_mailgun(subject, body, recipients, mail_from)
    if result is not None:
        return result

    result = _send_via_smtp(subject, body, recipients, mail_from)
    if result is not None:
        return result

    current_app.logger.info('No email provider configured (set MAILGUN_API_KEY+MAILGUN_DOMAIN or SMTP_HOST).')
    return False


def send_contact_notification(submission):
    recipients = _split_recipients(current_app.config.get('CONTACT_NOTIFICATION_EMAILS'))
    if not recipients:
        return False

    subject_text = (submission.subject or 'Website Contact').strip()
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


def send_ticket_notification(ticket, ticket_kind='support'):
    recipients = _split_recipients(current_app.config.get('TICKET_NOTIFICATION_EMAILS'))
    if not recipients:
        return False

    client = getattr(ticket, 'client', None)
    kind = 'Quote' if ticket_kind == 'quote' else 'Support'
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
