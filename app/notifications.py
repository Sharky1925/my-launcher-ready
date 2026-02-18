import smtplib
from email.message import EmailMessage

from flask import current_app


def _split_recipients(raw):
    return [item.strip() for item in (raw or '').split(',') if item.strip()]


def _ticket_admin_url(ticket_id):
    base = (current_app.config.get('APP_BASE_URL') or '').rstrip('/')
    if not base:
        return f"/admin/support-tickets/{ticket_id}"
    return f"{base}/admin/support-tickets/{ticket_id}"


def _send_email(subject, body, recipients):
    if not recipients:
        return False

    host = (current_app.config.get('SMTP_HOST') or '').strip()
    if not host:
        current_app.logger.info('SMTP_HOST is not configured; skipping email notification.')
        return False

    port = int(current_app.config.get('SMTP_PORT') or 587)
    username = current_app.config.get('SMTP_USERNAME') or ''
    password = current_app.config.get('SMTP_PASSWORD') or ''
    use_ssl = bool(current_app.config.get('SMTP_USE_SSL'))
    use_tls = bool(current_app.config.get('SMTP_USE_TLS'))

    message = EmailMessage()
    message['Subject'] = subject
    message['From'] = current_app.config.get('MAIL_FROM') or 'no-reply@localhost'
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
        current_app.logger.exception('Email notification delivery failed.')
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
