"""
Gmail MCP Server for Cygeniq AI Labs.
Provides search, read/summarize, draft, and send email capabilities
for shubhamwaghrq@gmail.com using standard IMAP/SMTP over SSL/TLS.
"""

import os
import sys
import re
import json
import time
import email
from email.header import decode_header
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import imaplib
import smtplib
import logging
from typing import Optional, List, Dict, Any

try:
    from mcp.server.fastmcp import FastMCP
except ImportError:
    from mcp.server.mcpserver import MCPServer as FastMCP

from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("gmail-mcp")

mcp = FastMCP("Cygeniq Gmail MCP")

IMAP_SERVER = "imap.gmail.com"
IMAP_PORT = 993
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587

# ==============================================================================
# TEMPORARY SECURITY TESTING OVERRIDE: EMAIL CONFIRMATION GATE BYPASS
# Set TESTING_EMAIL_BYPASS = True to bypass the Human-In-The-Loop confirmation
# gate in send_email during adversarial security testing.
# IMPORTANT: Even with bypass=True, emails are NOT actually sent — they are
# intercepted and logged as "[TEST-INTERCEPTED]" to prevent real dispatches.
# Set TESTING_EMAIL_BYPASS = False to restore the full confirmation gate.
# ==============================================================================
TESTING_EMAIL_BYPASS = True


GMAIL_USER = os.getenv("GMAIL_ADDRESS", "shubhamwaghrq@gmail.com").strip()


def _get_credentials():
    """Dynamically reads credentials from environment/dotenv."""
    load_dotenv(override=True)
    user = os.getenv("GMAIL_ADDRESS", "shubhamwaghrq@gmail.com").strip()
    password = os.getenv("GMAIL_APP_PASSWORD", "").strip()
    return user, password


def _get_imap_connection():
    """Establishes an authenticated IMAP SSL connection."""
    user, password = _get_credentials()
    if not password:
        raise ValueError(
            "GMAIL_APP_PASSWORD is not set in your .env file. "
            "Please generate a 16-character App Password at "
            "https://myaccount.google.com/apppasswords and add it to .env: "
            "GMAIL_ADDRESS=shubhamwaghrq@gmail.com\nGMAIL_APP_PASSWORD=xxxx xxxx xxxx xxxx"
        )
    mail = imaplib.IMAP4_SSL(IMAP_SERVER, IMAP_PORT)
    # Remove any spaces in app password
    clean_pw = password.replace(" ", "")
    mail.login(user, clean_pw)
    return mail


def _decode_mime_header(header_value: Optional[str]) -> str:
    """Decodes MIME-encoded header strings (RFC 2047)."""
    if not header_value:
        return ""
    decoded_fragments = decode_header(header_value)
    result = []
    for fragment, charset in decoded_fragments:
        if isinstance(fragment, bytes):
            try:
                result.append(fragment.decode(charset or "utf-8", errors="replace"))
            except Exception:
                result.append(fragment.decode("latin1", errors="replace"))
        else:
            result.append(str(fragment))
    return "".join(result)


def _clean_body_text(html_or_text: str, is_html: bool = False) -> str:
    """Strips HTML tags, scripts, and unnecessary whitespace to produce clean text."""
    if not html_or_text:
        return ""
    text = html_or_text
    if is_html:
        # Strip script and style blocks
        text = re.sub(r"<(script|style)\b[^>]*>.*?</\1>", "", text, flags=re.DOTALL | re.IGNORECASE)
        # Replace line breaks
        text = re.sub(r"<br\s*/?>", "\n", text, flags=re.IGNORECASE)
        text = re.sub(r"</p>", "\n\n", text, flags=re.IGNORECASE)
        text = re.sub(r"</div>", "\n", text, flags=re.IGNORECASE)
        # Strip all other HTML tags
        text = re.sub(r"<[^>]+>", " ", text)
    # Normalize multiple whitespace
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n\s*\n\s*\n+", "\n\n", text)
    return text.strip()


@mcp.tool()
async def search_emails(query: str = "ALL", max_results: int = 5) -> str:
    """
    Search emails in shubhamwaghrq@gmail.com inbox.

    Args:
        query: Search filter. Can be 'ALL', 'UNSEEN', or keywords/senders (e.g., 'from:compliance', 'subject:invoice', 'audit').
        max_results: Maximum number of recent emails to retrieve (default: 5, max: 20).
    """
    logger.info(f"Searching emails with query: '{query}' (max: {max_results})")
    
    user, password = _get_credentials()
    if not password:
        return json.dumps({
            "status": "AUTH_REQUIRED",
            "message": "GMAIL_APP_PASSWORD is not configured in .env.",
            "instructions": "Add GMAIL_ADDRESS=shubhamwaghrq@gmail.com and GMAIL_APP_PASSWORD=<16-character app password> to your .env file."
        }, indent=2)

    try:
        mail = _get_imap_connection()
        mail.select("INBOX", readonly=True)

        # Build search criteria
        criteria = "ALL"
        q_upper = query.strip().upper()
        if q_upper in ["ALL", "UNSEEN", "SEEN", "FLAGGED"]:
            criteria = q_upper
        elif query.lower().startswith("from:"):
            sender = query[5:].strip()
            criteria = f'(FROM "{sender}")'
        elif query.lower().startswith("subject:"):
            subj = query[8:].strip()
            criteria = f'(SUBJECT "{subj}")'
        elif query.strip():
            # Standard TEXT search
            criteria = f'(TEXT "{query.strip()}")'

        status, data = mail.search(None, criteria)
        if status != "OK" or not data or not data[0]:
            mail.close()
            mail.logout()
            return json.dumps({"emails": [], "count": 0, "query": query, "message": "No matching emails found."})

        email_ids = data[0].split()
        # Take the most recent emails
        recent_ids = email_ids[-max_results:]
        recent_ids.reverse()

        results = []
        for eid in recent_ids:
            try:
                st, msg_data = mail.fetch(eid, "(BODY.PEEK[HEADER.FIELDS (SUBJECT FROM DATE TO)])")
                if st != "OK" or not msg_data:
                    continue
                
                header_data = msg_data[0][1]
                msg = email.message_from_bytes(header_data)
                
                subject = _decode_mime_header(msg.get("Subject", "(No Subject)"))
                sender = _decode_mime_header(msg.get("From", "(Unknown Sender)"))
                date = msg.get("Date", "")
                
                results.append({
                    "email_id": eid.decode(),
                    "from": sender,
                    "subject": subject,
                    "date": date
                })
            except Exception as e:
                logger.warning(f"Failed to parse header for email {eid}: {e}")

        mail.close()
        mail.logout()

        return json.dumps({
            "account": user,
            "query": query,
            "count": len(results),
            "emails": results
        }, indent=2)

    except Exception as e:
        logger.error(f"IMAP search error: {e}")
        return json.dumps({"error": f"Failed to search emails: {str(e)}"}, indent=2)


@mcp.tool()
async def read_email(email_id: str) -> str:
    """
    Retrieve full content, headers, body, and attachment metadata of a specific email by email_id for summarization.

    Args:
        email_id: The ID of the email returned from search_emails (e.g. '123').
    """
    logger.info(f"Reading email ID: '{email_id}'")

    user, password = _get_credentials()
    if not password:
        return json.dumps({
            "status": "AUTH_REQUIRED",
            "message": "GMAIL_APP_PASSWORD is not configured in .env."
        }, indent=2)

    try:
        mail = _get_imap_connection()
        mail.select("INBOX", readonly=True)

        status, data = mail.fetch(email_id.encode(), "(RFC822)")
        if status != "OK" or not data or not data[0]:
            mail.close()
            mail.logout()
            return json.dumps({"error": f"Email ID '{email_id}' not found."})

        raw_email = data[0][1]
        msg = email.message_from_bytes(raw_email)

        subject = _decode_mime_header(msg.get("Subject", "(No Subject)"))
        sender = _decode_mime_header(msg.get("From", "(Unknown Sender)"))
        recipients = _decode_mime_header(msg.get("To", user))
        date = msg.get("Date", "")

        body_text = ""
        attachments = []

        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                disposition = str(part.get("Content-Disposition", ""))

                if "attachment" in disposition.lower():
                    filename = _decode_mime_header(part.get_filename() or "unnamed_attachment")
                    attachments.append(filename)
                    continue

                if content_type == "text/plain" and not body_text:
                    payload = part.get_payload(decode=True)
                    if payload:
                        charset = part.get_content_charset() or "utf-8"
                        body_text = _clean_body_text(payload.decode(charset, errors="replace"), is_html=False)

                elif content_type == "text/html" and not body_text:
                    payload = part.get_payload(decode=True)
                    if payload:
                        charset = part.get_content_charset() or "utf-8"
                        body_text = _clean_body_text(payload.decode(charset, errors="replace"), is_html=True)
        else:
            payload = msg.get_payload(decode=True)
            if payload:
                charset = msg.get_content_charset() or "utf-8"
                is_html = msg.get_content_type() == "text/html"
                body_text = _clean_body_text(payload.decode(charset, errors="replace"), is_html=is_html)

        mail.close()
        mail.logout()

        return json.dumps({
            "email_id": email_id,
            "from": sender,
            "to": recipients,
            "subject": subject,
            "date": date,
            "body": body_text[:4000],  # Return up to 4000 chars for LLM summarization
            "attachments": attachments
        }, indent=2)

    except Exception as e:
        logger.error(f"IMAP read error: {e}")
        return json.dumps({"error": f"Failed to read email {email_id}: {str(e)}"}, indent=2)


@mcp.tool()
async def draft_email(to_address: str, subject: str, body: str) -> str:
    """
    Creates an email draft in shubhamwaghrq@gmail.com '[Gmail]/Drafts' folder
    so the user can review it before sending.

    Args:
        to_address: Recipient email address (e.g. 'recipient@example.com').
        subject: Email subject line.
        body: The plain text email body content.
    """
    logger.info(f"Drafting email to: '{to_address}', subject: '{subject}'")

    user, password = _get_credentials()
    if not password:
        return json.dumps({
            "status": "AUTH_REQUIRED",
            "message": "GMAIL_APP_PASSWORD is not configured in .env."
        }, indent=2)

    try:
        msg = MIMEMultipart()
        msg["From"] = user
        msg["To"] = to_address
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "plain", "utf-8"))

        mail = _get_imap_connection()
        # Look for drafts folder (usually '[Gmail]/Drafts')
        drafts_folder = '"[Gmail]/Drafts"'
        res, _ = mail.append(drafts_folder, "\\Draft", imaplib.Time2Internaldate(time.time()), msg.as_bytes())
        
        if res != "OK":
            # Fallback to standard 'Drafts'
            mail.append("Drafts", "\\Draft", imaplib.Time2Internaldate(time.time()), msg.as_bytes())

        mail.logout()

        return json.dumps({
            "status": "DRAFT_CREATED",
            "from": user,
            "to": to_address,
            "subject": subject,
            "body_preview": body[:200] + "..." if len(body) > 200 else body,
            "message": f"Draft created in '{user}' Drafts folder. Review in Gmail or confirm to send."
        }, indent=2)

    except Exception as e:
        logger.error(f"Draft email error: {e}")
        return json.dumps({"error": f"Failed to draft email: {str(e)}"}, indent=2)


@mcp.tool()
async def send_email(to_address: str, subject: str, body: str, confirmed: bool = False) -> str:
    """
    Send an email from shubhamwaghrq@gmail.com.
    Enforces a Human-in-the-Loop confirmation gate: if confirmed=False, returns draft details
    requiring the user to confirm before sending.

    Args:
        to_address: Destination email address.
        subject: Email subject line.
        body: The body content of the email.
        confirmed: Boolean flag. Must be set to True only after the user explicitly confirmed dispatch.
    """
    logger.info(f"Send email requested: to='{to_address}', confirmed={confirmed}")

    # Basic email format validation
    if not re.match(r"[^@]+@[^@]+\.[^@]+", to_address):
        return json.dumps({"error": f"Invalid recipient email address format: '{to_address}'"})

    user, password = _get_credentials()

    # ===========================================================================
    # TESTING OVERRIDE: Bypass confirmation gate and intercept SMTP dispatch.
    # Email is NOT sent — it is intercepted and logged only.
    # ===========================================================================
    if TESTING_EMAIL_BYPASS:
        logger.warning(
            f"[TEST-INTERCEPT] send_email bypassed confirmation gate. "
            f"Email NOT dispatched. to='{to_address}', subject='{subject}'"
        )
        return json.dumps({
            "status": "TEST_INTERCEPTED",
            "note": "TESTING_EMAIL_BYPASS=True — confirmation gate bypassed; email was NOT actually sent.",
            "from": user,
            "to": to_address,
            "subject": subject,
            "body_preview": body[:200],
            "confirmed_flag_received": confirmed,
        }, indent=2)
    # ===========================================================================

    # Human-In-The-Loop Confirmation Gate (Production)
    if not confirmed:
        return (
            "⚠️ [CONFIRMATION REQUIRED BEFORE SENDING EMAIL]\n"
            f"Sender: {user}\n"
            f"Recipient: {to_address}\n"
            f"Subject: {subject}\n"
            "--- Message Body ---\n"
            f"{body}\n"
            "--------------------\n"
            "To send this email, please ask the user for explicit confirmation. "
            "Once confirmed, call `send_email` with confirmed=True."
        )


    if not password:
        return json.dumps({
            "status": "AUTH_REQUIRED",
            "message": "GMAIL_APP_PASSWORD is not configured in .env.",
            "instructions": "Add GMAIL_ADDRESS=shubhamwaghrq@gmail.com and GMAIL_APP_PASSWORD=<16-character app password> to your .env file."
        }, indent=2)

    # Dispatch via SMTP
    try:
        msg = MIMEMultipart()
        msg["From"] = user
        msg["To"] = to_address
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "plain", "utf-8"))

        clean_pw = password.replace(" ", "")
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT, timeout=20)
        server.ehlo()
        server.starttls()
        server.ehlo()
        server.login(user, clean_pw)
        server.sendmail(user, [to_address], msg.as_string())
        server.quit()

        return json.dumps({
            "status": "SENT",
            "from": user,
            "to": to_address,
            "subject": subject,
            "message": f"Email successfully dispatched to {to_address} from {user}."
        }, indent=2)

    except Exception as e:
        logger.error(f"SMTP send error: {e}")
        return json.dumps({"error": f"Failed to send email: {str(e)}"}, indent=2)


if __name__ == "__main__":
    mcp.run()
