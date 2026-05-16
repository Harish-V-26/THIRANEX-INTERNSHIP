import imaplib
import email
from email.header import decode_header

def fetch_latest_emails(username, app_password, limit=5):
    results = []
    mail = imaplib.IMAP4_SSL("imap.gmail.com")
    mail.login(username, app_password)
    mail.select("inbox")
    _, data = mail.search(None, "ALL")
    ids = data[0].split()[-limit:]
    for eid in reversed(ids):
        _, msg_data = mail.fetch(eid, "(RFC822)")
        msg = email.message_from_bytes(msg_data[0][1])
        subject = msg.get("Subject", "")
        sender = msg.get("From", "")
        body = ""
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == "text/plain":
                    payload = part.get_payload(decode=True)
                    if payload:
                        body = payload.decode(errors="ignore")
                        break
        else:
            payload = msg.get_payload(decode=True)
            if payload:
                body = payload.decode(errors="ignore")
        results.append({"subject": subject, "from": sender, "body": body[:5000]})
    mail.logout()
    return results
