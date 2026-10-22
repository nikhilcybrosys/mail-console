"""MIME parsing for inbound mail (stdlib only). Never executes or renders anything."""
import email
import email.policy
import email.utils
import re
from dataclasses import dataclass, field

from .redact import redact_text
from .sanitize import sanitize_html


@dataclass
class ParsedMail:
    from_addr: str = ""
    to_addrs: list = field(default_factory=list)
    subject: str = ""
    message_id: str = ""
    in_reply_to: str = ""
    references: str = ""
    text: str = ""
    html_clean: str = ""
    verdicts: dict = field(default_factory=dict)
    attachments: list = field(default_factory=list)  # {index, filename, content_type, size}


def _ids(value):
    return re.findall(r"<[^<>\s]+>", value or "")


def thread_key(parsed):
    """Root of the References chain, else In-Reply-To, else own Message-ID."""
    refs = _ids(parsed.references)
    return (refs[0] if refs else (_ids(parsed.in_reply_to) or [parsed.message_id])[0]) or ""


def _verdict(msg):
    v = {}
    for hdr, key in (("X-SES-Spam-Verdict", "spam"), ("X-SES-Virus-Verdict", "virus"), ("X-SES-SPF-Verdict", "spf"),
                     ("X-SES-DKIM-Verdict", "dkim"), ("X-SES-DMARC-Verdict", "dmarc")):
        if msg.get(hdr):
            v[key] = str(msg[hdr]).strip().upper()
    auth = str(msg.get("Authentication-Results", ""))
    for name in ("spf", "dkim", "dmarc"):
        m = re.search(rf"\b{name}=(\w+)", auth, re.I)
        if m:
            v.setdefault(name, m.group(1).upper())
    return v


def parse_mime(raw_bytes, extra_rules=()):
    msg = email.message_from_bytes(raw_bytes, policy=email.policy.default)
    p = ParsedMail(
        from_addr=email.utils.parseaddr(str(msg.get("From", "")))[1],
        to_addrs=[a for _, a in email.utils.getaddresses([str(msg.get("To", ""))]) if a],
        subject=str(msg.get("Subject", ""))[:998], message_id=str(msg.get("Message-ID", "")).strip(),
        in_reply_to=str(msg.get("In-Reply-To", "")).strip(), references=str(msg.get("References", "")).strip(),
        verdicts=_verdict(msg),
    )
    body_text = msg.get_body(preferencelist=("plain",))
    body_html = msg.get_body(preferencelist=("html",))
    if body_text is not None:
        p.text = redact_text(body_text.get_content(), extra_rules)
    if body_html is not None:
        p.html_clean = sanitize_html(body_html.get_content(), extra_rules)
    for i, part in enumerate(msg.iter_attachments()):
        payload = part.get_payload(decode=True) or b""
        p.attachments.append({
            "index": i, "filename": (part.get_filename() or f"attachment-{i}")[:255],
            "content_type": part.get_content_type(), "size": len(payload),
        })
    return p
