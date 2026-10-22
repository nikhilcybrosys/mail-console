"""Compose: checking a message, the sending limits, and the one path that actually sends.

Everything that makes sending safe lives here, not in the views:
  * the From address must be in MC_SEND_FROM_ADDRESSES AND switched on by a security admin (and AWS has its own list);
  * addresses and the subject are checked for line breaks and control characters (header injection);
  * recipients on the SES suppression list are refused, per-message and per-person/per-day limits apply;
  * what is sent is exactly what was previewed (a content hash), and a message can be sent only once (row lock + state);
  * a lost answer from AWS is "unknown", never "failed": the mail may have gone out, so it is not offered for re-sending.
"""
import hashlib
import html
import json
import re
from dataclasses import dataclass, field
from datetime import timedelta
from email.utils import formataddr

from botocore.exceptions import ClientError
from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.db import transaction
from django.db.models import Sum
from django.utils import timezone

from apps.audit.service import record
from apps.sesdata import aws
from apps.sesdata.models import SuppressionEntry

from .models import Draft, SenderAddress, SentMail

MAX_DRAFTS_PER_USER = 50
STUCK_AFTER = timedelta(minutes=2)  # a "sending" draft older than this is treated as unknown
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")  # includes CR, LF and tab
_SPLIT = re.compile(r"[,;\n]+")
_URL = re.compile(r"https?://[^\s<>\"']+")
_BAD_NAME = re.compile(r"[\x00-\x1f\x7f<>\"@,;\\]")


class SendError(Exception):
    """A problem to show the person, in plain words. Never carries AWS error text."""


@dataclass
class Prepared:
    from_address: str = ""
    from_header: str = ""
    reply_to: str = ""
    to: list = field(default_factory=list)
    cc: list = field(default_factory=list)
    bcc: list = field(default_factory=list)
    subject: str = ""
    text: str = ""
    errors: list = field(default_factory=list)
    warnings: list = field(default_factory=list)

    @property
    def ok(self):
        return not self.errors

    @property
    def recipients(self):
        return self.to + self.cc + self.bcc


# ---------------------------------------------------------------- sender addresses
def clean_display_name(name):
    return _BAD_NAME.sub("", (name or "")).strip()[:60]


def sync_senders():
    """Make sure each address in the environment has a row (switched OFF until a security admin enables it)."""
    for addr in settings.SEND_FROM_ADDRESSES:
        SenderAddress.objects.get_or_create(address=addr)


def usable_senders():
    """Enabled addresses that are still in the environment's list (removing one there switches it off here)."""
    return list(SenderAddress.objects.filter(enabled=True, address__in=settings.SEND_FROM_ADDRESSES).order_by("address"))


# ---------------------------------------------------------------- parsing and checking
_ANGLE = re.compile(r"^[^<>]{0,80}<([^<>\s]+)>$")


def parse_addresses(text):
    """-> (addresses, bad_entries). Strict: each entry is `a@b.com` or `Name <a@b.com>`, separated by commas, semicolons or
    new lines. Anything else is rejected, never guessed at: a lenient parser would turn a pasted line such as
    `Bcc: someone@x.com` into a real recipient the person never clearly chose."""
    found, bad, seen = [], [], set()
    for raw in _SPLIT.split(text or ""):
        if _CONTROL.search(raw):  # checked before trimming, so a trailing CR cannot hide
            bad.append(raw.strip()[:60] or "(control characters)")
            continue
        raw = raw.strip()
        if not raw:
            continue
        m = _ANGLE.match(raw)
        addr = m.group(1) if m else raw
        try:
            if (not m and re.search(r"\s", raw)) or not addr.isascii() or addr.count("@") != 1 or len(addr) > 254:
                raise ValidationError("bad")
            validate_email(addr)
        except ValidationError:
            bad.append(raw[:60])
            continue
        if addr.lower() not in seen:
            seen.add(addr.lower())
            found.append(addr)
    return found, bad


def prepare(draft, region=None):
    """Check a draft and return what would be sent, with every problem found (not just the first)."""
    p = Prepared()
    addr = (draft.from_address or "").strip().lower()
    sender = SenderAddress.objects.filter(address=addr).first() if addr else None
    if not addr:
        p.errors.append("Choose who the mail is from.")
    elif addr not in settings.SEND_FROM_ADDRESSES:
        p.errors.append("That From address is not allowed.")
    elif sender is None or not sender.enabled:
        p.errors.append("That From address is switched off. A security admin can turn it on under Sending addresses.")
    else:
        p.from_address = addr
        name = clean_display_name(sender.display_name)
        p.from_header = formataddr((name, addr), charset="utf-8") if name else addr
        p.reply_to = (sender.reply_to or settings.SEND_DEFAULT_REPLY_TO or "").strip()

    for label, attr, text in (("To", "to", draft.to_text), ("Cc", "cc", draft.cc_text), ("Bcc", "bcc", draft.bcc_text)):
        addrs, bad = parse_addresses(text)
        setattr(p, attr, addrs)
        if bad:
            p.errors.append(f"{label}: not a valid address: {', '.join(bad[:3])}" + (" and more" if len(bad) > 3 else "") + ".")
    if not p.to:
        p.errors.append("Add at least one recipient in To.")
    everyone = [a.lower() for a in p.recipients]
    if len(everyone) != len(set(everyone)):
        p.errors.append("An address appears more than once across To, Cc and Bcc.")
    if len(everyone) > settings.SEND_MAX_RECIPIENTS:
        p.errors.append(f"At most {settings.SEND_MAX_RECIPIENTS} recipients per message (this has {len(everyone)}).")

    p.subject = (draft.subject or "").strip()
    if not p.subject:
        p.errors.append("Add a subject.")
    elif len(p.subject) > settings.SEND_MAX_SUBJECT:
        p.errors.append(f"The subject is too long (at most {settings.SEND_MAX_SUBJECT} characters).")
    elif _CONTROL.search(p.subject):
        p.errors.append("The subject cannot contain line breaks or control characters.")
    p.text = (draft.body or "").replace("\r\n", "\n").replace("\r", "\n").strip()
    if not p.text:
        p.errors.append("Write the message.")
    elif len(p.text) > settings.SEND_MAX_BODY:
        p.errors.append(f"The message is too long (at most {settings.SEND_MAX_BODY:,} characters).")
    elif "\x00" in p.text:
        p.errors.append("The message contains characters that cannot be sent.")

    if everyone:
        blocked = SuppressionEntry.objects.filter(address_lower__in=everyone, **({"region": region} if region else {})).values_list("address", flat=True)
        blocked = sorted(set(blocked))
        if blocked:
            p.errors.append(f"On the SES suppression list, so SES would not deliver: {', '.join(blocked[:3])}" + (" and more" if len(blocked) > 3 else "")
                            + ". Leave them out, or have them removed from the list first.")
    return p


def render_html(text):
    """The HTML part: the text, escaped, in paragraphs, with http(s) links made clickable. Nothing the author types can
    become markup: every character is escaped, and only links matching http:// or https:// are turned into anchors."""
    def line(s):
        out, pos = [], 0
        for m in _URL.finditer(s):
            url = m.group(0).rstrip(".,;:!?)")
            end = m.start() + len(url)
            out.append(html.escape(s[pos:m.start()]))
            out.append(f'<a href="{html.escape(url, quote=True)}">{html.escape(url)}</a>')
            pos = end
        out.append(html.escape(s[pos:]))
        return "".join(out)

    paragraphs = [p for p in re.split(r"\n{2,}", text.strip()) if p.strip()]
    body = "".join(f"<p>{'<br>'.join(line(l) for l in p.split(chr(10)))}</p>" for p in paragraphs)
    return f'<div style="font-family:-apple-system,Segoe UI,Helvetica,Arial,sans-serif;font-size:14px;line-height:1.5;color:#222">{body}</div>'


def content_hash(p):
    return hashlib.sha256(json.dumps([p.from_address, p.to, p.cc, p.bcc, p.subject, p.text], ensure_ascii=False).encode()).hexdigest()


# ---------------------------------------------------------------- limits
def usage(user_email, now=None):
    now = now or timezone.now()

    def used(**f):
        return SentMail.objects.filter(**f).aggregate(n=Sum("recipient_count"))["n"] or 0
    return {"hour": used(user_email=user_email, sent_at__gte=now - timedelta(hours=1)),
            "day": used(user_email=user_email, sent_at__gte=now - timedelta(hours=24)),
            "all_day": used(sent_at__gte=now - timedelta(hours=24))}


def limits(user_email, now=None):
    u = usage(user_email, now)
    return {"hour_left": max(settings.SEND_PER_USER_PER_HOUR - u["hour"], 0), "day_left": max(settings.SEND_PER_USER_PER_DAY - u["day"], 0),
            "all_left": max(settings.SEND_PER_DAY - u["all_day"], 0)}


def check_limits(user_email, n, now=None):
    left = limits(user_email, now)
    if n > left["hour_left"]:
        raise SendError(f"That would pass your hourly limit of {settings.SEND_PER_USER_PER_HOUR} recipients ({left['hour_left']} left). Try again later.")
    if n > left["day_left"]:
        raise SendError(f"That would pass your daily limit of {settings.SEND_PER_USER_PER_DAY} recipients ({left['day_left']} left).")
    if n > left["all_left"]:
        raise SendError(f"The daily limit for everyone ({settings.SEND_PER_DAY} recipients) would be passed ({left['all_left']} left).")


# ---------------------------------------------------------------- drafts
def effective_state(draft, now=None):
    if draft.state == Draft.SENDING and (now or timezone.now()) - draft.updated_at > STUCK_AFTER:
        return Draft.UNKNOWN
    return draft.state


# ---------------------------------------------------------------- the one place mail is sent
_FRIENDLY = {
    "MessageRejected": "SES rejected the message.",
    "AccessDenied": "AWS refused: the send role is not allowed to send this. Check that its policy lists this From address and your e-mail.",
    "AccessDeniedException": "AWS refused: the send role is not allowed to send this. Check that its policy lists this From address and your e-mail.",
    "ThrottlingException": "SES is rate limiting. Try again in a minute.",
    "TooManyRequestsException": "SES is rate limiting. Try again in a minute.",
    "SendingPausedException": "Sending is paused for this AWS account.",
    "AccountSuspendedException": "This AWS account's sending is suspended.",
    "NotFoundException": "SES could not find the configuration set or identity. Check MC_SEND_CONFIG_SET and the From address.",
    "MailFromDomainNotVerifiedException": "The sending domain is not verified in SES.",
}


def _friendly(code):
    return _FRIENDLY.get(code, f"AWS refused the request ({code}).")


def send(user, draft_id, expected_hash, region, request=None):
    """Send exactly the draft that was previewed, once. Returns the SentMail row; raises SendError otherwise."""
    with transaction.atomic():
        d = Draft.objects.select_for_update().get(pk=draft_id, user=user)  # DoesNotExist: someone else's or gone
        state = effective_state(d)
        if state == Draft.UNKNOWN:
            raise SendError("An earlier attempt to send this had no clear answer, so it may already have gone out. Check Sent mail before doing anything else.")
        if state != Draft.DRAFT:
            raise SendError("This message is already being sent.")
        p = prepare(d, region)
        if not p.ok:
            raise SendError(p.errors[0])
        if content_hash(p) != expected_hash:
            raise SendError("The message changed after you previewed it. Preview it again before sending.")
        check_limits(user.email, len(p.recipients))
        d.state = Draft.SENDING
        d.save(update_fields=["state", "updated_at"])  # the row lock is released at the end of this block; the state keeps a second send out

    detail = {"from": p.from_address, "recipients": len(p.recipients), "subject": p.subject[:100]}
    rid = f"{user.pk}-{int(timezone.now().timestamp())}"
    try:
        sender = aws.assume_sender(region, user.email, rid)  # nothing can have been sent yet: any failure here is a clean "no"
    except Exception as exc:  # noqa: BLE001
        Draft.objects.filter(pk=d.pk).update(state=Draft.DRAFT)
        code = exc.response["Error"]["Code"] if isinstance(exc, ClientError) else exc.__class__.__name__
        record("compose.send_failed", actor=user.email, request=request, details={**detail, "stage": "assume-role", "error": code})
        raise SendError(_friendly(code) if isinstance(exc, ClientError) else "Could not reach AWS to prepare the send. Nothing was sent.") from None
    try:
        message_id = sender.send(from_address=p.from_header, to=p.to, cc=p.cc, bcc=p.bcc, reply_to=p.reply_to or None, subject=p.subject,
                                 text=p.text, html=render_html(p.text), config_set=settings.SEND_CONFIG_SET)
    except ClientError as exc:  # AWS answered, and the answer is no
        code = exc.response["Error"]["Code"]
        Draft.objects.filter(pk=d.pk).update(state=Draft.DRAFT)
        record("compose.send_failed", actor=user.email, request=request, details={**detail, "stage": "send", "error": code})
        raise SendError(_friendly(code)) from None
    except Exception as exc:  # noqa: BLE001: timeout or dropped connection: the mail may or may not have gone out
        Draft.objects.filter(pk=d.pk).update(state=Draft.UNKNOWN)
        record("compose.send_unknown", actor=user.email, request=request, details={**detail, "error": exc.__class__.__name__})
        raise SendError("AWS did not answer clearly, so the message MAY have been sent. Check Sent mail before trying again.") from None

    sent = SentMail.objects.create(user_email=user.email, from_address=p.from_address, to_addrs=p.to, cc_addrs=p.cc, bcc_addrs=p.bcc, subject=p.subject,
                                   recipient_count=len(p.recipients), ses_message_id=message_id)
    Draft.objects.filter(pk=d.pk).delete()
    record("compose.sent", actor=user.email, request=request, target=message_id, details={**detail, "message_id": message_id})
    return sent
