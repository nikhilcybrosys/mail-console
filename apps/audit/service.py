import hashlib
import ipaddress
import json

from django.db import connection, transaction
from django.utils import timezone

from .models import AuditLog

GENESIS = "0" * 64
_LOCK_KEY = 0x4D434155  # "MCAU" advisory lock id, serialises chain appends


def _canonical(ts, actor, action, target, ip, user_agent, request_id, details):
    return json.dumps(
        [ts.isoformat(), actor, action, target, ip or "", user_agent, request_id, details],
        sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str,
    )


def _hash(prev_hash, canonical):
    return hashlib.sha256((prev_hash + canonical).encode()).hexdigest()


def _norm_ip(value):
    try:
        return ipaddress.ip_address((value or "").strip()).compressed
    except ValueError:
        return None


def client_ip(request):
    # Behind the ALB the last X-Forwarded-For hop is the one the ALB appended.
    xff = request.META.get("HTTP_X_FORWARDED_FOR", "")
    return _norm_ip(xff.split(",")[-1] if xff else request.META.get("REMOTE_ADDR"))


def record(action, *, actor="system", target="", request=None, details=None):
    """Append one audit row. Never put secrets or message bodies in `details`."""
    ip = ua = rid = ""
    if request is not None:
        ip = client_ip(request) or ""
        ua = request.META.get("HTTP_USER_AGENT", "")[:300]
        rid = request.META.get("HTTP_X_AMZN_TRACE_ID", "")[:64]
        if getattr(request, "user", None) is not None and request.user.is_authenticated:
            actor = request.user.email
    ts = timezone.now()
    details = details or {}
    with transaction.atomic():
        with connection.cursor() as cur:
            cur.execute("SELECT pg_advisory_xact_lock(%s)", [_LOCK_KEY])
        last = AuditLog.objects.order_by("-id").values_list("row_hash", flat=True).first()
        prev = last or GENESIS
        row_hash = _hash(prev, _canonical(ts, actor, action, target, ip, ua, rid, details))
        return AuditLog.objects.create(
            ts=ts, actor=actor, action=action, target=target[:500], ip=ip or None,
            user_agent=ua, request_id=rid, details=details, prev_hash=prev, row_hash=row_hash,
        )


def verify_chain():
    """Return (ok, first_bad_id). Walks every row in order."""
    prev = GENESIS
    for row in AuditLog.objects.order_by("id").iterator():
        canon = _canonical(row.ts, row.actor, row.action, row.target, row.ip, row.user_agent, row.request_id, row.details)
        if row.prev_hash != prev or row.row_hash != _hash(prev, canon):
            return False, row.id
        prev = row.row_hash
    return True, None
