"""Renderer served on the separate mailview origin. No cookies, no session, no auth state.

Defense in depth for untrusted mail: sanitized HTML only, `default-src 'none'` CSP with `sandbox`,
frame-ancestors pinned to the console origin, nosniff, no-store. Authorization = a signed 60 s token.
"""
from django.conf import settings
from django.core import signing
from django.http import HttpResponse, HttpResponseNotFound
from django.utils.html import escape
from django.views.decorators.http import require_GET

from apps.sesdata.models import MailCategory, Message

from . import bodies
from .tokens import verify


def _csp():
    ancestors = f"https://{settings.CONSOLE_HOST}" if not settings.DEBUG else f"http://{settings.CONSOLE_HOST}:8000"
    return f"default-src 'none'; style-src 'unsafe-inline'; img-src data:; frame-ancestors {ancestors}; base-uri 'none'; form-action 'none'; sandbox"


PAGE = """<!doctype html><meta charset="utf-8"><meta name="referrer" content="no-referrer">
<style>body{{font:14px/1.5 system-ui,sans-serif;margin:16px;color:#1c2330;background:#fff;word-break:break-word}}
pre{{white-space:pre-wrap;font:13px/1.5 ui-monospace,monospace}}.lnk{{color:#4b5563;text-decoration:underline dotted}}
table{{border-collapse:collapse}}td,th{{border:1px solid #d6dbe4;padding:4px 8px}}.banner{{background:#fff7e0;border:1px solid #f0d080;padding:6px 10px;margin-bottom:12px;font-size:12px}}</style>
<div class="banner">{banner}</div>{body}"""


@require_GET
def render_body(request, token):
    try:
        payload = verify(token)
    except signing.BadSignature:  # includes SignatureExpired
        return HttpResponseNotFound()
    content = None
    rules = ()
    if payload["k"] == "msg":
        msg = Message.objects.filter(pk=payload["id"]).first()
        if msg and msg.body_ref:
            cat = MailCategory.objects.filter(name=msg.mail_category).first()
            rules = tuple(cat.redaction_rules) if cat else ()
            content = bodies.load_message_body(msg.body_ref, rules)
    elif payload["k"] == "inbound":
        content = bodies.load_inbound_body(payload["id"])
    if content is None:
        return HttpResponseNotFound()
    inner = content.html_clean if content.html_clean else f"<pre>{escape(content.text)}</pre>"
    resp = HttpResponse(PAGE.format(banner="Sanitized view: scripts, images, forms and links are disabled; secrets are redacted.", body=inner))
    resp["Content-Security-Policy"] = _csp()
    resp["X-Content-Type-Options"] = "nosniff"
    resp["Cache-Control"] = "no-store"
    resp["Referrer-Policy"] = "no-referrer"
    resp["Cross-Origin-Resource-Policy"] = "cross-origin"  # the console origin embeds this in an iframe
    return resp
