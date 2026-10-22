"""Compose pages. Thin on purpose: every rule is in service.py."""
from functools import wraps
from urllib.parse import urlencode

from django.conf import settings
from django.contrib import messages
from django.http import Http404
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.views.decorators.http import require_POST

from apps.audit.service import record
from apps.core.rbac import has_capability, require_capability

from . import service
from .models import Draft, SenderAddress, SentMail

TEXT_CAP = 5000  # recipient fields as typed


def _region(request):
    r = request.session.get("region")
    return r if r in settings.AWS_REGIONS else settings.AWS_REGIONS[0]


def compose_view(capability="compose_send", step_up=False):
    """Compose does not exist (404) unless it is switched on, then the usual capability (and passkey) rules apply."""
    def deco(view):
        guarded = require_capability(capability, step_up=step_up)(view)

        @wraps(view)
        def wrapper(request, *args, **kwargs):
            if not settings.SEND_ENABLED:
                raise Http404
            return guarded(request, *args, **kwargs)
        return wrapper
    return deco


def _mine(request, pk):
    return get_object_or_404(Draft, pk=pk, user=request.user)  # someone else's draft is a 404, not a 403


# ---------------------------------------------------------------- home
@compose_view()
def home(request):
    service.sync_senders()
    now_drafts = list(request.user.drafts.all())
    for d in now_drafts:
        d.shown_state = service.effective_state(d)
    return render(request, "compose/home.html", {
        "drafts": now_drafts, "sent": SentMail.objects.filter(user_email=request.user.email)[:15],
        "limits": service.limits(request.user.email), "senders": service.usable_senders(),
        "can_manage_senders": has_capability(request.user, "manage_senders"), "max_recipients": settings.SEND_MAX_RECIPIENTS})


# ---------------------------------------------------------------- write and check
def _form_context(request, draft, errors=None):
    return {"d": draft, "senders": service.usable_senders(), "errors": errors or [], "max_recipients": settings.SEND_MAX_RECIPIENTS,
            "max_subject": settings.SEND_MAX_SUBJECT}


@compose_view()
def edit(request, pk=None):
    service.sync_senders()
    draft = _mine(request, pk) if pk else Draft(user=request.user)
    if pk and service.effective_state(draft) != Draft.DRAFT:
        messages.error(request, "This message cannot be edited: a send is in progress or needs checking.")
        return redirect("compose")
    if request.method == "POST":
        if not pk and request.user.drafts.count() >= service.MAX_DRAFTS_PER_USER:
            messages.error(request, f"You can keep {service.MAX_DRAFTS_PER_USER} drafts. Delete some first.")
            return redirect("compose")
        p = request.POST

        def field(name, cap):
            return p.get(name, "").replace("\x00", "")[:cap]  # PostgreSQL text cannot hold NUL; it is never valid in mail anyway

        draft.from_address = field("from_address", 254).strip().lower()
        draft.to_text, draft.cc_text, draft.bcc_text = (field(k, TEXT_CAP) for k in ("to", "cc", "bcc"))
        draft.subject = field("subject", 500)
        draft.body = field("body", settings.SEND_MAX_BODY * 2)
        draft.save()
        if p.get("action") == "preview":
            prepared = service.prepare(draft, _region(request))
            if prepared.errors:
                return render(request, "compose/edit.html", _form_context(request, draft, prepared.errors))
            return redirect("compose_preview", pk=draft.pk)
        messages.success(request, "Draft saved.")
        return redirect("compose_edit", pk=draft.pk)
    return render(request, "compose/edit.html", _form_context(request, draft))


@compose_view(step_up=True)  # the passkey comes BEFORE the Send button is shown
def preview(request, pk):
    draft = _mine(request, pk)
    if service.effective_state(draft) != Draft.DRAFT:
        messages.error(request, "This message cannot be sent right now: a send is in progress or needs checking.")
        return redirect("compose")
    p = service.prepare(draft, _region(request))
    if p.errors:
        messages.error(request, p.errors[0])
        return redirect("compose_edit", pk=draft.pk)
    return render(request, "compose/preview.html", {
        "d": draft, "p": p, "hash": service.content_hash(p), "n": len(p.recipients), "limits": service.limits(request.user.email)})


@compose_view(step_up=True)
def send_view(request, pk):
    if request.method != "POST":  # e.g. returning here after a passkey prompt: go back to the preview
        return redirect("compose_preview", pk=pk)
    try:
        sent = service.send(request.user, pk, request.POST.get("hash", ""), _region(request), request=request)
    except Draft.DoesNotExist:
        raise Http404 from None
    except service.SendError as exc:
        messages.error(request, str(exc))
        return redirect("compose_preview", pk=pk) if Draft.objects.filter(pk=pk, user=request.user, state=Draft.DRAFT).exists() else redirect("compose")
    messages.success(request, f"Sent to {sent.recipient_count} recipient{'s' if sent.recipient_count != 1 else ''}.")
    return redirect("compose")


@require_POST
@compose_view()
def delete(request, pk):
    draft = _mine(request, pk)
    draft.delete()
    messages.success(request, "Draft deleted.")
    return redirect("compose")


@compose_view(step_up=True)
def release(request, pk):
    """After a send with no clear answer: the person says they checked Sent mail and it did NOT go out, so it may be edited
    and sent again. Deliberate and audited: this is the one way to risk a duplicate."""
    if request.method != "POST":
        return redirect("compose")
    draft = _mine(request, pk)
    if service.effective_state(draft) == Draft.UNKNOWN:
        Draft.objects.filter(pk=draft.pk).update(state=Draft.DRAFT)
        record("compose.unknown_released", request=request, details={"draft": draft.pk, "subject": draft.subject[:100]})
        messages.success(request, "Reopened as a draft. Only send it again if you are sure it did not go out.")
    return redirect("compose")


# ---------------------------------------------------------------- sending addresses (security admins)
@compose_view("manage_senders", step_up=False)
def senders(request):
    service.sync_senders()
    rows = list(SenderAddress.objects.filter(address__in=settings.SEND_FROM_ADDRESSES).order_by("address"))
    gone = list(SenderAddress.objects.exclude(address__in=settings.SEND_FROM_ADDRESSES).order_by("address"))
    errors = []
    if request.method == "POST":
        if not request.user.has_fresh_step_up(request.session):
            return redirect(f"{reverse('step_up')}?{urlencode({'next': request.get_full_path()})}")
        changes = {}
        for i, row in enumerate(rows):
            enabled = request.POST.get(f"enabled_{i}") == "on"
            name = service.clean_display_name(request.POST.get(f"name_{i}", ""))
            reply = (request.POST.get(f"reply_{i}", "")).strip()
            if reply:
                parsed, bad = service.parse_addresses(reply)
                if bad or len(parsed) != 1:
                    errors.append(f"{row.address}: Reply-To must be one valid address.")
                    continue
                reply = parsed[0].lower()
            if (row.enabled, row.display_name, row.reply_to) != (enabled, name, reply):
                changes[row.address] = {"enabled": [row.enabled, enabled], "display_name": [row.display_name, name], "reply_to": [row.reply_to, reply]}
                row.enabled, row.display_name, row.reply_to, row.updated_by = enabled, name, reply, request.user.email
        if not errors:
            for row in rows:
                if row.address in changes:
                    row.save()
            if changes:
                record("compose.senders_updated", request=request, details={"changes": changes})
            messages.success(request, "Saved." if changes else "Nothing changed.")
            return redirect("compose_senders")
    return render(request, "compose/senders.html", {"rows": rows, "gone": gone, "errors": errors, "default_reply": settings.SEND_DEFAULT_REPLY_TO})
