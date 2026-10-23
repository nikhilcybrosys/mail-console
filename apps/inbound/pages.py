"""Console-side inbox pages (authenticated). Message content only ever leaves via the mailview origin."""
import re

import boto3
from django.conf import settings
from django.core.paginator import Paginator
from django.db.models import Sum
from django.http import Http404, HttpResponseBadRequest, HttpResponseRedirect
from django.contrib import messages
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST

from apps.audit.service import record
from apps.core.rbac import has_capability, require_capability
from apps.sesdata.models import BodyAccessLog

from . import dmarc_upload as dmarc_upload_mod
from . import dmarcstats
from .models import DmarcReport, InboundAttachment, InboundMessage
from .tokens import issue

_SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")


@require_capability("view_inbound")
def inbox(request):
    qs = InboundMessage.objects.all()
    kind, q = request.GET.get("kind", ""), (request.GET.get("q") or "").strip()
    if kind in ("mail", "bounce", "dmarc_report"):
        qs = qs.filter(kind=kind)
    if q:
        qs = qs.filter(subject__icontains=q) | qs.filter(from_addr__icontains=q)
    page = Paginator(qs.order_by("-received_at"), 50).get_page(request.GET.get("page"))
    return render(request, "inbound/inbox.html", {"page": page, "q": q, "kind": kind})


@require_capability("view_inbound")
def inbound_detail(request, pk):
    m = get_object_or_404(InboundMessage, pk=pk)
    thread = InboundMessage.objects.filter(thread_key=m.thread_key).exclude(pk=m.pk).order_by("received_at") if m.thread_key else []
    return render(request, "inbound/detail.html", {"m": m, "thread": thread, "attachments": m.attachments.all()})


@require_POST
@require_capability("view_inbound", step_up=True)
def inbound_body(request, pk):
    m = get_object_or_404(InboundMessage, pk=pk)
    reason = (request.POST.get("reason") or "").strip()
    if not reason:
        return HttpResponseBadRequest("A reason is required")
    BodyAccessLog.objects.create(user_email=request.user.email, inbound_id=m.pk, reason=reason)
    record("inbound.body.view", target=f"inbound#{m.pk}", request=request, details={"reason": reason[:200]})
    return render(request, "console/body_frame.html", {"frame_url": issue("inbound", m.pk, request.user.pk), "title": m.subject})


@require_capability("view_inbound", step_up=True)
def attachment_download(request, pk, index):
    """Only attachments the malware scan has marked clean can leave. Short-lived presigned URL, audited."""
    att = get_object_or_404(InboundAttachment, message_id=pk, index=index)
    if att.scan_state != "clean" or not att.s3_key:
        raise Http404  # pending/infected/failed scans are indistinguishable from missing, on purpose
    url = boto3.client("s3").generate_presigned_url(
        "get_object", ExpiresIn=60, Params={
            "Bucket": settings.CONTENT_BUCKET, "Key": att.s3_key, "ResponseContentType": "application/octet-stream",
            "ResponseContentDisposition": f'attachment; filename="{_SAFE_NAME.sub("_", att.filename)[:100]}"'})
    record("inbound.attachment.download", target=f"inbound#{pk}/{index}", request=request, details={"size": att.size})
    return HttpResponseRedirect(url)


@require_capability("view_inbound")
def dmarc_dashboard(request):
    try:
        days = int(request.GET.get("days", 30))
    except ValueError:
        days = 30
    days = days if days in dmarcstats.PERIODS else 30
    domains = dmarcstats.overview(days)
    chosen = request.GET.get("domain", "")
    current = next((d for d in domains if d["domain"] == chosen), domains[0] if domains else None)
    src, more = dmarcstats.sources(current["domain"], days) if current else ([], 0)
    return render(request, "inbound/dmarc.html", {
        "days": days, "periods": dmarcstats.PERIODS, "domains": domains, "current": current, "sources": src, "more_sources": more,
        "reports": dmarcstats.recent_reports(current["domain"] if current else None, days=days),
        "can_upload": has_capability(request.user, "dmarc_upload"), "collection": dmarcstats.collection(settings.DMARC_ENABLED)})


@require_capability("dmarc_upload")
def dmarc_upload(request):
    """Add reports by hand: download the attachments from your rua mailbox and drop them here. Audited; nothing raw is kept."""
    results = []
    if request.method == "POST":
        files = request.FILES.getlist("reports")
        if not files:
            messages.error(request, "Choose at least one report file.")
            return redirect("dmarc_upload")
        if len(files) > dmarc_upload_mod.MAX_FILES:
            messages.error(request, f"At most {dmarc_upload_mod.MAX_FILES} files at a time.")
            return redirect("dmarc_upload")
        results = dmarc_upload_mod.ingest(files, request.user.email)
        count = lambda st: sum(r.status == st for r in results)  # noqa: E731
        record("dmarc.uploaded", request=request, details={"files": len(results), "added": count("added"), "duplicates": count("duplicate"),
                                                          "errors": count("error"), "domains": sorted({r.domain for r in results if r.domain})})
    return render(request, "inbound/dmarc_upload.html", {"results": results, "watched": sorted(dmarc_upload_mod.watched_domains()),
                                                         "max_files": dmarc_upload_mod.MAX_FILES, "max_mb": dmarc_upload_mod.MAX_FILE_BYTES // 1024 // 1024})
