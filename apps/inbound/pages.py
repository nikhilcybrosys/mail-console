"""Console-side inbox pages (authenticated). Message content only ever leaves via the mailview origin."""
import re

import boto3
from django.conf import settings
from django.core.paginator import Paginator
from django.db.models import Sum
from django.http import Http404, HttpResponseBadRequest, HttpResponseRedirect
from django.shortcuts import get_object_or_404, render
from django.views.decorators.http import require_POST

from apps.audit.service import record
from apps.core.rbac import require_capability
from apps.sesdata.models import BodyAccessLog

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
    rows = DmarcReport.objects.values("domain", "policy").annotate(ok=Sum("pass_count"), bad=Sum("fail_count")).order_by("domain")
    failing = []
    for r in DmarcReport.objects.order_by("-end")[:200]:
        for row in r.rows:
            if row["dkim"] != "pass" and row["spf"] != "pass":
                failing.append({"domain": r.domain, "org": r.org_name, **row})
    return render(request, "inbound/dmarc.html", {"summary": rows, "failing": failing[:50]})
