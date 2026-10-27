"""Settings > Appearance: change the console's name, logo, favicon, accent colour, default theme and density.

The page needs the passkey (like every other write) so a file chosen on it is never lost to a redirect, and every change is
audited. Nothing here touches AWS, so no second approver is asked for. Uploads are checked by apps/core/branding.py before
anything is saved; if any one is refused, nothing is saved.
"""
import base64

from django.conf import settings
from django.contrib import messages
from django.db import transaction
from django.shortcuts import redirect, render
from django.templatetags.static import static
from django.views.decorators.http import require_POST

from apps.audit.service import record
from apps.core import branding
from apps.core.models import BrandImage, Branding
from apps.core.rbac import require_capability

KINDS = [BrandImage.LOGO, BrandImage.LOGO_DARK, BrandImage.FAVICON]
LABELS = dict(BrandImage.KINDS)
TEXT_FIELDS = ["name", "login_text", "footer_text", "accent", "default_theme", "default_density"]
DEFAULTS = {"name": "", "login_text": "", "footer_text": "", "accent": "", "default_theme": "system", "default_density": "compact"}


def _read_form(request):
    """-> (values, uploads {kind: (raw, content_type)}, removes, errors). Nothing is saved here."""
    values, errors = branding.check_text_fields(request.POST)
    uploads, removes = {}, set()
    for kind in KINDS:
        f = request.FILES.get(kind)
        if f:
            raw = f.read(branding.MAX_IMAGE + 1)    # never reads more than the limit plus one byte; inspect_image refuses it
            try:
                uploads[kind] = (raw, branding.inspect_image(raw, kind))
            except branding.ImageRefused as exc:
                errors.append(f"{LABELS[kind]}: {exc}")
        elif request.POST.get(f"remove_{kind}") == "1":
            removes.add(kind)
    return values, uploads, removes, errors


def _stored_values():
    row = Branding.objects.first()
    return {f: getattr(row, f) if row else DEFAULTS[f] for f in TEXT_FIELDS}


def _preview(request, values, uploads=(), removes=()):
    """What the page would look like with these values. Uploaded files are shown as data: URIs (the CSP allows them), so
    nothing is stored to preview it."""
    cur = branding.current(request)
    stored = dict(BrandImage.objects.values_list("kind", "sha256"))
    eff = {}
    for kind in (BrandImage.LOGO, BrandImage.LOGO_DARK):
        if kind in uploads:
            raw, ct = uploads[kind]
            eff[kind] = f"data:{ct};base64,{base64.b64encode(raw).decode()}"
        elif kind in stored and kind not in removes:
            eff[kind] = cur["logo"] if kind == BrandImage.LOGO else cur["logo_dark"]
    accent = branding.usable_accent(values["accent"]) or branding.usable_accent(settings.BRAND_ACCENT) or branding.DEFAULT_ACCENT
    t = branding.accent_tones(accent)
    light = eff.get(BrandImage.LOGO) or static(settings.BRAND_LOGO)
    return {
        "name": values["name"] or settings.BRAND_NAME, "login_text": values["login_text"] or "", "footer_text": values["footer_text"],
        "logo": light, "logo_dark": eff.get(BrandImage.LOGO_DARK) or eff.get(BrandImage.LOGO) or static(settings.BRAND_LOGO_DARK),
        "accent": t["accent"], "soft": t["light_soft"], "text": t["light_text"],
        "dark_soft": t["dark_soft"], "dark_text": t["dark_text"],
    }


def _page(request, values, uploads=(), removes=(), errors=()):
    stored = dict(BrandImage.objects.values_list("kind", "sha256"))
    return render(request, "console/appearance.html", {
        "values": values, "errors": list(errors), "preview": _preview(request, values, uploads, removes),
        "themes": Branding.THEMES, "densities": Branding.DENSITIES, "defaults": {"name": settings.BRAND_NAME, "accent": branding.DEFAULT_ACCENT},
        "images": [{"kind": k, "label": LABELS[k], "set": k in stored, "formats": "PNG, ICO or SVG" if k == BrandImage.FAVICON else "PNG or SVG"} for k in KINDS],
        "customised": branding.current(request)["customised"], "max_kb": branding.MAX_IMAGE // 1024, "max_px": branding.MAX_PIXELS,
    })


@require_capability("manage_branding", step_up=True)
def appearance(request):
    if request.method != "POST":
        return _page(request, _stored_values())
    values, uploads, removes, errors = _read_form(request)
    if errors:
        return _page(request, values, uploads, removes, errors)
    with transaction.atomic():
        row = Branding.objects.filter(pk=1).first() or Branding(pk=1)    # saving the defaults on a fresh system creates nothing
        changed = {}
        for f in TEXT_FIELDS:
            if getattr(row, f) != values[f]:
                changed[f] = [getattr(row, f), values[f]]
                setattr(row, f, values[f])
        images = {}
        for kind in removes - set(uploads):
            if BrandImage.objects.filter(kind=kind).delete()[0]:
                images[kind] = "removed"
        for kind, (raw, ct) in uploads.items():
            sha = branding.digest(raw)
            BrandImage.objects.update_or_create(kind=kind, defaults={"data": raw, "content_type": ct, "sha256": sha})
            images[kind] = sha[:12]
        if changed or images:
            row.updated_by = request.user.email
            row.save()
    if not (changed or images):
        messages.info(request, "Nothing changed.")
        return redirect("appearance")
    record("branding.updated", request=request, target="appearance", details={"changed": changed, "images": images})
    messages.success(request, "Appearance saved. The new look is live for everyone.")
    return redirect("appearance")


@require_POST
@require_capability("manage_branding")
def appearance_preview(request):
    """A preview of the unsaved form (HTMX fragment). Changes nothing; refuses nothing the save would accept."""
    values, uploads, removes, errors = _read_form(request)
    return render(request, "console/_appearance_preview.html", {"p": _preview(request, values, uploads, removes), "errors": errors})


@require_POST
@require_capability("manage_branding", step_up=True)
def appearance_reset(request):
    with transaction.atomic():
        had = Branding.objects.all().delete()[0] + BrandImage.objects.all().delete()[0]
    if had:
        record("branding.reset", request=request, target="appearance")
        messages.success(request, "Appearance is back to the defaults.")
    else:
        messages.info(request, "Nothing to reset: the console already uses the defaults.")
    return redirect("appearance")
