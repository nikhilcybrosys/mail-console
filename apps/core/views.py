import hmac
import logging
import time

from django.conf import settings
from django.http import Http404, HttpResponse, HttpResponseNotModified
from django.views.decorators.http import require_GET

from .branding import accent_tones, contrast_with_white, current, usable_accent  # noqa: F401 (contrast_with_white is re-exported)
from .models import BrandImage

log = logging.getLogger(__name__)


@require_GET
def theme_css(request):
    """Same-origin brand override, so white-labelling works under `style-src 'self'`.

    The accent (from Settings > Appearance, else MC_BRAND_ACCENT) is validated as #RRGGBB (no CSS injection is possible) and must
    keep white button text at WCAG AA (4.5:1); otherwise it is ignored rather than shipping an unreadable UI. Everything derived
    from it (hover, tints, focus ring, accent text) is computed here for both themes.
    """
    raw = current(request)["accent"]
    accent, css = usable_accent(raw), ""
    if raw and not accent:
        log.warning("The brand accent was ignored: it is not #RRGGBB, or white text on it is below 4.5:1")
    if accent:
        t = accent_tones(accent)
        css = (f":root,[data-theme]{{--accent:{t['accent']};--accent-hover:{t['hover']};--btn-primary:{t['accent']};--btn-primary-hover:{t['hover']}}}\n"
               f":root,[data-theme=\"light\"]{{--accent-text:{t['light_text']};--accent-soft:{t['light_soft']};--ring:{t['light_soft']}}}\n"
               f"[data-theme=\"dark\"]{{--accent-text:{t['dark_text']};--accent-soft:{t['dark_soft']};--ring:{t['dark_ring']}}}\n")
    resp = HttpResponse(css, content_type="text/css; charset=utf-8")
    resp["Cache-Control"] = "public, max-age=300"
    return resp


@require_GET
def brand_image(request, kind):
    """An uploaded logo or favicon. Public (the sign-in page shows it). The type is the one recorded when the file was checked,
    never guessed; `nosniff` and a locked-down policy mean it can only ever be displayed, never run."""
    img = BrandImage.objects.filter(kind=kind).first()
    if img is None:
        raise Http404
    etag = f'"{img.sha256}"'
    resp = HttpResponseNotModified() if request.META.get("HTTP_IF_NONE_MATCH") == etag else HttpResponse(bytes(img.data), content_type=img.content_type)
    resp["ETag"] = etag
    resp["Cache-Control"] = "public, max-age=86400"
    resp["X-Content-Type-Options"] = "nosniff"
    resp["Content-Security-Policy"] = "default-src 'none'; style-src 'unsafe-inline'; sandbox"
    return resp


_METRICS_CACHE = {"at": 0.0, "body": ""}


@require_GET
def metrics_view(request):
    """Prometheus scrape endpoint. Not found unless MC_METRICS_TOKEN is set, then bearer-token only (no session, no cookies).

    A scrape is not a person acting, so successful scrapes are not written to the audit log (one row per scrape would
    bury it); a bad token is logged. The body is cached briefly so scrapers cannot turn this into database load.
    """
    token = settings.METRICS_TOKEN
    if not token:
        raise Http404
    header = request.META.get("HTTP_AUTHORIZATION", "")
    given = header[7:].strip() if header[:7].lower() == "bearer " else ""
    if not given or not hmac.compare_digest(given.encode(), token.encode()):
        log.warning("metrics: rejected a scrape with a missing or wrong token")
        resp = HttpResponse("unauthorized\n", status=401, content_type="text/plain")
        resp["WWW-Authenticate"] = "Bearer"
        return resp
    now = time.monotonic()
    if now - _METRICS_CACHE["at"] >= settings.METRICS_CACHE_SECONDS or not _METRICS_CACHE["body"]:
        from apps.core.prom import render
        from apps.sesdata.promstats import collect
        _METRICS_CACHE.update(at=now, body=render(collect()))
    resp = HttpResponse(_METRICS_CACHE["body"], content_type="text/plain; version=0.0.4; charset=utf-8")
    resp["Cache-Control"] = "no-store"
    return resp
