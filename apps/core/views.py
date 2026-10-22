import hmac
import logging
import time

from django.conf import settings
from django.http import Http404, HttpResponse
from django.views.decorators.http import require_GET

log = logging.getLogger(__name__)


def _lum(hex_color):
    def chan(c):
        c /= 255
        return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4
    r, g, b = (int(hex_color[i:i + 2], 16) for i in (1, 3, 5))
    return 0.2126 * chan(r) + 0.7152 * chan(g) + 0.0722 * chan(b)


def contrast_with_white(hex_color):
    return 1.05 / (_lum(hex_color) + 0.05)


def _darken(hex_color, factor=0.88):
    return "#" + "".join(f"{int(int(hex_color[i:i + 2], 16) * factor):02X}" for i in (1, 3, 5))


@require_GET
def theme_css(request):
    """Same-origin brand override, so white-labelling works under `style-src 'self'`.

    The accent is validated as #RRGGBB (no CSS injection is possible) and must keep white button text
    at WCAG AA (4.5:1); otherwise it is ignored with a warning rather than shipping an unreadable UI.
    """
    import re
    accent, css = settings.BRAND_ACCENT, ""
    if accent:
        if not re.fullmatch(r"#[0-9a-fA-F]{6}", accent):
            log.warning("MC_BRAND_ACCENT ignored: not a #RRGGBB colour")
        elif contrast_with_white(accent) < 4.5:
            log.warning("MC_BRAND_ACCENT ignored: white text on it is below 4.5:1")
        else:
            hover = _darken(accent)
            css = f":root,[data-theme]{{--accent:{accent};--btn-primary:{accent};--btn-primary-hover:{hover};--accent-text:{_darken(accent, 0.8)}}}\n"
    resp = HttpResponse(css, content_type="text/css; charset=utf-8")
    resp["Cache-Control"] = "public, max-age=300"
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
