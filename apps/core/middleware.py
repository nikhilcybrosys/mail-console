"""Security middleware: CSP with per-request nonce, and mailview host isolation."""
import secrets

from django.conf import settings
from django.http import HttpResponseNotFound


class HealthCheckMiddleware:
    """Answer GET /healthz/ with 200 for any Host header, touching nothing else.

    Load-balancer and container health checks send the task's IP as Host, which host validation would reject.
    It sits first in MIDDLEWARE so it runs before the SSL redirect, the session and the database.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.path == "/healthz/" and request.method in ("GET", "HEAD"):
            from django.http import HttpResponse
            resp = HttpResponse("ok", content_type="text/plain")
            resp["Cache-Control"] = "no-store"
            return resp
        return self.get_response(request)


class SecurityHeadersMiddleware:
    """Strict CSP (nonce-based, no inline script), plus hardening headers.

    The mailview host gets its own, even stricter CSP from the renderer view
    (it sets Content-Security-Policy itself), which this middleware never overrides.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        request.csp_nonce = secrets.token_urlsafe(18)
        response = self.get_response(request)
        if "Content-Security-Policy" not in response:
            mailview = f"https://{settings.MAILVIEW_HOST}" if not settings.DEBUG else f"http://{settings.MAILVIEW_HOST}:8000"
            response["Content-Security-Policy"] = "; ".join([
                "default-src 'none'",
                f"script-src 'self' 'nonce-{request.csp_nonce}'",
                "style-src 'self'",
                "img-src 'self' data:",
                "font-src 'self'",
                "connect-src 'self'",
                f"frame-src {mailview}",
                "form-action 'self'",
                "base-uri 'none'",
                "frame-ancestors 'none'",
            ])
        response.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
        response.setdefault("Cross-Origin-Resource-Policy", "same-origin")
        # Console pages are per-user and sensitive: never cache.
        if not request.path.startswith("/static/"):
            response.setdefault("Cache-Control", "no-store")
        return response


class HostRoutingMiddleware:
    """The mailview origin serves ONLY /mailview/*; the console origin never serves it.

    Keeps untrusted-mail HTML on a separate registrable domain with no cookies.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        host = request.get_host().split(":")[0]
        is_mailview_host = host == settings.MAILVIEW_HOST.split(":")[0]
        on_mailview_path = request.path.startswith("/mailview/")
        if is_mailview_host and not on_mailview_path:
            return HttpResponseNotFound()
        if on_mailview_path and not is_mailview_host:
            return HttpResponseNotFound()
        return self.get_response(request)
