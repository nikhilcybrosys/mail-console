"""Absolute + idle session limits, enforced server-side regardless of cookie age."""
import time

from django.conf import settings
from django.contrib.auth import logout


class SessionHardeningMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.user.is_authenticated:
            now = time.time()
            started = request.session.setdefault("session_started", now)
            last = request.session.get("last_seen", now)
            if now - started > settings.SESSION_COOKIE_AGE or now - last > settings.SESSION_IDLE_TIMEOUT:
                logout(request)
            else:
                request.session["last_seen"] = now
        return self.get_response(request)
