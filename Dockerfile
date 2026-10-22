# syntax=docker/dockerfile:1
# Two stages: dependencies are built in a throwaway stage, the runtime image has no compiler, no tests and no docs.

FROM python:3.12-slim-bookworm AS build
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /build
COPY requirements.lock .
RUN python -m venv /opt/venv && /opt/venv/bin/pip install --no-cache-dir --no-compile -r requirements.lock

FROM python:3.12-slim-bookworm
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PATH="/opt/venv/bin:${PATH}"
# Unprivileged user with no shell and no writable application directory.
RUN groupadd --system --gid 10001 app \
 && useradd --system --uid 10001 --gid app --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin app
WORKDIR /app
COPY --from=build /opt/venv /opt/venv
COPY manage.py LICENSE NOTICE THIRD_PARTY_NOTICES.md ./
COPY config ./config
COPY apps ./apps
COPY templates ./templates
COPY static ./static
COPY scripts ./scripts
# Collect static files at build time (WhiteNoise serves them). The key below exists only for this command.
RUN MC_SECRET_KEY=build-time-only-not-a-secret MC_DEBUG=0 python manage.py collectstatic --noinput \
 && chmod -R a+rX /app
USER 10001:10001
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz/', timeout=3)"]
# /dev/shm for worker heartbeat files keeps this working with a read-only root filesystem.
CMD ["gunicorn", "config.wsgi:application", "--bind", "0.0.0.0:8000", "--workers", "3", "--worker-tmp-dir", "/dev/shm", "--access-logfile", "-", "--error-logfile", "-"]
