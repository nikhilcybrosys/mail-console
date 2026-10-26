"""Long-running worker: copy every message in the SES archive into a Google Workspace mailbox (see archive_sync.py)."""
import logging
import pathlib
import time

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from apps.sesdata import archive_sync

log = logging.getLogger(__name__)


class Command(BaseCommand):
    help = "Copy archived mail into the configured Google Workspace mailbox"

    def add_arguments(self, parser):
        parser.add_argument("--once", action="store_true", help="Run one pass and exit (tests/ops)")

    def handle(self, *args, once, **opts):
        if not settings.ARCHIVE_SYNC_ENABLED:
            raise CommandError("The mailbox copy is off: set MC_ARCHIVE_SYNC_MAILBOX, a Google credential and MC_MAIL_ARCHIVE_ID")
        while True:
            try:  # the container health check fails if this file stops being refreshed
                pathlib.Path(settings.WORKER_HEARTBEAT_FILE).touch()
            except OSError:
                pass
            try:
                stats = archive_sync.Sync().run_once()
                self.stdout.write(f"archive sync: {stats}")
            except Exception:  # noqa: BLE001: AWS or Google trouble: logged, and the next pass tries again
                log.exception("archive sync pass failed")
            if once:
                return
            time.sleep(settings.ARCHIVE_SYNC_INTERVAL)
