"""Scheduled task (every ~5 min): poll SES state, run DNS checks, evaluate alerts, notify."""
import logging

from django.conf import settings
from django.core.management.base import BaseCommand

from apps.audit.service import record
from apps.sesdata import alerts, aws, dns, sync
from apps.sesdata.models import AwsAccount

log = logging.getLogger(__name__)


class Command(BaseCommand):
    help = "Sync SES account/identity/config-set/suppression state and evaluate alerts"

    def add_arguments(self, parser):
        parser.add_argument("--skip-dns", action="store_true")
        parser.add_argument("--skip-suppression", action="store_true")

    def handle(self, *args, skip_dns, skip_suppression, **opts):
        try:  # stored text of Compose mail ages out (and is blanked at once if keeping it is switched off)
            from apps.compose.service import prune_bodies
            blanked = prune_bodies()
            if blanked:
                log.info("blanked the stored text of %s sent mails", blanked)
        except Exception:
            log.exception("pruning stored mail text failed")
        account = AwsAccount.objects.filter(enabled=True).first()
        if not account:
            self.stderr.write("No AwsAccount registered (create one in the admin shell).")
            return
        for region in settings.AWS_REGIONS:
            reader = aws.reader(region)
            try:
                sync.sync_account(reader, account.aws_account_id, region)
                ids = sync.sync_identities(reader, account.aws_account_id, region)
                sync.sync_config_sets(reader, account.aws_account_id, region)
                if not skip_suppression:
                    a, r = sync.sync_suppression(reader, account.aws_account_id, region)
                    log.info("suppression sync %s: +%s -%s", region, a, r)
                if not skip_dns:
                    for snap in ids:
                        dns.check_identity(snap)
            except Exception:
                log.exception("sync failed for %s", region)
                record("sync.failed", details={"region": region})
        summary = alerts.evaluate()
        sent = alerts.notify_pending()
        self.stdout.write(f"alerts: {summary}, notified {sent}")
