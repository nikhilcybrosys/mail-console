"""Register the AWS account the console watches. `sync_ses_state` does nothing until one is registered."""
import re

from django.core.management.base import BaseCommand, CommandError

from apps.audit.service import record
from apps.sesdata.models import AwsAccount


class Command(BaseCommand):
    help = "Register (or update) the AWS account whose SES state the console syncs"

    def add_arguments(self, parser):
        parser.add_argument("alias", help="A short label, for example 'main'")
        parser.add_argument("account_id", help="The 12-digit AWS account id")

    def handle(self, *args, alias, account_id, **opts):
        if not re.fullmatch(r"\d{12}", account_id):
            raise CommandError("account_id must be exactly 12 digits")
        acct, created = AwsAccount.objects.update_or_create(alias=alias, defaults={"aws_account_id": account_id, "enabled": True})
        record("aws_account.registered", target=alias, details={"aws_account_id": account_id, "created": created})
        self.stdout.write(f"{'registered' if created else 'updated'} {alias} ({account_id})")
