"""Stream new audit rows to the Object Lock bucket as newline-delimited JSON.

Run on a schedule (ECS scheduled task). The bucket is COMPLIANCE-mode locked, so a
compromised app cannot rewrite history that has already been exported.
"""
import json

import boto3
from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from apps.audit.models import AuditExportCursor, AuditLog


class Command(BaseCommand):
    help = "Export un-exported audit rows to the audit S3 bucket"

    def add_arguments(self, parser):
        parser.add_argument("--batch", type=int, default=1000)
        parser.add_argument("--dry-run", action="store_true")

    def handle(self, *args, batch, dry_run, **opts):
        if not settings.AUDIT_BUCKET and not dry_run:
            raise CommandError("MC_AUDIT_BUCKET is not set")
        cursor, _ = AuditExportCursor.objects.get_or_create(pk=1)
        rows = list(AuditLog.objects.filter(id__gt=cursor.last_exported_id).order_by("id")[:batch])
        if not rows:
            self.stdout.write("nothing to export")
            return
        body = "\n".join(json.dumps({
            "id": r.id, "ts": r.ts.isoformat(), "actor": r.actor, "action": r.action, "target": r.target,
            "ip": r.ip, "user_agent": r.user_agent, "request_id": r.request_id, "details": r.details,
            "prev_hash": r.prev_hash, "row_hash": r.row_hash,
        }, sort_keys=True) for r in rows) + "\n"
        key = f"audit/{rows[0].ts:%Y/%m/%d}/{rows[0].id:012d}-{rows[-1].id:012d}.ndjson"
        if dry_run:
            self.stdout.write(f"would write {len(rows)} rows to {key}")
            return
        boto3.client("s3").put_object(
            Bucket=settings.AUDIT_BUCKET, Key=key, Body=body.encode(), ServerSideEncryption="aws:kms",
            ContentType="application/x-ndjson",
        )
        cursor.last_exported_id = rows[-1].id
        cursor.save()
        self.stdout.write(f"exported {len(rows)} rows to {key}")
