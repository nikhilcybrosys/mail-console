"""AWS access for the console.

READ: the web/worker task role (read-only, always on). Calls are throttled in-process
because SES control-plane calls are rate limited (~1 TPS, see docs/phase0/verify-findings.md).

WRITE: never with the task role. Each approved action assumes one of two write roles via STS
with SourceIdentity = the acting user's email, so CloudTrail attributes the call to a person.
The console roles carry an explicit Deny on every ses:Send* action (see infra permissions boundary).

Classes take a boto3-style client so tests can inject fakes/moto.
"""
import threading
import time

import boto3
from django.conf import settings


class Throttle:
    def __init__(self, min_interval=1.1):
        self.min_interval = min_interval
        self._last = 0.0
        self._lock = threading.Lock()

    def wait(self):
        with self._lock:
            delta = time.monotonic() - self._last
            if delta < self.min_interval:
                time.sleep(self.min_interval - delta)
            self._last = time.monotonic()


_THROTTLE = Throttle()


def _paginate(call, key, **kw):
    token = None
    while True:
        _THROTTLE.wait()
        resp = call(**kw, **({"NextToken": token} if token else {}))
        yield from resp.get(key, [])
        token = resp.get("NextToken")
        if not token:
            return


class SesReader:
    def __init__(self, client, cloudwatch=None, throttle=True):
        self.c = client
        self.cw = cloudwatch
        self._t = _THROTTLE if throttle else Throttle(0)

    def _call(self, name, **kw):
        self._t.wait()
        return getattr(self.c, name)(**kw)

    def get_account(self):
        return self._call("get_account")

    def list_identities(self):
        return list(_paginate(self.c.list_email_identities, "EmailIdentities", PageSize=100))

    def get_identity(self, name):
        return self._call("get_email_identity", EmailIdentity=name)

    def list_config_sets(self):
        resp = list(_paginate(self.c.list_configuration_sets, "ConfigurationSets", PageSize=100))
        return resp

    def get_config_set(self, name):
        return self._call("get_configuration_set", ConfigurationSetName=name)

    def get_event_destinations(self, name):
        return self._call("get_configuration_set_event_destinations", ConfigurationSetName=name).get("EventDestinations", [])

    def iter_suppressed(self, reason=None, start=None, end=None):
        kw = {"PageSize": 1000}
        if reason:
            kw["Reasons"] = [reason]
        if start:
            kw["StartDate"] = start
        if end:
            kw["EndDate"] = end
        yield from _paginate(self.c.list_suppressed_destinations, "SuppressedDestinationSummaries", **kw)

    def get_suppressed(self, address):
        try:
            return self._call("get_suppressed_destination", EmailAddress=address)["SuppressedDestination"]
        except self.c.exceptions.NotFoundException:
            return None

    def message_insights(self, message_id):
        return self._call("get_message_insights", MessageId=message_id)

    def reputation(self, region, minutes=1440):
        """Authoritative bounce/complaint rate from CloudWatch (AWS/SES Reputation.*)."""
        if self.cw is None:
            return {}
        from datetime import datetime, timedelta, timezone
        end = datetime.now(timezone.utc)
        resp = self.cw.get_metric_data(
            MetricDataQueries=[
                {"Id": "b", "MetricStat": {"Metric": {"Namespace": "AWS/SES", "MetricName": "Reputation.BounceRate"}, "Period": 3600, "Stat": "Maximum"}},
                {"Id": "c", "MetricStat": {"Metric": {"Namespace": "AWS/SES", "MetricName": "Reputation.ComplaintRate"}, "Period": 3600, "Stat": "Maximum"}},
            ],
            StartTime=end - timedelta(minutes=minutes), EndTime=end,
        )
        out = {}
        for r in resp.get("MetricDataResults", []):
            vals = r.get("Values", [])
            out["bounce_rate" if r["Id"] == "b" else "complaint_rate"] = vals[0] if vals else None
        return out


class SesWriter:
    """Constructed per action with an STS-assumed client; see `assume_writer`."""

    def __init__(self, client):
        self.c = client

    # suppression
    def delete_suppressed(self, address):
        _THROTTLE.wait()
        self.c.delete_suppressed_destination(EmailAddress=address)

    def put_suppressed(self, address, reason):
        _THROTTLE.wait()
        self.c.put_suppressed_destination(EmailAddress=address, Reason=reason)

    def bulk_suppression(self, action, s3_url, fmt="CSV"):
        _THROTTLE.wait()
        return self.c.create_import_job(
            ImportDestination={"SuppressionListDestination": {"SuppressionListImportAction": action}},
            ImportDataSource={"S3Url": s3_url, "DataFormat": fmt},
        )

    # identities
    def delete_identity(self, identity):
        _THROTTLE.wait()
        self.c.delete_email_identity(EmailIdentity=identity)

    def put_dkim_attributes(self, identity, signing_enabled):
        _THROTTLE.wait()
        self.c.put_email_identity_dkim_attributes(EmailIdentity=identity, SigningEnabled=signing_enabled)

    def put_dkim_signing(self, identity, **kw):
        _THROTTLE.wait()
        self.c.put_email_identity_dkim_signing_attributes(EmailIdentity=identity, **kw)

    def put_mail_from(self, identity, domain, behavior):
        _THROTTLE.wait()
        self.c.put_email_identity_mail_from_attributes(
            EmailIdentity=identity, MailFromDomain=domain, BehaviorOnMxFailure=behavior)

    def put_identity_default_config_set(self, identity, config_set):
        _THROTTLE.wait()
        self.c.put_email_identity_configuration_set_attributes(EmailIdentity=identity, ConfigurationSetName=config_set)

    # account
    def put_account_sending(self, enabled):
        _THROTTLE.wait()
        self.c.put_account_sending_attributes(SendingEnabled=enabled)

    def put_account_suppression(self, reasons):
        _THROTTLE.wait()
        self.c.put_account_suppression_attributes(SuppressedReasons=reasons)

    # event destinations
    def create_event_destination(self, config_set, name, definition):
        _THROTTLE.wait()
        self.c.create_configuration_set_event_destination(
            ConfigurationSetName=config_set, EventDestinationName=name, EventDestination=definition)

    def update_event_destination(self, config_set, name, definition):
        _THROTTLE.wait()
        self.c.update_configuration_set_event_destination(
            ConfigurationSetName=config_set, EventDestinationName=name, EventDestination=definition)

    def delete_event_destination(self, config_set, name):
        _THROTTLE.wait()
        self.c.delete_configuration_set_event_destination(ConfigurationSetName=config_set, EventDestinationName=name)

    # templates
    def put_template(self, name, subject, html, text, create):
        _THROTTLE.wait()
        content = {"Subject": subject, "Html": html, "Text": text}
        fn = self.c.create_email_template if create else self.c.update_email_template
        fn(TemplateName=name, TemplateContent=content)

    def delete_template(self, name):
        _THROTTLE.wait()
        self.c.delete_email_template(TemplateName=name)


class SesSender:
    """Can send ONE message at a time and nothing else: there is deliberately no bulk, raw or templated send here.

    Built from credentials of the separate send role (see `assume_sender`), whose AWS policy allows only ses:SendEmail,
    only from listed addresses and only for named people.
    """

    def __init__(self, client):
        self.c = client

    def send(self, *, from_address, to, cc, bcc, reply_to, subject, text, html, config_set):
        dest = {"ToAddresses": list(to)}
        if cc:
            dest["CcAddresses"] = list(cc)
        if bcc:
            dest["BccAddresses"] = list(bcc)
        kwargs = dict(
            FromEmailAddress=from_address, Destination=dest, ConfigurationSetName=config_set,
            Content={"Simple": {"Subject": {"Data": subject, "Charset": "UTF-8"},
                                "Body": {"Text": {"Data": text, "Charset": "UTF-8"}, "Html": {"Data": html, "Charset": "UTF-8"}}}},
            EmailTags=[{"Name": "mc-app", "Value": "compose"}])  # shows as the app in Sent mail
        if reply_to:
            kwargs["ReplyToAddresses"] = [reply_to]
        return self.c.send_email(**kwargs)["MessageId"]


TIERS = {"ops": "AWS_WRITE_ROLE_OPS_ARN", "security": "AWS_WRITE_ROLE_SECURITY_ARN"}


def reader(region):
    """Factory for the read client (task role credentials)."""
    return SesReader(boto3.client("sesv2", region_name=region), boto3.client("cloudwatch", region_name=region))


def assume_writer(region, tier, acting_email, request_id):
    """STS-assume the write role for ONE action, attributed to a person via SourceIdentity."""
    role_arn = getattr(settings, TIERS[tier])
    if not role_arn:
        raise RuntimeError(f"No write role configured for tier {tier!r}")
    kwargs = dict(RoleArn=role_arn, RoleSessionName=f"mc-{request_id}"[:64], SourceIdentity=acting_email,
                  DurationSeconds=settings.AWS_ASSUME_SESSION_SECONDS)
    if settings.AWS_WRITE_ROLE_EXTERNAL_ID:
        kwargs["ExternalId"] = settings.AWS_WRITE_ROLE_EXTERNAL_ID
    resp = boto3.client("sts").assume_role(**kwargs)
    c = resp["Credentials"]
    client = boto3.client(
        "sesv2", region_name=region, aws_access_key_id=c["AccessKeyId"],
        aws_secret_access_key=c["SecretAccessKey"], aws_session_token=c["SessionToken"],
    )
    return SesWriter(client)


def assume_sender(region, acting_email, request_id):
    """STS-assume the SEND role for one message, attributed to a person via SourceIdentity (and the shared ExternalId).

    The send client does not retry: SES has no idempotency token, so an automatic retry after a lost response could mail
    the same message twice. A lost response is surfaced to the caller instead, who must check Sent mail before resending.
    """
    from botocore.config import Config

    role_arn = settings.AWS_SEND_ROLE_ARN
    if not role_arn:
        raise RuntimeError("No send role configured")
    kwargs = dict(RoleArn=role_arn, RoleSessionName=f"mc-send-{request_id}"[:64], SourceIdentity=acting_email,
                  DurationSeconds=settings.AWS_ASSUME_SESSION_SECONDS)
    if settings.AWS_WRITE_ROLE_EXTERNAL_ID:
        kwargs["ExternalId"] = settings.AWS_WRITE_ROLE_EXTERNAL_ID
    c = boto3.client("sts").assume_role(**kwargs)["Credentials"]
    client = boto3.client(
        "sesv2", region_name=region, aws_access_key_id=c["AccessKeyId"], aws_secret_access_key=c["SecretAccessKey"],
        aws_session_token=c["SessionToken"], config=Config(retries={"mode": "standard", "max_attempts": 1}, connect_timeout=5, read_timeout=20))
    return SesSender(client)
