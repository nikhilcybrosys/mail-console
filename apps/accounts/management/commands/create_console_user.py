from django.core.management.base import BaseCommand, CommandError

from apps.accounts.models import User
from apps.audit.service import record
from apps.core.rbac import ROLES


class Command(BaseCommand):
    help = "Provision (or update the role of) a console user. SSO only: no password is set."

    def add_arguments(self, parser):
        parser.add_argument("email")
        parser.add_argument("--role", default="viewer", choices=ROLES)
        parser.add_argument("--name", default="")
        parser.add_argument("--reset-identity", action="store_true", help="Forget the bound identity-provider account so the next sign-in re-binds it")

    def handle(self, *args, email, role, name, reset_identity=False, **opts):
        email = email.strip().lower()
        if "@" not in email:
            raise CommandError("invalid email")
        user, created = User.objects.get_or_create(email=email, defaults={"role": role, "name": name})
        if not created:
            user.role = role
            if name:
                user.name = name
            user.save()
        else:
            user.set_unusable_password()
            user.save()
        if reset_identity and not created:
            user.oidc_issuer = user.oidc_subject = ""
            user.save(update_fields=["oidc_issuer", "oidc_subject"])
            record("user.identity_reset", target=email)
        record("user.provisioned", target=email, details={"role": role, "created": created})
        self.stdout.write(f"{'created' if created else 'updated'} {email} as {role}")
