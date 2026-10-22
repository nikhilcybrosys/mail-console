import time

from django.conf import settings
from django.contrib.auth.base_user import AbstractBaseUser, BaseUserManager
from django.db import models
from django.utils import timezone

from apps.core.rbac import ROLES, VIEWER


class UserManager(BaseUserManager):
    def create_user(self, email, role=VIEWER, **extra):
        email = email.strip().lower()
        if role not in ROLES:
            raise ValueError(f"Unknown role {role!r}")
        user = self.model(email=email, role=role, **extra)
        user.set_unusable_password()  # SSO only; no local passwords
        user.save(using=self._db)
        return user


class User(AbstractBaseUser):
    email = models.EmailField(unique=True)
    name = models.CharField(max_length=200, blank=True)
    role = models.CharField(max_length=32, choices=[(r, r) for r in ROLES], default=VIEWER)
    is_active = models.BooleanField(default=True)
    # Optional scope: restrict to these From-domains (empty list = all domains).
    scope_domains = models.JSONField(default=list, blank=True)
    # Break-glass elevation: time-boxed, reason-required, alerts on use (see accounts.services).
    break_glass_role = models.CharField(max_length=32, blank=True)
    break_glass_until = models.DateTimeField(null=True, blank=True)
    break_glass_reason = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    # Bound to the identity provider's stable (issuer, subject) on first sign-in, so a later change of the e-mail
    # address at the provider (or a provider that lets users assert any e-mail) cannot take over this account.
    oidc_issuer = models.CharField(max_length=255, blank=True)
    oidc_subject = models.CharField(max_length=255, blank=True)

    USERNAME_FIELD = "email"
    objects = UserManager()

    class Meta:
        constraints = [models.UniqueConstraint(fields=["oidc_issuer", "oidc_subject"], condition=~models.Q(oidc_subject=""), name="uniq_oidc_identity")]

    def __str__(self):
        return self.email

    @property
    def effective_role(self):
        if self.break_glass_role and self.break_glass_until and self.break_glass_until > timezone.now():
            return self.break_glass_role
        return self.role

    def has_fresh_step_up(self, session):
        at = session.get("step_up_at")
        return bool(at) and (time.time() - at) <= settings.STEP_UP_MAX_AGE

    def in_scope(self, domain):
        return not self.scope_domains or (domain or "").lower() in {d.lower() for d in self.scope_domains}


class WebAuthnCredential(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="passkeys")
    name = models.CharField(max_length=100, default="passkey")
    credential_data = models.BinaryField()  # serialized fido2 AttestedCredentialData
    created_at = models.DateTimeField(auto_now_add=True)
    last_used_at = models.DateTimeField(null=True, blank=True)


class SavedView(models.Model):
    """A named set of sent-mail filters, private to one person. `params` is a canonical, whitelisted query string."""

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="saved_views")
    name = models.CharField(max_length=80)
    params = models.CharField(max_length=500, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["name"]
        constraints = [models.UniqueConstraint(fields=["user", "name"], name="uniq_saved_view_name_per_user")]
