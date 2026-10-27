from django.db import models


class Branding(models.Model):
    """The console's look, edited in Settings > Appearance. One row (pk=1); no row means the MC_BRAND_* defaults apply.

    Every text field is plain text and is escaped wherever it is shown. A blank field means "use the default".
    """

    THEMES = [("system", "Match the device"), ("light", "Light"), ("dark", "Dark")]
    DENSITIES = [("compact", "Compact"), ("comfortable", "Comfortable")]

    name = models.CharField(max_length=40, blank=True)
    login_text = models.CharField(max_length=160, blank=True)
    footer_text = models.CharField(max_length=200, blank=True)
    accent = models.CharField(max_length=7, blank=True)
    default_theme = models.CharField(max_length=10, choices=THEMES, default="system")
    default_density = models.CharField(max_length=12, choices=DENSITIES, default="compact")
    updated_at = models.DateTimeField(auto_now=True)
    updated_by = models.CharField(max_length=254, blank=True)


class BrandImage(models.Model):
    """An uploaded logo or favicon, kept in the database so the container needs no writable disk. Checked before it is saved
    (apps/core/branding.py); `content_type` is one of three fixed values and is what the browser is told, never the upload's own claim."""

    LOGO, LOGO_DARK, FAVICON = "logo", "logo_dark", "favicon"
    KINDS = [(LOGO, "Logo"), (LOGO_DARK, "Logo for dark theme"), (FAVICON, "Favicon")]

    kind = models.CharField(max_length=12, choices=KINDS, unique=True)
    data = models.BinaryField()
    content_type = models.CharField(max_length=24)
    sha256 = models.CharField(max_length=64)
    updated_at = models.DateTimeField(auto_now=True)
