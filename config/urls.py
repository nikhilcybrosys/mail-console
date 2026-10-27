from django.urls import include, path

from apps.core import views as core_views

urlpatterns = [
    path("theme.css", core_views.theme_css, name="theme_css"),
    path("brand/logo", core_views.brand_image, {"kind": "logo"}, name="brand_logo"),
    path("brand/logo-dark", core_views.brand_image, {"kind": "logo_dark"}, name="brand_logo_dark"),
    path("brand/favicon", core_views.brand_image, {"kind": "favicon"}, name="brand_favicon"),
    path("metrics", core_views.metrics_view, name="metrics"),
    path("", include("apps.accounts.urls")),
    path("", include("apps.inbound.urls")),
    path("", include("apps.compose.urls")),
    path("", include("apps.console.urls")),
]
