from django.urls import include, path

from apps.core import views as core_views

urlpatterns = [
    path("theme.css", core_views.theme_css, name="theme_css"),
    path("metrics", core_views.metrics_view, name="metrics"),
    path("", include("apps.accounts.urls")),
    path("", include("apps.inbound.urls")),
    path("", include("apps.console.urls")),
]
