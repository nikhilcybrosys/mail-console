from django.urls import path

from . import views

urlpatterns = [
    path("login/", views.login_page, name="login"),
    path("oidc/start/", views.oidc_start, name="oidc_start"),
    path("oidc/callback/", views.oidc_callback, name="oidc_callback"),
    path("dev-login/", views.dev_login, name="dev_login"),
    path("logout/", views.logout_view, name="logout"),
    path("step-up/", views.step_up_page, name="step_up"),
    path("step-up/begin/", views.step_up_begin),
    path("step-up/complete/", views.step_up_complete),
    path("passkeys/register/begin/", views.passkey_register_begin),
    path("passkeys/register/complete/", views.passkey_register_complete),
]
