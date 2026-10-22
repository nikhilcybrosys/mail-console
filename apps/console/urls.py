from django.urls import path

from . import views

urlpatterns = [
    path("", views.dashboard, name="dashboard"),
    path("region/", views.set_region, name="set_region"),
    path("search/", views.global_search, name="search"),
    path("messages/", views.messages_list, name="messages"),
    path("search/palette/", views.palette, name="palette"),
    path("messages/<int:pk>/", views.message_detail, name="message_detail"),
    path("messages/<int:pk>/drawer/", views.message_drawer, name="message_drawer"),
    path("messages/<int:pk>/body/", views.message_body, name="message_body"),
    path("suppression/", views.suppression, name="suppression"),
    path("suppression/remove/", views.suppression_remove, name="suppression_remove"),
    path("identities/", views.identities, name="identities"),
    path("config-sets/", views.config_sets, name="config_sets"),
    path("alerts/", views.alerts_view, name="alerts"),
    path("alerts/test-notification/", views.alerts_test_channels, name="alerts_test_channels"),
    path("approvals/", views.approvals_queue, name="approvals"),
    path("approvals/<int:pk>/decide/", views.approval_decide, name="approval_decide"),
    path("audit/", views.audit_view, name="audit"),
    path("setup/", views.setup_check, name="setup_check"),
    path("setup/test-write-roles/", views.setup_test_write_roles, name="setup_test_write_roles"),
    path("users/", views.users_view, name="users"),
    path("users/<int:pk>/", views.user_update, name="user_update"),
]
