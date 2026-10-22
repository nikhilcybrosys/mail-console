from django.urls import path

from . import views

urlpatterns = [
    path("compose/", views.home, name="compose"),
    path("compose/new/", views.edit, name="compose_new"),
    path("compose/senders/", views.senders, name="compose_senders"),
    path("compose/templates/new/", views.template_new, name="compose_template_new"),
    path("compose/templates/<int:pk>/", views.template_edit, name="compose_template_edit"),
    path("compose/templates/<int:pk>/delete/", views.template_delete, name="compose_template_delete"),
    path("compose/templates/<int:pk>/use/", views.template_use, name="compose_template_use"),
    path("compose/<int:pk>/", views.edit, name="compose_edit"),
    path("compose/<int:pk>/preview/", views.preview, name="compose_preview"),
    path("compose/<int:pk>/send/", views.send_view, name="compose_send"),
    path("compose/<int:pk>/delete/", views.delete, name="compose_delete"),
    path("compose/<int:pk>/release/", views.release, name="compose_release"),
]
