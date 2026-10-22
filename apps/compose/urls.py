from django.urls import path

from . import views

urlpatterns = [
    path("compose/", views.home, name="compose"),
    path("compose/new/", views.edit, name="compose_new"),
    path("compose/senders/", views.senders, name="compose_senders"),
    path("compose/<int:pk>/", views.edit, name="compose_edit"),
    path("compose/<int:pk>/preview/", views.preview, name="compose_preview"),
    path("compose/<int:pk>/send/", views.send_view, name="compose_send"),
    path("compose/<int:pk>/delete/", views.delete, name="compose_delete"),
    path("compose/<int:pk>/release/", views.release, name="compose_release"),
]
