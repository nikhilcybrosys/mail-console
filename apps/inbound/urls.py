from django.urls import path

from . import pages, views

urlpatterns = [
    path("mailview/<str:token>/", views.render_body, name="mailview"),
    path("inbox/", pages.inbox, name="inbox"),
    path("inbox/dmarc/", pages.dmarc_dashboard, name="dmarc"),
    path("inbox/dmarc/upload/", pages.dmarc_upload, name="dmarc_upload"),
    path("inbox/<int:pk>/", pages.inbound_detail, name="inbound_detail"),
    path("inbox/<int:pk>/body/", pages.inbound_body, name="inbound_body"),
    path("inbox/<int:pk>/attachments/<int:index>/", pages.attachment_download, name="inbound_attachment"),
]
