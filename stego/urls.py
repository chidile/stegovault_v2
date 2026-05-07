from django.urls import path
from . import views

urlpatterns = [
    path("",               views.index,              name="index"),
    path("encode/",        views.EncodeView.as_view(), name="encode"),
    path("decode/",        views.DecodeView.as_view(), name="decode"),
    path("api/capacity/",  views.CapacityView.as_view(),  name="capacity"),
    path("api/check-lock/",views.CheckLockView.as_view(), name="check_lock"),
    path("export/txt/",    views.ExportTxtView.as_view(), name="export_txt"),
    path("export/pdf/",    views.ExportPdfView.as_view(), name="export_pdf"),
]
