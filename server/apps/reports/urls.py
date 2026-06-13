from django.urls import path
from .views import DownloadPDFReportView

urlpatterns = [
    path('scans/<int:scan_id>/pdf', DownloadPDFReportView.as_view(), name='download_pdf_report'),
]
