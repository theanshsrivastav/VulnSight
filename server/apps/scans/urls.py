from django.urls import path
from .views import ScanListCreateView, ScanDetailDestroyView

urlpatterns = [
    path('', ScanListCreateView.as_view(), name='scan_list_create'),
    path('<int:pk>', ScanDetailDestroyView.as_view(), name='scan_detail_destroy'),
]
