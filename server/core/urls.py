from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/auth/', include('apps.authentication.urls')),
    path('api/scans/', include('apps.scans.urls')),
    path('api/reports/', include('apps.reports.urls')),
]
