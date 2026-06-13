from rest_framework import generics, permissions, status
from rest_framework.response import Response
from .models import Scan
from .serializers import ScanSerializer, ScanDetailSerializer
from .tasks import execute_vulnerability_scan

class ScanListCreateView(generics.ListCreateAPIView):
    serializer_class = ScanSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        return Scan.objects.filter(user=self.request.user).order_by('-started_at')
        
    def perform_create(self, serializer):
        scan = serializer.save(user=self.request.user, status='pending')
        # Enqueue Celery Task asynchronously
        execute_vulnerability_scan.delay(scan.id)

class ScanDetailDestroyView(generics.RetrieveDestroyAPIView):
    permission_classes = [permissions.IsAuthenticated]
    
    def get_serializer_class(self):
        if self.request.method == 'DELETE':
            return ScanSerializer
        return ScanDetailSerializer
        
    def get_queryset(self):
        return Scan.objects.filter(user=self.request.user)
        
    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        self.perform_destroy(instance)
        return Response({"message": "Scan deleted successfully"}, status=status.HTTP_200_OK)
