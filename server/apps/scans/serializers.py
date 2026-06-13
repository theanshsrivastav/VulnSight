from rest_framework import serializers
from .models import Scan
from apps.vulnerabilities.serializers import VulnerabilitySerializer

class ScanSerializer(serializers.ModelSerializer):
    class Meta:
        model = Scan
        fields = ('id', 'target_url', 'scan_type', 'status', 'started_at', 'completed_at')
        read_only_fields = ('id', 'status', 'started_at', 'completed_at')

class ScanDetailSerializer(serializers.ModelSerializer):
    vulnerabilities = VulnerabilitySerializer(many=True, read_only=True)
    
    class Meta:
        model = Scan
        fields = ('id', 'target_url', 'scan_type', 'status', 'started_at', 'completed_at', 'vulnerabilities')
