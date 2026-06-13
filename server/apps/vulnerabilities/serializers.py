from rest_framework import serializers
from .models import Vulnerability
from apps.ai_remediation.models import AIRemediation

class AIRemediationSerializer(serializers.ModelSerializer):
    class Meta:
        model = AIRemediation
        fields = ('explanation', 'impact', 'fix_recommendation', 'secure_coding')

class VulnerabilitySerializer(serializers.ModelSerializer):
    ai_remediation = AIRemediationSerializer(read_only=True)
    
    class Meta:
        model = Vulnerability
        fields = (
            'id', 'vulnerability_type', 'severity', 'description', 
            'affected_url', 'evidence', 'remediation', 'ai_remediation', 'created_at'
        )
