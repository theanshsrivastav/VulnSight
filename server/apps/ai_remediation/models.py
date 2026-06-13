from django.db import models

class AIRemediation(models.Model):
    vulnerability = models.OneToOneField(
        'vulnerabilities.Vulnerability',
        related_name='ai_remediation',
        on_delete=models.CASCADE
    )
    explanation = models.TextField()
    impact = models.TextField()
    fix_recommendation = models.TextField()
    secure_coding = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"AI Remediation for Vuln ID {self.vulnerability.id}"
