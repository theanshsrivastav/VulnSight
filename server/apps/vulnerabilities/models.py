from django.db import models

class Vulnerability(models.Model):
    scan = models.ForeignKey('scans.Scan', related_name='vulnerabilities', on_delete=models.CASCADE)
    vulnerability_type = models.CharField(max_length=255)
    severity = models.CharField(max_length=50) # Critical, High, Medium, Low
    description = models.TextField()
    affected_url = models.CharField(max_length=2048)
    evidence = models.JSONField(null=True, blank=True)
    remediation = models.TextField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"{self.vulnerability_type} ({self.severity}) on {self.affected_url}"
