from celery import shared_task
from django.utils import timezone
from .models import Scan
from apps.vulnerabilities.models import Vulnerability
from apps.ai_remediation.services import generate_ai_remediation
from .services import VulnerabilityScanner
import logging

logger = logging.getLogger(__name__)

@shared_task
def execute_vulnerability_scan(scan_id):
    try:
        scan = Scan.objects.get(id=scan_id)
    except Scan.DoesNotExist:
        logger.error(f"Scan with ID {scan_id} does not exist.")
        return
        
    scan.status = 'running'
    scan.save()
    
    try:
        scanner = VulnerabilityScanner(scan.target_url)
        vulnerabilities_found = scanner.scan(scan.scan_type)
        
        for vuln in vulnerabilities_found:
            # Create Vulnerability object
            vuln_obj = Vulnerability.objects.create(
                scan=scan,
                vulnerability_type=vuln["vulnerability_type"],
                severity=vuln["severity"],
                description=vuln["description"],
                affected_url=vuln["affected_url"],
                evidence=vuln.get("evidence"),
                remediation=vuln.get("remediation")
            )
            
            # Generate AI Remediation & Suggestions
            try:
                generate_ai_remediation(vuln_obj)
            except Exception as ai_err:
                logger.error(f"Failed to generate AI remediation for vulnerability {vuln_obj.id}: {ai_err}")
                
        scan.status = 'completed'
        scan.completed_at = timezone.now()
    except Exception as e:
        logger.error(f"Error during scan {scan_id}: {e}")
        scan.status = 'failed'
        
    scan.save()
