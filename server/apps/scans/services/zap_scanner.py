from zapv2 import ZAPv2
from typing import List, Dict
import time
from django.conf import settings

class ZAPScanner:
    def __init__(self, target_url: str):
        self.target_url = target_url
        # Explicitly targets local headless ZAP container on 8080
        self.zap_proxy = getattr(settings, 'ZAP_PROXY', 'http://localhost:8080')
        # Forces empty API key since container is started with api.disablekey=true
        self.api_key = ''
        
    def scan(self) -> List[Dict]:
        vulnerabilities = []
        
        try:
            zap = ZAPv2(
                proxies={
                    'http': 'http://zap:8080',
                    'https': 'http://zap:8080'
                },
                apikey=self.api_key
            )
            
            print(f'Accessing target: {self.target_url}')
            zap.urlopen(self.target_url)
            time.sleep(2)
            
            print('Spidering target...')
            scan_id = zap.spider.scan(self.target_url)
            while int(zap.spider.status(scan_id)) < 100:
                time.sleep(2)
            
            print('Spider completed, starting active scan...')
            scan_id = zap.ascan.scan(self.target_url)
            while int(zap.ascan.status(scan_id)) < 100:
                time.sleep(5)
            
            print('Active scan completed, retrieving alerts...')
            alerts = zap.core.alerts(baseurl=self.target_url)
            
            for alert in alerts:
                vulnerabilities.append({
                    "vulnerability_type": alert.get('alert', 'ZAP Alert'),
                    "severity": self._map_severity(alert.get('risk', 'Medium')),
                    "description": alert.get('description', ''),
                    "affected_url": alert.get('url', self.target_url),
                    "evidence": {
                        "cweid": alert.get('cweid', ''),
                        "wascid": alert.get('wascid', ''),
                        "attack": alert.get('attack', ''),
                        "evidence": alert.get('evidence', '')
                    },
                    "remediation": alert.get('solution', 'Review and fix the identified vulnerability.')
                })
                
        except Exception as e:
            print(f"ZAP scan error: {e}")
            vulnerabilities.append({
                "vulnerability_type": "ZAP Scan Error",
                "severity": "Low",
                "description": f"OWASP ZAP container is not available on {self.zap_proxy} or API disabled key config failed. Error: {str(e)}",
                "affected_url": self.target_url,
                "evidence": {"error": str(e)},
                "remediation": "Ensure the OWASP ZAP container is running with command: docker run -u zap -p 8080:8080 -i owasp/zap2docker-stable zap.sh -daemon -host 0.0.0.0 -port 8080 -config api.disablekey=true"
            })
        
        return vulnerabilities
    
    def _map_severity(self, risk: str) -> str:
        risk_map = {
            'Informational': 'Low',
            'Low': 'Low',
            'Medium': 'Medium',
            'High': 'High'
        }
        return risk_map.get(risk, 'Medium')
