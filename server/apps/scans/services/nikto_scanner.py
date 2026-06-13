import subprocess
from typing import List, Dict
from urllib.parse import urlparse

class NiktoScanner:
    def __init__(self, target_url: str):
        self.target_url = target_url
        
    def _resolve_docker_target(self, url: str) -> str:
        # Maps local loopback to host.docker.internal for Docker container resolution
        parsed = urlparse(url)
        netloc = parsed.netloc or parsed.path
        
        # Split host and port
        host_parts = netloc.split(':')
        host = host_parts[0]
        port = host_parts[1] if len(host_parts) > 1 else None
        
        if host in ['localhost', '127.0.0.1']:
            host = 'host.docker.internal'
            
        new_netloc = f"{host}:{port}" if port else host
        
        # Build URL back
        if parsed.scheme:
            return f"{parsed.scheme}://{new_netloc}{parsed.path}"
        return new_netloc

    def scan(self) -> List[Dict]:
        vulnerabilities = []
        resolved_target = self._resolve_docker_target(self.target_url)
        
        try:
            # Execute Nikto via Docker container in clean subprocess
            result = subprocess.run(
                ['docker', 'run', '--rm', 'sullo/nikto', '-h', resolved_target],
                capture_output=True,
                text=True,
                timeout=300 # 5-minute timeout limit
            )
            
            output = result.stdout + result.stderr
            findings = self._parse_text_output(output)
            vulnerabilities.extend(findings)
                
        except subprocess.TimeoutExpired:
            print("Nikto Docker scan timed out")
            vulnerabilities.append({
                "vulnerability_type": "Nikto Scanner Timeout",
                "severity": "Low",
                "description": "Nikto Docker scan exceeded the time limit of 5 minutes.",
                "affected_url": self.target_url,
                "evidence": {"error": "timeout"},
                "remediation": "The target may be slow to respond. Try scanning with a longer timeout or check target availability."
            })
        except Exception as e:
            error_msg = str(e)
            print(f"Nikto Docker scan error: {error_msg}")
            vulnerabilities.append({
                "vulnerability_type": "Nikto Scanner Error",
                "severity": "Low",
                "description": f"Nikto Docker scanner failed to execute. Error: {error_msg}",
                "affected_url": self.target_url,
                "evidence": {"error": error_msg},
                "remediation": "Ensure Docker is running and the sullo/nikto image is pulled."
            })
        
        return vulnerabilities
    
    def _parse_text_output(self, output: str) -> List[Dict]:
        vulnerabilities = []
        lines = output.split('\n')
        
        for line in lines:
            if '+' in line and ('OSVDB' in line or 'vulnerability' in line.lower()):
                vulnerabilities.append({
                    "vulnerability_type": "Nikto Web Server Finding",
                    "severity": "Medium",
                    "description": line.strip(),
                    "affected_url": self.target_url,
                    "evidence": {"raw_output": line},
                    "remediation": "Review and address the security finding identified by Nikto."
                })
        
        return vulnerabilities
