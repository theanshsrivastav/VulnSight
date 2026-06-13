import subprocess
import xml.etree.ElementTree as ET
from typing import List, Dict
from urllib.parse import urlparse

class NmapScanner:
    def __init__(self, target_url: str):
        self.target_url = target_url
        
    def _resolve_docker_target(self, url: str) -> str:
        # Maps local loopback to host.docker.internal for Docker container resolution
        parsed = urlparse(url)
        netloc = parsed.netloc or parsed.path
        host = netloc.split(':')[0]
        
        if host in ['localhost', '127.0.0.1']:
            return 'host.docker.internal'
        return host

    def scan(self) -> List[Dict]:
        vulnerabilities = []
        host = self._resolve_docker_target(self.target_url)
        
        try:
            # Run Nmap container outputting XML directly to stdout
            result = subprocess.run(
                ['docker', 'run', '--rm', 'instrumentisto/nmap', '-T4', '-oX', '-', '-sV', '-sC', '--script', 'vuln', host],
                capture_output=True,
                text=True,
                timeout=600  # 10-minute timeout for script vuln scans
            )
            
            if result.returncode != 0:
                stderr = result.stderr.strip() or 'Nmap returned a non-zero exit status.'
                raise subprocess.CalledProcessError(result.returncode, result.args, output=result.stdout, stderr=stderr)

            xml_data = result.stdout
            
            if not xml_data.strip():
                raise ValueError("Nmap output is empty")
                
            try:
                root = ET.fromstring(xml_data)
                for host_node in root.findall('host'):
                    addr_node = host_node.find('address')
                    ip = addr_node.get('addr') if addr_node is not None else host
                    
                    ports_node = host_node.find('ports')
                    if ports_node is not None:
                        for port_node in ports_node.findall('port'):
                            port_id = int(port_node.get('portid'))
                            proto = port_node.get('protocol')
                            
                            state_node = port_node.find('state')
                            if state_node is not None and state_node.get('state') == 'open':
                                service_node = port_node.find('service')
                                service = 'unknown'
                                version = ''
                                product = ''
                                if service_node is not None:
                                    service = service_node.get('name', 'unknown')
                                    version = service_node.get('version', '')
                                    product = service_node.get('product', '')
                                    
                                severity = 'Low'
                                if port_id in [21, 23, 3389]:
                                    severity = 'High'
                                elif port_id in [22, 3306, 5432]:
                                    severity = 'Medium'
                                    
                                vulnerabilities.append({
                                    "vulnerability_type": "Open Port Detected",
                                    "severity": severity,
                                    "description": f"Port {port_id} is open running {service} {version}",
                                    "affected_url": f"{ip}:{port_id}",
                                    "evidence": {
                                        "port": port_id,
                                        "service": service,
                                        "version": version,
                                        "product": product,
                                        "protocol": proto
                                    },
                                    "remediation": f"Review if port {port_id} ({service}) needs to be publicly accessible. Consider implementing firewall rules or restricting access."
                                })
                                
                                # Process script vulnerabilities
                                for script_node in port_node.findall('script'):
                                    script_name = script_node.get('id')
                                    script_output = script_node.get('output', '')
                                    if 'VULNERABLE' in script_output or 'vuln' in script_name:
                                        vulnerabilities.append({
                                            "vulnerability_type": f"Nmap Script Detection: {script_name}",
                                            "severity": "High",
                                            "description": f"Vulnerability detected on port {port_id}",
                                            "affected_url": f"{ip}:{port_id}",
                                            "evidence": {
                                                "script": script_name,
                                                "output": script_output[:500]
                                            },
                                            "remediation": "Review the vulnerability details and apply necessary patches or security updates."
                                        })
            except ET.ParseError as pe:
                print(f"Failed to parse Nmap XML output: {pe}")
                # Fallback parser looking at text lines
                self._parse_raw_text(xml_data, vulnerabilities)
                
        except Exception as e:
            error_msg = str(e)
            print(f"Nmap Docker scan error: {error_msg}")
            vulnerabilities.append({
                "vulnerability_type": "Nmap Scanner Error",
                "severity": "Low",
                "description": f"Nmap Docker scanner failed to execute. Error: {error_msg}",
                "affected_url": self.target_url,
                "evidence": {"error": error_msg},
                "remediation": "Ensure Docker is running and the instrumentisto/nmap image is pulled."
            })
            
        return vulnerabilities

    def _parse_raw_text(self, text: str, vulnerabilities: List[Dict]):
        # Fallback text parsing if XML output failed or wasn't generated correctly
        import re
        port_lines = re.findall(r"(\d+)/(tcp|udp)\s+open\s+(\S+)(?:\s+(.*))?", text)
        for port, proto, service, version_info in port_lines:
            port_id = int(port)
            severity = 'Low'
            if port_id in [21, 23, 3389]:
                severity = 'High'
            elif port_id in [22, 3306, 5432]:
                severity = 'Medium'
                
            vulnerabilities.append({
                "vulnerability_type": "Open Port Detected (Fallback Parse)",
                "severity": severity,
                "description": f"Port {port_id} is open running {service} ({version_info or 'N/A'})",
                "affected_url": f"{self.target_url}:{port_id}",
                "evidence": {
                    "port": port_id,
                    "service": service,
                    "version": version_info or '',
                    "protocol": proto
                },
                "remediation": f"Review if port {port_id} ({service}) needs to be publicly accessible. Consider implementing firewall rules."
            })
