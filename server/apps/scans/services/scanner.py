import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import re
from typing import List, Dict

from .nmap_scanner import NmapScanner
from .nikto_scanner import NiktoScanner
from .zap_scanner import ZAPScanner

class VulnerabilityScanner:
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.vulnerabilities = []
        
    def scan(self, scan_type: str) -> List[Dict]:
        if scan_type == "xss":
            return self.scan_xss()
        elif scan_type == "sql_injection":
            return self.scan_sql_injection()
        elif scan_type == "nmap":
            return self.scan_nmap()
        elif scan_type == "nikto":
            return self.scan_nikto()
        elif scan_type == "zap":
            return self.scan_zap()
        elif scan_type == "full":
            xss_vulns = self.scan_xss()
            sql_vulns = self.scan_sql_injection()
            return xss_vulns + sql_vulns
        elif scan_type == "comprehensive":
            all_vulns = []
            all_vulns.extend(self.scan_xss())
            all_vulns.extend(self.scan_sql_injection())
            all_vulns.extend(self.scan_nmap())
            all_vulns.extend(self.scan_nikto())
            all_vulns.extend(self.scan_zap())
            return all_vulns
        else:
            return []
    
    def scan_nmap(self) -> List[Dict]:
        try:
            scanner = NmapScanner(self.target_url)
            return scanner.scan()
        except Exception as e:
            error_msg = str(e)
            print(f"Nmap scan failed: {error_msg}")
            return [{
                "vulnerability_type": "Nmap Scanner Critical Error",
                "severity": "Low",
                "description": f"Failed to initialize or run Nmap scanner: {error_msg}",
                "affected_url": self.target_url,
                "evidence": {"error": error_msg},
                "remediation": "Check Nmap installation and ensure proper permissions."
            }]
    
    def scan_nikto(self) -> List[Dict]:
        try:
            scanner = NiktoScanner(self.target_url)
            return scanner.scan()
        except Exception as e:
            error_msg = str(e)
            print(f"Nikto scan failed: {error_msg}")
            return [{
                "vulnerability_type": "Nikto Scanner Critical Error",
                "severity": "Low",
                "description": f"Failed to initialize or run Nikto scanner: {error_msg}",
                "affected_url": self.target_url,
                "evidence": {"error": error_msg},
                "remediation": "Check Nikto installation and ensure the target URL is accessible."
            }]
    
    def scan_zap(self) -> List[Dict]:
        try:
            scanner = ZAPScanner(self.target_url)
            return scanner.scan()
        except Exception as e:
            error_msg = str(e)
            print(f"ZAP scan failed: {error_msg}")
            return [{
                "vulnerability_type": "OWASP ZAP Scanner Critical Error",
                "severity": "Low",
                "description": f"Failed to initialize or run OWASP ZAP scanner: {error_msg}",
                "affected_url": self.target_url,
                "evidence": {"error": error_msg},
                "remediation": "Ensure OWASP ZAP is running on the configured proxy with API enabled."
            }]
    
    def scan_xss(self) -> List[Dict]:
        vulnerabilities = []
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<svg/onload=alert('XSS')>"
        ]
        
        try:
            response = requests.get(self.target_url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            forms = soup.find_all('form')
            for form in forms:
                form_details = self.get_form_details(form)
                
                for payload in xss_payloads:
                    test_data = {}
                    for input_tag in form_details["inputs"]:
                        if input_tag["type"] in ["text", "search"]:
                            test_data[input_tag["name"]] = payload
                        else:
                            test_data[input_tag["name"]] = "test"
                    
                    url = urljoin(self.target_url, form_details["action"])
                    
                    if form_details["method"] == "post":
                        test_response = requests.post(url, data=test_data, timeout=10)
                    else:
                        test_response = requests.get(url, params=test_data, timeout=10)
                    
                    if payload in test_response.text:
                        vulnerabilities.append({
                            "vulnerability_type": "Cross-Site Scripting (XSS)",
                            "severity": "High",
                            "description": f"XSS vulnerability detected in form at {form_details['action']}",
                            "affected_url": url,
                            "evidence": {"payload": payload, "form_action": form_details["action"]},
                            "remediation": "Implement input validation and output encoding. Use Content Security Policy (CSP) headers."
                        })
                        break
                        
        except Exception as e:
            error_msg = str(e)
            print(f"XSS scan error: {error_msg}")
            vulnerabilities.append({
                "vulnerability_type": "XSS Scanner Error",
                "severity": "Low",
                "description": f"XSS scanning encountered an error: {error_msg}",
                "affected_url": self.target_url,
                "evidence": {"error": error_msg},
                "remediation": "Check target accessibility and network connectivity."
            })
        
        return vulnerabilities
    
    def scan_sql_injection(self) -> List[Dict]:
        vulnerabilities = []
        sql_payloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' /*",
            "admin' --",
            "1' OR '1'='1",
            "' UNION SELECT NULL--"
        ]
        
        sql_errors = [
            "sql syntax",
            "mysql_fetch",
            "sqlite_",
            "postgresql",
            "ora-[0-9]",
            "syntax error",
            "unclosed quotation mark"
        ]
        
        try:
            response = requests.get(self.target_url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            forms = soup.find_all('form')
            for form in forms:
                form_details = self.get_form_details(form)
                
                for payload in sql_payloads:
                    test_data = {}
                    for input_tag in form_details["inputs"]:
                        if input_tag["type"] in ["text", "password"]:
                            test_data[input_tag["name"]] = payload
                        else:
                            test_data[input_tag["name"]] = "test"
                    
                    url = urljoin(self.target_url, form_details["action"])
                    
                    if form_details["method"] == "post":
                        # CRITICAL BUG FIX: Removed print(response.json()) and print(test_response.json()) from original code
                        test_response = requests.post(url, data=test_data, timeout=10)
                    else:
                        test_response = requests.get(url, params=test_data, timeout=10)
                    
                    for error in sql_errors:
                        if re.search(error, test_response.text, re.IGNORECASE):
                            vulnerabilities.append({
                                "vulnerability_type": "SQL Injection",
                                "severity": "Critical",
                                "description": f"SQL Injection vulnerability detected in form at {form_details['action']}",
                                "affected_url": url,
                                "evidence": {"payload": payload, "error_pattern": error},
                                "remediation": "Use parameterized queries or prepared statements. Implement input validation and sanitization."
                            })
                            break
                            
        except Exception as e:
            error_msg = str(e)
            print(f"SQL injection scan error: {error_msg}")
            vulnerabilities.append({
                "vulnerability_type": "SQL Injection Scanner Error",
                "severity": "Low",
                "description": f"SQL injection scanning encountered an error: {error_msg}",
                "affected_url": self.target_url,
                "evidence": {"error": error_msg},
                "remediation": "Check target accessibility and network connectivity."
            })
        
        return vulnerabilities
    
    def get_form_details(self, form):
        details = {}
        action = form.attrs.get("action", "").lower()
        method = form.attrs.get("method", "get").lower()
        inputs = []
        
        for input_tag in form.find_all("input"):
            input_type = input_tag.attrs.get("type", "text")
            input_name = input_tag.attrs.get("name")
            if input_name:
                inputs.append({"type": input_type, "name": input_name})
        
        details["action"] = action
        details["method"] = method
        details["inputs"] = inputs
        
        return details
