import json
import logging
from django.conf import settings
from .models import AIRemediation

logger = logging.getLogger(__name__)

def generate_ai_remediation(vulnerability):
    # Check if AI remediation already exists
    if hasattr(vulnerability, 'ai_remediation'):
        return vulnerability.ai_remediation

    vuln_type = vulnerability.vulnerability_type
    description = vulnerability.description
    severity = vulnerability.severity
    affected_url = vulnerability.affected_url

    # Check if Gemini API key or OpenAI API key is set
    gemini_key = getattr(settings, 'GEMINI_API_KEY', None)
    openai_key = getattr(settings, 'OPENAI_API_KEY', None)

    explanation = ""
    impact = ""
    fix_recommendation = ""
    secure_coding = ""

    if gemini_key:
        try:
            import google.generativeai as genai
            genai.configure(api_key=gemini_key)
            model = genai.GenerativeModel('gemini-1.5-flash')
            prompt = f"""
            You are a security expert. Analyze this vulnerability and return a JSON output with the exact keys:
            "explanation", "impact", "fix_recommendation", "secure_coding".
            Do not include markdown triple backticks. Just return raw JSON.
            
            Vulnerability Type: {vuln_type}
            Severity: {severity}
            Description: {description}
            Affected URL: {affected_url}
            """
            response = model.generate_content(prompt)
            data = json.loads(response.text.strip('`').replace('json', '').strip())
            explanation = data.get("explanation", "")
            impact = data.get("impact", "")
            fix_recommendation = data.get("fix_recommendation", "")
            secure_coding = data.get("secure_coding", "")
        except Exception as e:
            logger.error(f"Gemini API call failed: {e}")

    if not explanation and openai_key:
        try:
            from openai import OpenAI
            client = OpenAI(api_key=openai_key)
            prompt = f"""
            Analyze this vulnerability and return a JSON output with the exact keys:
            "explanation", "impact", "fix_recommendation", "secure_coding".
            
            Vulnerability Type: {vuln_type}
            Severity: {severity}
            Description: {description}
            Affected URL: {affected_url}
            """
            response = client.chat.completions.create(
                model="gpt-3.5-turbo",
                response_format={ "type": "json_object" },
                messages=[
                    {"role": "system", "content": "You are a cybersecurity assistant returning JSON."},
                    {"role": "user", "content": prompt}
                ]
            )
            data = json.loads(response.choices[0].message.content)
            explanation = data.get("explanation", "")
            impact = data.get("impact", "")
            fix_recommendation = data.get("fix_recommendation", "")
            secure_coding = data.get("secure_coding", "")
        except Exception as e:
            logger.error(f"OpenAI API call failed: {e}")

    # Fallback to local rule-based system if API calls failed or keys are not set
    if not explanation:
        explanation, impact, fix_recommendation, secure_coding = get_mock_remediation(vuln_type, severity)

    # Save to database
    remediation_obj = AIRemediation.objects.create(
        vulnerability=vulnerability,
        explanation=explanation,
        impact=impact,
        fix_recommendation=fix_recommendation,
        secure_coding=secure_coding
    )
    return remediation_obj

def get_mock_remediation(vuln_type, severity):
    vt_lower = vuln_type.lower()
    
    if "xss" in vt_lower or "cross-site scripting" in vt_lower:
        explanation = "Cross-Site Scripting (XSS) occurs when an application includes untrusted data in a web page without proper validation or escaping."
        impact = "An attacker can execute malicious scripts in the context of the user's browser, allowing session hijacking, defacement, or redirection to malicious sites."
        fix_recommendation = "Context-aware output encoding must be applied before inserting dynamic data into the HTML document. Sanitize user inputs using libraries like DOMPurify."
        secure_coding = "Use framework-level escaping (e.g., React's automatic escaping, Django's template engine autoescaping). Set a strict Content Security Policy (CSP) header."
    elif "sql" in vt_lower or "injection" in vt_lower:
        explanation = "SQL Injection (SQLi) vulnerabilities occur when untrusted user input is directly concatenated into database query strings instead of using parameterized inputs."
        impact = "Attackers can bypass authentication, read sensitive database contents, modify database data, or execute administrative operations on the database server."
        fix_recommendation = "Convert all queries to use parameterized queries (prepared statements). Never build SQL queries through string concatenation of raw parameters."
        secure_coding = "Employ ORMs like Django ORM or SQLAlchemy which utilize parameterized queries by default. Limit database user permissions to the absolute minimum required."
    elif "port" in vt_lower or "nmap" in vt_lower:
        explanation = "An open port is exposed to the internet. Depending on the service running, it might expose old, unpatched versions or administration interfaces."
        impact = "Attackers can perform reconnaissance, attempt brute force attacks on services like SSH/RDP, or exploit service vulnerabilities to gain remote server access."
        fix_recommendation = "Disable unused services. For services that must remain active, ensure they are updated to the latest secure version."
        secure_coding = "Implement strict firewall rules (e.g., iptables or AWS Security Groups) to limit access to known IPs only. Change default service credentials."
    else:
        explanation = f"Exposed system behavior matching the signature of a {vuln_type} configuration."
        impact = f"Allows attackers to inspect system configuration details or utilize common exploits associated with {severity} severity findings."
        fix_recommendation = "Audit the configuration settings of the target host, disable unrequired debug headers, and apply security patches."
        secure_coding = "Adopt the Principle of Least Privilege for user roles, keep system logs centralized, and perform automated vulnerability sweeps regularly."
        
    return explanation, impact, fix_recommendation, secure_coding
