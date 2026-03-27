"""
CyberSim6 - Phishing Detection Module
Analyzes emails and URLs for phishing indicators.
"""

import re
from urllib.parse import urlparse
from cybersim.core.base_module import BaseModule


# Phishing indicators — patterns pre-compiled at module load for performance
PHISHING_INDICATORS = {
    "urgency_keywords": [
        "urgent", "immediately", "action required", "verify your",
        "expire", "suspend", "locked", "unusual activity",
        "confirm your identity", "within 24 hours", "failure to",
    ],
    "suspicious_patterns": [
        re.compile(r"http://\d+\.\d+\.\d+\.\d+", re.IGNORECASE),  # IP-based URLs
        re.compile(r"@.*\.", re.IGNORECASE),  # URL with @ symbol
        re.compile(r"\.(?:tk|ml|ga|cf|gq)/", re.IGNORECASE),  # Free domain TLDs
        re.compile(r"bit\.ly|tinyurl|goo\.gl|t\.co", re.IGNORECASE),  # URL shorteners
    ],
    "spoofing_indicators": [
        re.compile(r"reply-to\s*:.*@(?!cybersim6\.local)", re.IGNORECASE),
        re.compile(r"from\s*:.*@(?!cybersim6\.local)", re.IGNORECASE),
    ],
}


class PhishingDetector(BaseModule):
    """Detects phishing indicators in emails and URLs."""

    MODULE_TYPE = "detection"
    MODULE_NAME = "phishing_detector"

    def _validate_safety(self):
        pass

    def analyze_email(self, subject: str = "", body: str = "",
                      sender: str = "", url: str = "") -> dict:
        """
        Analyze an email for phishing indicators.

        Returns:
            dict with analysis results and risk score.
        """
        findings = []
        risk_score = 0

        # Check urgency keywords
        text = f"{subject} {body}".lower()
        for keyword in PHISHING_INDICATORS["urgency_keywords"]:
            if keyword in text:
                findings.append({
                    "type": "urgency",
                    "indicator": keyword,
                    "description": f"Urgency keyword found: '{keyword}'",
                })
                risk_score += 10

        # Check suspicious URL patterns
        for pattern in PHISHING_INDICATORS["suspicious_patterns"]:
            if pattern.search(body) or (url and pattern.search(url)):
                findings.append({
                    "type": "suspicious_url",
                    "indicator": pattern.pattern,
                    "description": f"Suspicious URL pattern: {pattern.pattern}",
                })
                risk_score += 20

        # Check if URL domain differs from sender domain
        if url:
            parsed_url = urlparse(url)
            url_domain = parsed_url.hostname or ""
            if sender and "@" in sender:
                sender_domain = sender.split("@")[1]
                if url_domain and sender_domain and url_domain != sender_domain:
                    findings.append({
                        "type": "domain_mismatch",
                        "indicator": f"Sender: {sender_domain}, URL: {url_domain}",
                        "description": "URL domain does not match sender domain",
                    })
                    risk_score += 30

        # Check for HTTP (not HTTPS) login pages
        if url and url.startswith("http://") and any(w in url for w in ["login", "signin", "verify"]):
            findings.append({
                "type": "insecure_login",
                "indicator": url,
                "description": "Login page served over HTTP (not HTTPS)",
            })
            risk_score += 25

        # Check for credential request in body
        if any(w in text for w in ["password", "credential", "sign in", "log in"]):
            if any(w in text for w in ["click", "link", "http"]):
                findings.append({
                    "type": "credential_request",
                    "indicator": "Credential request with link",
                    "description": "Email asks for credentials via a link",
                })
                risk_score += 20

        risk_score = min(risk_score, 100)
        risk_level = "LOW" if risk_score < 30 else "MEDIUM" if risk_score < 60 else "HIGH"

        result = {
            "risk_score": risk_score,
            "risk_level": risk_level,
            "findings_count": len(findings),
            "findings": findings,
        }

        if findings:
            self.log_event("phishing_analyzed", {
                "message": f"Email analysis: {risk_level} risk (score: {risk_score}), {len(findings)} indicators found",
                "risk_score": risk_score,
                "risk_level": risk_level,
                "indicators": len(findings),
                "status": "warning" if risk_score >= 30 else "info",
            })

        return result

    def run(self, **kwargs):
        """Run analysis on sample phishing emails."""
        self._running = True
        self.log_event("detection_started", {
            "message": "Phishing detection analysis started",
            "status": "info",
        })

        # Analyze each campaign template as a demonstration
        from cybersim.phishing.campaign import PHISHING_EMAILS
        results = []

        phishing_url = self.config.get("phishing_url", "192.168.1.100:8083")

        for template_name, template in PHISHING_EMAILS.items():
            result = self.analyze_email(
                subject=template["subject"],
                body=template["body"].format(name="Test User", phishing_url=phishing_url),
                sender="security@suspicious-domain.tk",
                url=f"http://{phishing_url}/login",
            )
            result["template"] = template_name
            results.append(result)

            self.log_event("template_analyzed", {
                "message": f"Template '{template_name}': {result['risk_level']} risk (score: {result['risk_score']})",
                "template": template_name,
                "risk_level": result["risk_level"],
                "status": "info",
            })

        self._running = False
        self.log_event("detection_completed", {
            "message": f"Analyzed {len(results)} phishing templates.",
            "status": "info",
        })
        return results

    def stop(self):
        self._running = False
