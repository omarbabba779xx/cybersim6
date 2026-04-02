"""
CyberSim6 - Remediation Recommendations Engine
Maps detection findings to actionable remediation steps.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Recommendation:
    """A single remediation recommendation."""
    title: str
    priority: str  # critical, high, medium, low
    category: str  # patch, config, policy, monitoring
    description: str
    steps: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    mitre_technique: str = ""
    cwe: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "priority": self.priority,
            "category": self.category,
            "description": self.description,
            "steps": self.steps,
            "references": self.references,
            "mitre_technique": self.mitre_technique,
            "cwe": self.cwe,
        }


# Remediation database mapping attack types to recommendations
REMEDIATION_DB: dict[str, list[Recommendation]] = {
    "ddos": [
        Recommendation(
            title="Implement Rate Limiting",
            priority="critical",
            category="config",
            description="Configure rate limiting on all public-facing endpoints to prevent HTTP flood attacks.",
            steps=["Configure reverse proxy rate limits (e.g., nginx limit_req)", "Set per-IP connection limits", "Implement progressive throttling", "Add rate limit headers (X-RateLimit-*)"],
            references=["NIST SP 800-61r2", "OWASP DDoS Prevention"],
            mitre_technique="T1498",
            cwe="CWE-770",
        ),
        Recommendation(
            title="Deploy DDoS Mitigation Service",
            priority="high",
            category="config",
            description="Use cloud-based DDoS mitigation or on-premise appliances for volumetric attack protection.",
            steps=["Evaluate CDN with DDoS protection (Cloudflare, AWS Shield)", "Configure traffic scrubbing rules", "Set up automatic failover", "Test mitigation with controlled traffic"],
            references=["NIST SP 800-61r2"],
            mitre_technique="T1499",
            cwe="CWE-400",
        ),
    ],
    "sqli": [
        Recommendation(
            title="Use Parameterized Queries",
            priority="critical",
            category="patch",
            description="Replace all string-concatenated SQL queries with parameterized/prepared statements.",
            steps=["Audit all database query code", "Replace string formatting with parameterized queries", "Use ORM (SQLAlchemy, Django ORM) where possible", "Add SQL injection unit tests"],
            references=["OWASP SQL Injection Prevention", "CWE-89"],
            mitre_technique="T1190",
            cwe="CWE-89",
        ),
        Recommendation(
            title="Implement Input Validation",
            priority="high",
            category="patch",
            description="Validate and sanitize all user inputs before processing.",
            steps=["Define input validation schemas", "Implement whitelist validation", "Reject unexpected characters", "Log validation failures"],
            references=["OWASP Input Validation Cheat Sheet"],
            mitre_technique="T1190",
            cwe="CWE-20",
        ),
        Recommendation(
            title="Apply Least Privilege on Database",
            priority="high",
            category="config",
            description="Ensure database accounts used by the application have minimal required permissions.",
            steps=["Create dedicated app database user", "Grant only SELECT/INSERT/UPDATE as needed", "Remove DROP/ALTER/GRANT privileges", "Separate read and write database accounts"],
            references=["CIS Database Benchmarks"],
            mitre_technique="T1190",
            cwe="CWE-250",
        ),
    ],
    "xss": [
        Recommendation(
            title="Implement Output Encoding",
            priority="critical",
            category="patch",
            description="Apply context-appropriate output encoding for all user-controlled data rendered in HTML.",
            steps=["HTML-encode data in HTML context", "JavaScript-encode data in JS context", "URL-encode data in URL context", "Use templating engines with auto-escaping"],
            references=["OWASP XSS Prevention Cheat Sheet"],
            mitre_technique="T1204",
            cwe="CWE-79",
        ),
        Recommendation(
            title="Deploy Content Security Policy",
            priority="high",
            category="config",
            description="Add CSP headers to prevent inline script execution and restrict resource loading.",
            steps=["Set Content-Security-Policy header", "Disable unsafe-inline for scripts", "Use nonce-based script loading", "Monitor CSP violations with report-uri"],
            references=["MDN Content-Security-Policy", "OWASP CSP Cheat Sheet"],
            mitre_technique="T1204",
            cwe="CWE-79",
        ),
    ],
    "bruteforce": [
        Recommendation(
            title="Implement Account Lockout Policy",
            priority="critical",
            category="policy",
            description="Lock accounts after a configurable number of failed login attempts.",
            steps=["Set lockout threshold (e.g., 5 failed attempts)", "Implement progressive delay between attempts", "Add CAPTCHA after 3 failures", "Notify user of lockout via email"],
            references=["NIST SP 800-63B", "OWASP Authentication Cheat Sheet"],
            mitre_technique="T1110",
            cwe="CWE-307",
        ),
        Recommendation(
            title="Enforce Multi-Factor Authentication",
            priority="high",
            category="policy",
            description="Require MFA for all user accounts, especially admin and privileged accounts.",
            steps=["Deploy TOTP-based MFA", "Require MFA for admin accounts", "Implement backup codes", "Monitor MFA enrollment rates"],
            references=["NIST SP 800-63B"],
            mitre_technique="T1110",
            cwe="CWE-308",
        ),
    ],
    "phishing": [
        Recommendation(
            title="Deploy Email Security Controls",
            priority="critical",
            category="config",
            description="Implement SPF, DKIM, and DMARC to prevent email spoofing.",
            steps=["Configure SPF records", "Set up DKIM signing", "Deploy DMARC with reject policy", "Enable email filtering and sandboxing"],
            references=["NIST SP 800-177", "DMARC.org"],
            mitre_technique="T1566",
            cwe="CWE-451",
        ),
        Recommendation(
            title="Security Awareness Training",
            priority="high",
            category="policy",
            description="Conduct regular phishing awareness training for all employees.",
            steps=["Schedule quarterly phishing simulations", "Provide immediate feedback on clicked links", "Track and report phishing metrics", "Reward reporting of suspicious emails"],
            references=["SANS Security Awareness"],
            mitre_technique="T1566",
            cwe="CWE-451",
        ),
    ],
    "ransomware": [
        Recommendation(
            title="Implement Backup Strategy (3-2-1)",
            priority="critical",
            category="policy",
            description="Maintain 3 copies of data on 2 different media with 1 offsite copy.",
            steps=["Configure automated daily backups", "Store backups on separate network segment", "Maintain offline backup copy", "Test restoration quarterly"],
            references=["NIST SP 800-184", "CISA Ransomware Guide"],
            mitre_technique="T1486",
            cwe="CWE-693",
        ),
        Recommendation(
            title="Restrict Execution Policies",
            priority="high",
            category="config",
            description="Use application whitelisting and execution restrictions to prevent ransomware execution.",
            steps=["Enable AppLocker or equivalent", "Block execution from temp directories", "Restrict PowerShell execution policy", "Monitor for suspicious file encryption activity"],
            references=["CIS Controls v8", "NIST SP 800-184"],
            mitre_technique="T1486",
            cwe="CWE-693",
        ),
    ],
}


class RemediationEngine:
    """Generates prioritized remediation recommendations based on detection findings."""

    def __init__(self) -> None:
        self._findings: list[dict[str, Any]] = []

    def add_finding(self, attack_type: str, details: str = "") -> None:
        """Record a detection finding."""
        self._findings.append({"attack_type": attack_type.lower(), "details": details})

    def analyze_events(self, events: list[dict]) -> None:
        """Extract findings from CyberSim6 events."""
        for event in events:
            event_type = event.get("event_type", "").lower()
            module = event.get("module", "").lower()
            details = event.get("details", {})

            if details.get("status") != "warning" and "detected" not in event_type:
                continue

            for attack_type in REMEDIATION_DB:
                if attack_type in event_type or attack_type in module:
                    self.add_finding(attack_type, details.get("message", ""))
                    break

    def get_recommendations(self) -> list[Recommendation]:
        """Get all applicable recommendations, sorted by priority."""
        attack_types = sorted(set(f["attack_type"] for f in self._findings))
        recs: list[Recommendation] = []
        seen_titles: set[str] = set()

        for at in attack_types:
            for rec in REMEDIATION_DB.get(at, []):
                if rec.title not in seen_titles:
                    recs.append(rec)
                    seen_titles.add(rec.title)

        priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        recs.sort(key=lambda r: priority_order.get(r.priority, 99))
        return recs

    def generate_report(self) -> str:
        """Generate formatted remediation report."""
        recs = self.get_recommendations()
        if not recs:
            return "\n  No remediation recommendations (no attack findings detected).\n"

        lines = [
            "",
            "  ╔══════════════════════════════════════════════════════════════════╗",
            "  ║              REMEDIATION RECOMMENDATIONS                        ║",
            "  ╚══════════════════════════════════════════════════════════════════╝",
            "",
            f"  Findings: {len(self._findings)} | Recommendations: {len(recs)}",
            "",
        ]

        for i, rec in enumerate(recs, 1):
            prio_tag = {"critical": "[!!]", "high": "[! ]", "medium": "[. ]", "low": "[  ]"}.get(rec.priority, "[  ]")
            lines.append(f"  {i}. {prio_tag} {rec.title} ({rec.category})")
            lines.append(f"     {rec.description}")
            if rec.cwe:
                lines.append(f"     CWE: {rec.cwe} | MITRE: {rec.mitre_technique}")
            lines.append("     Steps:")
            for step in rec.steps:
                lines.append(f"       - {step}")
            lines.append("")

        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        recs = self.get_recommendations()
        return {
            "total_findings": len(self._findings),
            "total_recommendations": len(recs),
            "recommendations": [r.to_dict() for r in recs],
        }

    def reset(self) -> None:
        self._findings.clear()
