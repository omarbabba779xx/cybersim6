"""
Compliance Checker -- Verify security posture against ISO 27001, NIST CSF, and RGPD.

Evaluates simulation event logs and produces per-framework compliance
reports with control-level status, evidence, and recommendations.
Uses only the Python standard library.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


# ---------------------------------------------------------------------------
# Enums & Data classes
# ---------------------------------------------------------------------------

class ComplianceStatus(Enum):
    """Traffic-light status for a single compliance control."""

    COMPLIANT = "compliant"
    PARTIAL = "partial"
    NON_COMPLIANT = "non_compliant"


@dataclass
class ComplianceCheck:
    """Evaluation of one control within a framework.

    Attributes:
        framework: Framework label (e.g. ``"ISO 27001"``).
        control_id: Official control identifier (e.g. ``"A.12.6.1"``).
        control_name: Human-readable control title.
        description: What the control requires.
        status: Compliance result.
        evidence: Textual evidence that led to the status.
        recommendation: Suggested remediation when not fully compliant.
    """

    framework: str
    control_id: str
    control_name: str
    description: str
    status: ComplianceStatus
    evidence: str
    recommendation: str


@dataclass
class ComplianceReport:
    """Aggregated compliance results for a single framework.

    Attributes:
        framework: Framework label.
        total_controls: Number of controls evaluated.
        compliant: Count of ``COMPLIANT`` controls.
        partial: Count of ``PARTIAL`` controls.
        non_compliant: Count of ``NON_COMPLIANT`` controls.
        score_percent: Weighted percentage (compliant=1, partial=0.5).
        checks: Individual :class:`ComplianceCheck` results.
    """

    framework: str
    total_controls: int
    compliant: int
    partial: int
    non_compliant: int
    score_percent: float
    checks: list[ComplianceCheck]


# ---------------------------------------------------------------------------
# Control definitions
# ---------------------------------------------------------------------------

# Each tuple: (control_id, control_name, description)
_ControlDef = tuple[str, str, str]

_ISO_27001_CONTROLS: list[_ControlDef] = [
    ("A.5.1.1", "Information security policies", "Documented security policies exist"),
    ("A.9.4.2", "Secure log-on procedures", "Authentication mechanisms resist brute force"),
    ("A.12.2.1", "Controls against malware", "Ransomware detection in place"),
    ("A.12.6.1", "Management of technical vulnerabilities", "SQLi/XSS vulnerabilities detected and mitigated"),
    ("A.13.1.1", "Network controls", "DDoS detection and mitigation"),
    ("A.14.1.2", "Securing application services", "WAF protection active"),
    ("A.16.1.2", "Reporting information security events", "Logging and alerting active"),
]

_NIST_CSF_CONTROLS: list[_ControlDef] = [
    ("ID.AM-1", "Physical devices inventory", "Assets are inventoried and managed"),
    ("PR.AC-1", "Identity management", "Access control mechanisms are enforced"),
    ("PR.DS-1", "Data-at-rest protection", "Sensitive data is encrypted at rest"),
    ("PR.IP-1", "Baseline configuration", "Security baselines are maintained"),
    ("DE.CM-1", "Network monitoring", "Network is monitored for anomalies"),
    ("DE.CM-4", "Malicious code detection", "Malware and ransomware detected"),
    ("RS.RP-1", "Response plan execution", "Incident response plan is exercised"),
]

_RGPD_CONTROLS: list[_ControlDef] = [
    ("Art.5", "Data processing principles", "Personal data processed lawfully and transparently"),
    ("Art.25", "Data protection by design", "Privacy by design implemented"),
    ("Art.30", "Records of processing", "Processing activities are documented"),
    ("Art.32", "Security of processing", "Appropriate technical measures applied"),
    ("Art.33", "Breach notification", "Breach notification within 72 hours"),
    ("Art.35", "Data protection impact assessment", "DPIA conducted for high-risk processing"),
    ("Art.37", "Data protection officer", "DPO designated when required"),
]


# ---------------------------------------------------------------------------
# Keyword mappings: event keywords that count as evidence
# ---------------------------------------------------------------------------

# Maps a control_id to a set of keywords we look for in event fields.
_ISO_KEYWORDS: dict[str, list[str]] = {
    "A.5.1.1": ["policy", "security_policy", "policy_update"],
    "A.9.4.2": ["brute_force", "login", "authentication", "lockout"],
    "A.12.2.1": ["ransomware", "malware", "encryption_detected"],
    "A.12.6.1": ["sqli", "xss", "vulnerability", "injection"],
    "A.13.1.1": ["ddos", "flood", "rate_limit", "network_anomaly"],
    "A.14.1.2": ["waf", "firewall", "blocked_request"],
    "A.16.1.2": ["logging", "alert", "event_recorded", "siem"],
}

_NIST_KEYWORDS: dict[str, list[str]] = {
    "ID.AM-1": ["asset", "inventory", "device_discovered"],
    "PR.AC-1": ["access_control", "authentication", "login", "rbac"],
    "PR.DS-1": ["encryption", "encrypt", "data_at_rest"],
    "PR.IP-1": ["baseline", "configuration", "hardening"],
    "DE.CM-1": ["network_monitor", "anomaly", "ids", "traffic"],
    "DE.CM-4": ["malware", "ransomware", "antivirus", "detection"],
    "RS.RP-1": ["incident_response", "response_plan", "containment"],
}

_RGPD_KEYWORDS: dict[str, list[str]] = {
    "Art.5": ["data_processing", "consent", "lawful_basis"],
    "Art.25": ["privacy_by_design", "data_minimization", "pseudonymization"],
    "Art.30": ["processing_record", "data_register", "ropa"],
    "Art.32": ["encryption", "access_control", "security_measure"],
    "Art.33": ["breach_notification", "incident_report", "breach_detected"],
    "Art.35": ["dpia", "impact_assessment", "risk_assessment"],
    "Art.37": ["dpo", "data_protection_officer", "dpo_appointed"],
}


# ---------------------------------------------------------------------------
# Checker
# ---------------------------------------------------------------------------

class ComplianceChecker:
    """Check security simulation results against compliance frameworks.

    Args:
        logger: A ``CyberSimLogger`` instance (or compatible object with a
            ``log_event`` method).  May be ``None`` for headless usage.

    Usage::

        checker = ComplianceChecker(logger=my_logger)
        reports = checker.check_all(events)
        print(checker.generate_summary(reports))
    """

    ISO_27001_CONTROLS = _ISO_27001_CONTROLS
    NIST_CSF_CONTROLS = _NIST_CSF_CONTROLS
    RGPD_CONTROLS = _RGPD_CONTROLS

    def __init__(self, logger: Any = None) -> None:
        self._logger = logger

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def check_iso27001(self, events: list[dict[str, Any]]) -> ComplianceReport:
        """Evaluate *events* against ISO 27001 controls.

        Args:
            events: List of event dicts (as produced by ``CyberSimLogger``).

        Returns:
            A :class:`ComplianceReport` for ISO 27001.
        """
        return self._evaluate("ISO 27001", self.ISO_27001_CONTROLS, _ISO_KEYWORDS, events)

    def check_nist(self, events: list[dict[str, Any]]) -> ComplianceReport:
        """Evaluate *events* against NIST Cybersecurity Framework controls.

        Args:
            events: List of event dicts.

        Returns:
            A :class:`ComplianceReport` for NIST CSF.
        """
        return self._evaluate("NIST CSF", self.NIST_CSF_CONTROLS, _NIST_KEYWORDS, events)

    def check_rgpd(self, events: list[dict[str, Any]]) -> ComplianceReport:
        """Evaluate *events* against RGPD (GDPR) controls.

        Args:
            events: List of event dicts.

        Returns:
            A :class:`ComplianceReport` for RGPD.
        """
        return self._evaluate("RGPD", self.RGPD_CONTROLS, _RGPD_KEYWORDS, events)

    def check_all(self, events: list[dict[str, Any]]) -> list[ComplianceReport]:
        """Run all three framework checks and return a list of reports.

        Args:
            events: List of event dicts.

        Returns:
            Three :class:`ComplianceReport` objects (ISO, NIST, RGPD).
        """
        return [
            self.check_iso27001(events),
            self.check_nist(events),
            self.check_rgpd(events),
        ]

    def generate_summary(self, reports: list[ComplianceReport]) -> str:
        """Produce a human-readable text summary across all *reports*.

        Args:
            reports: List of :class:`ComplianceReport` objects.

        Returns:
            Multi-line summary string.
        """
        lines: list[str] = ["=" * 60, "COMPLIANCE SUMMARY", "=" * 60]
        for report in reports:
            lines.append(
                f"\n{report.framework}: {report.score_percent:.1f}% "
                f"({report.compliant}/{report.total_controls} compliant, "
                f"{report.partial} partial, {report.non_compliant} non-compliant)"
            )
            for check in report.checks:
                status_icon = {
                    ComplianceStatus.COMPLIANT: "[OK]",
                    ComplianceStatus.PARTIAL: "[!!]",
                    ComplianceStatus.NON_COMPLIANT: "[XX]",
                }[check.status]
                lines.append(f"  {status_icon} {check.control_id} - {check.control_name}")
                if check.status != ComplianceStatus.COMPLIANT:
                    lines.append(f"        Recommendation: {check.recommendation}")
        lines.append("\n" + "=" * 60)
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _evaluate(
        self,
        framework: str,
        controls: list[_ControlDef],
        keywords_map: dict[str, list[str]],
        events: list[dict[str, Any]],
    ) -> ComplianceReport:
        """Core evaluation loop shared by all frameworks.

        For each control, search *events* for keyword matches in the
        ``module``, ``event_type``, and ``details.message`` fields.

        - 2+ matching events  -> COMPLIANT
        - 1 matching event    -> PARTIAL
        - 0 matching events   -> NON_COMPLIANT
        """
        checks: list[ComplianceCheck] = []

        for control_id, control_name, description in controls:
            kws = keywords_map.get(control_id, [])
            matching = self._count_keyword_hits(events, kws)

            if matching >= 2:
                status = ComplianceStatus.COMPLIANT
                evidence = f"Found {matching} related events."
                recommendation = "Maintain current controls."
            elif matching == 1:
                status = ComplianceStatus.PARTIAL
                evidence = f"Found {matching} related event (insufficient coverage)."
                recommendation = f"Increase monitoring and evidence for {control_name}."
            else:
                status = ComplianceStatus.NON_COMPLIANT
                evidence = "No related events found."
                recommendation = f"Implement controls for {control_name} ({control_id})."

            checks.append(ComplianceCheck(
                framework=framework,
                control_id=control_id,
                control_name=control_name,
                description=description,
                status=status,
                evidence=evidence,
                recommendation=recommendation,
            ))

        compliant_n = sum(1 for c in checks if c.status == ComplianceStatus.COMPLIANT)
        partial_n = sum(1 for c in checks if c.status == ComplianceStatus.PARTIAL)
        non_compliant_n = sum(1 for c in checks if c.status == ComplianceStatus.NON_COMPLIANT)
        total = len(checks)
        score = ((compliant_n + partial_n * 0.5) / total * 100) if total else 0.0

        report = ComplianceReport(
            framework=framework,
            total_controls=total,
            compliant=compliant_n,
            partial=partial_n,
            non_compliant=non_compliant_n,
            score_percent=round(score, 2),
            checks=checks,
        )

        if self._logger is not None:
            self._logger.log_event(
                module="compliance",
                module_type="detection",
                event_type="compliance_check",
                details={
                    "framework": framework,
                    "score_percent": report.score_percent,
                    "compliant": compliant_n,
                    "partial": partial_n,
                    "non_compliant": non_compliant_n,
                    "message": f"{framework} compliance: {report.score_percent:.1f}%",
                },
            )

        return report

    @staticmethod
    def _count_keyword_hits(events: list[dict[str, Any]], keywords: list[str]) -> int:
        """Count how many *events* contain at least one keyword match.

        Searches in the ``module``, ``event_type``, and ``details.message``
        fields (case-insensitive).
        """
        count = 0
        for ev in events:
            searchable = " ".join([
                ev.get("module", ""),
                ev.get("event_type", ""),
                str(ev.get("details", {}).get("message", "")),
            ]).lower()
            if any(kw in searchable for kw in keywords):
                count += 1
        return count
