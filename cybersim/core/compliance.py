"""
Compliance Checker -- Verify security posture against ISO 27001, NIST CSF, and RGPD.

Evaluates simulation event logs and produces per-framework compliance
reports with control-level status, evidence, and recommendations.
Uses only the Python standard library.

Features:
- Weighted scoring per control (critical=3, high=2, medium=1)
- Evidence quality scoring (partial=0.5, full=1.0)
- Maturity levels: NOT_IMPLEMENTED, PARTIAL, COMPLIANT
- Overall compliance score per framework (percentage)
- Risk rating based on non-compliant critical controls
"""

from __future__ import annotations

from dataclasses import dataclass
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


class MaturityLevel(Enum):
    """Maturity level for a control based on evidence quality score."""

    NOT_IMPLEMENTED = "not_implemented"
    PARTIAL = "partial"
    COMPLIANT = "compliant"


class ControlSeverity(Enum):
    """Severity/weight classification for a control."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"


class RiskRating(Enum):
    """Overall risk rating for a framework based on non-compliant critical controls."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# Weights for each severity level
_SEVERITY_WEIGHTS: dict[ControlSeverity, int] = {
    ControlSeverity.CRITICAL: 3,
    ControlSeverity.HIGH: 2,
    ControlSeverity.MEDIUM: 1,
}


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
        severity: Control severity (critical, high, medium).
        weight: Numeric weight derived from severity.
        evidence_score: Quality score from 0.0 to 1.0.
        maturity: Maturity level derived from evidence quality.
    """

    framework: str
    control_id: str
    control_name: str
    description: str
    status: ComplianceStatus
    evidence: str
    recommendation: str
    severity: ControlSeverity = ControlSeverity.MEDIUM
    weight: int = 1
    evidence_score: float = 0.0
    maturity: MaturityLevel = MaturityLevel.NOT_IMPLEMENTED


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
        weighted_score_percent: Severity-weighted compliance percentage.
        risk_rating: Overall risk rating for the framework.
    """

    framework: str
    total_controls: int
    compliant: int
    partial: int
    non_compliant: int
    score_percent: float
    checks: list[ComplianceCheck]
    weighted_score_percent: float = 0.0
    risk_rating: RiskRating = RiskRating.LOW


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
# Severity mappings per control
# ---------------------------------------------------------------------------

_ISO_SEVERITY: dict[str, ControlSeverity] = {
    "A.5.1.1": ControlSeverity.HIGH,
    "A.9.4.2": ControlSeverity.CRITICAL,
    "A.12.2.1": ControlSeverity.CRITICAL,
    "A.12.6.1": ControlSeverity.CRITICAL,
    "A.13.1.1": ControlSeverity.HIGH,
    "A.14.1.2": ControlSeverity.HIGH,
    "A.16.1.2": ControlSeverity.MEDIUM,
}

_NIST_SEVERITY: dict[str, ControlSeverity] = {
    "ID.AM-1": ControlSeverity.MEDIUM,
    "PR.AC-1": ControlSeverity.CRITICAL,
    "PR.DS-1": ControlSeverity.CRITICAL,
    "PR.IP-1": ControlSeverity.MEDIUM,
    "DE.CM-1": ControlSeverity.HIGH,
    "DE.CM-4": ControlSeverity.CRITICAL,
    "RS.RP-1": ControlSeverity.HIGH,
}

_RGPD_SEVERITY: dict[str, ControlSeverity] = {
    "Art.5": ControlSeverity.CRITICAL,
    "Art.25": ControlSeverity.HIGH,
    "Art.30": ControlSeverity.MEDIUM,
    "Art.32": ControlSeverity.CRITICAL,
    "Art.33": ControlSeverity.CRITICAL,
    "Art.35": ControlSeverity.HIGH,
    "Art.37": ControlSeverity.MEDIUM,
}

# Map framework name to severity dict
_FRAMEWORK_SEVERITY: dict[str, dict[str, ControlSeverity]] = {
    "ISO 27001": _ISO_SEVERITY,
    "NIST CSF": _NIST_SEVERITY,
    "RGPD": _RGPD_SEVERITY,
}


# ---------------------------------------------------------------------------
# Strong evidence keywords (full match quality = 1.0 per event)
# Regular keywords from the maps above give partial quality = 0.5 per event
# Strong keywords indicate definitive evidence of a control being in place
# ---------------------------------------------------------------------------

_ISO_STRONG_KEYWORDS: dict[str, list[str]] = {
    "A.5.1.1": ["security_policy", "policy_update"],
    "A.9.4.2": ["lockout", "brute_force"],
    "A.12.2.1": ["ransomware", "encryption_detected"],
    "A.12.6.1": ["sqli", "xss", "injection"],
    "A.13.1.1": ["ddos", "network_anomaly"],
    "A.14.1.2": ["waf", "blocked_request"],
    "A.16.1.2": ["siem", "event_recorded"],
}

_NIST_STRONG_KEYWORDS: dict[str, list[str]] = {
    "ID.AM-1": ["inventory", "device_discovered"],
    "PR.AC-1": ["access_control", "rbac"],
    "PR.DS-1": ["encryption", "data_at_rest"],
    "PR.IP-1": ["baseline", "hardening"],
    "DE.CM-1": ["network_monitor", "ids"],
    "DE.CM-4": ["malware", "ransomware"],
    "RS.RP-1": ["incident_response", "response_plan"],
}

_RGPD_STRONG_KEYWORDS: dict[str, list[str]] = {
    "Art.5": ["consent", "lawful_basis"],
    "Art.25": ["privacy_by_design", "pseudonymization"],
    "Art.30": ["processing_record", "ropa"],
    "Art.32": ["encryption", "security_measure"],
    "Art.33": ["breach_notification", "incident_report"],
    "Art.35": ["dpia", "impact_assessment"],
    "Art.37": ["dpo_appointed", "data_protection_officer"],
}

_FRAMEWORK_STRONG_KEYWORDS: dict[str, dict[str, list[str]]] = {
    "ISO 27001": _ISO_STRONG_KEYWORDS,
    "NIST CSF": _NIST_STRONG_KEYWORDS,
    "RGPD": _RGPD_STRONG_KEYWORDS,
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

    def score(self, events: list[dict[str, Any]]) -> dict[str, float]:
        """Return a mapping of framework name to simple score percentage.

        This is a convenience method for quick scoring.

        Args:
            events: List of event dicts.

        Returns:
            Dict mapping framework name to ``score_percent``.
        """
        reports = self.check_all(events)
        return {r.framework: r.score_percent for r in reports}

    def detailed_report(self, events: list[dict[str, Any]]) -> dict[str, Any]:
        """Return a detailed report with maturity levels, weighted scores, and risk ratings.

        Args:
            events: List of event dicts.

        Returns:
            Dict with per-framework details including maturity breakdown,
            weighted scores, and risk ratings.
        """
        reports = self.check_all(events)
        result: dict[str, Any] = {}

        for report in reports:
            maturity_counts = {
                MaturityLevel.NOT_IMPLEMENTED.value: 0,
                MaturityLevel.PARTIAL.value: 0,
                MaturityLevel.COMPLIANT.value: 0,
            }
            controls_detail = []

            for check in report.checks:
                maturity_counts[check.maturity.value] += 1
                controls_detail.append({
                    "control_id": check.control_id,
                    "control_name": check.control_name,
                    "status": check.status.value,
                    "maturity": check.maturity.value,
                    "severity": check.severity.value,
                    "weight": check.weight,
                    "evidence_score": check.evidence_score,
                    "evidence": check.evidence,
                    "recommendation": check.recommendation,
                })

            result[report.framework] = {
                "score_percent": report.score_percent,
                "weighted_score_percent": report.weighted_score_percent,
                "risk_rating": report.risk_rating.value,
                "total_controls": report.total_controls,
                "maturity_breakdown": maturity_counts,
                "controls": controls_detail,
            }

        return result

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
            lines.append(
                f"  Weighted Score: {report.weighted_score_percent:.1f}% | "
                f"Risk Rating: {report.risk_rating.value.upper()}"
            )
            for check in report.checks:
                status_icon = {
                    ComplianceStatus.COMPLIANT: "[OK]",
                    ComplianceStatus.PARTIAL: "[!!]",
                    ComplianceStatus.NON_COMPLIANT: "[XX]",
                }[check.status]
                maturity_tag = f"[{check.maturity.value}]"
                lines.append(
                    f"  {status_icon} {check.control_id} - {check.control_name} "
                    f"{maturity_tag} (severity={check.severity.value}, score={check.evidence_score:.2f})"
                )
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

        Evidence quality scoring:
        - Strong keyword match in an event -> 1.0 quality per event
        - Regular keyword match in an event -> 0.5 quality per event
        - Total evidence_score is capped at 1.0

        Status thresholds (based on evidence_score):
        - evidence_score >= 0.75  -> COMPLIANT
        - evidence_score >= 0.25  -> PARTIAL
        - evidence_score < 0.25   -> NON_COMPLIANT

        Backward compatibility: the hit-count logic (2+ = COMPLIANT,
        1 = PARTIAL, 0 = NON_COMPLIANT) is preserved as the basis for
        the simple ``score_percent``.
        """
        severity_map = _FRAMEWORK_SEVERITY.get(framework, {})
        strong_kw_map = _FRAMEWORK_STRONG_KEYWORDS.get(framework, {})
        checks: list[ComplianceCheck] = []

        for control_id, control_name, description in controls:
            kws = keywords_map.get(control_id, [])
            strong_kws = strong_kw_map.get(control_id, [])
            severity = severity_map.get(control_id, ControlSeverity.MEDIUM)
            weight = _SEVERITY_WEIGHTS[severity]

            matching = self._count_keyword_hits(events, kws)
            evidence_score = self._compute_evidence_score(events, kws, strong_kws)
            maturity = self._score_to_maturity(evidence_score)

            # Backward-compatible status based on raw hit count
            if matching >= 2:
                status = ComplianceStatus.COMPLIANT
                evidence = f"Found {matching} related events (evidence quality: {evidence_score:.0%})."
                recommendation = "Maintain current controls."
            elif matching == 1:
                status = ComplianceStatus.PARTIAL
                evidence = f"Found {matching} related event (evidence quality: {evidence_score:.0%}, insufficient coverage)."
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
                severity=severity,
                weight=weight,
                evidence_score=evidence_score,
                maturity=maturity,
            ))

        compliant_n = sum(1 for c in checks if c.status == ComplianceStatus.COMPLIANT)
        partial_n = sum(1 for c in checks if c.status == ComplianceStatus.PARTIAL)
        non_compliant_n = sum(1 for c in checks if c.status == ComplianceStatus.NON_COMPLIANT)
        total = len(checks)
        # Backward-compatible simple score
        score = ((compliant_n + partial_n * 0.5) / total * 100) if total else 0.0

        # Weighted score: each control's evidence_score * weight / max possible weight
        total_weight = sum(c.weight for c in checks)
        weighted_score = (
            (sum(c.evidence_score * c.weight for c in checks) / total_weight * 100)
            if total_weight
            else 0.0
        )

        risk_rating = self._compute_risk_rating(checks)

        report = ComplianceReport(
            framework=framework,
            total_controls=total,
            compliant=compliant_n,
            partial=partial_n,
            non_compliant=non_compliant_n,
            score_percent=round(score, 2),
            checks=checks,
            weighted_score_percent=round(weighted_score, 2),
            risk_rating=risk_rating,
        )

        if self._logger is not None:
            self._logger.log_event(
                module="compliance",
                module_type="detection",
                event_type="compliance_check",
                details={
                    "framework": framework,
                    "score_percent": report.score_percent,
                    "weighted_score_percent": report.weighted_score_percent,
                    "risk_rating": report.risk_rating.value,
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

    @staticmethod
    def _compute_evidence_score(
        events: list[dict[str, Any]],
        keywords: list[str],
        strong_keywords: list[str],
    ) -> float:
        """Compute an evidence quality score between 0.0 and 1.0.

        Each matching event contributes:
        - 1.0 / required_events if it matches a strong keyword
        - 0.5 / required_events if it matches only a regular keyword

        The score is capped at 1.0. We consider 2 strong-keyword events
        as full evidence (required_events = 2).
        """
        required_events = 2  # two strong matches = full evidence
        total = 0.0

        for ev in events:
            searchable = " ".join([
                ev.get("module", ""),
                ev.get("event_type", ""),
                str(ev.get("details", {}).get("message", "")),
            ]).lower()

            if any(kw in searchable for kw in strong_keywords):
                total += 1.0 / required_events
            elif any(kw in searchable for kw in keywords):
                total += 0.5 / required_events

        return min(total, 1.0)

    @staticmethod
    def _score_to_maturity(evidence_score: float) -> MaturityLevel:
        """Map an evidence quality score to a maturity level.

        - >= 0.75 -> COMPLIANT
        - >= 0.25 -> PARTIAL
        - < 0.25  -> NOT_IMPLEMENTED
        """
        if evidence_score >= 0.75:
            return MaturityLevel.COMPLIANT
        if evidence_score >= 0.25:
            return MaturityLevel.PARTIAL
        return MaturityLevel.NOT_IMPLEMENTED

    @staticmethod
    def _compute_risk_rating(checks: list[ComplianceCheck]) -> RiskRating:
        """Derive an overall risk rating from non-compliant critical controls.

        - 0 non-compliant critical controls -> LOW
        - 1 non-compliant critical control  -> MEDIUM
        - 2 non-compliant critical controls -> HIGH
        - 3+ non-compliant critical controls -> CRITICAL
        """
        critical_failures = sum(
            1
            for c in checks
            if c.severity == ControlSeverity.CRITICAL
            and c.status == ComplianceStatus.NON_COMPLIANT
        )
        if critical_failures >= 3:
            return RiskRating.CRITICAL
        if critical_failures >= 2:
            return RiskRating.HIGH
        if critical_failures >= 1:
            return RiskRating.MEDIUM
        return RiskRating.LOW
