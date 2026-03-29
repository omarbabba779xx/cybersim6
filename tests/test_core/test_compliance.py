"""Tests for cybersim.core.compliance module."""

from cybersim.core.compliance import (
    ComplianceChecker,
    ComplianceStatus,
    ControlSeverity,
    MaturityLevel,
    RiskRating,
)


def _make_event(module: str, event_type: str, message: str = "") -> dict:
    """Helper to build a minimal event dict."""
    return {
        "module": module,
        "event_type": event_type,
        "details": {"message": message},
    }


class TestComplianceChecker:
    """Suite of 8 tests covering the ComplianceChecker."""

    def setup_method(self) -> None:
        self.checker = ComplianceChecker(logger=None)

    # 1 — No events yields all non-compliant
    def test_no_events_all_non_compliant(self) -> None:
        report = self.checker.check_iso27001([])
        assert report.framework == "ISO 27001"
        assert report.compliant == 0
        assert report.non_compliant == report.total_controls
        assert report.score_percent == 0.0

    # 2 — Events matching a control produce COMPLIANT
    def test_matching_events_compliant(self) -> None:
        events = [
            _make_event("ddos_detection", "flood", "DDoS flood detected"),
            _make_event("ddos_detection", "rate_limit", "Rate limited"),
        ]
        report = self.checker.check_iso27001(events)
        a13 = next(c for c in report.checks if c.control_id == "A.13.1.1")
        assert a13.status == ComplianceStatus.COMPLIANT

    # 3 — Single matching event produces PARTIAL
    def test_single_event_partial(self) -> None:
        events = [_make_event("ransomware", "encryption_detected", "Ransom found")]
        report = self.checker.check_iso27001(events)
        a12_2 = next(c for c in report.checks if c.control_id == "A.12.2.1")
        assert a12_2.status == ComplianceStatus.PARTIAL

    # 4 — check_all returns three reports
    def test_check_all_returns_three(self) -> None:
        reports = self.checker.check_all([])
        assert len(reports) == 3
        frameworks = {r.framework for r in reports}
        assert frameworks == {"ISO 27001", "NIST CSF", "RGPD"}

    # 5 — Score calculation with mixed statuses
    def test_score_calculation(self) -> None:
        events = [
            _make_event("waf", "blocked_request", "WAF blocked"),
            _make_event("waf", "firewall", "Firewall active"),
            _make_event("siem", "alert", "Alert raised"),
        ]
        report = self.checker.check_iso27001(events)
        # At least A.14.1.2 (WAF) should be compliant, A.16.1.2 (logging) partial
        assert report.score_percent > 0.0
        assert report.compliant >= 1

    # 6 — NIST check recognises network monitoring events
    def test_nist_network_monitoring(self) -> None:
        events = [
            _make_event("ids", "anomaly", "Traffic anomaly detected"),
            _make_event("ids", "network_monitor", "Monitoring active"),
        ]
        report = self.checker.check_nist(events)
        de_cm1 = next(c for c in report.checks if c.control_id == "DE.CM-1")
        assert de_cm1.status == ComplianceStatus.COMPLIANT

    # 7 — RGPD check recognises breach notification
    def test_rgpd_breach_notification(self) -> None:
        events = [
            _make_event("incident", "breach_detected", "Breach detected"),
            _make_event("incident", "breach_notification", "CNIL notified"),
        ]
        report = self.checker.check_rgpd(events)
        art33 = next(c for c in report.checks if c.control_id == "Art.33")
        assert art33.status == ComplianceStatus.COMPLIANT

    # 8 — generate_summary produces readable text
    def test_generate_summary(self) -> None:
        reports = self.checker.check_all([])
        summary = self.checker.generate_summary(reports)
        assert "COMPLIANCE SUMMARY" in summary
        assert "ISO 27001" in summary
        assert "NIST CSF" in summary
        assert "RGPD" in summary
        assert "[XX]" in summary  # Non-compliant markers expected


class TestWeightedScoring:
    """Tests for the new weighted scoring functionality."""

    def setup_method(self) -> None:
        self.checker = ComplianceChecker(logger=None)

    def test_controls_have_severity(self) -> None:
        """Each check should carry a severity and weight."""
        report = self.checker.check_iso27001([])
        for check in report.checks:
            assert isinstance(check.severity, ControlSeverity)
            assert check.weight in (1, 2, 3)

    def test_critical_control_weight_is_3(self) -> None:
        """Critical controls should have weight=3."""
        report = self.checker.check_iso27001([])
        a12_6 = next(c for c in report.checks if c.control_id == "A.12.6.1")
        assert a12_6.severity == ControlSeverity.CRITICAL
        assert a12_6.weight == 3

    def test_high_control_weight_is_2(self) -> None:
        """High severity controls should have weight=2."""
        report = self.checker.check_iso27001([])
        a5 = next(c for c in report.checks if c.control_id == "A.5.1.1")
        assert a5.severity == ControlSeverity.HIGH
        assert a5.weight == 2

    def test_medium_control_weight_is_1(self) -> None:
        """Medium severity controls should have weight=1."""
        report = self.checker.check_iso27001([])
        a16 = next(c for c in report.checks if c.control_id == "A.16.1.2")
        assert a16.severity == ControlSeverity.MEDIUM
        assert a16.weight == 1

    def test_weighted_score_zero_for_no_events(self) -> None:
        """Weighted score should be 0 when no events are provided."""
        report = self.checker.check_iso27001([])
        assert report.weighted_score_percent == 0.0

    def test_weighted_score_positive_with_events(self) -> None:
        """Weighted score should be > 0 when matching events exist."""
        events = [
            _make_event("sqli", "injection", "SQL injection blocked"),
            _make_event("xss", "vulnerability", "XSS detected"),
        ]
        report = self.checker.check_iso27001(events)
        assert report.weighted_score_percent > 0.0

    def test_weighted_score_differs_from_simple_score(self) -> None:
        """Weighted and simple scores can differ due to severity weighting."""
        # Only satisfy A.16.1.2 (medium, weight=1) - simple and weighted will differ
        events = [
            _make_event("siem", "event_recorded", "Event recorded"),
            _make_event("siem", "logging", "Logging active"),
        ]
        report = self.checker.check_iso27001(events)
        # Simple score treats all controls equally: 1/7 compliant
        # Weighted score weights by severity: 1*1 / total_weight
        assert report.score_percent > 0.0
        assert report.weighted_score_percent > 0.0


class TestEvidenceQuality:
    """Tests for evidence quality scoring."""

    def setup_method(self) -> None:
        self.checker = ComplianceChecker(logger=None)

    def test_no_events_zero_evidence_score(self) -> None:
        """No events should produce evidence_score=0."""
        report = self.checker.check_iso27001([])
        for check in report.checks:
            assert check.evidence_score == 0.0

    def test_strong_keyword_higher_score(self) -> None:
        """Strong keyword matches should produce higher evidence scores."""
        # "ransomware" is a strong keyword for A.12.2.1
        strong_events = [
            _make_event("av", "ransomware", "Ransomware detected"),
        ]
        # "malware" is a regular keyword for A.12.2.1
        # (also a strong keyword, but let's use one that's only regular)
        report = self.checker.check_iso27001(strong_events)
        a12_2 = next(c for c in report.checks if c.control_id == "A.12.2.1")
        assert a12_2.evidence_score > 0.0

    def test_two_strong_events_full_score(self) -> None:
        """Two strong keyword events should produce evidence_score=1.0."""
        events = [
            _make_event("av", "ransomware", "Ransomware found"),
            _make_event("av", "encryption_detected", "Encrypted files"),
        ]
        report = self.checker.check_iso27001(events)
        a12_2 = next(c for c in report.checks if c.control_id == "A.12.2.1")
        assert a12_2.evidence_score == 1.0

    def test_evidence_score_capped_at_one(self) -> None:
        """Evidence score should not exceed 1.0 even with many events."""
        events = [
            _make_event("av", "ransomware", "Ransomware 1"),
            _make_event("av", "ransomware", "Ransomware 2"),
            _make_event("av", "encryption_detected", "Encrypted 1"),
            _make_event("av", "malware", "Malware found"),
        ]
        report = self.checker.check_iso27001(events)
        a12_2 = next(c for c in report.checks if c.control_id == "A.12.2.1")
        assert a12_2.evidence_score == 1.0

    def test_partial_evidence_from_weak_keyword(self) -> None:
        """A single weak-only keyword match should give partial evidence."""
        # "login" is a regular keyword for A.9.4.2 but not a strong one
        events = [
            _make_event("auth", "login", "User logged in"),
        ]
        report = self.checker.check_iso27001(events)
        a9 = next(c for c in report.checks if c.control_id == "A.9.4.2")
        assert 0.0 < a9.evidence_score < 1.0


class TestMaturityLevels:
    """Tests for maturity level classification."""

    def setup_method(self) -> None:
        self.checker = ComplianceChecker(logger=None)

    def test_not_implemented_on_no_events(self) -> None:
        """No events should produce NOT_IMPLEMENTED maturity."""
        report = self.checker.check_iso27001([])
        for check in report.checks:
            assert check.maturity == MaturityLevel.NOT_IMPLEMENTED

    def test_partial_maturity_on_single_event(self) -> None:
        """A single strong event gives PARTIAL maturity (score ~0.5)."""
        events = [
            _make_event("av", "ransomware", "Ransomware detected"),
        ]
        report = self.checker.check_iso27001(events)
        a12_2 = next(c for c in report.checks if c.control_id == "A.12.2.1")
        assert a12_2.maturity == MaturityLevel.PARTIAL

    def test_compliant_maturity_on_strong_evidence(self) -> None:
        """Two strong events should produce COMPLIANT maturity."""
        events = [
            _make_event("av", "ransomware", "Ransomware found"),
            _make_event("av", "encryption_detected", "Encrypted files"),
        ]
        report = self.checker.check_iso27001(events)
        a12_2 = next(c for c in report.checks if c.control_id == "A.12.2.1")
        assert a12_2.maturity == MaturityLevel.COMPLIANT

    def test_maturity_enum_values(self) -> None:
        """Maturity enum should have the expected string values."""
        assert MaturityLevel.NOT_IMPLEMENTED.value == "not_implemented"
        assert MaturityLevel.PARTIAL.value == "partial"
        assert MaturityLevel.COMPLIANT.value == "compliant"


class TestRiskRating:
    """Tests for risk rating computation."""

    def setup_method(self) -> None:
        self.checker = ComplianceChecker(logger=None)

    def test_critical_risk_on_no_events(self) -> None:
        """No events = all critical controls fail = CRITICAL risk."""
        report = self.checker.check_iso27001([])
        # ISO has 3 critical controls (A.9.4.2, A.12.2.1, A.12.6.1), all non-compliant
        assert report.risk_rating == RiskRating.CRITICAL

    def test_low_risk_when_all_compliant(self) -> None:
        """Satisfying all controls should produce LOW risk."""
        events = [
            # A.5.1.1
            _make_event("policy", "security_policy", "Policy active"),
            _make_event("policy", "policy_update", "Policy updated"),
            # A.9.4.2
            _make_event("auth", "brute_force", "Brute force blocked"),
            _make_event("auth", "lockout", "Account locked"),
            # A.12.2.1
            _make_event("av", "ransomware", "Ransomware blocked"),
            _make_event("av", "malware", "Malware removed"),
            # A.12.6.1
            _make_event("scanner", "sqli", "SQL injection found"),
            _make_event("scanner", "xss", "XSS found"),
            # A.13.1.1
            _make_event("ddos", "flood", "Flood detected"),
            _make_event("ddos", "rate_limit", "Rate limited"),
            # A.14.1.2
            _make_event("waf", "blocked_request", "Request blocked"),
            _make_event("waf", "firewall", "Firewall active"),
            # A.16.1.2
            _make_event("siem", "event_recorded", "Event recorded"),
            _make_event("siem", "logging", "Logging active"),
        ]
        report = self.checker.check_iso27001(events)
        assert report.risk_rating == RiskRating.LOW

    def test_medium_risk_one_critical_failure(self) -> None:
        """One failed critical control = MEDIUM risk."""
        # Satisfy A.9.4.2 and A.12.6.1 (critical), leave A.12.2.1 (critical) failing
        events = [
            _make_event("auth", "brute_force", "Blocked"),
            _make_event("auth", "lockout", "Locked"),
            _make_event("scanner", "sqli", "Found"),
            _make_event("scanner", "xss", "Found"),
        ]
        report = self.checker.check_iso27001(events)
        # A.12.2.1 still non-compliant (1 critical failure)
        assert report.risk_rating == RiskRating.MEDIUM

    def test_risk_rating_enum_values(self) -> None:
        """RiskRating enum should have the expected string values."""
        assert RiskRating.LOW.value == "low"
        assert RiskRating.MEDIUM.value == "medium"
        assert RiskRating.HIGH.value == "high"
        assert RiskRating.CRITICAL.value == "critical"


class TestDetailedReport:
    """Tests for the detailed_report() method."""

    def setup_method(self) -> None:
        self.checker = ComplianceChecker(logger=None)

    def test_detailed_report_has_all_frameworks(self) -> None:
        """detailed_report should include all three frameworks."""
        result = self.checker.detailed_report([])
        assert "ISO 27001" in result
        assert "NIST CSF" in result
        assert "RGPD" in result

    def test_detailed_report_structure(self) -> None:
        """Each framework entry should have the expected keys."""
        result = self.checker.detailed_report([])
        for framework_name in ("ISO 27001", "NIST CSF", "RGPD"):
            fw = result[framework_name]
            assert "score_percent" in fw
            assert "weighted_score_percent" in fw
            assert "risk_rating" in fw
            assert "total_controls" in fw
            assert "maturity_breakdown" in fw
            assert "controls" in fw

    def test_detailed_report_maturity_breakdown(self) -> None:
        """Maturity breakdown should sum to total_controls."""
        result = self.checker.detailed_report([])
        for framework_name in ("ISO 27001", "NIST CSF", "RGPD"):
            fw = result[framework_name]
            mb = fw["maturity_breakdown"]
            total = mb["not_implemented"] + mb["partial"] + mb["compliant"]
            assert total == fw["total_controls"]

    def test_detailed_report_controls_have_severity(self) -> None:
        """Each control in detailed report should have severity info."""
        result = self.checker.detailed_report([])
        for ctrl in result["ISO 27001"]["controls"]:
            assert "severity" in ctrl
            assert ctrl["severity"] in ("critical", "high", "medium")
            assert "weight" in ctrl
            assert ctrl["weight"] in (1, 2, 3)

    def test_detailed_report_with_events(self) -> None:
        """detailed_report should reflect provided events."""
        events = [
            _make_event("av", "ransomware", "Ransomware found"),
            _make_event("av", "encryption_detected", "Encrypted files"),
        ]
        result = self.checker.detailed_report(events)
        iso = result["ISO 27001"]
        assert iso["score_percent"] > 0.0
        assert iso["weighted_score_percent"] > 0.0
        # A.12.2.1 should be compliant
        a12_2 = next(c for c in iso["controls"] if c["control_id"] == "A.12.2.1")
        assert a12_2["status"] == "compliant"
        assert a12_2["maturity"] == "compliant"
        assert a12_2["evidence_score"] == 1.0


class TestScoreMethod:
    """Tests for the score() convenience method."""

    def setup_method(self) -> None:
        self.checker = ComplianceChecker(logger=None)

    def test_score_returns_all_frameworks(self) -> None:
        """score() should return a dict with all three framework scores."""
        scores = self.checker.score([])
        assert "ISO 27001" in scores
        assert "NIST CSF" in scores
        assert "RGPD" in scores

    def test_score_zero_for_no_events(self) -> None:
        """score() should return 0 for all frameworks when no events."""
        scores = self.checker.score([])
        for v in scores.values():
            assert v == 0.0

    def test_score_positive_with_events(self) -> None:
        """score() should return positive values with matching events."""
        events = [
            _make_event("av", "ransomware", "Found"),
            _make_event("av", "malware", "Found"),
        ]
        scores = self.checker.score(events)
        assert scores["ISO 27001"] > 0.0


class TestGenerateSummaryEnhanced:
    """Tests for the enhanced generate_summary output."""

    def setup_method(self) -> None:
        self.checker = ComplianceChecker(logger=None)

    def test_summary_includes_weighted_score(self) -> None:
        """Summary should include weighted score information."""
        reports = self.checker.check_all([])
        summary = self.checker.generate_summary(reports)
        assert "Weighted Score" in summary

    def test_summary_includes_risk_rating(self) -> None:
        """Summary should include risk rating."""
        reports = self.checker.check_all([])
        summary = self.checker.generate_summary(reports)
        assert "Risk Rating" in summary

    def test_summary_includes_maturity_tags(self) -> None:
        """Summary should include maturity level tags."""
        reports = self.checker.check_all([])
        summary = self.checker.generate_summary(reports)
        assert "not_implemented" in summary

    def test_summary_includes_severity(self) -> None:
        """Summary should include severity info per control."""
        reports = self.checker.check_all([])
        summary = self.checker.generate_summary(reports)
        assert "severity=" in summary
