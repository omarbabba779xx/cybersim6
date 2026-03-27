"""Tests for cybersim.core.compliance module."""

import pytest

from cybersim.core.compliance import (
    ComplianceChecker,
    ComplianceReport,
    ComplianceCheck,
    ComplianceStatus,
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
