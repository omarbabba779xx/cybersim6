"""Tests for the incident response engine."""

from __future__ import annotations

from cybersim.core.logging_engine import CyberSimLogger
from cybersim.incident_response.response_engine import (
    IncidentResponse, IRPhase, Severity, PLAYBOOKS,
)


def _make_events():
    return [
        {"event_type": "ddos_detected", "module": "ddos_detector", "timestamp": "2026-01-01T00:00:00", "details": {"status": "warning", "message": "DDoS DETECTED"}},
        {"event_type": "sqli_detected", "module": "sqli_detector", "timestamp": "2026-01-01T00:01:00", "details": {"status": "warning", "message": "SQLi DETECTED"}},
        {"event_type": "http_flood_started", "module": "ddos", "timestamp": "2026-01-01T00:00:30", "details": {"status": "info", "message": "HTTP Flood started"}},
    ]


class TestIncidentResponse:
    def test_analyze_classifies_attack_types(self, tmp_path):
        logger = CyberSimLogger(log_dir=tmp_path, session_id="test")
        ir = IncidentResponse(logger=logger, events=_make_events())
        ir.analyze()
        assert "ddos" in ir.incident.attack_types
        assert "sqli" in ir.incident.attack_types

    def test_analyze_sets_severity(self, tmp_path):
        logger = CyberSimLogger(log_dir=tmp_path, session_id="test")
        ir = IncidentResponse(logger=logger, events=_make_events())
        ir.analyze()
        # sqli is CRITICAL, so severity should be CRITICAL
        assert ir.incident.severity == Severity.CRITICAL

    def test_get_playbook(self, tmp_path):
        logger = CyberSimLogger(log_dir=tmp_path, session_id="test")
        ir = IncidentResponse(logger=logger, events=_make_events())
        ir.analyze()
        actions = ir.get_playbook(IRPhase.CONTAINMENT)
        assert len(actions) > 0

    def test_run_full_workflow(self, tmp_path):
        logger = CyberSimLogger(log_dir=tmp_path, session_id="test")
        ir = IncidentResponse(logger=logger, events=_make_events())
        report = ir.run()
        assert report["resolved"] is True
        assert report["phases_completed"] >= 4
        assert len(report["timeline"]) > 0

    def test_run_empty_events(self, tmp_path):
        logger = CyberSimLogger(log_dir=tmp_path, session_id="test")
        ir = IncidentResponse(logger=logger, events=[])
        report = ir.run()
        assert report["resolved"] is False

    def test_generate_text_report(self, tmp_path):
        logger = CyberSimLogger(log_dir=tmp_path, session_id="test")
        ir = IncidentResponse(logger=logger, events=_make_events())
        ir.run()
        text = ir.generate_text_report()
        assert "INCIDENT RESPONSE REPORT" in text
        assert "CRITICAL" in text

    def test_all_attack_types_have_playbooks(self):
        for attack_type in ["ddos", "sqli", "xss", "bruteforce", "phishing", "ransomware"]:
            assert attack_type in PLAYBOOKS
            assert "containment" in PLAYBOOKS[attack_type]
            assert "eradication" in PLAYBOOKS[attack_type]
            assert "recovery" in PLAYBOOKS[attack_type]

    def test_sla_tracking(self, tmp_path):
        logger = CyberSimLogger(log_dir=tmp_path, session_id="test")
        ir = IncidentResponse(logger=logger, events=_make_events())
        ir.analyze()
        assert ir.incident.sla_minutes > 0
        assert ir.incident.sla_remaining() >= 0
