"""Tests for the remediation recommendations engine."""

from __future__ import annotations

from cybersim.core.remediation import RemediationEngine, REMEDIATION_DB


class TestRemediationEngine:
    def test_empty_engine(self):
        engine = RemediationEngine()
        recs = engine.get_recommendations()
        assert len(recs) == 0

    def test_add_finding(self):
        engine = RemediationEngine()
        engine.add_finding("sqli", "SQL Injection detected")
        recs = engine.get_recommendations()
        assert len(recs) > 0
        assert any("SQL" in r.title or "Parameterized" in r.title for r in recs)

    def test_all_attack_types_have_recommendations(self):
        for attack_type in ["ddos", "sqli", "xss", "bruteforce", "phishing", "ransomware"]:
            assert attack_type in REMEDIATION_DB
            assert len(REMEDIATION_DB[attack_type]) > 0

    def test_recommendations_sorted_by_priority(self):
        engine = RemediationEngine()
        engine.add_finding("ddos")
        engine.add_finding("sqli")
        recs = engine.get_recommendations()
        priorities = [r.priority for r in recs]
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        for i in range(len(priorities) - 1):
            assert order.get(priorities[i], 99) <= order.get(priorities[i + 1], 99)

    def test_analyze_events(self):
        engine = RemediationEngine()
        events = [
            {"event_type": "ddos_detected", "module": "ddos", "details": {"status": "warning", "message": "DDoS detected"}},
            {"event_type": "sqli_detected", "module": "sqli", "details": {"status": "warning", "message": "SQL injection"}},
        ]
        engine.analyze_events(events)
        recs = engine.get_recommendations()
        assert len(recs) > 0

    def test_generate_report(self):
        engine = RemediationEngine()
        engine.add_finding("xss")
        text = engine.generate_report()
        assert "REMEDIATION RECOMMENDATIONS" in text

    def test_to_dict(self):
        engine = RemediationEngine()
        engine.add_finding("bruteforce")
        d = engine.to_dict()
        assert "total_findings" in d
        assert "recommendations" in d
        assert d["total_findings"] == 1

    def test_reset(self):
        engine = RemediationEngine()
        engine.add_finding("ddos")
        engine.reset()
        assert len(engine.get_recommendations()) == 0

    def test_no_duplicate_recommendations(self):
        engine = RemediationEngine()
        engine.add_finding("sqli")
        engine.add_finding("sqli")
        recs = engine.get_recommendations()
        titles = [r.title for r in recs]
        assert len(titles) == len(set(titles))
