"""Tests for SQL Injection module (detection)."""

import pytest

from cybersim.core.logging_engine import CyberSimLogger
from cybersim.sqli.detection import SQLInjectionDetector


class TestSQLInjectionDetector:
    def setup_method(self):
        self.logger = CyberSimLogger(session_id="test_sqli")
        self.detector = SQLInjectionDetector(config={}, logger=self.logger)

    def test_clean_query(self):
        detections = self.detector.analyze_query("SELECT * FROM users WHERE id = 1")
        assert len(detections) == 0

    def test_detect_union_injection(self):
        detections = self.detector.analyze_query("' UNION SELECT username,password FROM users --")
        patterns = [d["pattern"] for d in detections]
        assert "UNION-based injection" in patterns

    def test_detect_boolean_injection(self):
        detections = self.detector.analyze_query("' OR '1'='1' --")
        patterns = [d["pattern"] for d in detections]
        assert "Boolean-based injection" in patterns

    def test_detect_stacked_query(self):
        detections = self.detector.analyze_query("1; DROP TABLE users --")
        patterns = [d["pattern"] for d in detections]
        assert "Stacked query injection" in patterns

    def test_detect_schema_extraction(self):
        detections = self.detector.analyze_query("SELECT * FROM sqlite_master")
        patterns = [d["pattern"] for d in detections]
        assert "Schema extraction attempt" in patterns

    def test_detect_time_based(self):
        detections = self.detector.analyze_query("1 AND SLEEP(5)")
        patterns = [d["pattern"] for d in detections]
        assert "Time-based injection" in patterns

    def test_analyze_query_log(self):
        log = [
            {"sql": "SELECT * FROM users WHERE id = 1", "endpoint": "/user"},
            {"sql": "' UNION SELECT * FROM users --", "endpoint": "/search"},
            {"sql": "1; DROP TABLE users --", "endpoint": "/api"},
        ]
        summary = self.detector.analyze_query_log(log)
        assert summary["total_queries"] == 3
        assert summary["malicious_queries"] > 0

    def test_events_logged(self):
        self.detector.analyze_query("' UNION SELECT * FROM users --", endpoint="/search")
        sqli_events = [e for e in self.logger.events if e["event_type"] == "sqli_detected"]
        assert len(sqli_events) > 0
