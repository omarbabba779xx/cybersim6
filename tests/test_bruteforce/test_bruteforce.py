"""Tests for Brute Force module (detection)."""

import pytest

from cybersim.core.logging_engine import CyberSimLogger
from cybersim.bruteforce.detection import BruteForceDetector


class TestBruteForceDetector:
    def setup_method(self):
        self.logger = CyberSimLogger(session_id="test_bf")
        self.detector = BruteForceDetector(
            config={"max_failures": 5, "window_seconds": 60},
            logger=self.logger,
        )

    def test_no_attempts_safe(self):
        result = self.detector.check_brute_force()
        assert result == []

    def test_detect_brute_force(self):
        for _ in range(10):
            self.detector.record_attempt("10.0.0.1", success=False)
        detections = self.detector.check_brute_force()
        assert len(detections) == 1
        assert detections[0]["source_ip"] == "10.0.0.1"
        assert detections[0]["failures_in_window"] >= 10

    def test_successful_login_not_counted(self):
        for _ in range(10):
            self.detector.record_attempt("10.0.0.1", success=True)
        detections = self.detector.check_brute_force()
        assert len(detections) == 0

    def test_different_ips_isolated(self):
        for _ in range(10):
            self.detector.record_attempt("10.0.0.1", success=False)
        # IP .2 has no failures
        detections = self.detector.check_brute_force()
        ips = [d["source_ip"] for d in detections]
        assert "10.0.0.1" in ips
        assert "10.0.0.2" not in ips

    def test_below_threshold(self):
        for _ in range(3):
            self.detector.record_attempt("10.0.0.1", success=False)
        detections = self.detector.check_brute_force()
        assert len(detections) == 0

    def test_events_logged(self):
        for _ in range(10):
            self.detector.record_attempt("10.0.0.1", success=False)
        self.detector.check_brute_force()
        events = [e for e in self.logger.events if e["event_type"] == "bruteforce_detected"]
        assert len(events) > 0
