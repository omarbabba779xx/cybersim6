"""Tests for DDoS module (detection + HTTP flood)."""

from cybersim.core.logging_engine import CyberSimLogger
from cybersim.ddos.detection import DDoSDetector


class TestDDoSDetector:
    def setup_method(self):
        self.logger = CyberSimLogger(session_id="test_ddos")
        self.detector = DDoSDetector(config={}, logger=self.logger)

    def test_no_requests_no_attack(self):
        result = self.detector.check_threshold(threshold_rps=10, window=5)
        assert result["is_attack"] is False
        assert result["requests_in_window"] == 0

    def test_detect_high_rate(self):
        for _ in range(200):
            self.detector.record_request("127.0.0.1")
        result = self.detector.check_threshold(threshold_rps=10, window=5)
        assert result["is_attack"] is True
        assert result["requests_in_window"] == 200

    def test_below_threshold(self):
        for _ in range(5):
            self.detector.record_request("127.0.0.1")
        result = self.detector.check_threshold(threshold_rps=100, window=5)
        assert result["is_attack"] is False

    def test_events_logged_on_detection(self):
        for _ in range(500):
            self.detector.record_request("127.0.0.1")
        self.detector.check_threshold(threshold_rps=10, window=5)
        ddos_events = self.logger.get_events(event_type="ddos_detected")
        assert len(ddos_events) > 0
