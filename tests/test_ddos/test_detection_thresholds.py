"""Tests for DDoS detection at boundary threshold values."""
import time
import pytest
from cybersim.ddos.detection import DDoSDetector
from cybersim.core.logging_engine import CyberSimLogger


@pytest.fixture
def detector():
    return DDoSDetector(config={"threshold_pps": 10, "window_seconds": 1}, logger=CyberSimLogger())


class TestDDoSThresholds:
    def test_below_threshold_no_attack(self, detector):
        # 5 requests in 1s window, threshold 10 → no attack
        for _ in range(5):
            detector.record_request()
        result = detector.check_threshold(threshold_rps=10, window=1)
        assert result["is_attack"] is False
        assert result["requests_in_window"] == 5

    def test_at_threshold_no_attack(self, detector):
        # Exactly at threshold — not strictly above → no attack
        for _ in range(10):
            detector.record_request()
        result = detector.check_threshold(threshold_rps=10, window=1)
        assert result["is_attack"] is False

    def test_above_threshold_is_attack(self, detector):
        # 11 requests → above 10/s threshold
        for _ in range(11):
            detector.record_request()
        result = detector.check_threshold(threshold_rps=10, window=1)
        assert result["is_attack"] is True

    def test_rate_calculation(self, detector):
        for _ in range(20):
            detector.record_request()
        result = detector.check_threshold(threshold_rps=100, window=2)
        assert result["rate_per_second"] == pytest.approx(10.0, abs=0.1)
        assert result["window_seconds"] == 2

    def test_zero_requests(self, detector):
        result = detector.check_threshold(threshold_rps=10, window=1)
        assert result["is_attack"] is False
        assert result["requests_in_window"] == 0
        assert result["rate_per_second"] == 0.0

    def test_old_requests_excluded(self, detector):
        # Add requests and pretend they're old by manipulating the log
        detector.record_request()
        # Manually age the entry
        with detector._lock:
            old_entry = detector._request_log[0].copy()
            old_entry["time"] = time.time() - 10  # 10 seconds ago
            detector._request_log[0] = old_entry
        result = detector.check_threshold(threshold_rps=10, window=1)
        assert result["requests_in_window"] == 0

    def test_result_structure(self, detector):
        result = detector.check_threshold()
        assert "requests_in_window" in result
        assert "window_seconds" in result
        assert "rate_per_second" in result
        assert "threshold" in result
        assert "is_attack" in result

    def test_high_volume_attack(self, detector):
        for _ in range(1000):
            detector.record_request()
        result = detector.check_threshold(threshold_rps=10, window=1)
        assert result["is_attack"] is True
        assert result["requests_in_window"] == 1000

    def test_custom_window(self, detector):
        for _ in range(5):
            detector.record_request()
        result = detector.check_threshold(threshold_rps=1, window=5)
        assert result["window_seconds"] == 5
        assert result["rate_per_second"] == pytest.approx(1.0, abs=0.1)

    def test_uses_config_defaults(self):
        det = DDoSDetector(config={"threshold_pps": 50, "window_seconds": 5}, logger=CyberSimLogger())
        for _ in range(300):
            det.record_request()
        result = det.check_threshold()
        assert result["threshold"] == 50
        assert result["window_seconds"] == 5
        assert result["is_attack"] is True
