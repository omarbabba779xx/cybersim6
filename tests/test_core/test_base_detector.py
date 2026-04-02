"""Tests for the base detector class."""

from __future__ import annotations

from cybersim.core.base_detector import BaseDetector
from cybersim.core.logging_engine import CyberSimLogger


class ConcreteDetector(BaseDetector):
    MODULE_NAME = "test_detector"

    def __init__(self, config, logger):
        self.cycle_count = 0
        super().__init__(config, logger)

    def _check_cycle(self, **kwargs):
        self.cycle_count += 1


class TestBaseDetector:
    def test_init(self, tmp_path):
        logger = CyberSimLogger(log_dir=tmp_path, session_id="test")
        det = ConcreteDetector(config={}, logger=logger)
        assert det.metrics is not None
        assert det._running is False

    def test_record_detection(self, tmp_path):
        logger = CyberSimLogger(log_dir=tmp_path, session_id="test")
        det = ConcreteDetector(config={}, logger=logger)
        det.record_detection(True, True, "found something")
        report = det.metrics.get_metrics("test_detector")
        assert report.true_positives == 1

    def test_run_and_stop(self, tmp_path):
        logger = CyberSimLogger(log_dir=tmp_path, session_id="test")
        det = ConcreteDetector(config={}, logger=logger)
        det.run(duration=1, interval=0.2)
        assert det.cycle_count > 0
        assert det._running is False

    def test_stop_method(self, tmp_path):
        logger = CyberSimLogger(log_dir=tmp_path, session_id="test")
        det = ConcreteDetector(config={}, logger=logger)
        det._running = True
        det.stop()
        assert det._running is False
