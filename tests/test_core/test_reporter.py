"""Tests for cybersim.core.reporter module."""

from cybersim.core.logging_engine import CyberSimLogger
from cybersim.core.reporter import generate_summary


class TestReporter:
    def test_empty_summary(self, tmp_path):
        logger = CyberSimLogger(log_dir=tmp_path)
        summary = generate_summary(logger)
        assert summary["total_events"] == 0

    def test_summary_with_events(self, tmp_path):
        logger = CyberSimLogger(log_dir=tmp_path)
        logger.log_event("ddos", "attack", "start", {"status": "warning"})
        logger.log_event("ddos", "attack", "complete", {"status": "info"})
        logger.log_event("sqli", "attack", "start", {"status": "info"})

        summary = generate_summary(logger)
        assert summary["total_events"] == 3
        assert summary["events_by_module"]["ddos"] == 2
        assert summary["events_by_module"]["sqli"] == 1
        assert "start" in summary["time_range"]
