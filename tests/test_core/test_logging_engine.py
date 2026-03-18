"""Tests for cybersim.core.logging_engine module."""

import json
import pytest
from pathlib import Path

from cybersim.core.logging_engine import CyberSimLogger


class TestCyberSimLogger:
    def test_init_creates_session(self, tmp_path):
        logger = CyberSimLogger(log_dir=tmp_path)
        assert logger.session_id
        assert len(logger.session_id) == 8
        assert logger.events == []

    def test_custom_session_id(self, tmp_path):
        logger = CyberSimLogger(log_dir=tmp_path, session_id="test1234")
        assert logger.session_id == "test1234"

    def test_log_event(self, tmp_path):
        logger = CyberSimLogger(log_dir=tmp_path)
        record = logger.log_event("test_module", "attack", "test_event", {"message": "hello"})
        assert record["module"] == "test_module"
        assert record["module_type"] == "attack"
        assert record["event_type"] == "test_event"
        assert record["timestamp"]
        assert record["session_id"] == logger.session_id
        assert len(logger.events) == 1

    def test_multiple_events(self, tmp_path):
        logger = CyberSimLogger(log_dir=tmp_path)
        for i in range(5):
            logger.log_event("mod", "attack", f"event_{i}")
        assert len(logger.events) == 5

    def test_export_json(self, tmp_path):
        logger = CyberSimLogger(log_dir=tmp_path)
        logger.log_event("mod", "attack", "test", {"message": "hi"})
        path = logger.export_json()
        assert path.exists()
        data = json.loads(path.read_text())
        assert len(data) == 1
        assert data[0]["module"] == "mod"

    def test_export_csv(self, tmp_path):
        logger = CyberSimLogger(log_dir=tmp_path)
        logger.log_event("mod", "attack", "test", {"message": "hi"})
        path = logger.export_csv()
        assert path.exists()
        content = path.read_text()
        assert "mod" in content
        assert "attack" in content

    def test_get_events_filter_module(self, tmp_path):
        logger = CyberSimLogger(log_dir=tmp_path)
        logger.log_event("ddos", "attack", "flood")
        logger.log_event("sqli", "attack", "inject")
        logger.log_event("ddos", "attack", "flood2")
        result = logger.get_events(module="ddos")
        assert len(result) == 2

    def test_get_events_filter_type(self, tmp_path):
        logger = CyberSimLogger(log_dir=tmp_path)
        logger.log_event("mod", "attack", "start")
        logger.log_event("mod", "attack", "progress")
        logger.log_event("mod", "attack", "start")
        result = logger.get_events(event_type="start")
        assert len(result) == 2

    def test_clear(self, tmp_path):
        logger = CyberSimLogger(log_dir=tmp_path)
        logger.log_event("mod", "attack", "test")
        logger.clear()
        assert len(logger.events) == 0
