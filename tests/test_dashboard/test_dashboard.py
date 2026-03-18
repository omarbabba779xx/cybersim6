"""Tests for the web dashboard module."""

import json
import time
import pytest
import requests as http_requests

from cybersim.core.logging_engine import CyberSimLogger
from cybersim.dashboard.server import Dashboard

_dashboard = None
_logger = None


def setup_module(module):
    global _dashboard, _logger
    _logger = CyberSimLogger(session_id="test_dash")
    _dashboard = Dashboard(port=18888, logger=_logger)
    _dashboard.start()
    time.sleep(0.5)


def teardown_module(module):
    global _dashboard
    if _dashboard:
        _dashboard.stop()


class TestDashboard:
    def setup_method(self):
        _logger.clear()

    def test_dashboard_serves_html(self):
        resp = http_requests.get("http://127.0.0.1:18888/dashboard", timeout=3)
        assert resp.status_code == 200
        assert "CyberSim6" in resp.text

    def test_api_stats_empty(self):
        resp = http_requests.get("http://127.0.0.1:18888/api/stats", timeout=3)
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_events"] == 0

    def test_api_stats_with_events(self):
        _logger.log_event("ddos", "attack", "test", {"status": "info"})
        _logger.log_event("sqli", "attack", "test", {"status": "warning"})
        resp = http_requests.get("http://127.0.0.1:18888/api/stats", timeout=3)
        data = resp.json()
        assert data["total_events"] == 2
        assert "ddos" in data["events_by_module"]

    def test_api_events(self):
        _logger.log_event("xss", "attack", "inject", {"message": "test xss"})
        resp = http_requests.get("http://127.0.0.1:18888/api/events", timeout=3)
        data = resp.json()
        assert len(data) == 1
        assert data[0]["module"] == "xss"

    def test_api_events_module_filter(self):
        _logger.log_event("ddos", "attack", "flood")
        _logger.log_event("sqli", "attack", "inject")
        resp = http_requests.get("http://127.0.0.1:18888/api/events?module=ddos", timeout=3)
        data = resp.json()
        assert len(data) == 1
        assert data[0]["module"] == "ddos"

    def test_api_timeline(self):
        _logger.log_event("phishing", "attack", "send", {"message": "email sent"})
        resp = http_requests.get("http://127.0.0.1:18888/api/timeline", timeout=3)
        data = resp.json()
        assert len(data) == 1
        assert data[0]["module"] == "phishing"
