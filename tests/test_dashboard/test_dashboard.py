"""Tests for the web dashboard module."""

import json
import socket
import time
import tempfile
import requests as http_requests
from pathlib import Path

from cybersim.core.logging_engine import CyberSimLogger
from cybersim.dashboard.server import Dashboard

_dashboard = None
_logger = None
_tmpdir = None
_port = None


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _url(path: str) -> str:
    return f"http://127.0.0.1:{_port}{path}"


def _wait_for_dashboard_ready(timeout: float = 5.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            resp = http_requests.get(_url("/api/stats"), timeout=0.5)
            if resp.status_code == 200:
                return
        except http_requests.RequestException:
            time.sleep(0.1)
    raise RuntimeError("Dashboard did not become ready in time")


def setup_module(module):
    global _dashboard, _logger, _tmpdir, _port
    _tmpdir = tempfile.TemporaryDirectory()
    _port = _find_free_port()
    _logger = CyberSimLogger(log_dir=Path(_tmpdir.name), session_id="test_dash")
    _dashboard = Dashboard(port=_port, logger=_logger)
    _dashboard.start()
    _wait_for_dashboard_ready()


def teardown_module(module):
    if _dashboard:
        _dashboard.stop()
    if _tmpdir:
        _tmpdir.cleanup()


class TestDashboard:
    def setup_method(self):
        _logger.clear()
        http_requests.get(_url("/api/replay/live"), timeout=3)

    def test_dashboard_serves_html(self):
        resp = http_requests.get(_url("/dashboard"), timeout=3)
        assert resp.status_code == 200
        assert "CyberSim6" in resp.text
        assert "SOC Mode" in resp.text
        assert "Replay &amp; Forensics" in resp.text
        assert "ATT&amp;CK Command Center" in resp.text

    def test_api_stats_empty(self):
        resp = http_requests.get(_url("/api/stats"), timeout=3)
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_events"] == 0

    def test_api_stats_with_events(self):
        _logger.log_event("ddos", "attack", "test", {"status": "info"})
        _logger.log_event("sqli", "attack", "test", {"status": "warning"})
        resp = http_requests.get(_url("/api/stats"), timeout=3)
        data = resp.json()
        assert data["total_events"] == 2
        assert "ddos" in data["events_by_module"]

    def test_api_events(self):
        _logger.log_event("xss", "attack", "inject", {"message": "test xss"})
        resp = http_requests.get(_url("/api/events"), timeout=3)
        data = resp.json()
        assert len(data) == 1
        assert data[0]["module"] == "xss"

    def test_api_events_module_filter(self):
        _logger.log_event("ddos", "attack", "flood")
        _logger.log_event("sqli", "attack", "inject")
        resp = http_requests.get(_url("/api/events?module=ddos"), timeout=3)
        data = resp.json()
        assert len(data) == 1
        assert data[0]["module"] == "ddos"

    def test_api_events_invalid_limit_falls_back_safely(self):
        _logger.log_event("xss", "attack", "inject", {"message": "payload"})
        resp = http_requests.get(_url("/api/events?limit=invalid"), timeout=3)
        data = resp.json()
        assert resp.status_code == 200
        assert len(data) == 1

    def test_dashboard_html_contains_escape_helper(self):
        resp = http_requests.get(_url("/dashboard"), timeout=3)
        assert "function escapeHtml(value)" in resp.text

    def test_api_timeline(self):
        _logger.log_event("phishing", "attack", "send", {"message": "email sent"})
        resp = http_requests.get(_url("/api/timeline"), timeout=3)
        data = resp.json()
        assert len(data) == 1
        assert data[0]["module"] == "phishing"

    def test_api_soc(self):
        _logger.log_event("ddos_http_flood", "attack", "attack_started", {"status": "warning", "message": "Flood"})
        _logger.log_event("sqli_detector", "detection", "pattern_match", {"status": "error", "message": "SQLi"})
        resp = http_requests.get(_url("/api/soc"), timeout=3)
        data = resp.json()
        assert data["incidents_open"] == 2
        assert data["threat_level"] in {"low", "medium", "high", "critical", "safe"}
        assert data["audit_trail"]["valid"] is True

    def test_api_attack_map(self):
        _logger.log_event("ddos_http_flood", "attack", "attack_started", {"status": "warning"})
        _logger.log_event("sqli_detector", "detection", "pattern_match", {"status": "warning"})
        resp = http_requests.get(_url("/api/attack-map"), timeout=3)
        data = resp.json()
        techniques = {item["technique"] for item in data["techniques"]}
        assert "T1498" in techniques
        assert "T1190" in techniques

    def test_replay_load_and_step(self):
        session_path = Path(_logger.log_dir) / "session_replaydemo.json"
        payload = [
            {
                "timestamp": "2026-03-28T10:00:00+00:00",
                "session_id": "replaydemo",
                "module": "ddos_http_flood",
                "module_type": "attack",
                "event_type": "attack_started",
                "source": "localhost",
                "target": "http://127.0.0.1:8080",
                "status": "warning",
                "details": {"message": "Flood", "status": "warning"},
            },
            {
                "timestamp": "2026-03-28T10:00:05+00:00",
                "session_id": "replaydemo",
                "module": "sqli_detector",
                "module_type": "detection",
                "event_type": "pattern_match",
                "source": "localhost",
                "target": "localhost",
                "status": "error",
                "details": {"message": "SQLi", "status": "error"},
            },
        ]
        session_path.write_text(json.dumps(payload), encoding="utf-8")

        sessions = http_requests.get(_url("/api/replay/sessions"), timeout=3).json()
        assert any(item["session_id"] == "replaydemo" for item in sessions)

        state = http_requests.get(_url("/api/replay/load?session=replaydemo"), timeout=3).json()
        assert state["mode"] == "replay"
        assert state["session_id"] == "replaydemo"

        stats = http_requests.get(_url("/api/stats"), timeout=3).json()
        assert stats["mode"] == "replay"
        assert stats["total_events"] == 2

        reset = http_requests.get(_url("/api/replay/reset"), timeout=3).json()
        assert reset["position"] == 0

        stepped = http_requests.get(_url("/api/replay/step?count=1"), timeout=3).json()
        assert stepped["position"] == 1

        live = http_requests.get(_url("/api/replay/live"), timeout=3).json()
        assert live["mode"] == "live"
