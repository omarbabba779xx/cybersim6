"""Runtime tests for the XSS attack module."""

from __future__ import annotations

import pytest

import cybersim.xss.xss_attack as xss_attack_module
from cybersim.core.safety import SafetyError
from cybersim.xss.vulnerable_app import XSSVulnerableServer
from cybersim.xss.xss_attack import XSSAttack
from tests.helpers import wait_for_http_ready


def test_xss_attack_runs_against_local_vulnerable_app(logger, monkeypatch):
    monkeypatch.setattr(xss_attack_module.time, "sleep", lambda *_: None)

    server = XSSVulnerableServer(port=0, logger=logger)
    server.start()
    base_url = f"http://{server.host}:{server.port}"
    wait_for_http_ready(base_url)

    try:
        attack = XSSAttack(config={"target_url": base_url}, logger=logger)
        result = attack.run()
    finally:
        server.stop()

    assert result["total"] == (
        (2 * len(xss_attack_module.XSS_PAYLOADS["reflected"]))
        + len(xss_attack_module.XSS_PAYLOADS["stored"])
        + 1
    )
    assert result["injected"] >= 13
    assert len(result["findings"]) >= 13
    assert server.get_request_log()
    assert logger.get_events(module="xss_attack", event_type="attack_completed")


def test_xss_attack_blocks_non_loopback_target(logger):
    with pytest.raises(SafetyError):
        XSSAttack(config={"target_url": "http://example.com:8082"}, logger=logger)


def test_xss_attack_stop_logs_event(logger):
    attack = XSSAttack(config={"target_url": "http://127.0.0.1:8082"}, logger=logger)
    attack.stop()

    stopped = logger.get_events(module="xss_attack", event_type="attack_stopped")
    assert stopped
