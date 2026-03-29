"""Runtime tests for the SQL injection attack module."""

from __future__ import annotations

import pytest

import cybersim.sqli.injection_attack as sqli_attack_module
from cybersim.core.safety import SafetyError
from cybersim.sqli.injection_attack import SQLInjectionAttack
from cybersim.sqli.vulnerable_server import VulnerableSQLServer
from tests.helpers import wait_for_http_ready


def test_sqli_attack_runs_against_local_vulnerable_server(logger, monkeypatch):
    monkeypatch.setattr(sqli_attack_module.time, "sleep", lambda *_: None)

    server = VulnerableSQLServer(port=0, logger=logger)
    server.start()
    base_url = f"http://{server.host}:{server.port}"
    wait_for_http_ready(base_url)

    try:
        attack = SQLInjectionAttack(config={"target_url": base_url}, logger=logger)
        result = attack.run()
    finally:
        server.stop()

    assert result["total"] == sum(len(payloads) for payloads in sqli_attack_module.SQLI_PAYLOADS.values())
    assert result["successful"] >= 8
    assert len(result["findings"]) >= 8
    assert server.get_query_log()
    assert logger.get_events(module="sqli_attack", event_type="attack_completed")


def test_sqli_attack_blocks_non_loopback_target(logger):
    with pytest.raises(SafetyError):
        SQLInjectionAttack(config={"target_url": "http://0.0.0.0:8081"}, logger=logger)


def test_sqli_attack_stop_logs_event(logger):
    attack = SQLInjectionAttack(config={"target_url": "http://127.0.0.1:8081"}, logger=logger)
    attack.stop()

    stopped = logger.get_events(module="sqli_attack", event_type="attack_stopped")
    assert stopped

