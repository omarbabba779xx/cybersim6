"""Runtime tests for the HTTP flood module."""

from __future__ import annotations

from cybersim.ddos.http_flood import HTTPFloodAttack
from cybersim.ddos.target_server import TargetServer
from tests.helpers import wait_for_http_ready


def test_http_flood_attack_hits_local_target(logger):
    server = TargetServer(port=0, logger=logger)
    server.start()
    base_url = f"http://{server.host}:{server.port}"
    wait_for_http_ready(base_url)

    try:
        attack = HTTPFloodAttack(
            config={"target_url": base_url, "request_count": 12, "threads": 3},
            logger=logger,
        )
        result = attack.run()
    finally:
        server.stop()

    assert result["success_count"] == 12
    assert result["fail_count"] == 0
    assert server.get_request_count() >= 12

    completed = logger.get_events(module="ddos_http_flood", event_type="attack_completed")
    assert completed
