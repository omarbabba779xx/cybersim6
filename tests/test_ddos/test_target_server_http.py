"""HTTP-level tests for the DDoS target server."""

from __future__ import annotations

import requests as http_requests

from cybersim.ddos.target_server import TargetServer
from tests.helpers import wait_for_http_ready


def test_target_server_serves_requests_and_logs(logger):
    server = TargetServer(port=0, logger=logger)
    server.start()
    base_url = f"http://{server.host}:{server.port}"
    wait_for_http_ready(base_url)

    try:
        resp_get = http_requests.get(f"{base_url}/", timeout=3)
        resp_post = http_requests.post(f"{base_url}/submit", timeout=3)
    finally:
        server.stop()

    assert resp_get.status_code == 200
    assert resp_post.status_code == 200
    assert "CyberSim6 Target Server" in resp_get.text
    assert server.get_request_count() >= 2

    events = logger.get_events(module="ddos_target")
    assert len(events) >= 2
    assert events[0]["event_type"] == "request_received"
