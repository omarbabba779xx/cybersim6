"""HTTP-level tests for the phishing simulation server."""

from __future__ import annotations

import requests as http_requests

from cybersim.phishing.phishing_server import PhishingServer
from tests.helpers import wait_for_http_ready


def test_phishing_server_serves_templates_and_captures_credentials(logger):
    server = PhishingServer(port=0, template="office365", logger=logger)
    server.start()
    base_url = f"http://{server.host}:{server.port}"
    wait_for_http_ready(base_url)

    try:
        landing = http_requests.get(base_url, timeout=3)
        capture = http_requests.post(
            f"{base_url}/capture",
            data={"email": "victim@example.com", "password": "super-secret"},
            timeout=3,
        )
        reveal = http_requests.get(f"{base_url}/reveal", timeout=3)
        stats = http_requests.get(f"{base_url}/stats", timeout=3).json()
    finally:
        server.stop()

    assert landing.status_code == 200
    assert "Sign in" in landing.text
    assert capture.status_code == 200
    assert "You Have Been Phished" in capture.text
    assert reveal.status_code == 200
    assert stats["total_captures"] == 1
    assert stats["credentials"][0]["email"] == "victim@example.com"
    assert "office365" in PhishingServer.list_templates()
