"""HTTP-level tests for the brute force auth server."""

from __future__ import annotations

import requests as http_requests

from cybersim.bruteforce.auth_server import AuthHandler, AuthServer
from tests.helpers import wait_for_http_ready


def test_auth_server_supports_login_stats_and_lockout(logger, monkeypatch):
    monkeypatch.setattr(AuthHandler, "LOCKOUT_THRESHOLD", 2)
    monkeypatch.setattr(AuthHandler, "LOCKOUT_DURATION", 60)

    server = AuthServer(port=0, logger=logger, credentials={"admin": "letmein"})
    server.start()
    base_url = f"http://{server.host}:{server.port}"
    wait_for_http_ready(f"{base_url}/login")

    try:
        login_page = http_requests.get(f"{base_url}/login", timeout=3)
        success = http_requests.post(
            f"{base_url}/login",
            data={"username": "admin", "password": "letmein"},
            timeout=3,
        )
        fail_one = http_requests.post(
            f"{base_url}/login",
            data={"username": "admin", "password": "wrong"},
            timeout=3,
        )
        fail_two = http_requests.post(
            f"{base_url}/login",
            data={"username": "admin", "password": "wrong-again"},
            timeout=3,
        )
        locked = http_requests.post(
            f"{base_url}/login",
            data={"username": "admin", "password": "still-wrong"},
            timeout=3,
        )
        stats = http_requests.get(f"{base_url}/stats", timeout=3).json()
    finally:
        server.stop()

    assert login_page.status_code == 200
    assert "FICTITIOUS" in login_page.text
    assert success.status_code == 200
    assert fail_one.status_code == 401
    assert fail_two.status_code == 401
    assert locked.status_code == 429
    assert stats == {"total_attempts": 3, "successes": 1, "failures": 2}
    assert len(server.get_attempt_log()) == 3

    locked_events = logger.get_events(module="bruteforce_auth_server", event_type="account_locked")
    assert locked_events
