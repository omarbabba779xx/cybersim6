"""HTTP-level tests for the intentionally vulnerable XSS app."""

from __future__ import annotations

import requests as http_requests

from cybersim.xss.vulnerable_app import XSSVulnerableServer
from tests.helpers import wait_for_http_ready


def test_xss_vulnerable_app_exposes_training_endpoints(logger):
    server = XSSVulnerableServer(port=0, logger=logger)
    server.start()
    base_url = f"http://{server.host}:{server.port}"
    wait_for_http_ready(base_url)

    try:
        search = http_requests.get(f"{base_url}/search", params={"q": "<script>alert(1)</script>"}, timeout=3)
        add_comment = http_requests.post(
            f"{base_url}/comment",
            data={"name": "alice", "message": "<img src=x onerror=alert(1)>"},
            timeout=3,
            allow_redirects=False,
        )
        guestbook = http_requests.get(f"{base_url}/guestbook", timeout=3)
        error_page = http_requests.get(f"{base_url}/error", params={"msg": "<b>boom</b>"}, timeout=3)
        api_comments = http_requests.get(f"{base_url}/api/comments", timeout=3).json()
        dom_page = http_requests.get(f"{base_url}/dom", timeout=3)
    finally:
        server.stop()

    assert search.status_code == 200
    assert "<script>alert(1)</script>" in search.text
    assert add_comment.status_code == 302
    assert "onerror=alert(1)" in guestbook.text
    assert "<b>boom</b>" in error_page.text
    assert api_comments["comments"][0]["name"] == "alice"
    assert "window.location.hash" in dom_page.text
    assert len(server.get_request_log()) >= 4
