"""HTTP-level tests for the intentionally vulnerable SQL server."""

from __future__ import annotations

import requests as http_requests

from cybersim.sqli.vulnerable_server import VulnerableSQLServer
from tests.helpers import wait_for_http_ready


def test_vulnerable_sql_server_exposes_insecure_endpoints(logger):
    server = VulnerableSQLServer(port=0, logger=logger)
    server.start()
    base_url = f"http://{server.host}:{server.port}"
    wait_for_http_ready(base_url)

    try:
        search = http_requests.get(f"{base_url}/search", params={"q": "Firewall"}, timeout=3)
        login = http_requests.post(
            f"{base_url}/login",
            data={"username": "admin", "password": "admin_s3cr3t_pw"},
            timeout=3,
        )
        user = http_requests.get(f"{base_url}/user", params={"id": "1"}, timeout=3)
        api_users = http_requests.get(f"{base_url}/api/users", params={"id": "1 OR 1=1"}, timeout=3).json()
        broken = http_requests.get(f"{base_url}/search", params={"q": "'"}, timeout=3)
    finally:
        server.stop()

    assert search.status_code == 200
    assert "Firewall Pro" in search.text
    assert login.status_code == 200
    assert "Login Successful" in login.text
    assert "admin@cybersim6.local" in user.text
    assert len(api_users["data"]) >= 1
    assert broken.status_code == 500
    assert len(server.get_query_log()) >= 4
