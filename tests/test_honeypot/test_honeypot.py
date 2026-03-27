"""Tests for Honeypot module (server, traps, analyzer)."""

import time
import urllib.request
import urllib.error

import pytest

from cybersim.core.logging_engine import CyberSimLogger
from cybersim.honeypot.honeypot import (
    DEFAULT_TRAPS,
    HoneypotAnalyzer,
    HoneypotServer,
    HoneypotTrap,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get(url: str) -> tuple[int, str]:
    """Issue a GET request and return (status_code, body)."""
    try:
        resp = urllib.request.urlopen(url, timeout=5)
        return resp.status, resp.read().decode()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode()


def _post(url: str, data: str = "") -> tuple[int, str]:
    """Issue a POST request and return (status_code, body)."""
    req = urllib.request.Request(url, data=data.encode(), method="POST")
    try:
        resp = urllib.request.urlopen(req, timeout=5)
        return resp.status, resp.read().decode()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def logger(tmp_path):
    return CyberSimLogger(log_dir=tmp_path, session_id="test_honeypot")


@pytest.fixture()
def server(logger):
    """Start a honeypot on a free port and tear it down after the test."""
    srv = HoneypotServer(logger=logger, host="127.0.0.1", port=0)
    # Port 0 lets the OS assign a free port
    srv.start()
    # Retrieve the actual port from the underlying socket
    srv.port = srv._server.server_address[1]
    yield srv
    srv.stop()


@pytest.fixture()
def analyzer(logger):
    return HoneypotAnalyzer(logger=logger)


# ---------------------------------------------------------------------------
# Tests — traps
# ---------------------------------------------------------------------------

class TestDefaultTraps:
    """Verify the built-in trap catalogue."""

    def test_default_traps_exist(self):
        """DEFAULT_TRAPS list is populated with 8 entries."""
        assert len(DEFAULT_TRAPS) == 8

    def test_all_traps_have_required_fields(self):
        for trap in DEFAULT_TRAPS:
            assert trap.name
            assert trap.path.startswith("/")
            assert isinstance(trap.response_code, int)
            assert trap.response_body
            assert trap.trap_type in (
                "login", "api", "admin", "error", "file", "banner",
            )

    def test_trap_paths_unique(self):
        paths = [t.path for t in DEFAULT_TRAPS]
        assert len(paths) == len(set(paths)), "Duplicate trap paths found"


# ---------------------------------------------------------------------------
# Tests — server responses
# ---------------------------------------------------------------------------

class TestHoneypotServer:
    """Integration tests that hit the running honeypot."""

    def test_fake_login_trap_response(self, server):
        """GET /admin/login returns the login form HTML."""
        status, body = _get(f"http://127.0.0.1:{server.port}/admin/login")
        assert status == 200
        assert "Admin Panel" in body
        assert "<form" in body

    def test_fake_env_trap_response(self, server):
        """GET /.env returns fake credentials."""
        status, body = _get(f"http://127.0.0.1:{server.port}/.env")
        assert status == 200
        assert "DB_PASSWORD" in body
        assert "SECRET_KEY" in body

    def test_fake_api_response(self, server):
        """GET /api/v1/users returns JSON user list."""
        status, body = _get(f"http://127.0.0.1:{server.port}/api/v1/users")
        assert status == 200
        import json
        data = json.loads(body)
        assert "users" in data
        assert data["users"][0]["name"] == "admin"

    def test_sql_error_trap(self, server):
        """GET /search returns a 500 with a fake MySQL error."""
        status, body = _get(f"http://127.0.0.1:{server.port}/search?q=test")
        assert status == 500
        assert "MySQL Error" in body

    def test_unknown_path_returns_404(self, server):
        """Paths not matching any trap still return a realistic 404."""
        status, body = _get(f"http://127.0.0.1:{server.port}/nonexistent")
        assert status == 404
        assert "Not Found" in body


# ---------------------------------------------------------------------------
# Tests — interaction logging and stats
# ---------------------------------------------------------------------------

class TestInteractionLogging:
    """Verify that all hits are recorded."""

    def test_interaction_logged(self, server):
        """Each request is stored in the interactions list."""
        _get(f"http://127.0.0.1:{server.port}/admin/login")
        _get(f"http://127.0.0.1:{server.port}/.env")
        interactions = server.get_interactions()
        assert len(interactions) == 2
        assert interactions[0]["method"] == "GET"
        assert interactions[0]["path"] == "/admin/login"
        assert interactions[1]["path"] == "/.env"

    def test_interaction_contains_all_fields(self, server):
        """Each interaction record has the expected keys."""
        _get(f"http://127.0.0.1:{server.port}/admin/login")
        ix = server.get_interactions()[0]
        required = {"timestamp", "source_ip", "source_port", "method", "path", "headers", "body"}
        assert required.issubset(ix.keys())

    def test_post_body_logged(self, server):
        """POST body is captured in the interaction."""
        _post(
            f"http://127.0.0.1:{server.port}/admin/login",
            data="username=admin&password=secret",
        )
        ix = server.get_interactions()[0]
        assert ix["method"] == "POST"
        assert "username=admin" in ix["body"]

    def test_stats_tracking(self, server):
        """get_stats returns correct aggregate numbers."""
        _get(f"http://127.0.0.1:{server.port}/admin/login")
        _get(f"http://127.0.0.1:{server.port}/.env")
        _get(f"http://127.0.0.1:{server.port}/nonexistent")

        stats = server.get_stats()
        assert stats["total_interactions"] == 3
        assert stats["unique_ips"] >= 1
        assert stats["by_method"]["GET"] == 3
        assert stats["traps_hit"] == 2  # /admin/login and /.env
        assert stats["traps_missed"] == 6  # the other 6 default traps

    def test_attacker_profile(self, server):
        """get_attacker_profile returns a populated summary."""
        _get(f"http://127.0.0.1:{server.port}/admin/login")
        _get(f"http://127.0.0.1:{server.port}/.env")
        profile = server.get_attacker_profile()
        assert profile["unique_ips"] >= 1
        assert profile["total_interactions"] == 2
        assert "GET" in profile["methods_used"]

    def test_custom_trap_addition(self, server):
        """A custom trap added at runtime responds correctly."""
        custom = HoneypotTrap(
            name="Custom Trap",
            path="/secret/data",
            response_code=200,
            response_body='{"secret": "value"}',
            trap_type="api",
        )
        server.add_trap(custom)
        status, body = _get(f"http://127.0.0.1:{server.port}/secret/data")
        assert status == 200
        assert '"secret"' in body


# ---------------------------------------------------------------------------
# Tests — analyzer
# ---------------------------------------------------------------------------

class TestHoneypotAnalyzer:
    """Unit tests for offline analysis of interaction logs."""

    @staticmethod
    def _make_interactions(
        paths: list[str],
        *,
        ip: str = "10.0.0.1",
        method: str = "GET",
        include_post: bool = False,
    ) -> list[dict]:
        """Helper to build fake interaction records."""
        interactions = []
        for i, path in enumerate(paths):
            m = "POST" if include_post and i == len(paths) - 1 else method
            interactions.append(
                {
                    "timestamp": time.time() + i,
                    "source_ip": ip,
                    "source_port": 50000 + i,
                    "method": m,
                    "path": path,
                    "headers": {"User-Agent": "TestBot/1.0"},
                    "body": "payload=test" if m == "POST" else "",
                }
            )
        return interactions

    def test_classify_scanner(self, analyzer):
        """Many unique scanner paths => 'scanner'."""
        ix = self._make_interactions(
            ["/.env", "/wp-admin/", "/phpmyadmin/", "/backup.sql.gz"]
        )
        assert analyzer.classify_attacker(ix) == "scanner"

    def test_classify_bot(self, analyzer):
        """Repetitive requests to the same path => 'bot'."""
        ix = self._make_interactions(["/admin/login"] * 6)
        assert analyzer.classify_attacker(ix) == "bot"

    def test_classify_manual(self, analyzer):
        """Very few requests => 'manual'."""
        ix = self._make_interactions(["/admin/login"])
        assert analyzer.classify_attacker(ix) == "manual"

    def test_classify_apt(self, analyzer):
        """Recon + exploit paths + POST => 'apt'."""
        ix = self._make_interactions(
            ["/.env", "/wp-admin/", "/phpmyadmin/", "/backup.sql.gz", "/admin/login"],
            include_post=True,
        )
        assert analyzer.classify_attacker(ix) == "apt"

    def test_classify_none(self, analyzer):
        """Empty list => 'none'."""
        assert analyzer.classify_attacker([]) == "none"

    def test_ioc_generation(self, analyzer):
        """generate_ioc extracts IP, UA, paths, payloads."""
        ix = self._make_interactions(
            ["/admin/login", "/.env"], include_post=True
        )
        ioc = analyzer.generate_ioc(ix)
        assert "10.0.0.1" in ioc["ip_addresses"]
        assert "TestBot/1.0" in ioc["user_agents"]
        assert "/admin/login" in ioc["paths_accessed"]
        assert len(ioc["timestamps"]) == 2

    def test_ioc_captures_payloads(self, analyzer):
        """POST payloads appear in the IOC output."""
        ix = self._make_interactions(
            ["/admin/login"], include_post=True
        )
        ioc = analyzer.generate_ioc(ix)
        assert any("payload" in p for p in ioc["payloads"])

    def test_analyze_interactions_full(self, analyzer):
        """analyze_interactions returns a complete report dict."""
        ix = self._make_interactions(
            ["/.env", "/wp-admin/", "/phpmyadmin/", "/admin/login"]
        )
        report = analyzer.analyze_interactions(ix)
        assert report["total"] == 4
        assert report["unique_ips"] == 1
        assert report["classification"] == "scanner"
        assert "ip_addresses" in report["ioc"]
        assert len(report["timeline"]) == 4

    def test_analyze_empty(self, analyzer):
        """Empty interaction list produces a safe empty report."""
        report = analyzer.analyze_interactions([])
        assert report["total"] == 0
        assert report["classification"] == "none"
