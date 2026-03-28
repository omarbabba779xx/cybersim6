"""Tests for Honeypot module (server, traps, analyzer)."""

import time
import urllib.request
import urllib.error
from typing import Any

import pytest

from cybersim.core.logging_engine import CyberSimLogger
from cybersim.honeypot.honeypot import (
    DEFAULT_TRAPS,
    AttackCorrelator,
    HoneypotAnalyzer,
    HoneypotServer,
    HoneypotTrap,
    ThreatLevel,
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


# ---------------------------------------------------------------------------
# Tests — AttackCorrelator
# ---------------------------------------------------------------------------

class TestAttackCorrelator:
    """Unit tests for the cross-trap AttackCorrelator."""

    @staticmethod
    def _interaction(
        ip: str,
        path: str,
        ts: float | None = None,
        method: str = "GET",
        body: str = "",
    ) -> dict[str, Any]:
        """Build a single fake interaction dict."""
        return {
            "timestamp": ts if ts is not None else time.time(),
            "source_ip": ip,
            "source_port": 50000,
            "method": method,
            "path": path,
            "headers": {"User-Agent": "TestBot/1.0"},
            "body": body,
        }

    @pytest.fixture()
    def correlator(self):
        return AttackCorrelator(traps=DEFAULT_TRAPS, fast_threshold=2.0, brute_force_threshold=5)

    # -- threat level escalation ---------------------------------------------

    def test_single_trap_low_threat(self, correlator):
        """One trap visited => LOW threat level."""
        correlator.record(self._interaction("10.0.0.1", "/admin/login", ts=1000.0))
        report = correlator.get_threat_report()
        assert report["threats"]["10.0.0.1"]["threat_level"] == "LOW"

    def test_two_traps_medium_threat(self, correlator):
        """Two traps visited => at least MEDIUM threat level."""
        correlator.record(self._interaction("10.0.0.1", "/admin/login", ts=1000.0))
        correlator.record(self._interaction("10.0.0.1", "/.env", ts=1010.0))
        report = correlator.get_threat_report()
        level = report["threats"]["10.0.0.1"]["threat_level"]
        assert level in ("MEDIUM", "HIGH", "CRITICAL")

    def test_four_traps_high_threat(self, correlator):
        """Four traps visited => at least HIGH threat level."""
        paths = ["/admin/login", "/.env", "/api/v1/users", "/phpmyadmin/"]
        for i, p in enumerate(paths):
            correlator.record(self._interaction("10.0.0.1", p, ts=1000.0 + i * 10))
        report = correlator.get_threat_report()
        level = report["threats"]["10.0.0.1"]["threat_level"]
        assert level in ("HIGH", "CRITICAL")

    def test_six_traps_critical_threat(self, correlator):
        """Six or more traps visited => CRITICAL threat level."""
        paths = [
            "/admin/login", "/.env", "/api/v1/users",
            "/phpmyadmin/", "/wp-admin/", "/search",
        ]
        for i, p in enumerate(paths):
            correlator.record(self._interaction("10.0.0.1", p, ts=1000.0 + i * 10))
        report = correlator.get_threat_report()
        assert report["threats"]["10.0.0.1"]["threat_level"] == "CRITICAL"

    def test_escalation_from_speed(self, correlator):
        """Fast interactions escalate the threat level (automated tooling)."""
        # Two traps, very fast => base MEDIUM escalated to HIGH
        correlator.record(self._interaction("10.0.0.1", "/admin/login", ts=1000.0))
        correlator.record(self._interaction("10.0.0.1", "/.env", ts=1000.5))
        report = correlator.get_threat_report()
        level = report["threats"]["10.0.0.1"]["threat_level"]
        assert level in ("HIGH", "CRITICAL")

    def test_escalation_from_payload(self, correlator):
        """Attack payloads escalate the threat level."""
        correlator.record(
            self._interaction("10.0.0.1", "/admin/login", ts=1000.0, method="POST",
                              body="username=admin' OR 1=1--&password=x")
        )
        report = correlator.get_threat_report()
        # Base is LOW (1 trap), escalated once for payload => MEDIUM
        level = report["threats"]["10.0.0.1"]["threat_level"]
        assert level in ("MEDIUM", "HIGH", "CRITICAL")

    # -- pattern detection ---------------------------------------------------

    def test_brute_force_detection(self, correlator):
        """Repeated hits to the same trap path flags brute force."""
        for i in range(6):
            correlator.record(self._interaction("10.0.0.1", "/admin/login", ts=1000.0 + i * 10))
        assert correlator.detect_brute_force("10.0.0.1") is True

    def test_no_brute_force_below_threshold(self, correlator):
        """Fewer than threshold hits is not brute force."""
        for i in range(3):
            correlator.record(self._interaction("10.0.0.1", "/admin/login", ts=1000.0 + i * 10))
        assert correlator.detect_brute_force("10.0.0.1") is False

    def test_recon_detection(self, correlator):
        """Visiting 3+ traps indicates reconnaissance."""
        paths = ["/admin/login", "/.env", "/api/v1/users"]
        for i, p in enumerate(paths):
            correlator.record(self._interaction("10.0.0.1", p, ts=1000.0 + i * 10))
        assert correlator.detect_recon("10.0.0.1") is True

    def test_no_recon_below_threshold(self, correlator):
        """Fewer than 3 traps is not reconnaissance."""
        correlator.record(self._interaction("10.0.0.1", "/admin/login", ts=1000.0))
        correlator.record(self._interaction("10.0.0.1", "/.env", ts=1010.0))
        assert correlator.detect_recon("10.0.0.1") is False

    def test_lateral_movement_detection(self, correlator):
        """Probing different trap types indicates lateral movement."""
        # login type + api type
        correlator.record(self._interaction("10.0.0.1", "/admin/login", ts=1000.0))
        correlator.record(self._interaction("10.0.0.1", "/api/v1/users", ts=1010.0))
        assert correlator.detect_lateral_movement("10.0.0.1") is True

    def test_no_lateral_single_type(self, correlator):
        """Same trap type only is not lateral movement."""
        # Both are admin type
        correlator.record(self._interaction("10.0.0.1", "/phpmyadmin/", ts=1000.0))
        correlator.record(self._interaction("10.0.0.1", "/wp-admin/", ts=1010.0))
        assert correlator.detect_lateral_movement("10.0.0.1") is False

    # -- reports and timelines -----------------------------------------------

    def test_threat_report_structure(self, correlator):
        """get_threat_report returns expected top-level keys."""
        correlator.record(self._interaction("10.0.0.1", "/admin/login", ts=1000.0))
        report = correlator.get_threat_report()
        assert "total_ips" in report
        assert "threats" in report
        assert report["total_ips"] == 1
        threat = report["threats"]["10.0.0.1"]
        for key in ("threat_level", "traps_visited", "trap_types",
                     "interaction_count", "first_seen", "last_seen",
                     "is_recon", "is_brute_force", "is_lateral_movement",
                     "timeline"):
            assert key in threat, f"Missing key: {key}"

    def test_attack_timeline_chronological(self, correlator):
        """get_attack_timeline returns entries sorted by timestamp."""
        correlator.record(self._interaction("10.0.0.1", "/.env", ts=1002.0))
        correlator.record(self._interaction("10.0.0.1", "/admin/login", ts=1000.0))
        correlator.record(self._interaction("10.0.0.1", "/api/v1/users", ts=1001.0))
        timeline = correlator.get_attack_timeline("10.0.0.1")
        assert len(timeline) == 3
        assert timeline[0]["timestamp"] == 1000.0
        assert timeline[1]["timestamp"] == 1001.0
        assert timeline[2]["timestamp"] == 1002.0

    def test_top_threats_ranking(self, correlator):
        """get_top_threats ranks IPs by severity then interaction count."""
        # IP-A: 6 traps => CRITICAL
        for i, p in enumerate(["/admin/login", "/.env", "/api/v1/users",
                                "/phpmyadmin/", "/wp-admin/", "/search"]):
            correlator.record(self._interaction("10.0.0.1", p, ts=1000.0 + i * 10))

        # IP-B: 1 trap => LOW
        correlator.record(self._interaction("10.0.0.2", "/admin/login", ts=2000.0))

        # IP-C: 3 traps => MEDIUM
        for i, p in enumerate(["/admin/login", "/.env", "/api/v1/users"]):
            correlator.record(self._interaction("10.0.0.3", p, ts=3000.0 + i * 10))

        top = correlator.get_top_threats(n=3)
        assert len(top) == 3
        assert top[0]["ip"] == "10.0.0.1"
        assert top[0]["threat_level"] == "CRITICAL"
        assert top[-1]["ip"] == "10.0.0.2"
        assert top[-1]["threat_level"] == "LOW"

    def test_top_threats_default_limit(self, correlator):
        """get_top_threats defaults to 5 results."""
        for i in range(10):
            correlator.record(self._interaction(f"10.0.0.{i}", "/admin/login", ts=1000.0 + i))
        top = correlator.get_top_threats()
        assert len(top) == 5

    def test_unknown_ip_returns_empty(self, correlator):
        """Querying an unknown IP returns safe defaults."""
        assert correlator.detect_recon("99.99.99.99") is False
        assert correlator.detect_brute_force("99.99.99.99") is False
        assert correlator.detect_lateral_movement("99.99.99.99") is False
        assert correlator.get_attack_timeline("99.99.99.99") == []

    # -- integration with HoneypotServer ------------------------------------

    def test_server_has_correlator(self, logger):
        """HoneypotServer creates an AttackCorrelator on init."""
        srv = HoneypotServer(logger=logger, host="127.0.0.1", port=0)
        assert isinstance(srv.correlator, AttackCorrelator)

    def test_server_correlator_records_on_interaction(self, server):
        """Live server interactions feed through to the correlator."""
        _get(f"http://127.0.0.1:{server.port}/admin/login")
        _get(f"http://127.0.0.1:{server.port}/.env")
        report = server.correlator.get_threat_report()
        assert report["total_ips"] >= 1
        # The test client IP should have visited at least 2 traps
        for ip_data in report["threats"].values():
            if ip_data["interaction_count"] >= 2:
                assert len(ip_data["traps_visited"]) >= 2
                break
        else:
            pytest.fail("Expected at least one IP with 2+ trap visits")
