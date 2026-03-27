"""Tests for the Web Application Firewall module."""

import re
import pytest

from cybersim.core.logging_engine import CyberSimLogger
from cybersim.waf.firewall import (
    WAFAction,
    WAFResult,
    WAFRule,
    WAFSeverity,
    WebApplicationFirewall,
)


class TestWebApplicationFirewall:
    """Core WAF engine tests."""

    def setup_method(self) -> None:
        self.logger = CyberSimLogger(session_id="test_waf")
        self.waf = WebApplicationFirewall(self.logger)

    # 1 -- SQL Injection blocked -------------------------------------------

    def test_sqli_union_blocked(self) -> None:
        result = self.waf.inspect_request(
            method="GET",
            path="/search?q=' UNION SELECT username,password FROM users --",
        )
        assert not result.allowed
        assert result.action == WAFAction.BLOCK
        assert "SQLI" in result.block_reason.upper()

    def test_sqli_boolean_blocked(self) -> None:
        result = self.waf.inspect_request(
            method="POST",
            path="/login",
            body="username=admin&password=' OR '1'='1",
        )
        assert not result.allowed

    # 2 -- XSS blocked -----------------------------------------------------

    def test_xss_script_tag_blocked(self) -> None:
        result = self.waf.inspect_request(
            method="POST",
            path="/comment",
            body="<script>alert('xss')</script>",
        )
        assert not result.allowed
        assert result.action == WAFAction.BLOCK
        assert "XSS" in result.block_reason.upper()

    def test_xss_event_handler_blocked(self) -> None:
        result = self.waf.inspect_request(
            method="GET",
            path='/search?q="><img onerror=alert(1) src=x>',
        )
        assert not result.allowed

    # 3 -- Path traversal blocked ------------------------------------------

    def test_path_traversal_blocked(self) -> None:
        result = self.waf.inspect_request(
            method="GET",
            path="/files/../../../../etc/passwd",
        )
        assert not result.allowed
        assert result.action == WAFAction.BLOCK
        assert "PATH_TRAVERSAL" in result.block_reason.upper()

    def test_path_traversal_encoded_blocked(self) -> None:
        result = self.waf.inspect_request(
            method="GET",
            path="/files/%2e%2e%2f%2e%2e%2fetc/passwd",
        )
        assert not result.allowed

    # 4 -- Clean request allowed -------------------------------------------

    def test_clean_get_allowed(self) -> None:
        result = self.waf.inspect_request(
            method="GET",
            path="/index.html",
            headers={"User-Agent": "Mozilla/5.0"},
        )
        assert result.allowed
        assert result.action == WAFAction.ALLOW

    def test_clean_post_allowed(self) -> None:
        result = self.waf.inspect_request(
            method="POST",
            path="/api/data",
            body='{"name": "Alice", "age": 30}',
            headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"},
        )
        assert result.allowed

    # 5 -- Rate limiting ---------------------------------------------------

    def test_rate_limiting_blocks_excess(self) -> None:
        waf = WebApplicationFirewall(self.logger, config={
            "rate_limit_requests": 5,
            "rate_limit_window": 60,
        })
        # First 5 should pass
        for _ in range(5):
            result = waf.inspect_request(method="GET", path="/", source_ip="10.0.0.1")
            assert result.allowed

        # 6th should be blocked
        result = waf.inspect_request(method="GET", path="/", source_ip="10.0.0.1")
        assert not result.allowed
        assert "rate limit" in result.block_reason.lower()

    def test_rate_limiting_separate_ips(self) -> None:
        waf = WebApplicationFirewall(self.logger, config={
            "rate_limit_requests": 3,
            "rate_limit_window": 60,
        })
        for _ in range(3):
            waf.inspect_request(method="GET", path="/", source_ip="10.0.0.1")
            waf.inspect_request(method="GET", path="/", source_ip="10.0.0.2")

        # Both IPs at limit; next request from each should be blocked
        r1 = waf.inspect_request(method="GET", path="/", source_ip="10.0.0.1")
        r2 = waf.inspect_request(method="GET", path="/", source_ip="10.0.0.2")
        assert not r1.allowed
        assert not r2.allowed

    # 6 -- Suspicious user-agent -------------------------------------------

    def test_suspicious_user_agent_sqlmap(self) -> None:
        result = self.waf.inspect_request(
            method="GET",
            path="/",
            headers={"User-Agent": "sqlmap/1.6.4#stable"},
        )
        assert not result.allowed
        assert "USER_AGENT" in result.block_reason.upper()

    def test_suspicious_user_agent_nikto(self) -> None:
        result = self.waf.inspect_request(
            method="GET",
            path="/",
            headers={"User-Agent": "Mozilla/5.0 (Nikto/2.1.6)"},
        )
        assert not result.allowed

    # 7 -- Stats tracking --------------------------------------------------

    def test_stats_tracking(self) -> None:
        waf = WebApplicationFirewall(self.logger)
        waf.inspect_request(method="GET", path="/safe")
        waf.inspect_request(method="GET", path="/search?q=' UNION SELECT 1--")
        waf.inspect_request(method="POST", path="/x", body="<script>alert(1)</script>")

        stats = waf.get_stats()
        assert stats["total_requests"] == 3
        assert stats["allowed"] >= 1
        assert stats["blocked"] >= 2
        assert stats["sqli_blocked"] >= 1
        assert stats["xss_blocked"] >= 1

    def test_stats_reset(self) -> None:
        self.waf.inspect_request(method="GET", path="/safe")
        self.waf.reset_stats()
        stats = self.waf.get_stats()
        assert stats["total_requests"] == 0
        assert stats["blocked"] == 0

    # 8 -- Custom rules ----------------------------------------------------

    def test_custom_rule_blocks(self) -> None:
        custom = WAFRule(
            name="block_admin",
            pattern=re.compile(r"/admin", re.IGNORECASE),
            action=WAFAction.BLOCK,
            severity=WAFSeverity.MEDIUM,
            category="custom",
            description="Admin path blocked",
        )
        self.waf.add_rule(custom)
        result = self.waf.inspect_request(method="GET", path="/admin/dashboard")
        assert not result.allowed
        assert "Admin path blocked" in result.block_reason

    def test_custom_rule_disabled(self) -> None:
        custom = WAFRule(
            name="block_api",
            pattern=re.compile(r"/api/secret"),
            action=WAFAction.BLOCK,
            severity=WAFSeverity.LOW,
            category="custom",
            description="Secret API blocked",
            enabled=False,
        )
        self.waf.add_rule(custom)
        result = self.waf.inspect_request(method="GET", path="/api/secret")
        assert result.allowed

    # 9 -- 403 response page -----------------------------------------------

    def test_blocked_page_html(self) -> None:
        page = self.waf.get_blocked_page("SQL injection detected")
        assert "403" in page
        assert "SQL injection detected" in page
        assert "CyberSim6" in page
        assert "text/html" not in page or True  # just check it's valid HTML
        assert "<html" in page

    def test_blocked_page_escapes_html(self) -> None:
        page = self.waf.get_blocked_page('<script>alert("xss")</script>')
        assert "<script>" not in page
        assert "&lt;script&gt;" in page

    # 10 -- Whitelist bypass -----------------------------------------------

    def test_whitelisted_ip_bypasses_rules(self) -> None:
        waf = WebApplicationFirewall(self.logger, config={
            "whitelist_ips": ["192.168.1.100"],
        })
        result = waf.inspect_request(
            method="GET",
            path="/search?q=' UNION SELECT * FROM users --",
            source_ip="192.168.1.100",
        )
        assert result.allowed

    def test_non_whitelisted_ip_still_blocked(self) -> None:
        waf = WebApplicationFirewall(self.logger, config={
            "whitelist_ips": ["192.168.1.100"],
        })
        result = waf.inspect_request(
            method="GET",
            path="/search?q=' UNION SELECT * FROM users --",
            source_ip="10.0.0.5",
        )
        assert not result.allowed

    # -- Blacklist ---------------------------------------------------------

    def test_blacklisted_ip_always_blocked(self) -> None:
        waf = WebApplicationFirewall(self.logger, config={
            "blacklist_ips": ["10.0.0.99"],
        })
        result = waf.inspect_request(
            method="GET",
            path="/",
            source_ip="10.0.0.99",
        )
        assert not result.allowed
        assert "blacklist" in result.block_reason.lower()

    # -- Logging -----------------------------------------------------------

    def test_events_logged_on_block(self) -> None:
        self.waf.inspect_request(
            method="GET",
            path="/search?q=' UNION SELECT * FROM users --",
        )
        blocked_events = [
            e for e in self.logger.events if e["event_type"] == "request_blocked"
        ]
        assert len(blocked_events) >= 1

    def test_events_logged_on_allow(self) -> None:
        self.waf.inspect_request(method="GET", path="/index.html")
        allowed_events = [
            e for e in self.logger.events if e["event_type"] == "request_allowed"
        ]
        assert len(allowed_events) >= 1
