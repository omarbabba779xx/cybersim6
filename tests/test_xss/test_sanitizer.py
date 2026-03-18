"""Tests for XSS sanitize_input and pattern detection with extensive payloads."""
import pytest
from cybersim.xss.detection import sanitize_input, XSSDetector, XSS_PATTERNS
from cybersim.core.logging_engine import CyberSimLogger


@pytest.fixture
def detector():
    logger = CyberSimLogger()
    return XSSDetector(config={}, logger=logger)


# ─── sanitize_input ───────────────────────────────────────────────────────────

SANITIZE_CASES = [
    # (input, should_not_contain)
    ("<script>alert(1)</script>", "<script>"),
    ("<img src=x onerror=alert(1)>", "<img"),
    ("javascript:void(0)", None),  # html.escape doesn't escape colons — detected by pattern, not sanitizer
    ("<iframe src='evil.com'></iframe>", "<iframe"),
    ('"<>&', '"'),          # quote escaped
    ("'single'", "'"),
    ("<b>bold</b>", "<b>"),
    ("&lt;already&gt;", "<"),  # double-encode prevention check
    ("<svg onload=alert(1)>", "<svg"),
    ("normal text", None),  # safe input passes through
    ("", None),             # empty is safe
    ("   spaces   ", None), # whitespace preserved
    ("<SCRIPT>ALERT(1)</SCRIPT>", "<SCRIPT>"),
    ("<<script>alert(1)<</script>", "<<"),
    ("<scr<script>ipt>alert(1)</script>", "<scr"),
    ("';DROP TABLE users;--", None),  # not XSS but should survive
    ("<object data='data:text/html,<h1>xss</h1>'></object>", "<object"),
    ('<a href="javascript:alert(1)">click</a>', "<a"),
    ('<div style="background:url(javascript:alert(1))"></div>', "<div"),
    ("<marquee onstart=alert(1)>", "<marquee"),
]


class TestSanitizeInput:
    @pytest.mark.parametrize("inp,bad", SANITIZE_CASES)
    def test_sanitize_removes_raw_tags(self, inp, bad):
        result = sanitize_input(inp)
        if bad:
            assert bad not in result, f"Expected '{bad}' to be escaped in: {result!r}"

    def test_sanitize_returns_string(self):
        assert isinstance(sanitize_input("<b>test</b>"), str)

    def test_sanitize_empty_string(self):
        assert sanitize_input("") == ""

    def test_sanitize_plain_text_unchanged(self):
        plain = "Hello, Omar! How are you?"
        assert sanitize_input(plain) == plain

    def test_sanitize_escapes_ampersand(self):
        assert "&amp;" in sanitize_input("a & b")

    def test_sanitize_escapes_less_than(self):
        assert "&lt;" in sanitize_input("<div>")

    def test_sanitize_escapes_greater_than(self):
        assert "&gt;" in sanitize_input("<div>")

    def test_sanitize_escapes_double_quote(self):
        result = sanitize_input('"quoted"')
        assert '"' not in result or "&quot;" in result


# ─── Pattern detection ────────────────────────────────────────────────────────

POSITIVE_PAYLOADS = [
    ("<script>alert(1)</script>", "Script tag injection"),
    ("<SCRIPT SRC='evil.js'></SCRIPT>", "Script tag injection"),
    ('<img src=x onerror="alert(1)">', "IMG onerror"),
    ("<svg onload=alert(1)>", "SVG onload"),
    ("javascript:alert(document.cookie)", "Javascript protocol"),
    ("<iframe src='http://evil.com'></iframe>", "Iframe injection"),
    ('onclick="alert(1)"', "Event handler attribute"),
    ('onmouseover=alert(1)', "Event handler attribute"),
    ("document.cookie", "DOM manipulation"),
    ("document.location='http://evil.com'", "DOM manipulation"),
    ("eval(atob('YWxlcnQoMSk='))", "Dangerous JS function"),
    ("alert(document.cookie)", "Dangerous JS function"),
    ("<b>injected</b>", "HTML tag injection"),
    ("&#60;script&#62;", "HTML entity encoding"),
    ("&#x3C;script&#x3E;", "HTML entity encoding"),
]

NEGATIVE_PAYLOADS = [
    "Hello World",
    "SELECT * FROM users",
    "Normal text with numbers 123",
    "http://example.com/page",
    "user@example.com",
    "price: $9.99",
]


class TestXSSPatterns:
    @pytest.mark.parametrize("payload,expected_pattern", POSITIVE_PAYLOADS)
    def test_detects_known_payload(self, detector, payload, expected_pattern):
        results = detector.analyze_input(payload, context="test")
        patterns_found = [r["pattern"] for r in results]
        assert expected_pattern in patterns_found, (
            f"Expected '{expected_pattern}' to be detected in: {payload!r}\n"
            f"Got: {patterns_found}"
        )

    @pytest.mark.parametrize("payload", NEGATIVE_PAYLOADS)
    def test_no_false_positives(self, detector, payload):
        # These are patterns likely to not trigger XSS (basic sanity)
        # Some may still trigger generic HTML tag pattern — that's acceptable
        results = detector.analyze_input(payload, context="safe")
        critical = [r for r in results if r["pattern"] in (
            "Script tag injection", "Javascript protocol",
            "SVG onload", "IMG onerror", "Iframe injection",
        )]
        assert len(critical) == 0, f"False positive on: {payload!r} → {critical}"

    def test_analyze_input_returns_list(self, detector):
        result = detector.analyze_input("<script>x</script>")
        assert isinstance(result, list)

    def test_analyze_input_empty(self, detector):
        result = detector.analyze_input("")
        assert result == []

    def test_analyze_request_log(self, detector):
        log = [
            {"details": "<script>alert(1)</script>", "type": "reflected"},
            {"details": "safe text", "type": "input"},
        ]
        summary = detector.analyze_request_log(log)
        assert summary["total_requests"] == 2
        assert summary["malicious_requests"] >= 1

    def test_patterns_precompiled(self):
        """All patterns should be compiled regex objects."""
        import re
        for pat, _ in XSS_PATTERNS:
            assert isinstance(pat, type(re.compile(""))), f"Not compiled: {pat}"
