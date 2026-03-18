"""Tests for all 9 SQL injection regex patterns — positive and negative cases."""
import re
import pytest
from cybersim.sqli.detection import SQLI_PATTERNS, SQLInjectionDetector
from cybersim.core.logging_engine import CyberSimLogger


@pytest.fixture
def detector():
    return SQLInjectionDetector(config={}, logger=CyberSimLogger())


# Map pattern descriptions to test payloads
PATTERN_POSITIVE = {
    "Boolean-based injection": [
        "' OR 1=1",
        "' AND 1=1",
        "' OR '1'='1",
        "admin' OR '1'='1'--",
    ],
    "UNION-based injection": [
        "' UNION SELECT username, password FROM users--",
        "1 UNION ALL SELECT NULL,NULL,NULL--",
        "' union select 1,2,3--",
    ],
    "Comment-based injection": [
        "admin'--",
        "' /*comment*/",
        "1--",
    ],
    "Stacked query injection": [
        "'; DROP TABLE users;",
        "1; DELETE FROM logs;",
        "'; UPDATE users SET admin=1;",
    ],
    "Quote-semicolon injection": [
        "'; ",
        "test'  ;  ",
    ],
    "Schema extraction attempt": [
        "' UNION SELECT name FROM sqlite_master--",
        "SELECT * FROM information_schema.tables",
        "SELECT * FROM sys.tables",
    ],
    "Time-based injection": [
        "'; SLEEP(5)--",
        "1; WAITFOR DELAY '0:0:5'--",
        "' AND BENCHMARK(1000000,MD5(1))--",
    ],
    "Function-based obfuscation": [
        "' UNION SELECT CHAR(117,115,101,114)--",
        "CONCAT(0x61,0x64,0x6d,0x69,0x6e)",
        "GROUP_CONCAT(username SEPARATOR ',')",
    ],
    "Hex-encoded injection": [
        "SELECT 0x61646d696e",
        "' OR 0x3d--",
        "CHAR(0x41)",
    ],
}

PATTERN_NEGATIVE = {
    "Boolean-based injection": [
        "SELECT * FROM users",
        "normal search query",
        "price > 100 AND price < 200",
    ],
    "UNION-based injection": [
        "This is a union of ideas",
        "SELECT union_id FROM contracts",
    ],
    "Comment-based injection": [
        "normal text",
        "url: http://example.com",
    ],
    "Stacked query injection": [
        "SELECT id FROM users",
        "INSERT INTO logs VALUES (1, 'test')",  # no semicolon prefix
    ],
    "Time-based injection": [
        "sleep well tonight",
        "benchmark test results",
    ],
    "Hex-encoded injection": [
        "color: #ff0000",  # CSS hex not SQL hex
        "id=abc123",
    ],
}


class TestSQLiPatterns:
    @pytest.mark.parametrize("description,payloads", PATTERN_POSITIVE.items())
    def test_pattern_detects_positive(self, description, payloads):
        pattern = next((p for p, d in SQLI_PATTERNS if d == description), None)
        assert pattern is not None, f"Pattern '{description}' not found"
        for payload in payloads:
            assert pattern.search(payload), (
                f"Pattern '{description}' should match: {payload!r}"
            )

    @pytest.mark.parametrize("description,payloads", PATTERN_NEGATIVE.items())
    def test_pattern_no_false_positives(self, description, payloads):
        pattern = next((p for p, d in SQLI_PATTERNS if d == description), None)
        if pattern is None:
            pytest.skip(f"Pattern '{description}' not found")
        for payload in payloads:
            assert not pattern.search(payload), (
                f"Pattern '{description}' should NOT match: {payload!r}"
            )

    def test_all_patterns_precompiled(self):
        for pat, desc in SQLI_PATTERNS:
            assert isinstance(pat, type(re.compile(""))), f"Not compiled: {desc}"

    def test_nine_patterns_defined(self):
        assert len(SQLI_PATTERNS) == 9

    def test_analyze_query_detects_union(self, detector):
        result = detector.analyze_query("' UNION SELECT * FROM users--")
        descriptions = [d["pattern"] for d in result]
        assert "UNION-based injection" in descriptions

    def test_analyze_query_clean_input(self, detector):
        result = detector.analyze_query("SELECT id FROM products WHERE id=1")
        assert result == []

    def test_analyze_query_log_summary(self, detector):
        log = [
            {"sql": "' UNION SELECT 1,2--", "endpoint": "/login"},
            {"sql": "SELECT * FROM users WHERE id=1", "endpoint": "/profile"},
            {"sql": "'; DROP TABLE users;--", "endpoint": "/search"},
        ]
        summary = detector.analyze_query_log(log)
        assert summary["total_queries"] == 3
        assert summary["malicious_queries"] >= 2

    def test_analyze_query_truncates_long_sql(self, detector):
        long_sql = "'" + "A" * 500 + "' OR 1=1"
        result = detector.analyze_query(long_sql)
        assert isinstance(result, list)

    def test_analyze_query_returns_endpoint(self, detector):
        result = detector.analyze_query("' OR 1=1--", endpoint="/api/login")
        assert any(d["endpoint"] == "/api/login" for d in result)
