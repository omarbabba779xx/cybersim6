"""Integration tests: full attack + detection pipeline for all 6 modules."""
import pytest
from cybersim.core.logging_engine import CyberSimLogger


@pytest.fixture
def logger():
    return CyberSimLogger()


@pytest.fixture
def config():
    return {"target": "127.0.0.1"}


# ─── SQL Injection Integration ────────────────────────────────────────────────

class TestSQLiIntegration:
    def test_attack_log_then_detect(self, logger, config):
        from cybersim.sqli.detection import SQLInjectionDetector
        detector = SQLInjectionDetector(config=config, logger=logger)
        query_log = [
            {"sql": "' UNION SELECT username,password FROM users--", "endpoint": "/login"},
            {"sql": "SELECT * FROM products WHERE id=1", "endpoint": "/product"},
            {"sql": "'; DROP TABLE sessions;--", "endpoint": "/auth"},
            {"sql": "1 OR 1=1", "endpoint": "/search"},
        ]
        summary = detector.analyze_query_log(query_log)
        assert summary["total_queries"] == 4
        assert summary["malicious_queries"] >= 2
        assert len(summary["patterns_found"]) >= 1
        # Events should be logged
        sqli_events = [e for e in logger.events if e["module"] == "sqli_detector"]
        assert len(sqli_events) >= 1

    def test_clean_queries_no_alerts(self, logger, config):
        from cybersim.sqli.detection import SQLInjectionDetector
        detector = SQLInjectionDetector(config=config, logger=logger)
        query_log = [
            {"sql": "SELECT id, name FROM products WHERE category='electronics'", "endpoint": "/shop"},
            {"sql": "INSERT INTO cart VALUES (1, 42, 2)", "endpoint": "/cart"},
        ]
        summary = detector.analyze_query_log(query_log)
        assert summary["malicious_queries"] == 0


# ─── XSS Integration ─────────────────────────────────────────────────────────

class TestXSSIntegration:
    def test_attack_log_then_detect(self, logger, config):
        from cybersim.xss.detection import XSSDetector
        detector = XSSDetector(config=config, logger=logger)
        request_log = [
            {"details": "<script>document.cookie</script>", "type": "reflected"},
            {"details": "normal user input", "type": "input"},
            {"details": "<img src=x onerror=alert(1)>", "type": "stored"},
            {"details": "javascript:void(0)", "type": "dom"},
        ]
        summary = detector.analyze_request_log(request_log)
        assert summary["total_requests"] == 4
        assert summary["malicious_requests"] >= 2

    def test_events_logged(self, logger, config):
        from cybersim.xss.detection import XSSDetector
        detector = XSSDetector(config=config, logger=logger)
        detector.analyze_input("<script>alert(1)</script>", context="test")
        events = [e for e in logger.events if e["module"] == "xss_detector"]
        assert len(events) >= 1


# ─── DDoS Integration ────────────────────────────────────────────────────────

class TestDDoSIntegration:
    def test_high_rate_detected(self, logger, config):
        from cybersim.ddos.detection import DDoSDetector
        detector = DDoSDetector(config=config, logger=logger)
        for _ in range(100):
            detector.record_request("127.0.0.1")
        result = detector.check_threshold(threshold_rps=10, window=1)
        assert result["is_attack"] is True
        # Should have logged a warning event
        events = [e for e in logger.events if e["module"] == "ddos_detector"]
        assert len(events) >= 1

    def test_low_rate_not_detected(self, logger, config):
        from cybersim.ddos.detection import DDoSDetector
        detector = DDoSDetector(config=config, logger=logger)
        for _ in range(3):
            detector.record_request("127.0.0.1")
        result = detector.check_threshold(threshold_rps=10, window=1)
        assert result["is_attack"] is False


# ─── Phishing Integration ─────────────────────────────────────────────────────

class TestPhishingIntegration:
    def test_high_risk_email(self, logger, config):
        from cybersim.phishing.detection import PhishingDetector
        detector = PhishingDetector(config=config, logger=logger)
        result = detector.analyze_email(
            subject="URGENT: Your account will be suspended!",
            body="Please verify your credentials immediately. Click here: http://192.168.1.1/login",
            sender="security@bank-alerts.tk",
            url="http://192.168.1.1/login",
        )
        assert result["risk_score"] >= 30
        assert result["risk_level"] in ("MEDIUM", "HIGH")
        assert result["findings_count"] >= 2

    def test_clean_email(self, logger, config):
        from cybersim.phishing.detection import PhishingDetector
        detector = PhishingDetector(config=config, logger=logger)
        result = detector.analyze_email(
            subject="Team meeting tomorrow",
            body="Hi team, don't forget our standup at 9am.",
            sender="manager@company.com",
        )
        assert result["risk_level"] == "LOW"

    def test_events_logged_for_risky_email(self, logger, config):
        from cybersim.phishing.detection import PhishingDetector
        detector = PhishingDetector(config=config, logger=logger)
        detector.analyze_email(
            subject="Urgent: verify now or lose access!",
            body="Click here: http://1.2.3.4/login to confirm your identity immediately.",
            url="http://1.2.3.4/login",
        )
        events = [e for e in logger.events if e["module"] == "phishing_detector"]
        assert len(events) >= 1


# ─── Ransomware Integration ───────────────────────────────────────────────────

class TestRansomwareIntegration:
    def test_encrypted_dir_detected(self, logger, config):
        import tempfile
        from pathlib import Path
        from cybersim.ransomware.detection import RansomwareDetector, calculate_entropy
        import os

        detector = RansomwareDetector(config=config, logger=logger)
        with tempfile.TemporaryDirectory() as tmpdir:
            p = Path(tmpdir)
            (p / "doc.txt.locked").write_bytes(os.urandom(512))
            (p / "README_RANSOM.txt").write_bytes(b"pay 1 BTC")
            (p / "normal.txt").write_bytes(b"normal file")
            results = detector.scan_directory(p)

        assert results["is_compromised"] is True
        assert len(results["encrypted_files"]) == 1
        assert len(results["ransom_notes"]) == 1
        events = [e for e in logger.events if e["module"] == "ransomware_detector"]
        assert len(events) >= 1


# ─── Logger Integration ───────────────────────────────────────────────────────

class TestLoggerIntegration:
    def test_shared_logger_accumulates_cross_module(self, logger, config):
        from cybersim.sqli.detection import SQLInjectionDetector
        from cybersim.xss.detection import XSSDetector
        from cybersim.ddos.detection import DDoSDetector

        sqli = SQLInjectionDetector(config=config, logger=logger)
        xss = XSSDetector(config=config, logger=logger)
        ddos = DDoSDetector(config=config, logger=logger)

        sqli.analyze_query("' OR 1=1--", "/login")
        xss.analyze_input("<script>alert(1)</script>", "input")
        for _ in range(50):
            ddos.record_request()
        ddos.check_threshold(threshold_rps=10, window=1)

        modules = {e["module"] for e in logger.events}
        assert "sqli_detector" in modules
        assert "xss_detector" in modules
        assert "ddos_detector" in modules
        assert len(logger.events) >= 3
