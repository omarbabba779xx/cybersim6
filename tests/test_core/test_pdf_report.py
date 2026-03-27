"""Tests for cybersim.core.pdf_report module."""

from __future__ import annotations

from pathlib import Path

from cybersim.core.logging_engine import CyberSimLogger
from cybersim.core.pdf_report import MITRE_MAPPING, ReportGenerator


def _make_logger(tmp_path: Path, events: bool = True) -> CyberSimLogger:
    """Helper: create a logger optionally pre-loaded with sample events."""
    logger = CyberSimLogger(log_dir=tmp_path, session_id="test1234")
    if events:
        logger.log_event("ddos", "attack", "attack_started", {
            "status": "warning", "message": "DDoS flood initiated",
            "source": "10.0.0.1", "target": "192.168.1.1",
        })
        logger.log_event("ddos", "attack", "attack_complete", {
            "status": "error", "message": "Target overwhelmed",
        })
        logger.log_event("sqli", "attack", "attack_started", {
            "status": "info", "message": "SQL injection attempt",
        })
        logger.log_event("bruteforce", "attack", "attack_started", {
            "status": "warning", "message": "Brute force login attempt",
        })
    return logger


def _make_logger_with_real_module_names(tmp_path: Path) -> CyberSimLogger:
    """Use concrete runtime module names to mirror exported session logs."""
    logger = CyberSimLogger(log_dir=tmp_path, session_id="realmods")
    logger.log_event("ddos_http_flood", "attack", "attack_started", {
        "status": "warning", "message": "HTTP flood initiated",
    })
    logger.log_event("sqli_detector", "detection", "pattern_match", {
        "status": "warning", "message": "SQLi pattern detected",
    })
    logger.log_event("bruteforce_auth_server", "target", "login_attempt", {
        "status": "warning", "message": "Repeated login attempts",
    })
    return logger


class TestReportGenerator:
    """Tests for the HTML report generator."""

    def test_generate_creates_html_file(self, tmp_path: Path) -> None:
        """generate() should write an HTML file and return its path."""
        logger = _make_logger(tmp_path)
        gen = ReportGenerator(logger)
        path = gen.generate()

        assert Path(path).exists()
        assert path.endswith(".html")
        content = Path(path).read_text(encoding="utf-8")
        assert content.startswith("<!DOCTYPE html>")

    def test_report_contains_session_id(self, tmp_path: Path) -> None:
        """The report must include the session identifier."""
        logger = _make_logger(tmp_path)
        gen = ReportGenerator(logger)
        path = gen.generate()
        content = Path(path).read_text(encoding="utf-8")

        assert "test1234" in content

    def test_report_contains_module_sections(self, tmp_path: Path) -> None:
        """The module analysis section should list every active module."""
        logger = _make_logger(tmp_path)
        gen = ReportGenerator(logger)
        path = gen.generate()
        content = Path(path).read_text(encoding="utf-8")

        assert "Module Analysis" in content
        assert "ddos" in content
        assert "sqli" in content
        assert "bruteforce" in content

    def test_report_contains_mitre_mapping(self, tmp_path: Path) -> None:
        """The MITRE ATT&CK mapping table should appear with technique IDs."""
        logger = _make_logger(tmp_path)
        gen = ReportGenerator(logger)
        path = gen.generate()
        content = Path(path).read_text(encoding="utf-8")

        assert "MITRE" in content
        assert "T1498" in content  # ddos
        assert "T1190" in content  # sqli
        assert "T1110" in content  # bruteforce

    def test_report_contains_recommendations(self, tmp_path: Path) -> None:
        """Recommendations section should be present with NIST reference."""
        logger = _make_logger(tmp_path)
        gen = ReportGenerator(logger)
        path = gen.generate()
        content = Path(path).read_text(encoding="utf-8")

        assert "Recommendations" in content
        assert "NIST SP 800-61" in content
        # Should have module-specific recs for observed modules
        assert "DDoS Mitigation" in content
        assert "SQL Injection Prevention" in content
        assert "Brute Force Protection" in content

    def test_empty_events_produce_valid_report(self, tmp_path: Path) -> None:
        """A logger with zero events should still produce valid HTML."""
        logger = _make_logger(tmp_path, events=False)
        gen = ReportGenerator(logger)
        path = gen.generate()

        assert Path(path).exists()
        content = Path(path).read_text(encoding="utf-8")
        assert "<!DOCTYPE html>" in content
        assert "test1234" in content
        # Should contain graceful empty-state messages
        assert "No module events recorded" in content or "Module Analysis" in content

    def test_custom_output_path(self, tmp_path: Path) -> None:
        """generate() should respect a custom output path."""
        logger = _make_logger(tmp_path)
        gen = ReportGenerator(logger)
        custom = str(tmp_path / "custom" / "my_report.html")
        path = gen.generate(output_path=custom)

        assert Path(path).exists()
        assert "my_report.html" in path

    def test_custom_session_id_override(self, tmp_path: Path) -> None:
        """Passing session_id to the constructor should override the logger's."""
        logger = _make_logger(tmp_path)
        gen = ReportGenerator(logger, session_id="override99")
        path = gen.generate()
        content = Path(path).read_text(encoding="utf-8")

        assert "override99" in content

    def test_report_contains_charts(self, tmp_path: Path) -> None:
        """The report should include SVG chart elements."""
        logger = _make_logger(tmp_path)
        gen = ReportGenerator(logger)
        path = gen.generate()
        content = Path(path).read_text(encoding="utf-8")

        assert "<svg" in content
        assert "Event Timeline" in content
        assert "Attack Distribution" in content

    def test_mitre_mapping_dict_complete(self) -> None:
        """MITRE_MAPPING should have all required keys for each entry."""
        for key, info in MITRE_MAPPING.items():
            assert "technique" in info, f"Missing 'technique' for {key}"
            assert "tactic" in info, f"Missing 'tactic' for {key}"
            assert "name" in info, f"Missing 'name' for {key}"
            assert info["technique"].startswith("T"), f"Bad technique ID for {key}"

    def test_report_normalizes_runtime_module_names(self, tmp_path: Path) -> None:
        """Concrete runtime module IDs should still trigger family-level report sections."""
        logger = _make_logger_with_real_module_names(tmp_path)
        gen = ReportGenerator(logger)
        path = gen.generate()
        content = Path(path).read_text(encoding="utf-8")

        assert "DDoS Mitigation" in content
        assert "SQL Injection Prevention" in content
        assert "Brute Force Protection" in content
        assert "No MITRE mapping defined" not in content
