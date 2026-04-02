"""Tests for the forensic analyzer."""

from __future__ import annotations

from pathlib import Path

from cybersim.core.logging_engine import CyberSimLogger
from cybersim.forensics.analyzer import ForensicAnalyzer


def _make_events():
    return [
        {"event_type": "ddos_detected", "module": "ddos", "timestamp": "2026-01-01T00:00:00", "details": {"status": "warning", "message": "DDoS DETECTED", "source_ip": "127.0.0.1"}},
        {"event_type": "sqli_detected", "module": "sqli", "timestamp": "2026-01-01T00:01:00", "details": {"status": "warning", "message": "SQL injection found", "endpoint": "/login", "sql": "' OR 1=1--"}},
        {"event_type": "scan_started", "module": "scanner", "timestamp": "2026-01-01T00:02:00", "details": {"status": "info", "message": "Port scan started"}},
    ]


class TestForensicAnalyzer:
    def test_reconstruct_timeline(self, tmp_path):
        logger = CyberSimLogger(log_dir=tmp_path, session_id="test")
        analyzer = ForensicAnalyzer(logger=logger, events=_make_events())
        timeline = analyzer.reconstruct_timeline()
        assert len(timeline) == 3
        # Should be sorted by timestamp
        assert timeline[0].timestamp <= timeline[1].timestamp

    def test_collect_log_evidence(self, tmp_path):
        logger = CyberSimLogger(log_dir=tmp_path, session_id="test")
        analyzer = ForensicAnalyzer(logger=logger, events=_make_events())
        evidence = analyzer.collect_log_evidence()
        assert evidence.evidence_id == "EVD-0001"
        assert evidence.sha256_hash
        assert len(evidence.chain_of_custody) == 1

    def test_verify_evidence_integrity(self, tmp_path):
        logger = CyberSimLogger(log_dir=tmp_path, session_id="test")
        analyzer = ForensicAnalyzer(logger=logger, events=_make_events())
        evidence = analyzer.collect_log_evidence()
        assert analyzer.verify_evidence_integrity(evidence) is True

    def test_collect_file_evidence(self, tmp_path):
        logger = CyberSimLogger(log_dir=tmp_path, session_id="test")
        test_file = tmp_path / "test.txt"
        test_file.write_text("test content")
        analyzer = ForensicAnalyzer(logger=logger, events=_make_events())
        evidence = analyzer.collect_file_evidence(test_file)
        assert evidence is not None
        assert evidence.sha256_hash
        assert "test.txt" in evidence.description

    def test_collect_file_evidence_missing(self, tmp_path):
        logger = CyberSimLogger(log_dir=tmp_path, session_id="test")
        analyzer = ForensicAnalyzer(logger=logger, events=_make_events())
        result = analyzer.collect_file_evidence(Path("/nonexistent/file.txt"))
        assert result is None

    def test_extract_iocs(self, tmp_path):
        logger = CyberSimLogger(log_dir=tmp_path, session_id="test")
        analyzer = ForensicAnalyzer(logger=logger, events=_make_events())
        iocs = analyzer.extract_iocs()
        assert "attack_types" in iocs
        assert len(iocs["attack_types"]) > 0
        assert "ddos" in iocs["attack_types"]

    def test_run_full_analysis(self, tmp_path):
        logger = CyberSimLogger(log_dir=tmp_path, session_id="test")
        analyzer = ForensicAnalyzer(logger=logger, events=_make_events())
        report = analyzer.run()
        assert report["timeline_events"] == 3
        assert report["evidence_collected"] >= 1

    def test_generate_text_report(self, tmp_path):
        logger = CyberSimLogger(log_dir=tmp_path, session_id="test")
        analyzer = ForensicAnalyzer(logger=logger, events=_make_events())
        text = analyzer.generate_text_report()
        assert "DIGITAL FORENSIC ANALYSIS REPORT" in text
