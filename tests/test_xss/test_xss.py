"""Tests for XSS module (detection + sanitization)."""

from cybersim.core.logging_engine import CyberSimLogger
from cybersim.xss.detection import XSSDetector, sanitize_input


class TestXSSDetector:
    def setup_method(self):
        self.logger = CyberSimLogger(session_id="test_xss")
        self.detector = XSSDetector(config={}, logger=self.logger)

    def test_clean_input(self):
        detections = self.detector.analyze_input("Hello world")
        assert len(detections) == 0

    def test_detect_script_tag(self):
        detections = self.detector.analyze_input("<script>alert('XSS')</script>")
        patterns = [d["pattern"] for d in detections]
        assert "Script tag injection" in patterns

    def test_detect_event_handler(self):
        detections = self.detector.analyze_input("<img src=x onerror=alert(1)>")
        patterns = [d["pattern"] for d in detections]
        assert "Event handler attribute" in patterns

    def test_detect_javascript_protocol(self):
        detections = self.detector.analyze_input("javascript:alert(1)")
        patterns = [d["pattern"] for d in detections]
        assert "Javascript protocol" in patterns

    def test_detect_iframe(self):
        detections = self.detector.analyze_input("<iframe src='evil.com'>")
        patterns = [d["pattern"] for d in detections]
        assert "Iframe injection" in patterns

    def test_detect_dom_manipulation(self):
        detections = self.detector.analyze_input("document.cookie")
        patterns = [d["pattern"] for d in detections]
        assert "DOM manipulation" in patterns

    def test_events_logged(self):
        self.detector.analyze_input("<script>alert('XSS')</script>", context="search")
        xss_events = [e for e in self.logger.events if e["event_type"] == "xss_detected"]
        assert len(xss_events) > 0


class TestSanitizeInput:
    def test_sanitize_script(self):
        result = sanitize_input("<script>alert('XSS')</script>")
        assert "<script>" not in result
        assert "&lt;script&gt;" in result

    def test_sanitize_quotes(self):
        result = sanitize_input('" onmouseover="alert(1)"')
        assert '"' not in result or "&quot;" in result

    def test_normal_text_unchanged(self):
        result = sanitize_input("Hello World 123")
        assert result == "Hello World 123"
