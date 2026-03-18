"""
CyberSim6 - XSS Detection Module
Detects XSS patterns in HTTP requests and stored content.
"""

import re
import time
import html
from cybersim.core.base_module import BaseModule

# XSS patterns — pre-compiled at module load for performance
XSS_PATTERNS = [
    (re.compile(r"<script[^>]*>", re.IGNORECASE), "Script tag injection"),
    (re.compile(r"on\w+\s*=", re.IGNORECASE), "Event handler attribute"),
    (re.compile(r"javascript\s*:", re.IGNORECASE), "Javascript protocol"),
    (re.compile(r"<iframe", re.IGNORECASE), "Iframe injection"),
    (re.compile(r"<svg[^>]*onload", re.IGNORECASE), "SVG onload"),
    (re.compile(r"<img[^>]*onerror", re.IGNORECASE), "IMG onerror"),
    (re.compile(r"document\.(cookie|location|write)", re.IGNORECASE), "DOM manipulation"),
    (re.compile(r"(eval|alert|confirm|prompt)\s*\(", re.IGNORECASE), "Dangerous JS function"),
    (re.compile(r"<\s*/?\s*\w+[^>]*>", re.IGNORECASE), "HTML tag injection"),
    (re.compile(r"&#\d+;|&#x[0-9a-f]+;", re.IGNORECASE), "HTML entity encoding"),
]


def sanitize_input(user_input: str) -> str:
    """Sanitize user input to prevent XSS (counter-measure demonstration)."""
    return html.escape(user_input, quote=True)


class XSSDetector(BaseModule):
    """Detects XSS injection attempts in HTTP traffic."""

    MODULE_TYPE = "detection"
    MODULE_NAME = "xss_detector"

    def _validate_safety(self):
        pass

    def analyze_input(self, user_input: str, context: str = "") -> list:
        """
        Analyze user input for XSS patterns.

        Returns:
            List of detected XSS patterns.
        """
        detections = []
        for pattern, description in XSS_PATTERNS:
            if pattern.search(user_input):
                detection = {
                    "pattern": description,
                    "input": user_input[:200],
                    "context": context,
                }
                detections.append(detection)
                self.log_event("xss_detected", {
                    "message": f"XSS DETECTED [{description}] in {context}: {user_input[:80]}",
                    "pattern": description,
                    "context": context,
                    "status": "warning",
                })
        return detections

    def analyze_request_log(self, request_log: list) -> dict:
        """Analyze a batch of logged requests for XSS."""
        all_detections = []
        for entry in request_log:
            details = entry.get("details", "")
            xss_type = entry.get("type", "")
            detections = self.analyze_input(details, context=xss_type)
            all_detections.extend(detections)

        summary = {
            "total_requests": len(request_log),
            "malicious_requests": len(all_detections),
            "detections": all_detections,
            "patterns_found": list(set(d["pattern"] for d in all_detections)),
        }

        self.log_event("analysis_complete", {
            "message": f"Analyzed {len(request_log)} requests: {len(all_detections)} XSS attempts detected",
            "total": len(request_log),
            "malicious": len(all_detections),
            "status": "info",
        })
        return summary

    def run(self, vulnerable_server=None, duration: int = 30,
            interval: float = 2.0, **kwargs):
        """Continuously monitor requests for XSS patterns."""
        self._running = True
        self.log_event("detection_started", {
            "message": f"XSS detection started (monitoring for {duration}s)",
            "status": "info",
        })

        start = time.time()
        last_checked = 0

        while self._running and (time.time() - start) < duration:
            if vulnerable_server:
                log = vulnerable_server.get_request_log()
                new_entries = log[last_checked:]
                if new_entries:
                    for entry in new_entries:
                        self.analyze_input(entry["details"], entry["type"])
                    last_checked = len(log)
            time.sleep(interval)

        self._running = False
        self.log_event("detection_stopped", {
            "message": "XSS detection stopped.",
            "status": "info",
        })

    def stop(self):
        self._running = False
