"""
CyberSim6 - SQL Injection Detection Module
Monitors SQL queries for injection patterns.
"""

import re
import time

from cybersim.core.base_module import BaseModule

# Common SQLi patterns to detect — pre-compiled at module load for performance
SQLI_PATTERNS = [
    (re.compile(r"'\s*(OR|AND)\s+[\d'\"]+\s*=\s*[\d'\"]+", re.IGNORECASE), "Boolean-based injection"),
    (re.compile(r"UNION\s+(ALL\s+)?SELECT", re.IGNORECASE), "UNION-based injection"),
    (re.compile(r"--\s*$|/\*.*\*/", re.IGNORECASE | re.DOTALL), "Comment-based injection"),
    (re.compile(r";\s*(DROP|DELETE|UPDATE|INSERT|ALTER)", re.IGNORECASE), "Stacked query injection"),
    (re.compile(r"'\s*;\s*", re.IGNORECASE), "Quote-semicolon injection"),
    (re.compile(r"sqlite_master|information_schema|sys\.tables", re.IGNORECASE), "Schema extraction attempt"),
    (re.compile(r"SLEEP\s*\(|BENCHMARK\s*\(|WAITFOR\s+DELAY", re.IGNORECASE), "Time-based injection"),
    (re.compile(r"(CHAR|CHR|CONCAT|GROUP_CONCAT)\s*\(", re.IGNORECASE), "Function-based obfuscation"),
    (re.compile(r"0x[0-9a-fA-F]+", re.IGNORECASE), "Hex-encoded injection"),
]


class SQLInjectionDetector(BaseModule):
    """Detects SQL injection attempts by analyzing query patterns."""

    MODULE_TYPE = "detection"
    MODULE_NAME = "sqli_detector"

    def _validate_safety(self):
        pass

    def analyze_query(self, sql: str, endpoint: str = "") -> list:
        """
        Analyze a SQL query for injection patterns.

        Returns:
            List of detected patterns with descriptions.
        """
        detections = []
        for pattern, description in SQLI_PATTERNS:
            if pattern.search(sql):
                detection = {
                    "pattern": description,
                    "regex": pattern.pattern,
                    "sql": sql[:200],
                    "endpoint": endpoint,
                }
                detections.append(detection)
                self.log_event("sqli_detected", {
                    "message": f"SQLi DETECTED [{description}] on {endpoint}: {sql[:100]}",
                    "pattern": description,
                    "endpoint": endpoint,
                    "status": "warning",
                })
        return detections

    def analyze_query_log(self, query_log: list) -> dict:
        """
        Analyze a batch of logged queries.

        Returns:
            Summary of all detections.
        """
        all_detections = []
        for entry in query_log:
            sql = entry.get("sql", "")
            endpoint = entry.get("endpoint", "")
            detections = self.analyze_query(sql, endpoint)
            all_detections.extend(detections)

        summary = {
            "total_queries": len(query_log),
            "malicious_queries": len(all_detections),
            "detections": all_detections,
            "patterns_found": list(set(d["pattern"] for d in all_detections)),
        }

        self.log_event("analysis_complete", {
            "message": f"Analyzed {len(query_log)} queries: {len(all_detections)} malicious detected",
            "total_queries": len(query_log),
            "malicious": len(all_detections),
            "status": "info",
        })

        return summary

    def run(self, vulnerable_server=None, duration: int = 30,
            interval: float = 2.0, **kwargs):
        """
        Continuously monitor queries from the vulnerable server.
        """
        self._running = True
        self.log_event("detection_started", {
            "message": f"SQL Injection detection started (monitoring for {duration}s)",
            "status": "info",
        })

        start = time.time()
        last_checked = 0

        while self._running and (time.time() - start) < duration:
            if vulnerable_server:
                query_log = vulnerable_server.get_query_log()
                new_queries = query_log[last_checked:]
                if new_queries:
                    for entry in new_queries:
                        self.analyze_query(entry["sql"], entry["endpoint"])
                    last_checked = len(query_log)
            time.sleep(interval)

        self._running = False
        self.log_event("detection_stopped", {
            "message": "SQL Injection detection stopped.",
            "status": "info",
        })

    def stop(self):
        self._running = False
