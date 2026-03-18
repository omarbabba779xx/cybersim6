"""
CyberSim6 - Brute Force Detection Module
Monitors login attempts and detects brute force patterns.
"""

import time
import threading
from collections import defaultdict, deque

from cybersim.core.base_module import BaseModule


class BruteForceDetector(BaseModule):
    """Detects brute force attack patterns from login attempts."""

    MODULE_TYPE = "detection"
    MODULE_NAME = "bruteforce_detector"

    def __init__(self, config: dict, logger):
        self._attempts = defaultdict(deque)  # ip -> deque of timestamps
        self._lock = threading.Lock()
        super().__init__(config, logger)

    def _validate_safety(self):
        pass

    def record_attempt(self, source_ip: str, success: bool):
        """Record a login attempt."""
        if not success:
            with self._lock:
                self._attempts[source_ip].append(time.time())

    def check_brute_force(self, max_failures: int = None,
                          window_seconds: int = None) -> list:
        """
        Check for brute force patterns.

        Returns:
            List of detected attacker IPs with details.
        """
        max_failures = max_failures or self.config.get("max_failures", 5)
        window = window_seconds or self.config.get("window_seconds", 60)
        now = time.time()
        cutoff = now - window
        detections = []

        with self._lock:
            for ip, timestamps in self._attempts.items():
                # Remove old entries
                while timestamps and timestamps[0] < cutoff:
                    timestamps.popleft()

                if len(timestamps) >= max_failures:
                    detection = {
                        "source_ip": ip,
                        "failures_in_window": len(timestamps),
                        "window_seconds": window,
                        "threshold": max_failures,
                    }
                    detections.append(detection)
                    self.log_event("bruteforce_detected", {
                        "message": f"Brute force DETECTED from {ip}: {len(timestamps)} failures in {window}s",
                        "source": ip,
                        "status": "warning",
                        **detection,
                    })

        return detections

    def run(self, auth_server=None, duration: int = 60,
            interval: float = 2.0, **kwargs):
        """
        Run continuous monitoring.

        Args:
            auth_server: AuthServer instance to monitor
            duration: Monitoring duration in seconds
            interval: Check interval in seconds
        """
        self._running = True
        self.log_event("detection_started", {
            "message": f"Brute force detection started (monitoring for {duration}s)",
            "status": "info",
        })

        start = time.time()
        last_checked = 0

        while self._running and (time.time() - start) < duration:
            # If we have an auth server, sync its attempt log
            if auth_server:
                attempt_log = auth_server.get_attempt_log()
                for attempt in attempt_log[last_checked:]:
                    self.record_attempt(attempt["source"], attempt["success"])
                last_checked = len(attempt_log)

            self.check_brute_force()
            time.sleep(interval)

        self._running = False
        self.log_event("detection_stopped", {
            "message": "Brute force detection stopped.",
            "status": "info",
        })

    def stop(self):
        self._running = False
