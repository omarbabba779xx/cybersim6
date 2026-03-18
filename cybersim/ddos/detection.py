"""
CyberSim6 - DDoS Detection Module
Monitors request rates and detects flood patterns.
"""

import threading
import time
from collections import deque

from cybersim.core.base_module import BaseModule


class DDoSDetector(BaseModule):
    """Detects DDoS patterns by monitoring request rates."""

    MODULE_TYPE = "detection"
    MODULE_NAME = "ddos_detector"

    def __init__(self, config: dict, logger):
        self._request_log = deque()
        self._lock = threading.Lock()
        super().__init__(config, logger)

    def _validate_safety(self):
        pass  # Detection module - no safety constraints needed

    def record_request(self, source_ip: str = "127.0.0.1"):
        """Record an incoming request timestamp."""
        with self._lock:
            self._request_log.append({
                "time": time.time(),
                "source": source_ip,
            })

    def check_threshold(self, threshold_rps: int = None, window: int = None) -> dict:
        """
        Check if request rate exceeds threshold.

        Args:
            threshold_rps: Requests per second threshold
            window: Time window in seconds

        Returns:
            dict with detection result
        """
        threshold_rps = threshold_rps or self.config.get("threshold_pps", 50)
        window = window or self.config.get("window_seconds", 5)

        now = time.time()
        cutoff = now - window

        with self._lock:
            # Remove old entries
            while self._request_log and self._request_log[0]["time"] < cutoff:
                self._request_log.popleft()
            count = len(self._request_log)

        rate = count / window if window > 0 else 0
        is_attack = rate > threshold_rps

        result = {
            "requests_in_window": count,
            "window_seconds": window,
            "rate_per_second": round(rate, 2),
            "threshold": threshold_rps,
            "is_attack": is_attack,
        }

        if is_attack:
            self.log_event("ddos_detected", {
                "message": f"DDoS DETECTED! Rate: {rate:.1f} req/s (threshold: {threshold_rps})",
                "status": "warning",
                **result,
            })
        return result

    def run(self, duration: int = 30, interval: float = 1.0, **kwargs):
        """
        Run continuous monitoring for a specified duration.

        Args:
            duration: Monitoring duration in seconds
            interval: Check interval in seconds
        """
        self._running = True
        self.log_event("detection_started", {
            "message": f"DDoS detection started (monitoring for {duration}s)",
            "status": "info",
        })

        start = time.time()
        while self._running and (time.time() - start) < duration:
            self.check_threshold()
            time.sleep(interval)

        self._running = False
        self.log_event("detection_stopped", {
            "message": "DDoS detection stopped.",
            "status": "info",
        })

    def stop(self):
        self._running = False
