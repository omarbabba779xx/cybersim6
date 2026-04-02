"""
CyberSim6 - Base Detector
Common base class for all detection modules.
"""

from __future__ import annotations

import time
from typing import Any

from cybersim.core.base_module import BaseModule
from cybersim.core.detection_metrics import DetectionMetrics


class BaseDetector(BaseModule):
    """Base class for all CyberSim6 detection modules.

    Provides common detection infrastructure:
    - Metrics tracking (precision, recall, F1)
    - Run loop with configurable interval
    - Start/stop lifecycle
    """

    MODULE_TYPE = "detection"

    def __init__(self, config: dict, logger: Any) -> None:
        self.metrics = DetectionMetrics()
        self._running = False
        super().__init__(config, logger)

    def _validate_safety(self) -> None:
        pass  # Detection modules have no safety constraints

    def record_detection(self, predicted: bool, actual: bool, details: str = "") -> None:
        """Record a detection result for metrics tracking."""
        self.metrics.record(predicted, actual, module=self.MODULE_NAME, details=details)

    def get_metrics_report(self) -> str:
        """Get formatted metrics report for this detector."""
        return self.metrics.generate_report()

    def run(self, duration: int = 30, interval: float = 1.0, **kwargs: Any) -> None:
        """Run continuous monitoring for a specified duration."""
        self._running = True
        self.log_event("detection_started", {
            "message": f"{self.MODULE_NAME} detection started (monitoring for {duration}s)",
            "status": "info",
        })

        start = time.time()
        while self._running and (time.time() - start) < duration:
            self._check_cycle(**kwargs)
            time.sleep(interval)

        self._running = False
        self.log_event("detection_stopped", {
            "message": f"{self.MODULE_NAME} detection stopped.",
            "status": "info",
        })

    def _check_cycle(self, **kwargs: Any) -> None:
        """Override in subclasses to implement per-cycle check logic."""
        pass

    def stop(self) -> None:
        self._running = False
