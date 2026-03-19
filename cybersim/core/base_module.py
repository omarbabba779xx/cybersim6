"""
CyberSim6 - Base Module
Abstract base class for all attack and detection modules.

All modules (attack and detection) inherit from BaseModule, which
enforces a consistent lifecycle: safety validation on init, run/stop
control, and structured event logging through the unified engine.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from cybersim.core.logging_engine import CyberSimLogger


class BaseModule(ABC):
    """Abstract base class for all CyberSim6 simulation modules.

    Attributes:
        MODULE_TYPE: Either ``"attack"`` or ``"detection"``.
        MODULE_NAME: Unique identifier, e.g. ``"ddos_http_flood"``.
        config: Module-specific configuration dictionary.
        logger: Shared :class:`CyberSimLogger` instance for event recording.
    """

    MODULE_TYPE: str | None = None
    MODULE_NAME: str | None = None

    def __init__(self, config: dict[str, Any], logger: CyberSimLogger) -> None:
        self.config = config
        self.logger = logger
        self._running: bool = False
        self._validate_safety()

    @abstractmethod
    def _validate_safety(self) -> None:
        """Verify sandbox constraints before execution.

        Raises:
            SafetyError: If the module's target violates safety rules.
        """
        pass

    @abstractmethod
    def run(self, **kwargs: Any) -> None:
        """Execute the module's primary function (attack or detection)."""
        pass

    @abstractmethod
    def stop(self) -> None:
        """Gracefully stop the module and release resources."""
        pass

    def log_event(self, event_type: str, details: dict[str, Any] | None = None) -> None:
        """Emit a structured log entry through the unified logger.

        Args:
            event_type: Category of the event (e.g. ``"attack_started"``).
            details: Optional key-value payload for the log record.
        """
        self.logger.log_event(
            module=self.MODULE_NAME,
            module_type=self.MODULE_TYPE,
            event_type=event_type,
            details=details or {},
        )
