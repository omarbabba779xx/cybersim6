"""
CyberSim6 - Base Module
Abstract base class for all attack and detection modules.
"""

from abc import ABC, abstractmethod
from cybersim.core.logging_engine import CyberSimLogger


class BaseModule(ABC):
    """Base class for all CyberSim6 modules."""

    MODULE_TYPE = None   # "attack" or "detection"
    MODULE_NAME = None   # e.g., "ddos_syn_flood"

    def __init__(self, config: dict, logger: CyberSimLogger):
        self.config = config
        self.logger = logger
        self._running = False
        self._validate_safety()

    @abstractmethod
    def _validate_safety(self):
        """Verify sandbox constraints before execution."""
        pass

    @abstractmethod
    def run(self, **kwargs):
        """Execute the module's primary function."""
        pass

    @abstractmethod
    def stop(self):
        """Gracefully stop the module."""
        pass

    def log_event(self, event_type: str, details: dict = None):
        """Emit a structured log entry through the unified logger."""
        self.logger.log_event(
            module=self.MODULE_NAME,
            module_type=self.MODULE_TYPE,
            event_type=event_type,
            details=details or {},
        )
