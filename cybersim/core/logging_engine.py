"""
CyberSim6 - Unified Logging Engine
Central logging for all attack and detection modules.
"""

import json
import csv
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path


class CyberSimLogger:
    """Unified logger for all CyberSim6 modules."""

    def __init__(self, log_dir: Path = None, session_id: str = None):
        self.log_dir = Path(log_dir) if log_dir else Path("./logs")
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.session_id = session_id or uuid.uuid4().hex[:8]
        self.events = []

        # Console logger
        self._logger = logging.getLogger(f"cybersim.{self.session_id}")
        if not self._logger.handlers:
            handler = logging.StreamHandler()
            handler.setFormatter(logging.Formatter(
                "[%(asctime)s] [%(levelname)s] %(message)s",
                datefmt="%H:%M:%S"
            ))
            self._logger.addHandler(handler)
            self._logger.setLevel(logging.DEBUG)

    def log_event(self, module: str, module_type: str,
                  event_type: str, details: dict = None):
        """Record a structured event."""
        details = details or {}
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "session_id": self.session_id,
            "module": module,
            "module_type": module_type,
            "event_type": event_type,
            "source": details.get("source", "localhost"),
            "target": details.get("target", "localhost"),
            "status": details.get("status", "info"),
            "details": details,
        }
        self.events.append(record)

        # Console output
        level = details.get("status", "info").upper()
        msg = f"[{module}] {event_type}: {details.get('message', '')}"
        if level == "ERROR":
            self._logger.error(msg)
        elif level == "WARNING":
            self._logger.warning(msg)
        else:
            self._logger.info(msg)

        return record

    def export_json(self, filepath: Path = None):
        """Export all events to JSON file."""
        filepath = filepath or self.log_dir / f"session_{self.session_id}.json"
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(self.events, f, indent=2, ensure_ascii=False)
        self._logger.info(f"Exported {len(self.events)} events to {filepath}")
        return filepath

    def export_csv(self, filepath: Path = None):
        """Export all events to CSV file."""
        filepath = filepath or self.log_dir / f"session_{self.session_id}.csv"
        if not self.events:
            return filepath

        fieldnames = ["timestamp", "session_id", "module", "module_type",
                      "event_type", "source", "target", "status"]
        with open(filepath, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for event in self.events:
                row = {k: event.get(k, "") for k in fieldnames}
                writer.writerow(row)
        self._logger.info(f"Exported {len(self.events)} events to {filepath}")
        return filepath

    def get_events(self, module: str = None, event_type: str = None):
        """Filter events by module and/or event type."""
        results = self.events
        if module:
            results = [e for e in results if e["module"] == module]
        if event_type:
            results = [e for e in results if e["event_type"] == event_type]
        return results

    def clear(self):
        """Clear all events from memory."""
        self.events.clear()
