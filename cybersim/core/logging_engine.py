"""
CyberSim6 - Unified Logging Engine
Central logging for all attack and detection modules.

Every event flows through :class:`CyberSimLogger`, which stores structured
records in memory and can export them to JSON or CSV for post-analysis.
The dashboard also reads from this logger in real time via the REST API.
"""

from __future__ import annotations

import json
import csv
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class CyberSimLogger:
    """Unified logger for all CyberSim6 modules.

    Attributes:
        log_dir: Directory where exported files are written.
        session_id: Short hex identifier for the current session.
        events: In-memory list of all recorded event dictionaries.
    """

    def __init__(self, log_dir: Path | None = None, session_id: str | None = None) -> None:
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
                  event_type: str, details: dict[str, Any] | None = None) -> dict[str, Any]:
        """Record a structured event and emit it to the console.

        Args:
            module: Source module name (e.g. ``"sqli_attack"``).
            module_type: ``"attack"`` or ``"detection"``.
            event_type: Category (e.g. ``"attack_started"``).
            details: Arbitrary payload dict.

        Returns:
            The complete event record that was stored.
        """
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

    def export_json(self, filepath: Path | None = None) -> Path:
        """Export all events to a JSON file.

        Returns:
            Path to the written file.
        """
        filepath = filepath or self.log_dir / f"session_{self.session_id}.json"
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(self.events, f, indent=2, ensure_ascii=False)
        self._logger.info(f"Exported {len(self.events)} events to {filepath}")
        return filepath

    def export_csv(self, filepath: Path | None = None) -> Path:
        """Export all events to a CSV file.

        Returns:
            Path to the written file.
        """
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

    def get_events(self, module: str | None = None, event_type: str | None = None) -> list[dict[str, Any]]:
        """Filter events by module and/or event type."""
        results = self.events
        if module:
            results = [e for e in results if e["module"] == module]
        if event_type:
            results = [e for e in results if e["event_type"] == event_type]
        return results

    def clear(self) -> None:
        """Clear all events from memory."""
        self.events.clear()
