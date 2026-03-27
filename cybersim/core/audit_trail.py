"""
Audit Trail -- Immutable hash-chain log for forensic integrity.

Each entry is cryptographically linked to the previous one (like a
blockchain).  Tampering with any entry breaks the chain, detectable
via :meth:`AuditTrail.verify_chain`.

Uses only the Python standard library (``hashlib``, ``json``,
``threading``).
"""

from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class AuditEntry:
    """A single immutable record in the audit trail.

    Attributes:
        index: Zero-based position in the chain.
        timestamp: ISO-8601 UTC timestamp of the event.
        action: High-level action label (e.g. ``"login_attempt"``).
        actor: Who triggered the action (user, module, system, ...).
        module: Originating CyberSim6 module name.
        details: Arbitrary metadata dictionary.
        previous_hash: SHA-256 hash of the preceding entry (``"0"`` for genesis).
        hash: SHA-256 hash of **this** entry's content.
    """

    index: int
    timestamp: str
    action: str
    actor: str
    module: str
    details: dict[str, Any]
    previous_hash: str
    hash: str


# ---------------------------------------------------------------------------
# Audit Trail
# ---------------------------------------------------------------------------

class AuditTrail:
    """Thread-safe, append-only hash-chain log.

    Usage::

        trail = AuditTrail()
        trail.record("scan_started", actor="admin", module="sqli")
        valid, last_idx = trail.verify_chain()
        assert valid
    """

    def __init__(self) -> None:
        """Initialise an empty audit trail."""
        self._entries: list[AuditEntry] = []
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def record(
        self,
        action: str,
        actor: str,
        module: str,
        details: dict[str, Any] | None = None,
    ) -> AuditEntry:
        """Append a new entry to the chain.

        Args:
            action: Descriptive action label.
            actor: Identifier of the entity that triggered the action.
            module: CyberSim6 module originating the event.
            details: Optional metadata dictionary.

        Returns:
            The newly created :class:`AuditEntry`.
        """
        details = details or {}

        with self._lock:
            index = len(self._entries)
            timestamp = datetime.now(timezone.utc).isoformat()
            previous_hash = self._entries[-1].hash if self._entries else "0"
            entry_hash = self._compute_hash(
                index, timestamp, action, actor, module, details, previous_hash,
            )
            entry = AuditEntry(
                index=index,
                timestamp=timestamp,
                action=action,
                actor=actor,
                module=module,
                details=details,
                previous_hash=previous_hash,
                hash=entry_hash,
            )
            self._entries.append(entry)

        return entry

    def verify_chain(self) -> tuple[bool, int]:
        """Verify the integrity of the entire chain.

        Returns:
            A ``(valid, last_valid_index)`` tuple.  If ``valid`` is
            ``True``, ``last_valid_index`` equals the index of the last
            entry.  On failure, ``last_valid_index`` is the index of the
            last entry whose hash **is** correct (``-1`` if the very
            first entry is corrupted).
        """
        with self._lock:
            if not self._entries:
                return (True, -1)

            for entry in self._entries:
                expected = self._compute_hash(
                    entry.index,
                    entry.timestamp,
                    entry.action,
                    entry.actor,
                    entry.module,
                    entry.details,
                    entry.previous_hash,
                )
                if entry.hash != expected:
                    return (False, entry.index - 1)

                # Verify linkage to previous entry
                if entry.index > 0:
                    if entry.previous_hash != self._entries[entry.index - 1].hash:
                        return (False, entry.index - 1)

            return (True, self._entries[-1].index)

    def get_entries(
        self,
        module: str | None = None,
        actor: str | None = None,
    ) -> list[AuditEntry]:
        """Return entries, optionally filtered by *module* and/or *actor*.

        Args:
            module: If given, only entries from this module.
            actor: If given, only entries by this actor.

        Returns:
            List of matching :class:`AuditEntry` objects.
        """
        with self._lock:
            results = list(self._entries)

        if module is not None:
            results = [e for e in results if e.module == module]
        if actor is not None:
            results = [e for e in results if e.actor == actor]
        return results

    def export_json(self, path: str) -> None:
        """Serialise the full chain to a JSON file at *path*.

        Args:
            path: Filesystem path for the output file.
        """
        with self._lock:
            data = [asdict(e) for e in self._entries]

        out = Path(path)
        out.parent.mkdir(parents=True, exist_ok=True)
        with open(out, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _compute_hash(
        index: int,
        timestamp: str,
        action: str,
        actor: str,
        module: str,
        details: dict[str, Any],
        previous_hash: str,
    ) -> str:
        """Compute a SHA-256 digest for the given entry fields.

        The hash covers every field except ``hash`` itself.
        """
        payload = json.dumps(
            {
                "index": index,
                "timestamp": timestamp,
                "action": action,
                "actor": actor,
                "module": module,
                "details": details,
                "previous_hash": previous_hash,
            },
            sort_keys=True,
            ensure_ascii=False,
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()
