"""
CyberSim6 - Threat Scoring Engine
Real-time risk assessment combining all module events.

Scores from 0 (safe) to 100 (critical), with color-coded threat levels.
The scorer uses exponential time decay so recent events contribute more
to the overall score, and weights differ by module and event type
(e.g. ransomware attacks score higher than DDoS detections).

Thread-safe: all mutations are protected by a reentrant lock so the
scorer can be shared across simulation threads.
"""

from __future__ import annotations

import math
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class ThreatLevel(Enum):
    """Discrete threat level derived from a 0-100 score."""

    SAFE = "safe"           # 0-20
    LOW = "low"             # 21-40
    MEDIUM = "medium"       # 41-60
    HIGH = "high"           # 61-80
    CRITICAL = "critical"   # 81-100

    @staticmethod
    def from_score(score: float) -> ThreatLevel:
        """Return the threat level corresponding to a numeric score.

        Args:
            score: Threat score in the 0-100 range.

        Returns:
            The matching :class:`ThreatLevel` member.
        """
        if score <= 20:
            return ThreatLevel.SAFE
        if score <= 40:
            return ThreatLevel.LOW
        if score <= 60:
            return ThreatLevel.MEDIUM
        if score <= 80:
            return ThreatLevel.HIGH
        return ThreatLevel.CRITICAL


@dataclass
class ThreatEvent:
    """A single weighted threat event recorded by the scorer.

    Attributes:
        module: Source module category (e.g. ``"ddos"``, ``"sqli"``).
        event_type: ``"attack"`` or ``"detection"``.
        severity: Normalised severity between 0.0 and 1.0.
        timestamp: UTC timestamp of when the event was recorded.
        details: Arbitrary payload dictionary.
    """

    module: str
    event_type: str
    severity: float
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    details: dict[str, Any] = field(default_factory=dict)


class ThreatScorer:
    """Real-time threat scoring engine.

    Combines events from all six CyberSim6 modules with weighted scoring
    and exponential time decay.  The resulting score is clamped to [0, 100].

    Args:
        decay_minutes: Half-life for exponential decay in minutes.  After
            *decay_minutes* have elapsed an event contributes roughly half
            its original weight.
        snapshot_interval_seconds: Interval at which automatic timeline
            snapshots are taken (default 30 s).

    Example::

        scorer = ThreatScorer()
        scorer.record_event("sqli", "attack", severity=0.8)
        print(scorer.get_score())   # e.g. 16.0
        print(scorer.get_level())   # ThreatLevel.SAFE
    """

    WEIGHTS: dict[str, dict[str, float]] = {
        "ddos": {"attack": 15, "detection": 5},
        "sqli": {"attack": 20, "detection": 8},
        "xss": {"attack": 18, "detection": 7},
        "bruteforce": {"attack": 12, "detection": 5},
        "phishing": {"attack": 25, "detection": 10},
        "ransomware": {"attack": 30, "detection": 15},
    }

    DEFAULT_WEIGHT: float = 10.0

    def __init__(
        self,
        decay_minutes: float = 10.0,
        snapshot_interval_seconds: float = 30.0,
    ) -> None:
        self._decay_minutes = decay_minutes
        self._snapshot_interval = snapshot_interval_seconds
        self._events: list[ThreatEvent] = []
        self._timeline: list[dict[str, Any]] = []
        self._lock = threading.RLock()
        self._last_snapshot: datetime | None = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def record_event(
        self,
        module: str,
        event_type: str,
        severity: float,
        details: dict[str, Any] | None = None,
    ) -> ThreatEvent:
        """Record a threat event and optionally take a timeline snapshot.

        Args:
            module: Module category key (must match a key in :attr:`WEIGHTS`).
            event_type: ``"attack"`` or ``"detection"``.
            severity: Normalised severity in [0.0, 1.0].
            details: Optional payload dictionary.

        Returns:
            The newly created :class:`ThreatEvent`.

        Raises:
            ValueError: If *severity* is outside the [0.0, 1.0] range.
        """
        if not 0.0 <= severity <= 1.0:
            raise ValueError(f"severity must be in [0.0, 1.0], got {severity}")

        event = ThreatEvent(
            module=module,
            event_type=event_type,
            severity=severity,
            timestamp=datetime.now(timezone.utc),
            details=details or {},
        )

        with self._lock:
            self._events.append(event)
            self._maybe_snapshot()

        return event

    def get_score(self) -> float:
        """Compute the current threat score in [0, 100].

        The score is the sum of each event's contribution, where
        contribution = weight * severity * decay_factor, clamped to 100.
        """
        with self._lock:
            now = datetime.now(timezone.utc)
            total = 0.0
            for event in self._events:
                total += self._event_contribution(event, now)
            return min(total, 100.0)

    def get_level(self) -> ThreatLevel:
        """Return the :class:`ThreatLevel` for the current score."""
        return ThreatLevel.from_score(self.get_score())

    def get_breakdown(self) -> dict[str, float]:
        """Return a per-module breakdown of the current score.

        Returns:
            Dictionary mapping module names to their individual score
            contributions (before the global 100-cap).
        """
        with self._lock:
            now = datetime.now(timezone.utc)
            breakdown: dict[str, float] = {}
            for event in self._events:
                contribution = self._event_contribution(event, now)
                breakdown[event.module] = breakdown.get(event.module, 0.0) + contribution
            return breakdown

    def get_timeline(self, minutes: int = 30) -> list[dict[str, Any]]:
        """Return timeline snapshots within the last *minutes* minutes.

        Each snapshot is a dict with keys ``"timestamp"`` (ISO string)
        and ``"score"`` (float).

        Args:
            minutes: How far back to look.

        Returns:
            List of snapshot dicts ordered oldest-first.
        """
        with self._lock:
            cutoff = datetime.now(timezone.utc).timestamp() - minutes * 60
            return [
                snap for snap in self._timeline
                if datetime.fromisoformat(snap["timestamp"]).timestamp() >= cutoff
            ]

    def reset(self) -> None:
        """Clear all events and timeline snapshots."""
        with self._lock:
            self._events.clear()
            self._timeline.clear()
            self._last_snapshot = None

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _event_contribution(self, event: ThreatEvent, now: datetime) -> float:
        """Compute a single event's decayed contribution to the score."""
        weight = self._weight_for(event.module, event.event_type)
        age_minutes = (now - event.timestamp).total_seconds() / 60.0
        decay = math.exp(-math.log(2) * age_minutes / self._decay_minutes)
        return weight * event.severity * decay

    def _weight_for(self, module: str, event_type: str) -> float:
        """Look up the weight for a module/event_type pair."""
        module_weights = self.WEIGHTS.get(module)
        if module_weights is None:
            return self.DEFAULT_WEIGHT
        return module_weights.get(event_type, self.DEFAULT_WEIGHT)

    def _maybe_snapshot(self) -> None:
        """Take a timeline snapshot if enough time has elapsed.

        Must be called while holding ``self._lock``.
        """
        now = datetime.now(timezone.utc)
        if (
            self._last_snapshot is None
            or (now - self._last_snapshot).total_seconds() >= self._snapshot_interval
        ):
            score = 0.0
            for event in self._events:
                score += self._event_contribution(event, now)
            score = min(score, 100.0)

            self._timeline.append({
                "timestamp": now.isoformat(),
                "score": score,
            })
            self._last_snapshot = now
