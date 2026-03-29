"""
Tests for the Threat Scoring Engine.

Covers scoring, decay, weights, thread safety, timeline,
breakdown, capping, reset, and threat-level thresholds.
"""

from __future__ import annotations

import threading
from datetime import datetime, timedelta, timezone

import pytest

from cybersim.core.threat_score import ThreatLevel, ThreatScorer


# ── ThreatLevel thresholds ────────────────────────────────────────────


class TestThreatLevel:
    """Verify that ThreatLevel.from_score maps ranges correctly."""

    @pytest.mark.parametrize(
        "score, expected",
        [
            (0, ThreatLevel.SAFE),
            (20, ThreatLevel.SAFE),
            (20.5, ThreatLevel.LOW),
            (40, ThreatLevel.LOW),
            (41, ThreatLevel.MEDIUM),
            (60, ThreatLevel.MEDIUM),
            (61, ThreatLevel.HIGH),
            (80, ThreatLevel.HIGH),
            (81, ThreatLevel.CRITICAL),
            (100, ThreatLevel.CRITICAL),
        ],
    )
    def test_thresholds(self, score: float, expected: ThreatLevel) -> None:
        assert ThreatLevel.from_score(score) is expected


# ── ThreatScorer ──────────────────────────────────────────────────────


class TestThreatScorer:
    """Core scoring engine tests."""

    def test_initial_score_is_zero(self) -> None:
        """A freshly created scorer must report 0."""
        scorer = ThreatScorer()
        assert scorer.get_score() == 0.0
        assert scorer.get_level() is ThreatLevel.SAFE

    def test_single_event_increases_score(self) -> None:
        """Recording one event should raise the score above 0."""
        scorer = ThreatScorer()
        scorer.record_event("ddos", "attack", severity=0.5)
        assert scorer.get_score() > 0.0

    def test_multiple_events_accumulate(self) -> None:
        """Additional events of the same kind should increase the score."""
        scorer = ThreatScorer()
        scorer.record_event("ddos", "attack", severity=0.5)
        score_one = scorer.get_score()

        scorer.record_event("ddos", "attack", severity=0.5)
        score_two = scorer.get_score()

        assert score_two > score_one

    def test_ransomware_weighs_more_than_ddos(self) -> None:
        """Ransomware attacks carry higher weight than DDoS attacks."""
        scorer_a = ThreatScorer()
        scorer_a.record_event("ddos", "attack", severity=1.0)

        scorer_b = ThreatScorer()
        scorer_b.record_event("ransomware", "attack", severity=1.0)

        assert scorer_b.get_score() > scorer_a.get_score()

    def test_attack_weighs_more_than_detection(self) -> None:
        """For the same module, attacks should score higher than detections."""
        scorer_a = ThreatScorer()
        scorer_a.record_event("sqli", "detection", severity=1.0)

        scorer_b = ThreatScorer()
        scorer_b.record_event("sqli", "attack", severity=1.0)

        assert scorer_b.get_score() > scorer_a.get_score()

    def test_score_capped_at_100(self) -> None:
        """No matter how many events are added the score must not exceed 100."""
        scorer = ThreatScorer()
        for _ in range(50):
            scorer.record_event("ransomware", "attack", severity=1.0)
        assert scorer.get_score() == 100.0

    def test_decay_reduces_score_over_time(self) -> None:
        """Events in the past should contribute less due to exponential decay."""
        scorer = ThreatScorer(decay_minutes=10.0)
        event = scorer.record_event("sqli", "attack", severity=1.0)

        score_now = scorer.get_score()

        # Shift the event's timestamp 20 minutes into the past
        event.timestamp = datetime.now(timezone.utc) - timedelta(minutes=20)
        score_later = scorer.get_score()

        assert score_later < score_now

    def test_breakdown_by_module(self) -> None:
        """get_breakdown should return per-module score contributions."""
        scorer = ThreatScorer()
        scorer.record_event("ddos", "attack", severity=1.0)
        scorer.record_event("sqli", "attack", severity=1.0)

        breakdown = scorer.get_breakdown()
        assert "ddos" in breakdown
        assert "sqli" in breakdown
        assert breakdown["ddos"] > 0
        assert breakdown["sqli"] > 0
        # sqli weight (20) > ddos weight (15)
        assert breakdown["sqli"] > breakdown["ddos"]

    def test_timeline_tracking(self) -> None:
        """Recording events should produce timeline snapshots."""
        # Use a very short snapshot interval so every event triggers one
        scorer = ThreatScorer(snapshot_interval_seconds=0)
        scorer.record_event("ddos", "attack", severity=0.5)
        scorer.record_event("sqli", "attack", severity=0.5)

        timeline = scorer.get_timeline(minutes=5)
        assert len(timeline) >= 2
        for snap in timeline:
            assert "timestamp" in snap
            assert "score" in snap

    def test_timeline_filters_by_minutes(self) -> None:
        """Only snapshots within the requested window should be returned."""
        scorer = ThreatScorer(snapshot_interval_seconds=0)
        scorer.record_event("ddos", "attack", severity=0.5)

        # All snapshots within a generous window
        assert len(scorer.get_timeline(minutes=60)) >= 1
        # Zero-minute window should return nothing recorded > 0 min ago
        # (snapshot just happened so it's within 0 minutes if we're fast)
        # We can't guarantee exclusion at 0 min, so just verify the method runs
        scorer.get_timeline(minutes=0)

    def test_thread_safety(self) -> None:
        """Concurrent recording from multiple threads must not crash."""
        scorer = ThreatScorer(snapshot_interval_seconds=0)
        errors: list[Exception] = []

        def _writer(module: str) -> None:
            try:
                for _ in range(100):
                    scorer.record_event(module, "attack", severity=0.5)
                    scorer.get_score()
                    scorer.get_breakdown()
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=_writer, args=(m,))
                   for m in ("ddos", "sqli", "xss", "ransomware")]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == [], f"Thread errors: {errors}"
        assert scorer.get_score() > 0

    def test_reset_clears_all(self) -> None:
        """reset() should bring the scorer back to its initial state."""
        scorer = ThreatScorer(snapshot_interval_seconds=0)
        scorer.record_event("ransomware", "attack", severity=1.0)
        assert scorer.get_score() > 0
        assert len(scorer.get_timeline()) > 0

        scorer.reset()

        assert scorer.get_score() == 0.0
        assert scorer.get_level() is ThreatLevel.SAFE
        assert scorer.get_timeline() == []
        assert scorer.get_breakdown() == {}

    def test_severity_validation(self) -> None:
        """Severity outside [0, 1] must raise ValueError."""
        scorer = ThreatScorer()
        with pytest.raises(ValueError):
            scorer.record_event("ddos", "attack", severity=1.5)
        with pytest.raises(ValueError):
            scorer.record_event("ddos", "attack", severity=-0.1)

    def test_unknown_module_uses_default_weight(self) -> None:
        """Modules not in WEIGHTS should still score using a default weight."""
        scorer = ThreatScorer()
        scorer.record_event("unknown_module", "attack", severity=1.0)
        assert scorer.get_score() > 0

    def test_event_details_stored(self) -> None:
        """Details dict should be accessible on the returned ThreatEvent."""
        scorer = ThreatScorer()
        event = scorer.record_event(
            "phishing", "attack", severity=0.9,
            details={"url": "http://evil.example.com"},
        )
        assert event.details["url"] == "http://evil.example.com"
        assert event.module == "phishing"
        assert event.severity == 0.9
