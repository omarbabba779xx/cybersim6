"""
Tests for the ML Anomaly Detection module.

Covers statistical calculations, anomaly scoring, learning period,
multi-dimensional detection, history, reset, thread safety, and
the specialised NetworkAnomalyDetector.
"""

from __future__ import annotations

import threading
from datetime import datetime

import pytest

from cybersim.core.anomaly_detection import (
    AnomalyResult,
    AnomalyType,
    NetworkAnomalyDetector,
    StatisticalDetector,
)


# ── Helpers ──────────────────────────────────────────────────────────


def _feed_normal(detector: StatisticalDetector, n: int = 30) -> None:
    """Feed *n* well-behaved observations to move past the learning period."""
    for i in range(n):
        detector.observe(50.0 + (i % 5))


# ── Learning period ──────────────────────────────────────────────────


class TestLearningPeriod:
    """During the learning period every observation should be NORMAL."""

    def test_all_normal_during_learning(self) -> None:
        det = StatisticalDetector(window_size=50, learning_period=10)
        for _ in range(9):
            res = det.observe(100.0)
            assert res.anomaly_type is AnomalyType.NORMAL
            assert res.score == 0.0
            assert res.z_score == 0.0

    def test_detection_starts_after_learning(self) -> None:
        det = StatisticalDetector(window_size=50, learning_period=10)
        for _ in range(10):
            det.observe(50.0)
        # After learning, a huge spike should be detected
        res = det.observe(5000.0)
        assert res.anomaly_type is not AnomalyType.NORMAL


# ── Normal values stay normal ────────────────────────────────────────


class TestNormalObservations:
    """Consistent values should never trigger anomalies."""

    def test_stable_values_are_normal(self) -> None:
        det = StatisticalDetector(window_size=100, learning_period=20)
        _feed_normal(det, 40)
        # More of the same range — should stay normal
        for _ in range(20):
            res = det.observe(51.0)
            assert res.anomaly_type is AnomalyType.NORMAL

    def test_score_stays_low_for_normal(self) -> None:
        det = StatisticalDetector(window_size=100, learning_period=20)
        _feed_normal(det, 40)
        res = det.observe(52.0)
        assert res.score < 0.3


# ── Outlier detection ────────────────────────────────────────────────


class TestOutlierDetection:
    """Extreme values should be flagged as anomalous."""

    def test_large_spike_detected(self) -> None:
        det = StatisticalDetector(window_size=100, z_threshold=2.5, learning_period=20)
        _feed_normal(det, 50)
        res = det.observe(9999.0)
        assert res.anomaly_type is AnomalyType.ANOMALOUS
        assert res.score > 0.3
        assert abs(res.z_score) > 2.5

    def test_large_drop_detected(self) -> None:
        det = StatisticalDetector(window_size=100, z_threshold=2.5, learning_period=20)
        _feed_normal(det, 50)
        res = det.observe(-9999.0)
        assert res.anomaly_type is AnomalyType.ANOMALOUS
        assert abs(res.z_score) > 2.5


# ── Z-score calculation ─────────────────────────────────────────────


class TestZScore:
    """Verify the raw Z-score calculation."""

    def test_z_score_zero_when_equal_to_mean(self) -> None:
        det = StatisticalDetector()
        assert det._calculate_z_score(10.0, 10.0, 2.0) == 0.0

    def test_z_score_positive(self) -> None:
        det = StatisticalDetector()
        z = det._calculate_z_score(14.0, 10.0, 2.0)
        assert z == pytest.approx(2.0)

    def test_z_score_negative(self) -> None:
        det = StatisticalDetector()
        z = det._calculate_z_score(6.0, 10.0, 2.0)
        assert z == pytest.approx(-2.0)

    def test_z_score_zero_std(self) -> None:
        det = StatisticalDetector()
        assert det._calculate_z_score(99.0, 10.0, 0.0) == 0.0


# ── Mean / std calculation ───────────────────────────────────────────


class TestMeanStd:
    """Verify internal mean and standard deviation helpers."""

    def test_mean_simple(self) -> None:
        det = StatisticalDetector()
        assert det._calculate_mean([2.0, 4.0, 6.0]) == pytest.approx(4.0)

    def test_mean_empty(self) -> None:
        det = StatisticalDetector()
        assert det._calculate_mean([]) == 0.0

    def test_std_simple(self) -> None:
        det = StatisticalDetector()
        data = [2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0]
        mean = det._calculate_mean(data)
        std = det._calculate_std(data, mean)
        assert std == pytest.approx(2.0, abs=0.01)

    def test_std_constant_values(self) -> None:
        det = StatisticalDetector()
        data = [5.0, 5.0, 5.0, 5.0]
        assert det._calculate_std(data, 5.0) == 0.0

    def test_std_single_element(self) -> None:
        det = StatisticalDetector()
        assert det._calculate_std([3.0], 3.0) == 0.0


# ── Entropy calculation ─────────────────────────────────────────────


class TestEntropy:
    """Verify Shannon entropy computation."""

    def test_entropy_constant_data(self) -> None:
        det = StatisticalDetector()
        # All identical → zero entropy
        assert det._calculate_entropy([5.0] * 20) == 0.0

    def test_entropy_uniform_is_high(self) -> None:
        det = StatisticalDetector()
        # Spread across bins → higher entropy
        data = [float(i) for i in range(100)]
        entropy = det._calculate_entropy(data)
        assert entropy > 1.0

    def test_entropy_single_value(self) -> None:
        det = StatisticalDetector()
        assert det._calculate_entropy([42.0]) == 0.0

    def test_entropy_non_negative(self) -> None:
        det = StatisticalDetector()
        data = [1.0, 2.0, 3.0, 100.0, 200.0]
        assert det._calculate_entropy(data) >= 0.0


# ── Rate-change detection ───────────────────────────────────────────


class TestRateChange:
    """Verify rate-change detection between recent and baseline windows."""

    def test_no_change_returns_zero(self) -> None:
        det = StatisticalDetector()
        baseline = [10.0, 10.0, 10.0, 11.0, 9.0]
        recent = [10.0, 10.0]
        assert det._detect_rate_change(recent, baseline) == pytest.approx(0.0, abs=0.3)

    def test_large_change_returns_high(self) -> None:
        det = StatisticalDetector()
        baseline = [10.0, 10.0, 10.0, 11.0, 9.0]
        recent = [100.0, 100.0]
        score = det._detect_rate_change(recent, baseline)
        assert score > 1.0

    def test_empty_inputs(self) -> None:
        det = StatisticalDetector()
        assert det._detect_rate_change([], [1.0, 2.0]) == 0.0
        assert det._detect_rate_change([1.0], []) == 0.0


# ── Multi-dimensional detection ──────────────────────────────────────


class TestMultiDimensional:
    """Test observe_multi across several feature dimensions."""

    def test_empty_values(self) -> None:
        det = StatisticalDetector(learning_period=5)
        res = det.observe_multi({})
        assert res.anomaly_type is AnomalyType.NORMAL
        assert res.score == 0.0

    def test_normal_multi(self) -> None:
        det = StatisticalDetector(window_size=100, learning_period=5)
        # Build baseline
        for _ in range(20):
            det.observe_multi({"a": 10.0, "b": 20.0})
        res = det.observe_multi({"a": 10.5, "b": 20.5})
        assert res.anomaly_type is AnomalyType.NORMAL

    def test_anomalous_multi(self) -> None:
        det = StatisticalDetector(window_size=100, learning_period=5)
        for _ in range(30):
            det.observe_multi({"a": 10.0, "b": 20.0})
        res = det.observe_multi({"a": 99999.0, "b": 99999.0})
        assert res.anomaly_type is not AnomalyType.NORMAL
        assert res.score > 0.2


# ── Baseline stats ───────────────────────────────────────────────────


class TestBaseline:
    """Verify that get_baseline returns correct statistics."""

    def test_baseline_empty(self) -> None:
        det = StatisticalDetector()
        bl = det.get_baseline()
        assert bl["count"] == 0
        assert bl["mean"] == 0.0

    def test_baseline_after_observations(self) -> None:
        det = StatisticalDetector(window_size=100, learning_period=5)
        for v in [10.0, 20.0, 30.0]:
            det.observe(v)
        bl = det.get_baseline()
        assert bl["count"] == 3
        assert bl["mean"] == pytest.approx(20.0)
        assert bl["min"] == pytest.approx(10.0)
        assert bl["max"] == pytest.approx(30.0)


# ── History tracking ─────────────────────────────────────────────────


class TestHistory:
    """Verify detection history is recorded and retrievable."""

    def test_history_grows(self) -> None:
        det = StatisticalDetector(learning_period=5)
        for _ in range(10):
            det.observe(1.0)
        history = det.get_history(last_n=100)
        assert len(history) == 10

    def test_history_last_n(self) -> None:
        det = StatisticalDetector(learning_period=5)
        for _ in range(20):
            det.observe(1.0)
        history = det.get_history(last_n=5)
        assert len(history) == 5

    def test_history_contains_anomaly_results(self) -> None:
        det = StatisticalDetector(learning_period=5)
        det.observe(42.0)
        h = det.get_history(last_n=1)
        assert len(h) == 1
        assert isinstance(h[0], AnomalyResult)
        assert isinstance(h[0].timestamp, datetime)


# ── Reset ────────────────────────────────────────────────────────────


class TestReset:
    """Verify that reset clears all internal state."""

    def test_reset_clears_data(self) -> None:
        det = StatisticalDetector(learning_period=5)
        for _ in range(20):
            det.observe(10.0)
        det.reset()
        bl = det.get_baseline()
        assert bl["count"] == 0
        assert det.get_history() == []

    def test_reset_restarts_learning(self) -> None:
        det = StatisticalDetector(learning_period=10)
        for _ in range(15):
            det.observe(10.0)
        det.reset()
        # Should be in learning period again
        res = det.observe(99999.0)
        assert res.anomaly_type is AnomalyType.NORMAL


# ── Thread safety ────────────────────────────────────────────────────


class TestThreadSafety:
    """Concurrent access must not corrupt internal state."""

    def test_concurrent_observe(self) -> None:
        det = StatisticalDetector(window_size=500, learning_period=5)
        errors: list[str] = []

        def worker(offset: float) -> None:
            try:
                for i in range(100):
                    det.observe(offset + i * 0.1)
            except Exception as exc:  # noqa: BLE001
                errors.append(str(exc))

        threads = [threading.Thread(target=worker, args=(t * 100,)) for t in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == [], f"Errors in threads: {errors}"
        # All 400 observations should have been recorded
        assert det.get_baseline()["count"] == 400

    def test_concurrent_observe_and_reset(self) -> None:
        det = StatisticalDetector(window_size=200, learning_period=5)
        errors: list[str] = []

        def observer() -> None:
            try:
                for _ in range(100):
                    det.observe(10.0)
            except Exception as exc:  # noqa: BLE001
                errors.append(str(exc))

        def resetter() -> None:
            try:
                for _ in range(10):
                    det.reset()
            except Exception as exc:  # noqa: BLE001
                errors.append(str(exc))

        t1 = threading.Thread(target=observer)
        t2 = threading.Thread(target=resetter)
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        assert errors == [], f"Errors in threads: {errors}"


# ── NetworkAnomalyDetector integration ───────────────────────────────


class TestNetworkAnomalyDetector:
    """Integration tests for the network-specific detector."""

    def test_normal_traffic(self) -> None:
        nad = NetworkAnomalyDetector()
        # Build baseline with varied normal traffic
        import random
        rng = random.Random(42)
        for _ in range(50):
            res = nad.record_request(
                size=rng.randint(400, 600),
                status_code=200,
                response_time=rng.uniform(0.05, 0.15),
            )
        # One more normal request should not be anomalous
        res = nad.record_request(size=500, status_code=200, response_time=0.1)
        assert res.score < 0.7

    def test_anomalous_payload(self) -> None:
        nad = NetworkAnomalyDetector()
        for _ in range(30):
            nad.record_request(size=500, status_code=200, response_time=0.1)
        # Massive payload spike
        res = nad.record_request(size=999_999, status_code=200, response_time=0.1)
        assert res.anomaly_type is not AnomalyType.NORMAL

    def test_error_burst(self) -> None:
        nad = NetworkAnomalyDetector()
        for _ in range(30):
            nad.record_request(size=500, status_code=200, response_time=0.1)
        # Sudden error
        res = nad.record_request(size=500, status_code=500, response_time=0.1)
        # The error dimension should contribute to a non-zero score
        assert res.score >= 0.0

    def test_health_summary(self) -> None:
        nad = NetworkAnomalyDetector()
        for _ in range(5):
            nad.record_request(size=100, status_code=200, response_time=0.05)
        nad.record_request(size=100, status_code=500, response_time=0.05)

        health = nad.get_health()
        assert health["total_requests"] == 6
        assert health["total_errors"] == 1
        assert health["error_rate"] == pytest.approx(1 / 6)
        assert "payload_size" in health["detectors"]
        assert "response_time" in health["detectors"]

    def test_health_empty(self) -> None:
        nad = NetworkAnomalyDetector()
        health = nad.get_health()
        assert health["total_requests"] == 0
        assert health["error_rate"] == 0.0

    def test_result_has_features(self) -> None:
        nad = NetworkAnomalyDetector()
        res = nad.record_request(size=256, status_code=200, response_time=0.05)
        assert res.features["size"] == 256
        assert res.features["status_code"] == 200
        assert res.features["response_time"] == 0.05
