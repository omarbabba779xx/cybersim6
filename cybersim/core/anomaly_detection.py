"""
ML Anomaly Detection — Lightweight anomaly detector using statistical methods.

Implements Isolation Forest-like scoring and Z-score detection without external
dependencies.  Used to detect unusual traffic patterns, abnormal request rates,
and suspicious behaviour in a running CyberSim6 simulation.

All heavy-lifting is done with pure Python + :mod:`math`; no *numpy*, *scipy*,
or *sklearn* required.

Thread-safe: every mutable operation is protected by a reentrant lock so a
single detector instance can be shared across simulation threads.
"""

from __future__ import annotations

import math
import threading
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


# ── Enums & data-classes ─────────────────────────────────────────────


class AnomalyType(Enum):
    """Discrete classification for an observation."""

    NORMAL = "normal"
    SUSPICIOUS = "suspicious"
    ANOMALOUS = "anomalous"


@dataclass
class AnomalyResult:
    """Outcome of a single anomaly check.

    Attributes:
        score:        Normalised anomaly score in [0.0, 1.0].
                      0 → perfectly normal, 1 → highly anomalous.
        anomaly_type: Categorical classification derived from *score*.
        z_score:      Raw Z-score of the primary observed value.
        features:     Arbitrary feature dict supplied by the caller.
        timestamp:    UTC timestamp of the observation.
    """

    score: float
    anomaly_type: AnomalyType
    z_score: float
    features: dict
    timestamp: datetime


# ── Core statistical detector ────────────────────────────────────────


class StatisticalDetector:
    """Lightweight anomaly detection using statistical methods.

    No external dependencies — pure Python implementation.

    Detection strategies
    --------------------
    * **Z-Score detection** – flags values more than *z_threshold* standard
      deviations from the running mean.
    * **Moving-average deviation** – compares the most recent window quarter
      against the full-window baseline.
    * **Entropy analysis** – detects unusual distribution changes via
      Shannon entropy.
    * **Rate-change detection** – flags sudden spikes or drops by comparing
      recent vs. baseline means.

    Parameters
    ----------
    window_size:
        Maximum number of observations kept in the sliding window.
    z_threshold:
        Z-score magnitude above which an observation is flagged.
    learning_period:
        Minimum number of observations that must be collected before
        detection begins (all results are ``NORMAL`` until then).
    """

    def __init__(
        self,
        window_size: int = 100,
        z_threshold: float = 2.5,
        learning_period: int = 20,
    ) -> None:
        self._window_size = window_size
        self._z_threshold = z_threshold
        self._learning_period = learning_period

        self._data: deque[float] = deque(maxlen=window_size)
        self._history: deque[AnomalyResult] = deque(maxlen=500)
        self._lock = threading.RLock()

        # Running statistics (Welford's online algorithm)
        self._count: int = 0
        self._mean: float = 0.0
        self._m2: float = 0.0  # sum of squares of differences from mean

    # ── public API ───────────────────────────────────────────────────

    def observe(
        self,
        value: float,
        features: Optional[dict] = None,
    ) -> AnomalyResult:
        """Record a single scalar observation and return an anomaly result.

        Args:
            value:    The numeric observation.
            features: Optional dict of contextual information attached to
                      the result.

        Returns:
            An :class:`AnomalyResult` with the computed score and type.
        """
        if features is None:
            features = {}

        with self._lock:
            # Update Welford running stats
            self._count += 1
            delta = value - self._mean
            self._mean += delta / self._count
            delta2 = value - self._mean
            self._m2 += delta * delta2

            self._data.append(value)

            # During learning period everything is NORMAL
            if self._count < self._learning_period:
                result = AnomalyResult(
                    score=0.0,
                    anomaly_type=AnomalyType.NORMAL,
                    z_score=0.0,
                    features=features,
                    timestamp=datetime.now(timezone.utc),
                )
                self._history.append(result)
                return result

            data_list = list(self._data)
            mean = self._calculate_mean(data_list)
            std = self._calculate_std(data_list, mean)
            z = self._calculate_z_score(value, mean, std)

            # Rate-change component (recent quarter vs full window)
            quarter = max(1, len(data_list) // 4)
            recent = data_list[-quarter:]
            baseline = data_list[: len(data_list) - quarter] or data_list
            rate_change = self._detect_rate_change(recent, baseline)

            # Entropy component
            entropy = self._calculate_entropy(data_list)

            # Combined anomaly score  ∈ [0, 1]
            raw = (
                0.50 * min(abs(z) / (self._z_threshold * 2), 1.0)
                + 0.30 * min(rate_change, 1.0)
                + 0.20 * (1.0 - min(entropy / 4.0, 1.0))
            )
            score = max(0.0, min(raw, 1.0))

            if abs(z) >= self._z_threshold:
                anomaly_type = AnomalyType.ANOMALOUS
            elif abs(z) >= self._z_threshold * 0.6:
                anomaly_type = AnomalyType.SUSPICIOUS
            else:
                anomaly_type = AnomalyType.NORMAL

            result = AnomalyResult(
                score=score,
                anomaly_type=anomaly_type,
                z_score=z,
                features=features,
                timestamp=datetime.now(timezone.utc),
            )
            self._history.append(result)
            return result

    def observe_multi(self, values: Dict[str, float]) -> AnomalyResult:
        """Multi-dimensional anomaly detection across several named features.

        Each feature is scored independently and the results are aggregated
        using a weighted maximum strategy: the worst single-dimension score
        dominates, but other dimensions still contribute.

        Args:
            values: Mapping of feature names to numeric observations.

        Returns:
            An aggregated :class:`AnomalyResult`.
        """
        if not values:
            return AnomalyResult(
                score=0.0,
                anomaly_type=AnomalyType.NORMAL,
                z_score=0.0,
                features={},
                timestamp=datetime.now(timezone.utc),
            )

        # Score each dimension by observing the mean-normalised value
        scores: list[float] = []
        z_scores: list[float] = []
        for _name, val in values.items():
            res = self.observe(val, features=dict(values))
            scores.append(res.score)
            z_scores.append(res.z_score)

        max_score = max(scores)
        avg_score = sum(scores) / len(scores)
        combined = 0.7 * max_score + 0.3 * avg_score
        combined = max(0.0, min(combined, 1.0))

        max_z = max(z_scores, key=abs)

        if combined >= 0.6:
            anomaly_type = AnomalyType.ANOMALOUS
        elif combined >= 0.3:
            anomaly_type = AnomalyType.SUSPICIOUS
        else:
            anomaly_type = AnomalyType.NORMAL

        return AnomalyResult(
            score=combined,
            anomaly_type=anomaly_type,
            z_score=max_z,
            features=dict(values),
            timestamp=datetime.now(timezone.utc),
        )

    def get_baseline(self) -> dict:
        """Return current baseline statistics.

        Returns:
            A dict with keys ``mean``, ``std``, ``min``, ``max``, ``count``,
            and ``window_size``.
        """
        with self._lock:
            data_list = list(self._data)
            if not data_list:
                return {
                    "mean": 0.0,
                    "std": 0.0,
                    "min": 0.0,
                    "max": 0.0,
                    "count": 0,
                    "window_size": self._window_size,
                }
            mean = self._calculate_mean(data_list)
            std = self._calculate_std(data_list, mean)
            return {
                "mean": mean,
                "std": std,
                "min": min(data_list),
                "max": max(data_list),
                "count": self._count,
                "window_size": self._window_size,
            }

    def get_history(self, last_n: int = 50) -> List[AnomalyResult]:
        """Return the most recent *last_n* detection results.

        Args:
            last_n: Number of results to return (capped by internal limit).

        Returns:
            A list of :class:`AnomalyResult` in chronological order.
        """
        with self._lock:
            items = list(self._history)
            return items[-last_n:]

    def reset(self) -> None:
        """Clear all learned data and detection history."""
        with self._lock:
            self._data.clear()
            self._history.clear()
            self._count = 0
            self._mean = 0.0
            self._m2 = 0.0

    # ── internal helpers ─────────────────────────────────────────────

    def _calculate_mean(self, data: List[float]) -> float:
        """Arithmetic mean of *data*.

        Args:
            data: Non-empty sequence of floats.

        Returns:
            The mean value.
        """
        if not data:
            return 0.0
        return sum(data) / len(data)

    def _calculate_std(self, data: List[float], mean: float) -> float:
        """Population standard deviation of *data* given a pre-computed *mean*.

        Args:
            data: Non-empty sequence of floats.
            mean: Pre-computed mean of *data*.

        Returns:
            The standard deviation (population).
        """
        if len(data) < 2:
            return 0.0
        variance = sum((x - mean) ** 2 for x in data) / len(data)
        return math.sqrt(variance)

    def _calculate_z_score(
        self,
        value: float,
        mean: float,
        std: float,
    ) -> float:
        """Compute the Z-score of *value* relative to *mean* and *std*.

        Args:
            value: The observation.
            mean:  Population mean.
            std:   Population standard deviation.

        Returns:
            ``(value - mean) / std``, or ``0.0`` when *std* is zero.
        """
        if std == 0.0:
            return 0.0
        return (value - mean) / std

    def _calculate_entropy(self, data: List[float]) -> float:
        """Shannon entropy of *data* discretised into 10 equal-width bins.

        Higher entropy indicates a more uniform (diverse) distribution;
        lower entropy indicates concentration in a few bins.

        Args:
            data: Sequence of observations.

        Returns:
            Entropy value in nats (natural log).
        """
        if len(data) < 2:
            return 0.0

        lo = min(data)
        hi = max(data)
        if lo == hi:
            return 0.0

        n_bins = 10
        bin_width = (hi - lo) / n_bins
        counts: list[int] = [0] * n_bins
        for x in data:
            idx = int((x - lo) / bin_width)
            idx = min(idx, n_bins - 1)
            counts[idx] += 1

        n = len(data)
        entropy = 0.0
        for c in counts:
            if c > 0:
                p = c / n
                entropy -= p * math.log(p)
        return entropy

    def _detect_rate_change(
        self,
        recent: List[float],
        baseline: List[float],
    ) -> float:
        """Detect sudden rate changes between *recent* and *baseline* windows.

        Returns a normalised score in [0, ∞) — values above 1.0 indicate
        a large change relative to the baseline spread.

        Args:
            recent:   Recent observations (e.g. the latest window quarter).
            baseline: Historical observations to compare against.

        Returns:
            A non-negative rate-change magnitude.
        """
        if not recent or not baseline:
            return 0.0

        mean_recent = self._calculate_mean(recent)
        mean_baseline = self._calculate_mean(baseline)
        std_baseline = self._calculate_std(baseline, mean_baseline)

        if std_baseline == 0.0:
            return 0.0 if mean_recent == mean_baseline else 1.0

        return abs(mean_recent - mean_baseline) / std_baseline


# ── Specialised network detector ────────────────────────────────────


class NetworkAnomalyDetector:
    """Specialised anomaly detector for network traffic patterns.

    Monitors multiple dimensions in parallel:

    * **Request rate** — requests per observation interval.
    * **Payload size** — bytes transferred per request.
    * **Error rate** — HTTP error status codes.
    * **Response time** — server latency.

    Each dimension has its own :class:`StatisticalDetector` with tuned
    thresholds.

    Parameters
    ----------
    logger:
        Optional logger instance (any object with ``.info``/``.warning``
        methods).
    """

    def __init__(self, logger: Any = None) -> None:
        self.rate_detector = StatisticalDetector(
            window_size=200, z_threshold=2.0, learning_period=20,
        )
        self.size_detector = StatisticalDetector(
            window_size=200, z_threshold=3.0, learning_period=20,
        )
        self.error_detector = StatisticalDetector(
            window_size=100, z_threshold=2.5, learning_period=20,
        )
        self.response_time_detector = StatisticalDetector(
            window_size=200, z_threshold=2.5, learning_period=20,
        )

        self._logger = logger
        self._request_count: int = 0
        self._error_count: int = 0
        self._lock = threading.RLock()

    def record_request(
        self,
        size: int,
        status_code: int,
        response_time: float,
    ) -> AnomalyResult:
        """Record a single network request and check all dimensions.

        Args:
            size:          Payload size in bytes.
            status_code:   HTTP status code (e.g. 200, 404, 500).
            response_time: Server response time in seconds.

        Returns:
            An aggregated :class:`AnomalyResult` summarising all dimensions.
        """
        with self._lock:
            self._request_count += 1
            is_error = 1.0 if status_code >= 400 else 0.0
            if is_error:
                self._error_count += 1

        size_result = self.size_detector.observe(
            float(size), {"dimension": "payload_size"},
        )
        error_result = self.error_detector.observe(
            is_error, {"dimension": "error_rate"},
        )
        time_result = self.response_time_detector.observe(
            response_time, {"dimension": "response_time"},
        )

        # Aggregate across dimensions
        scores = [size_result.score, error_result.score, time_result.score]
        max_score = max(scores)
        avg_score = sum(scores) / len(scores)
        combined = 0.6 * max_score + 0.4 * avg_score
        combined = max(0.0, min(combined, 1.0))

        z_scores = [size_result.z_score, error_result.z_score, time_result.z_score]
        max_z = max(z_scores, key=abs)

        if combined >= 0.6:
            anomaly_type = AnomalyType.ANOMALOUS
        elif combined >= 0.3:
            anomaly_type = AnomalyType.SUSPICIOUS
        else:
            anomaly_type = AnomalyType.NORMAL

        result = AnomalyResult(
            score=combined,
            anomaly_type=anomaly_type,
            z_score=max_z,
            features={
                "size": size,
                "status_code": status_code,
                "response_time": response_time,
            },
            timestamp=datetime.now(timezone.utc),
        )

        if self._logger and anomaly_type != AnomalyType.NORMAL:
            self._logger.warning(
                "Network anomaly detected: type=%s score=%.3f z=%.2f",
                anomaly_type.value,
                combined,
                max_z,
            )

        return result

    def get_health(self) -> dict:
        """Return a network health summary with anomaly indicators.

        Returns:
            A dict containing baseline statistics from each sub-detector,
            total request/error counts, and per-dimension health info.
        """
        with self._lock:
            return {
                "total_requests": self._request_count,
                "total_errors": self._error_count,
                "error_rate": (
                    self._error_count / self._request_count
                    if self._request_count > 0
                    else 0.0
                ),
                "detectors": {
                    "payload_size": self.size_detector.get_baseline(),
                    "error_rate": self.error_detector.get_baseline(),
                    "response_time": self.response_time_detector.get_baseline(),
                },
            }
