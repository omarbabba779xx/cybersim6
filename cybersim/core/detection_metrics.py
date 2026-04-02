"""
CyberSim6 - Detection Metrics Engine
Calculates Precision, Recall, F1-Score for attack detection evaluation.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class DetectionResult:
    """Single detection evaluation result."""
    predicted_attack: bool
    actual_attack: bool
    module: str = ""
    details: str = ""


@dataclass
class MetricsReport:
    """Aggregated metrics for a detection module or global."""
    module: str
    true_positives: int = 0
    false_positives: int = 0
    true_negatives: int = 0
    false_negatives: int = 0

    @property
    def total(self) -> int:
        return self.true_positives + self.false_positives + self.true_negatives + self.false_negatives

    @property
    def precision(self) -> float:
        denom = self.true_positives + self.false_positives
        return self.true_positives / denom if denom > 0 else 0.0

    @property
    def recall(self) -> float:
        denom = self.true_positives + self.false_negatives
        return self.true_positives / denom if denom > 0 else 0.0

    @property
    def f1_score(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) > 0 else 0.0

    @property
    def accuracy(self) -> float:
        return (self.true_positives + self.true_negatives) / self.total if self.total > 0 else 0.0

    @property
    def detection_rate(self) -> float:
        """Alias for recall - percentage of attacks detected."""
        return self.recall

    @property
    def false_positive_rate(self) -> float:
        denom = self.false_positives + self.true_negatives
        return self.false_positives / denom if denom > 0 else 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "module": self.module,
            "total_samples": self.total,
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "true_negatives": self.true_negatives,
            "false_negatives": self.false_negatives,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1_score": round(self.f1_score, 4),
            "accuracy": round(self.accuracy, 4),
            "detection_rate": round(self.detection_rate, 4),
            "false_positive_rate": round(self.false_positive_rate, 4),
        }


class DetectionMetrics:
    """Tracks and evaluates detection performance across modules."""

    def __init__(self) -> None:
        self._results: list[DetectionResult] = []

    def record(self, predicted: bool, actual: bool, module: str = "global", details: str = "") -> None:
        """Record a single detection evaluation."""
        self._results.append(DetectionResult(
            predicted_attack=predicted,
            actual_attack=actual,
            module=module,
            details=details,
        ))

    def record_batch(self, predictions: list[bool], actuals: list[bool], module: str = "global") -> None:
        """Record a batch of detection evaluations."""
        for pred, actual in zip(predictions, actuals):
            self.record(pred, actual, module)

    def get_metrics(self, module: str | None = None) -> MetricsReport:
        """Get metrics for a specific module or all modules."""
        results = self._results
        if module:
            results = [r for r in results if r.module == module]

        report = MetricsReport(module=module or "global")
        for r in results:
            if r.predicted_attack and r.actual_attack:
                report.true_positives += 1
            elif r.predicted_attack and not r.actual_attack:
                report.false_positives += 1
            elif not r.predicted_attack and not r.actual_attack:
                report.true_negatives += 1
            else:
                report.false_negatives += 1
        return report

    def get_all_module_metrics(self) -> list[MetricsReport]:
        """Get metrics for each module that has recorded results."""
        modules = sorted(set(r.module for r in self._results))
        return [self.get_metrics(m) for m in modules]

    def generate_report(self) -> str:
        """Generate a formatted text report of all metrics."""
        lines = [
            "",
            "  ╔══════════════════════════════════════════════════════════════════╗",
            "  ║              DETECTION PERFORMANCE METRICS                      ║",
            "  ╚══════════════════════════════════════════════════════════════════╝",
            "",
            f"  {'Module':<15} {'Prec':>7} {'Recall':>7} {'F1':>7} {'Acc':>7} {'TP':>5} {'FP':>5} {'TN':>5} {'FN':>5}",
            "  " + "─" * 66,
        ]

        all_metrics = self.get_all_module_metrics()
        for m in all_metrics:
            lines.append(
                f"  {m.module:<15} {m.precision:>7.1%} {m.recall:>7.1%} "
                f"{m.f1_score:>7.1%} {m.accuracy:>7.1%} "
                f"{m.true_positives:>5} {m.false_positives:>5} "
                f"{m.true_negatives:>5} {m.false_negatives:>5}"
            )

        # Global summary
        g = self.get_metrics()
        lines.extend([
            "  " + "─" * 66,
            f"  {'GLOBAL':<15} {g.precision:>7.1%} {g.recall:>7.1%} "
            f"{g.f1_score:>7.1%} {g.accuracy:>7.1%} "
            f"{g.true_positives:>5} {g.false_positives:>5} "
            f"{g.true_negatives:>5} {g.false_negatives:>5}",
            "",
        ])

        return "\n".join(lines)

    def reset(self) -> None:
        """Clear all recorded results."""
        self._results.clear()
