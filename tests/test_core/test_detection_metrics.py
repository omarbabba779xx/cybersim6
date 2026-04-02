"""Tests for the detection metrics engine."""

from __future__ import annotations

from cybersim.core.detection_metrics import DetectionMetrics, MetricsReport


class TestMetricsReport:
    def test_empty_report(self):
        r = MetricsReport(module="test")
        assert r.total == 0
        assert r.precision == 0.0
        assert r.recall == 0.0
        assert r.f1_score == 0.0
        assert r.accuracy == 0.0

    def test_perfect_precision_recall(self):
        r = MetricsReport(module="test", true_positives=10, true_negatives=10)
        assert r.precision == 1.0
        assert r.recall == 1.0
        assert r.f1_score == 1.0
        assert r.accuracy == 1.0

    def test_only_false_positives(self):
        r = MetricsReport(module="test", false_positives=10, true_negatives=10)
        assert r.precision == 0.0
        assert r.recall == 0.0
        assert r.false_positive_rate == 0.5

    def test_to_dict_keys(self):
        r = MetricsReport(module="ddos", true_positives=5, false_positives=1, true_negatives=90, false_negatives=4)
        d = r.to_dict()
        assert "precision" in d
        assert "recall" in d
        assert "f1_score" in d
        assert d["module"] == "ddos"
        assert d["total_samples"] == 100


class TestDetectionMetrics:
    def test_record_and_get(self):
        m = DetectionMetrics()
        m.record(True, True, "ddos")
        m.record(True, False, "ddos")
        m.record(False, True, "ddos")
        m.record(False, False, "ddos")
        report = m.get_metrics("ddos")
        assert report.true_positives == 1
        assert report.false_positives == 1
        assert report.false_negatives == 1
        assert report.true_negatives == 1

    def test_batch_record(self):
        m = DetectionMetrics()
        m.record_batch([True, True, False], [True, False, False], module="xss")
        report = m.get_metrics("xss")
        assert report.true_positives == 1
        assert report.false_positives == 1
        assert report.true_negatives == 1

    def test_global_metrics(self):
        m = DetectionMetrics()
        m.record(True, True, "ddos")
        m.record(True, True, "sqli")
        report = m.get_metrics()
        assert report.true_positives == 2

    def test_all_module_metrics(self):
        m = DetectionMetrics()
        m.record(True, True, "ddos")
        m.record(True, True, "sqli")
        reports = m.get_all_module_metrics()
        assert len(reports) == 2

    def test_generate_report_not_empty(self):
        m = DetectionMetrics()
        m.record(True, True, "ddos")
        text = m.generate_report()
        assert "DETECTION PERFORMANCE METRICS" in text
        assert "ddos" in text

    def test_reset(self):
        m = DetectionMetrics()
        m.record(True, True, "test")
        m.reset()
        assert m.get_metrics().total == 0
