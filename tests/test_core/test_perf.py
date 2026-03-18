"""Tests for cybersim.core.perf — timer decorator and PerfTracker."""
import time
import pytest
from cybersim.core.perf import timer, PerfTracker


@pytest.fixture(autouse=True)
def reset_default():
    PerfTracker.reset_default()
    yield
    PerfTracker.reset_default()


class TestPerfTracker:
    def test_record_and_stats(self):
        t = PerfTracker()
        t.record("op_a", 0.1)
        t.record("op_a", 0.3)
        s = t.stats("op_a")
        assert s["count"] == 2
        assert s["min"] == pytest.approx(0.1, abs=1e-6)
        assert s["max"] == pytest.approx(0.3, abs=1e-6)
        assert s["avg"] == pytest.approx(0.2, abs=1e-6)

    def test_unknown_operation_returns_none(self):
        t = PerfTracker()
        s = t.stats("nonexistent")
        assert s["count"] == 0
        assert s["min"] is None
        assert s["max"] is None
        assert s["avg"] is None

    def test_all_stats_returns_all(self):
        t = PerfTracker()
        t.record("a", 0.01)
        t.record("b", 0.02)
        all_s = t.all_stats()
        ops = {s["operation"] for s in all_s}
        assert "a" in ops
        assert "b" in ops

    def test_clear(self):
        t = PerfTracker()
        t.record("x", 0.5)
        t.clear()
        assert t.stats("x")["count"] == 0

    def test_operations_list(self):
        t = PerfTracker()
        t.record("alpha", 0.1)
        t.record("beta", 0.2)
        assert set(t.operations()) == {"alpha", "beta"}

    def test_default_singleton(self):
        a = PerfTracker.default()
        b = PerfTracker.default()
        assert a is b

    def test_reset_default_creates_new(self):
        a = PerfTracker.default()
        PerfTracker.reset_default()
        b = PerfTracker.default()
        assert a is not b

    def test_single_value_min_max_avg_equal(self):
        t = PerfTracker()
        t.record("solo", 0.42)
        s = t.stats("solo")
        assert s["min"] == s["max"] == s["avg"]


class TestTimerDecorator:
    def test_timer_records_to_default(self):
        @timer
        def slow():
            time.sleep(0.01)

        slow()
        s = PerfTracker.default().stats(slow._perf_label)
        assert s["count"] == 1
        assert s["min"] >= 0.005  # at least some time passed

    def test_timer_with_custom_name(self):
        @timer(name="my_custom_op")
        def fast():
            return 42

        result = fast()
        assert result == 42
        s = PerfTracker.default().stats("my_custom_op")
        assert s["count"] == 1

    def test_timer_preserves_return_value(self):
        @timer
        def add(a, b):
            return a + b

        assert add(3, 4) == 7

    def test_timer_multiple_calls_accumulate(self):
        @timer(name="multi")
        def noop():
            pass

        for _ in range(5):
            noop()
        assert PerfTracker.default().stats("multi")["count"] == 5

    def test_timer_preserves_function_name(self):
        @timer
        def my_func():
            pass

        assert my_func.__name__ == "my_func"

    def test_timer_with_args_and_kwargs(self):
        @timer
        def greet(name, greeting="Hello"):
            return f"{greeting}, {name}!"

        result = greet("Omar", greeting="Hi")
        assert result == "Hi, Omar!"
