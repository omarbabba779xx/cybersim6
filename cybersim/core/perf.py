"""
CyberSim6 - Performance Tracking
Timer decorator and PerfTracker for monitoring execution times.
"""

import time
import functools
from collections import defaultdict
from typing import Callable


def timer(func: Callable = None, *, name: str = None):
    """
    Decorator that measures execution time and prints it.
    Can be used as @timer or @timer(name='custom_name').
    """
    def decorator(fn):
        label = name or f"{fn.__module__}.{fn.__qualname__}"

        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            start = time.perf_counter()
            result = fn(*args, **kwargs)
            elapsed = time.perf_counter() - start
            PerfTracker.default().record(label, elapsed)
            return result

        wrapper._perf_label = label
        return wrapper

    if func is not None:
        # Called as @timer without arguments
        return decorator(func)
    return decorator


class PerfTracker:
    """Tracks min/max/avg execution times per operation."""

    _default: "PerfTracker" = None

    def __init__(self):
        self._data: dict[str, list[float]] = defaultdict(list)

    @classmethod
    def default(cls) -> "PerfTracker":
        if cls._default is None:
            cls._default = cls()
        return cls._default

    @classmethod
    def reset_default(cls):
        cls._default = cls()

    def record(self, operation: str, elapsed: float):
        """Record an elapsed time for an operation."""
        self._data[operation].append(elapsed)

    def stats(self, operation: str) -> dict:
        """Return min/max/avg/count for an operation."""
        times = self._data.get(operation, [])
        if not times:
            return {"operation": operation, "count": 0, "min": None, "max": None, "avg": None}
        return {
            "operation": operation,
            "count": len(times),
            "min": round(min(times), 6),
            "max": round(max(times), 6),
            "avg": round(sum(times) / len(times), 6),
        }

    def all_stats(self) -> list[dict]:
        """Return stats for all tracked operations."""
        return [self.stats(op) for op in self._data]

    def clear(self):
        """Clear all recorded data."""
        self._data.clear()

    def operations(self) -> list[str]:
        """Return list of tracked operation names."""
        return list(self._data.keys())
