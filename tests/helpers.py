"""Shared HTTP test helpers."""

from __future__ import annotations

import time

import requests as http_requests


def wait_for_http_ready(url: str, timeout: float = 5.0) -> None:
    """Wait until an HTTP endpoint accepts connections."""
    deadline = time.time() + timeout
    last_error: Exception | None = None
    while time.time() < deadline:
        try:
            http_requests.get(url, timeout=0.5, allow_redirects=False)
            return
        except http_requests.RequestException as exc:  # pragma: no cover - timing dependent
            last_error = exc
            time.sleep(0.05)
    raise RuntimeError(f"Endpoint did not become ready in time: {url}") from last_error
