"""
CyberSim6 - HTTP Flood Simulation
Simulates an HTTP Flood attack using concurrent requests on localhost only.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

import requests as http_requests

from cybersim.core.base_module import BaseModule
from cybersim.core.safety import validate_url_localhost


class HTTPFloodAttack(BaseModule):
    """HTTP Flood attack simulation using ThreadPoolExecutor."""

    MODULE_TYPE = "attack"
    MODULE_NAME = "ddos_http_flood"

    def _validate_safety(self) -> None:
        url = self.config.get("target_url", "http://127.0.0.1:8080")
        validate_url_localhost(url)

    def _send_request(self, url: str, request_id: int) -> dict[str, Any]:
        """Send a single HTTP request."""
        try:
            resp = http_requests.get(url, timeout=5)
            return {"id": request_id, "status_code": resp.status_code, "success": True}
        except http_requests.RequestException as e:
            return {"id": request_id, "status_code": 0, "success": False, "error": str(e)}

    def run(
        self,
        target_url: str | None = None,
        request_count: int | None = None,
        threads: int | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """
        Launch HTTP Flood simulation.

        Args:
            target_url: URL to flood (must be localhost)
            request_count: Total number of requests
            threads: Number of concurrent threads
        """
        target_url = target_url or self.config.get("target_url", "http://127.0.0.1:8080")
        request_count = request_count or self.config.get("request_count", 500)
        threads = threads or self.config.get("threads", 4)

        validate_url_localhost(target_url)

        self._running = True
        self.log_event("attack_started", {
            "message": f"HTTP Flood started -> {target_url} ({request_count} requests, {threads} threads)",
            "target": target_url,
            "request_count": request_count,
            "threads": threads,
            "status": "warning",
        })

        success_count = 0
        fail_count = 0

        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {}
            for i in range(request_count):
                if not self._running:
                    break
                future = executor.submit(self._send_request, target_url, i)
                futures[future] = i

            for future in as_completed(futures):
                if not self._running:
                    break
                result = future.result()
                if result["success"]:
                    success_count += 1
                else:
                    fail_count += 1

                total = success_count + fail_count
                if total % 100 == 0:
                    self.log_event("progress", {
                        "message": f"Sent {total}/{request_count} requests ({success_count} OK, {fail_count} failed)",
                        "status": "info",
                    })

        self._running = False
        self.log_event("attack_completed", {
            "message": f"HTTP Flood completed. {success_count} successful, {fail_count} failed.",
            "target": target_url,
            "success_count": success_count,
            "fail_count": fail_count,
            "status": "info",
        })
        return {
            "target": target_url,
            "request_count": request_count,
            "success_count": success_count,
            "fail_count": fail_count,
        }

    def stop(self) -> None:
        """Stop the HTTP Flood attack."""
        self._running = False
        self.log_event("attack_stopped", {
            "message": "HTTP Flood stopped by user.",
            "status": "info",
        })
