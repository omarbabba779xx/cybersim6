"""Runtime tests for the dictionary attack module."""

from __future__ import annotations

from pathlib import Path

from cybersim.bruteforce.auth_server import AuthServer
from cybersim.bruteforce.dictionary_attack import DictionaryAttack
from tests.helpers import wait_for_http_ready


def test_dictionary_attack_finds_password(logger, tmp_path):
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("guest\nletmein\nadmin123\n", encoding="utf-8")

    server = AuthServer(port=0, logger=logger, credentials={"admin": "letmein"})
    server.start()
    target_url = f"http://{server.host}:{server.port}/login"
    wait_for_http_ready(target_url)

    try:
        attack = DictionaryAttack(
            config={"target_url": target_url, "username": "admin", "wordlist": str(wordlist), "delay_ms": 0},
            logger=logger,
        )
        found = attack.run(max_attempts=5, delay_ms=0)
    finally:
        server.stop()

    assert found == "letmein"
    assert logger.get_events(module="bruteforce_dictionary", event_type="credential_found")


def test_dictionary_attack_reports_missing_wordlist(logger, tmp_path):
    missing_path = Path(tmp_path / "missing.txt")
    attack = DictionaryAttack(
        config={"target_url": "http://127.0.0.1:9090/login", "wordlist": str(missing_path)},
        logger=logger,
    )

    result = attack.run(wordlist=str(missing_path))

    assert result is None
    assert logger.get_events(module="bruteforce_dictionary", event_type="error")
