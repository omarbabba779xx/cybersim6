"""Tests for cybersim.core.audit_trail module."""

import json
import threading

import pytest

from cybersim.core.audit_trail import AuditTrail, AuditEntry


class TestAuditTrail:
    """Suite of 8 tests covering the AuditTrail hash-chain."""

    # 1 — Empty chain is valid
    def test_empty_chain_is_valid(self) -> None:
        trail = AuditTrail()
        valid, idx = trail.verify_chain()
        assert valid is True
        assert idx == -1

    # 2 — Record creates linked entries
    def test_record_creates_entries(self) -> None:
        trail = AuditTrail()
        e1 = trail.record("login", actor="admin", module="auth")
        e2 = trail.record("scan", actor="admin", module="sqli")
        assert e1.index == 0
        assert e2.index == 1
        assert e2.previous_hash == e1.hash
        assert e1.previous_hash == "0"

    # 3 — Chain verifies after multiple records
    def test_chain_verifies_multiple_records(self) -> None:
        trail = AuditTrail()
        for i in range(10):
            trail.record(f"action_{i}", actor="bot", module="ddos")
        valid, idx = trail.verify_chain()
        assert valid is True
        assert idx == 9

    # 4 — Tampered entry breaks verification
    def test_tampered_entry_detected(self) -> None:
        trail = AuditTrail()
        trail.record("a", actor="x", module="m")
        trail.record("b", actor="x", module="m")
        trail.record("c", actor="x", module="m")

        # Tamper with the second entry's action
        trail._entries[1].action = "TAMPERED"

        valid, last_valid = trail.verify_chain()
        assert valid is False
        assert last_valid == 0  # entry 0 is OK; entry 1 is broken

    # 5 — get_entries filters by module
    def test_get_entries_filter_module(self) -> None:
        trail = AuditTrail()
        trail.record("a", actor="x", module="sqli")
        trail.record("b", actor="x", module="ddos")
        trail.record("c", actor="x", module="sqli")
        result = trail.get_entries(module="sqli")
        assert len(result) == 2
        assert all(e.module == "sqli" for e in result)

    # 6 — get_entries filters by actor
    def test_get_entries_filter_actor(self) -> None:
        trail = AuditTrail()
        trail.record("a", actor="admin", module="m")
        trail.record("b", actor="user", module="m")
        result = trail.get_entries(actor="admin")
        assert len(result) == 1
        assert result[0].actor == "admin"

    # 7 — export_json creates valid JSON
    def test_export_json(self, tmp_path) -> None:
        trail = AuditTrail()
        trail.record("login", actor="admin", module="auth", details={"ip": "10.0.0.1"})
        out = tmp_path / "audit.json"
        trail.export_json(str(out))
        assert out.exists()
        data = json.loads(out.read_text(encoding="utf-8"))
        assert len(data) == 1
        assert data[0]["action"] == "login"
        assert data[0]["details"]["ip"] == "10.0.0.1"

    # 8 — Thread-safe concurrent writes
    def test_concurrent_writes(self) -> None:
        trail = AuditTrail()
        errors: list[Exception] = []

        def writer(n: int) -> None:
            try:
                for i in range(20):
                    trail.record(f"action_{n}_{i}", actor=f"t{n}", module="stress")
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=writer, args=(t,)) for t in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        assert len(trail.get_entries()) == 100
        valid, _ = trail.verify_chain()
        assert valid is True
