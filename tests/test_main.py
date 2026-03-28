"""Tests for the ``python -m cybersim`` entrypoint."""

import runpy
import types


def test_module_entrypoint_calls_cli_main(monkeypatch):
    called = {"value": False}

    def fake_main():
        called["value"] = True

    monkeypatch.setitem(__import__("sys").modules, "cybersim.cli", types.SimpleNamespace(main=fake_main))

    runpy.run_module("cybersim", run_name="__main__")

    assert called["value"] is True
