"""CLI dispatch regression tests."""

from __future__ import annotations

import sys

import pytest

from cybersim import cli


class _DummyLogger:
    """Minimal logger stub for CLI dispatch tests."""

    def __init__(self) -> None:
        self.session_id = "dispatch"
        self.events = []

    def export_json(self, *_args, **_kwargs):
        return "unused.json"

    def export_csv(self, *_args, **_kwargs):
        return "unused.csv"


@pytest.mark.parametrize(
    ("argv", "handler_name"),
    [
        (["cybersim", "waf"], "_handle_waf"),
        (["cybersim", "scanner"], "_handle_scanner"),
        (["cybersim", "honeypot"], "_handle_honeypot"),
        (["cybersim", "tutorial"], "_handle_tutorial"),
        (["cybersim", "scenario"], "_handle_scenario"),
        (["cybersim", "report", "--session", "abc123"], "_handle_report"),
        (["cybersim", "compliance"], "_handle_compliance"),
        (["cybersim", "analyze-password", "--password", "StrongPass1!"], "_handle_password"),
    ],
)
def test_cli_dispatches_new_modules(monkeypatch, argv, handler_name):
    """Every registered top-level module should route to its dedicated handler."""
    called = {"value": None}

    monkeypatch.setattr(cli, "load_config", lambda *_args, **_kwargs: {"general": {"log_dir": "."}})
    monkeypatch.setattr(cli, "CyberSimLogger", lambda *args, **kwargs: _DummyLogger())
    monkeypatch.setattr(
        cli,
        handler_name,
        lambda *args, **kwargs: called.__setitem__("value", handler_name),
    )
    monkeypatch.setattr(sys, "argv", argv)

    cli.main()

    assert called["value"] == handler_name
