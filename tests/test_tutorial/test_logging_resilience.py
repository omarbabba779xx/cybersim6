"""Resilience tests for tutorial logging hooks."""

from __future__ import annotations

from cybersim.tutorial.interactive import InteractiveTutorial


class _BrokenLogger:
    def log_event(self, **_kwargs):
        raise RuntimeError("logger unavailable")


def test_tutorial_survives_logger_failures(capsys):
    tutorial = InteractiveTutorial(logger=_BrokenLogger())

    result = tutorial.start_tutorial("ddos")
    captured = capsys.readouterr()

    assert result.module_name == "ddos"
    assert "Session logging unavailable" in captured.out
