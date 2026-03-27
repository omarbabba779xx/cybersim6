"""Tests for the Interactive Tutorial module."""

import pytest

from cybersim.tutorial.interactive import (
    InteractiveTutorial,
    TutorialModule,
    TutorialResult,
    TutorialStep,
)


EXPECTED_MODULES = {"ddos", "sqli", "xss", "bruteforce", "phishing", "ransomware"}


class TestTutorialModuleCatalogue:
    """Verify that all six tutorial modules are registered and well-formed."""

    def setup_method(self) -> None:
        self.tutorial = InteractiveTutorial()

    # 1 -- all six modules exist
    def test_all_six_modules_exist(self) -> None:
        assert set(InteractiveTutorial.MODULES.keys()) == EXPECTED_MODULES

    # 2 -- list_modules returns exactly 6 entries
    def test_list_modules_returns_six(self) -> None:
        modules = self.tutorial.list_modules()
        assert len(modules) == 6

    # 3 -- list_modules entries contain expected keys
    def test_list_modules_entry_keys(self) -> None:
        entry = self.tutorial.list_modules()[0]
        for key in (
            "key", "name", "description", "difficulty",
            "estimated_time", "steps_count", "prerequisites",
        ):
            assert key in entry, f"Missing key '{key}' in list_modules entry"

    # 4 -- get_module returns correct module
    def test_get_module_returns_correct(self) -> None:
        mod = self.tutorial.get_module("ddos")
        assert isinstance(mod, TutorialModule)
        assert mod.name == "DDoS Attack & Defense"

    # 5 -- unknown module raises KeyError
    def test_get_module_unknown_raises(self) -> None:
        with pytest.raises(KeyError, match="Unknown tutorial module"):
            self.tutorial.get_module("nonexistent")


class TestTutorialModuleStructure:
    """Ensure every module has valid steps and metadata."""

    def setup_method(self) -> None:
        self.tutorial = InteractiveTutorial()

    # 6 -- every module has at least 3 steps
    @pytest.mark.parametrize("key", sorted(EXPECTED_MODULES))
    def test_module_has_steps(self, key: str) -> None:
        mod = self.tutorial.get_module(key)
        assert isinstance(mod.steps, list)
        assert len(mod.steps) >= 3, f"Module '{key}' has fewer than 3 steps"

    # 7 -- every module has required metadata
    @pytest.mark.parametrize("key", sorted(EXPECTED_MODULES))
    def test_module_metadata(self, key: str) -> None:
        mod = self.tutorial.get_module(key)
        assert mod.name, "Module name must not be empty"
        assert mod.description, "Module description must not be empty"
        assert mod.difficulty in {"beginner", "intermediate", "advanced"}
        assert mod.estimated_time, "estimated_time must not be empty"
        assert isinstance(mod.prerequisites, list)


class TestTutorialStepStructure:
    """Validate that every step in every module is fully populated."""

    def setup_method(self) -> None:
        self.tutorial = InteractiveTutorial()

    # 8 -- every step has all required fields populated
    @pytest.mark.parametrize("key", sorted(EXPECTED_MODULES))
    def test_step_fields_populated(self, key: str) -> None:
        mod = self.tutorial.get_module(key)
        for idx, step in enumerate(mod.steps):
            assert isinstance(step, TutorialStep), (
                f"Step {idx} in '{key}' is not a TutorialStep"
            )
            assert step.title, f"Step {idx} in '{key}' has empty title"
            assert step.explanation, f"Step {idx} in '{key}' has empty explanation"
            assert step.action, f"Step {idx} in '{key}' has empty action"
            assert step.mitre_technique, (
                f"Step {idx} in '{key}' has empty mitre_technique"
            )
            assert step.defense_tip, f"Step {idx} in '{key}' has empty defense_tip"

    # 9 -- every step has quiz question AND answer
    @pytest.mark.parametrize("key", sorted(EXPECTED_MODULES))
    def test_quiz_question_and_answer_present(self, key: str) -> None:
        mod = self.tutorial.get_module(key)
        for idx, step in enumerate(mod.steps):
            assert step.quiz_question, (
                f"Step {idx} in '{key}' missing quiz_question"
            )
            assert step.quiz_answer, (
                f"Step {idx} in '{key}' missing quiz_answer"
            )


class TestTutorialExecution:
    """Test running a tutorial end-to-end."""

    def setup_method(self) -> None:
        self.tutorial = InteractiveTutorial()

    # 10 -- start_tutorial returns a TutorialResult
    def test_start_tutorial_returns_result(self) -> None:
        result = self.tutorial.start_tutorial("ddos")
        assert isinstance(result, TutorialResult)

    # 11 -- result has correct module name and step count
    def test_result_fields(self) -> None:
        result = self.tutorial.start_tutorial("ddos")
        assert result.module_name == "ddos"
        mod = self.tutorial.get_module("ddos")
        assert result.steps_completed == len(mod.steps)
        assert result.quiz_total > 0
        assert result.quiz_score <= result.quiz_total
        assert result.duration_seconds >= 0

    # 12 -- start_tutorial with unknown module raises KeyError
    def test_start_tutorial_unknown_raises(self) -> None:
        with pytest.raises(KeyError):
            self.tutorial.start_tutorial("nonexistent")

    def test_start_tutorial_logs_completion_event(self, logger) -> None:
        tutorial = InteractiveTutorial(logger=logger)
        tutorial.start_tutorial("ddos")

        assert logger.events, "Tutorial should emit at least one event"
        event = logger.events[-1]
        assert event["module"] == "tutorial_ddos"
        assert event["module_type"] == "education"
        assert event["event_type"] == "tutorial_completed"
