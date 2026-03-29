"""Tests for the Attack Chaining / APT Scenario system."""

import pytest

from cybersim.core.logging_engine import CyberSimLogger
from cybersim.scenarios.attack_chain import (
    APTScenario1_DataBreach,
    APTScenario2_WebCompromise,
    APTScenario3_RansomwareAttack,
    ChainResult,
    ChainStep,
    KillChainPhase,
    ScenarioRunner,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_logger(tmp_path) -> CyberSimLogger:
    return CyberSimLogger(log_dir=tmp_path, session_id="test_scenario")


# ---------------------------------------------------------------------------
# KillChainPhase
# ---------------------------------------------------------------------------

class TestKillChainPhase:
    """Tests for the KillChainPhase enum."""

    def test_phase_values(self) -> None:
        """All seven kill-chain phases should be present."""
        assert len(KillChainPhase) == 7

    def test_phase_ordering(self) -> None:
        """Phases should be declared in logical kill-chain order."""
        phases = list(KillChainPhase)
        assert phases[0] is KillChainPhase.RECONNAISSANCE
        assert phases[1] is KillChainPhase.WEAPONIZATION
        assert phases[2] is KillChainPhase.DELIVERY
        assert phases[3] is KillChainPhase.EXPLOITATION
        assert phases[4] is KillChainPhase.INSTALLATION
        assert phases[5] is KillChainPhase.COMMAND_CONTROL
        assert phases[6] is KillChainPhase.ACTIONS


# ---------------------------------------------------------------------------
# ChainStep / ChainResult data structures
# ---------------------------------------------------------------------------

class TestChainStep:
    """Tests for the ChainStep dataclass."""

    def test_creation_with_defaults(self) -> None:
        """A step should be constructable with only required fields."""
        step = ChainStep(
            phase=KillChainPhase.RECONNAISSANCE,
            module="port_scanner",
            description="Scan ports",
        )
        assert step.phase is KillChainPhase.RECONNAISSANCE
        assert step.module == "port_scanner"
        assert step.config == {}
        assert step.success_condition == ""
        assert step.mitre_technique == ""

    def test_creation_with_all_fields(self) -> None:
        """A step should store every field correctly."""
        step = ChainStep(
            phase=KillChainPhase.EXPLOITATION,
            module="sqli",
            description="Union-based injection",
            config={"attack_type": "union"},
            success_condition="Credentials extracted",
            mitre_technique="T1190",
        )
        assert step.config["attack_type"] == "union"
        assert step.mitre_technique == "T1190"


class TestChainResult:
    """Tests for the ChainResult dataclass."""

    def test_default_values(self) -> None:
        """ChainResult should have sensible defaults for list/float fields."""
        result = ChainResult(
            scenario_name="test",
            steps_completed=0,
            steps_total=3,
            success=False,
        )
        assert result.timeline == []
        assert result.mitre_techniques == []
        assert result.duration_seconds == 0.0

    def test_full_construction(self) -> None:
        """ChainResult should store all provided values."""
        result = ChainResult(
            scenario_name="Test Scenario",
            steps_completed=3,
            steps_total=3,
            success=True,
            timeline=[{"step": 1}],
            mitre_techniques=["T1046"],
            duration_seconds=1.23,
        )
        assert result.success is True
        assert result.steps_completed == result.steps_total
        assert len(result.timeline) == 1
        assert "T1046" in result.mitre_techniques


# ---------------------------------------------------------------------------
# Scenario structure tests
# ---------------------------------------------------------------------------

class TestAPTScenario1_DataBreach:
    """Tests for the Corporate Data Breach scenario."""

    def test_has_correct_phase_count(self) -> None:
        """Data Breach scenario should have 5 kill-chain steps."""
        scenario = APTScenario1_DataBreach()
        assert len(scenario.kill_chain) == 5

    def test_starts_with_reconnaissance(self) -> None:
        """First phase should be reconnaissance."""
        scenario = APTScenario1_DataBreach()
        assert scenario.kill_chain[0].phase is KillChainPhase.RECONNAISSANCE

    def test_ends_with_installation(self) -> None:
        """Last phase should be ransomware installation."""
        scenario = APTScenario1_DataBreach()
        assert scenario.kill_chain[-1].phase is KillChainPhase.INSTALLATION
        assert scenario.kill_chain[-1].module == "ransomware"

    def test_mitre_techniques_populated(self) -> None:
        """Every step should map to a MITRE ATT&CK technique."""
        scenario = APTScenario1_DataBreach()
        for step in scenario.kill_chain:
            assert step.mitre_technique, f"Step '{step.description}' has no MITRE ID"

    def test_difficulty_is_hard(self) -> None:
        """Data breach is a hard scenario."""
        scenario = APTScenario1_DataBreach()
        assert scenario.difficulty == "hard"

    def test_run_returns_chain_result(self, tmp_path) -> None:
        """Running the scenario should produce a valid ChainResult."""
        logger = _make_logger(tmp_path)
        scenario = APTScenario1_DataBreach()
        result = scenario.run(logger)

        assert isinstance(result, ChainResult)
        assert result.scenario_name == "Corporate Data Breach"
        assert result.steps_total == 5
        assert result.steps_completed == 5
        assert result.success is True
        assert result.duration_seconds > 0
        assert len(result.timeline) == 5
        assert len(result.mitre_techniques) == 5


class TestAPTScenario2_WebCompromise:
    """Tests for the Web Application Compromise scenario."""

    def test_has_correct_phase_count(self) -> None:
        """Web Compromise should have 4 steps."""
        scenario = APTScenario2_WebCompromise()
        assert len(scenario.kill_chain) == 4

    def test_includes_xss_and_sqli(self) -> None:
        """Scenario must use both XSS and SQLi modules."""
        scenario = APTScenario2_WebCompromise()
        modules = [step.module for step in scenario.kill_chain]
        assert "xss" in modules
        assert "sqli" in modules

    def test_difficulty_is_medium(self) -> None:
        """Web compromise is a medium scenario."""
        scenario = APTScenario2_WebCompromise()
        assert scenario.difficulty == "medium"

    def test_ends_with_actions_phase(self) -> None:
        """Last step should be actions-on-objectives."""
        scenario = APTScenario2_WebCompromise()
        assert scenario.kill_chain[-1].phase is KillChainPhase.ACTIONS


class TestAPTScenario3_RansomwareAttack:
    """Tests for the Targeted Ransomware Attack scenario."""

    def test_has_correct_phase_count(self) -> None:
        """Ransomware scenario should have 4 steps."""
        scenario = APTScenario3_RansomwareAttack()
        assert len(scenario.kill_chain) == 4

    def test_includes_ddos_smokescreen(self) -> None:
        """Scenario must include a DDoS smokescreen step."""
        scenario = APTScenario3_RansomwareAttack()
        ddos_steps = [s for s in scenario.kill_chain if s.module == "ddos"]
        assert len(ddos_steps) == 1
        assert ddos_steps[0].phase is KillChainPhase.COMMAND_CONTROL

    def test_ends_with_ransomware(self) -> None:
        """Last step should deploy ransomware."""
        scenario = APTScenario3_RansomwareAttack()
        assert scenario.kill_chain[-1].module == "ransomware"

    def test_starts_with_phishing(self) -> None:
        """First step should be a phishing delivery."""
        scenario = APTScenario3_RansomwareAttack()
        assert scenario.kill_chain[0].phase is KillChainPhase.DELIVERY
        assert scenario.kill_chain[0].module == "phishing"


# ---------------------------------------------------------------------------
# Describe output
# ---------------------------------------------------------------------------

class TestDescribeOutput:
    """Tests for the scenario describe() method."""

    def test_describe_contains_name(self) -> None:
        """describe() output should include the scenario name."""
        scenario = APTScenario1_DataBreach()
        text = scenario.describe()
        assert "Corporate Data Breach" in text

    def test_describe_contains_steps(self) -> None:
        """describe() output should list every step."""
        scenario = APTScenario2_WebCompromise()
        text = scenario.describe()
        # Should reference each module
        assert "port_scanner" in text
        assert "xss" in text
        assert "sqli" in text
        assert "bruteforce" in text

    def test_describe_contains_difficulty(self) -> None:
        """describe() output should show the difficulty level."""
        scenario = APTScenario3_RansomwareAttack()
        text = scenario.describe()
        assert "hard" in text


# ---------------------------------------------------------------------------
# ScenarioRunner
# ---------------------------------------------------------------------------

class TestScenarioRunner:
    """Tests for the ScenarioRunner."""

    def test_list_scenarios_returns_all_three(self, tmp_path) -> None:
        """list_scenarios() should return metadata for all 3 scenarios."""
        runner = ScenarioRunner(logger=_make_logger(tmp_path))
        scenarios = runner.list_scenarios()

        assert len(scenarios) == 3
        keys = {s["key"] for s in scenarios}
        assert keys == {"data_breach", "web_compromise", "ransomware_attack"}

    def test_list_scenarios_structure(self, tmp_path) -> None:
        """Each item in list_scenarios() should have the expected keys."""
        runner = ScenarioRunner(logger=_make_logger(tmp_path))
        for item in runner.list_scenarios():
            assert "key" in item
            assert "name" in item
            assert "description" in item
            assert "difficulty" in item
            assert "steps" in item
            assert isinstance(item["steps"], int)

    def test_run_single_scenario(self, tmp_path) -> None:
        """run_scenario() should execute and return a ChainResult."""
        runner = ScenarioRunner(logger=_make_logger(tmp_path))
        result = runner.run_scenario("web_compromise")

        assert isinstance(result, ChainResult)
        assert result.success is True
        assert result.steps_total == 4

    def test_run_unknown_scenario_raises(self, tmp_path) -> None:
        """run_scenario() with a bad key should raise ValueError."""
        runner = ScenarioRunner(logger=_make_logger(tmp_path))
        with pytest.raises(ValueError, match="Unknown scenario"):
            runner.run_scenario("nonexistent_scenario")

    def test_run_all_returns_three_results(self, tmp_path) -> None:
        """run_all() should return one ChainResult per scenario."""
        runner = ScenarioRunner(logger=_make_logger(tmp_path))
        results = runner.run_all()

        assert len(results) == 3
        assert all(isinstance(r, ChainResult) for r in results)
        assert all(r.success for r in results)

    def test_run_logs_events(self, tmp_path) -> None:
        """Running a scenario should produce logger events."""
        logger = _make_logger(tmp_path)
        runner = ScenarioRunner(logger=logger)
        runner.run_scenario("data_breach")

        scenario_events = [
            e for e in logger.events if e.get("module") == "scenario"
        ]
        # At minimum: scenario_started + 5 chain_step_completed + scenario_finished
        assert len(scenario_events) >= 7
