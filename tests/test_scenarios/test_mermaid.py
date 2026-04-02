"""Tests for Mermaid diagram generation."""

from __future__ import annotations

from cybersim.core.logging_engine import CyberSimLogger
from cybersim.scenarios.attack_chain import ScenarioRunner, APTScenario1_DataBreach


class TestMermaidGeneration:
    def test_generate_mermaid_for_scenario(self):
        scenario = APTScenario1_DataBreach()
        mermaid = ScenarioRunner.generate_mermaid(scenario)
        assert "graph LR" in mermaid
        assert "port_scanner" in mermaid
        assert "T1046" in mermaid

    def test_generate_all_diagrams(self, tmp_path):
        logger = CyberSimLogger(log_dir=tmp_path, session_id="test")
        runner = ScenarioRunner(logger)
        diagrams = runner.generate_all_diagrams()
        assert len(diagrams) == 3
        for key, mermaid in diagrams.items():
            assert "graph LR" in mermaid
