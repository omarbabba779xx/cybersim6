"""
Attack Chaining -- Multi-stage APT (Advanced Persistent Threat) scenarios.

Chains multiple attack modules to simulate realistic cyber kill chains.
Based on the Lockheed Martin Cyber Kill Chain and MITRE ATT&CK framework.

Each scenario walks through a sequence of :class:`ChainStep` objects, printing
coloured progress banners and logging every phase through the unified
:class:`~cybersim.core.logging_engine.CyberSimLogger`.  The scenarios do
**not** start real attack servers; instead they simulate the chain logically
using detection / analysis components so that the *concept* of attack chaining
is demonstrated end-to-end.
"""

from __future__ import annotations

import time
from abc import ABC
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from cybersim.core.logging_engine import CyberSimLogger


# ---------------------------------------------------------------------------
# ANSI helpers (mirrors cybersim.demo style)
# ---------------------------------------------------------------------------

R = "\033[91m"
G = "\033[92m"
Y = "\033[93m"
B = "\033[94m"
M = "\033[95m"
C = "\033[96m"
W = "\033[97m"
D = "\033[2m"
BOLD = "\033[1m"
RST = "\033[0m"

_PHASE_COLOURS: dict[str, str] = {
    "reconnaissance": C,
    "weaponization": M,
    "delivery": Y,
    "exploitation": R,
    "installation": R,
    "command_and_control": B,
    "actions_on_objectives": G,
}


# ---------------------------------------------------------------------------
# Kill-chain data model
# ---------------------------------------------------------------------------

class KillChainPhase(Enum):
    """Phases of the Lockheed Martin Cyber Kill Chain."""

    RECONNAISSANCE = "reconnaissance"
    WEAPONIZATION = "weaponization"
    DELIVERY = "delivery"
    EXPLOITATION = "exploitation"
    INSTALLATION = "installation"
    COMMAND_CONTROL = "command_and_control"
    ACTIONS = "actions_on_objectives"


@dataclass
class ChainStep:
    """A single step in an attack scenario.

    Attributes:
        phase: Kill-chain phase this step belongs to.
        module: Name of the CyberSim6 module used (e.g. ``"port_scanner"``).
        description: Human-readable explanation of what happens.
        config: Parameters forwarded to the simulated module.
        success_condition: Plain-English description of what counts as success.
        mitre_technique: MITRE ATT&CK technique ID (e.g. ``"T1046"``).
    """

    phase: KillChainPhase
    module: str
    description: str
    config: dict[str, Any] = field(default_factory=dict)
    success_condition: str = ""
    mitre_technique: str = ""


@dataclass
class ChainResult:
    """Structured result returned after running a full scenario.

    Attributes:
        scenario_name: Display name of the scenario.
        steps_completed: How many steps finished successfully.
        steps_total: Total number of steps in the chain.
        success: ``True`` when every step completed.
        timeline: Ordered list of per-step records with timing.
        mitre_techniques: Aggregated MITRE ATT&CK technique IDs.
        duration_seconds: Wall-clock time for the entire scenario.
    """

    scenario_name: str
    steps_completed: int
    steps_total: int
    success: bool
    timeline: list[dict[str, Any]] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)
    duration_seconds: float = 0.0


# ---------------------------------------------------------------------------
# Base scenario
# ---------------------------------------------------------------------------

class AttackScenario(ABC):
    """Base class for multi-stage attack scenarios.

    Subclasses must populate :pyattr:`name`, :pyattr:`description`,
    :pyattr:`difficulty`, and :pyattr:`kill_chain` and may override
    :meth:`_simulate_step` for custom per-step logic.
    """

    name: str = ""
    description: str = ""
    difficulty: str = "medium"  # easy | medium | hard
    kill_chain: list[ChainStep] = []

    def describe(self) -> str:
        """Return a multi-line human-readable description of the scenario."""
        lines: list[str] = [
            f"{BOLD}{self.name}{RST}",
            f"{D}{self.description}{RST}",
            f"Difficulty: {self.difficulty}",
            f"Steps ({len(self.kill_chain)}):",
        ]
        for i, step in enumerate(self.kill_chain, 1):
            colour = _PHASE_COLOURS.get(step.phase.value, W)
            lines.append(
                f"  {i}. {colour}{step.phase.value:<25}{RST} "
                f"[{step.module}] {step.description}"
            )
        return "\n".join(lines)

    # -- execution -----------------------------------------------------------

    def run(self, logger: CyberSimLogger) -> ChainResult:
        """Execute every step in the kill chain sequentially.

        Args:
            logger: The unified CyberSim logger for event recording.

        Returns:
            A :class:`ChainResult` summarising the run.
        """
        timeline: list[dict[str, Any]] = []
        mitre: list[str] = []
        steps_completed = 0
        t0 = time.monotonic()

        logger.log_event(
            module="scenario",
            module_type="attack",
            event_type="scenario_started",
            details={"scenario": self.name, "steps": len(self.kill_chain)},
        )

        self._print_banner()

        for idx, step in enumerate(self.kill_chain, 1):
            step_t0 = time.monotonic()
            colour = _PHASE_COLOURS.get(step.phase.value, W)

            print(
                f"\n  {colour}{BOLD}[Step {idx}/{len(self.kill_chain)}]{RST} "
                f"{colour}{step.phase.value}{RST}  {D}-- {step.description}{RST}"
            )

            # Simulate the step
            success, details = self._simulate_step(step, logger)

            elapsed = time.monotonic() - step_t0
            record = {
                "step": idx,
                "phase": step.phase.value,
                "module": step.module,
                "description": step.description,
                "success": success,
                "duration_seconds": round(elapsed, 4),
                "details": details,
            }
            timeline.append(record)

            if step.mitre_technique:
                mitre.append(step.mitre_technique)

            logger.log_event(
                module="scenario",
                module_type="attack",
                event_type="chain_step_completed",
                details=record,
            )

            if success:
                steps_completed += 1
                print(f"    {G}[+] Step {idx} completed{RST}  {D}({elapsed:.2f}s){RST}")
            else:
                print(f"    {R}[-] Step {idx} failed{RST}  {D}({elapsed:.2f}s){RST}")
                break  # chain is broken

        total_time = time.monotonic() - t0
        all_ok = steps_completed == len(self.kill_chain)

        self._print_summary(steps_completed, all_ok, total_time)

        logger.log_event(
            module="scenario",
            module_type="attack",
            event_type="scenario_finished",
            details={
                "scenario": self.name,
                "success": all_ok,
                "steps_completed": steps_completed,
                "duration_seconds": round(total_time, 4),
            },
        )

        return ChainResult(
            scenario_name=self.name,
            steps_completed=steps_completed,
            steps_total=len(self.kill_chain),
            success=all_ok,
            timeline=timeline,
            mitre_techniques=mitre,
            duration_seconds=round(total_time, 4),
        )

    # -- simulation hook (override for custom behaviour) ---------------------

    def _simulate_step(
        self, step: ChainStep, logger: CyberSimLogger
    ) -> tuple[bool, dict[str, Any]]:
        """Simulate a single kill-chain step.

        The default implementation logs the step and returns success.
        Subclasses may override this for richer simulation logic.

        Returns:
            ``(success, details)`` tuple.
        """
        # Small delay to make console output readable
        time.sleep(0.05)
        return True, {"simulated": True, "module": step.module}

    # -- pretty-printing helpers ---------------------------------------------

    def _print_banner(self) -> None:
        """Print a coloured scenario header."""
        border = "=" * 56
        print(
            f"\n  {M}{BOLD}{border}{RST}"
            f"\n  {M}{BOLD}  SCENARIO: {self.name}{RST}"
            f"\n  {D}  {self.description}{RST}"
            f"\n  {D}  Difficulty: {self.difficulty}  |  "
            f"Steps: {len(self.kill_chain)}{RST}"
            f"\n  {M}{BOLD}{border}{RST}"
        )

    def _print_summary(
        self, completed: int, success: bool, duration: float
    ) -> None:
        """Print a coloured end-of-scenario summary."""
        status_colour = G if success else R
        status_text = "SUCCESS" if success else "PARTIAL"
        print(
            f"\n  {D}{'- ' * 28}{RST}"
            f"\n  {status_colour}{BOLD}  Result: {status_text}  "
            f"({completed}/{len(self.kill_chain)} steps){RST}"
            f"\n  {D}  Duration: {duration:.2f}s{RST}"
        )


# ---------------------------------------------------------------------------
# Concrete APT scenarios
# ---------------------------------------------------------------------------

class APTScenario1_DataBreach(AttackScenario):
    """Corporate Data Breach scenario.

    Kill Chain: Recon -> Phishing -> SQLi -> BruteForce -> Ransomware

    1. Port scan to find open services
    2. Phishing campaign to get initial access
    3. SQL Injection to extract credentials
    4. Brute force with extracted info
    5. Ransomware deployment on compromised system
    """

    name = "Corporate Data Breach"
    description = (
        "Full APT lifecycle: reconnaissance through data exfiltration "
        "and ransomware deployment."
    )
    difficulty = "hard"

    kill_chain = [
        ChainStep(
            phase=KillChainPhase.RECONNAISSANCE,
            module="port_scanner",
            description="Port scan target to discover open services",
            config={"ports": "1-1024", "target": "127.0.0.1"},
            success_condition="At least one open port found",
            mitre_technique="T1046",
        ),
        ChainStep(
            phase=KillChainPhase.DELIVERY,
            module="phishing",
            description="Phishing campaign targeting employees for initial access",
            config={"template": "corporate_login", "targets": 50},
            success_condition="At least one credential captured",
            mitre_technique="T1566.001",
        ),
        ChainStep(
            phase=KillChainPhase.EXPLOITATION,
            module="sqli",
            description="SQL Injection to extract database credentials",
            config={"attack_type": "union", "target_url": "http://127.0.0.1:8081"},
            success_condition="Database credentials extracted",
            mitre_technique="T1190",
        ),
        ChainStep(
            phase=KillChainPhase.EXPLOITATION,
            module="bruteforce",
            description="Brute force admin panel with extracted credentials",
            config={"username": "admin", "max_attempts": 100},
            success_condition="Valid admin password found",
            mitre_technique="T1110.001",
        ),
        ChainStep(
            phase=KillChainPhase.INSTALLATION,
            module="ransomware",
            description="Deploy ransomware on compromised system",
            config={"sandbox_only": True, "algorithm": "AES-256"},
            success_condition="Files encrypted in sandbox",
            mitre_technique="T1486",
        ),
    ]


class APTScenario2_WebCompromise(AttackScenario):
    """Web Application Compromise scenario.

    Kill Chain: Recon -> XSS -> SQLi -> Privilege Escalation

    1. Port scan to find web services
    2. XSS attack to steal session tokens
    3. SQL Injection to dump database
    4. Brute force admin credentials
    """

    name = "Web Application Compromise"
    description = (
        "Targeted web application attack: XSS session hijacking "
        "followed by database exfiltration."
    )
    difficulty = "medium"

    kill_chain = [
        ChainStep(
            phase=KillChainPhase.RECONNAISSANCE,
            module="port_scanner",
            description="Scan for web services on common ports",
            config={"ports": "80,443,8080,8443", "target": "127.0.0.1"},
            success_condition="Web server port discovered",
            mitre_technique="T1046",
        ),
        ChainStep(
            phase=KillChainPhase.EXPLOITATION,
            module="xss",
            description="Reflected XSS to steal session tokens",
            config={"attack_type": "reflected", "target_url": "http://127.0.0.1:8082"},
            success_condition="Session token captured via XSS payload",
            mitre_technique="T1059.007",
        ),
        ChainStep(
            phase=KillChainPhase.EXPLOITATION,
            module="sqli",
            description="SQL Injection to dump user database",
            config={"attack_type": "union", "target_url": "http://127.0.0.1:8081"},
            success_condition="User table dumped successfully",
            mitre_technique="T1190",
        ),
        ChainStep(
            phase=KillChainPhase.ACTIONS,
            module="bruteforce",
            description="Brute force admin credentials from dumped hashes",
            config={"username": "admin", "max_attempts": 50},
            success_condition="Admin credentials cracked",
            mitre_technique="T1110.002",
        ),
    ]


class APTScenario3_RansomwareAttack(AttackScenario):
    """Targeted Ransomware Attack scenario.

    Kill Chain: Phishing -> BruteForce -> DDoS (smokescreen) -> Ransomware

    1. Phishing campaign targeting employees
    2. Brute force discovered credentials
    3. DDoS as a smokescreen distraction
    4. Ransomware deployment
    """

    name = "Targeted Ransomware Attack"
    description = (
        "Ransomware delivery with DDoS smokescreen: phishing for entry, "
        "credential brute-forcing, then encrypt-and-extort."
    )
    difficulty = "hard"

    kill_chain = [
        ChainStep(
            phase=KillChainPhase.DELIVERY,
            module="phishing",
            description="Spear-phishing campaign targeting key employees",
            config={"template": "urgent_update", "targets": 25},
            success_condition="Employee credentials captured",
            mitre_technique="T1566.002",
        ),
        ChainStep(
            phase=KillChainPhase.EXPLOITATION,
            module="bruteforce",
            description="Brute force internal services with captured creds",
            config={"username": "svc_admin", "max_attempts": 200},
            success_condition="Service account compromised",
            mitre_technique="T1110.001",
        ),
        ChainStep(
            phase=KillChainPhase.COMMAND_CONTROL,
            module="ddos",
            description="DDoS smokescreen to distract security operations",
            config={"target_url": "http://127.0.0.1:8080", "request_count": 500},
            success_condition="SOC diverted to DDoS incident",
            mitre_technique="T1498",
        ),
        ChainStep(
            phase=KillChainPhase.INSTALLATION,
            module="ransomware",
            description="Deploy ransomware across compromised hosts",
            config={"sandbox_only": True, "algorithm": "AES-256"},
            success_condition="Target files encrypted",
            mitre_technique="T1486",
        ),
    ]


# ---------------------------------------------------------------------------
# Scenario runner
# ---------------------------------------------------------------------------

class ScenarioRunner:
    """Execute and manage attack scenarios.

    Attributes:
        SCENARIOS: Registry mapping short names to scenario classes.
    """

    SCENARIOS: dict[str, type[AttackScenario]] = {
        "data_breach": APTScenario1_DataBreach,
        "web_compromise": APTScenario2_WebCompromise,
        "ransomware_attack": APTScenario3_RansomwareAttack,
    }

    def __init__(self, logger: CyberSimLogger) -> None:
        self._logger = logger

    def list_scenarios(self) -> list[dict[str, Any]]:
        """Return metadata for every registered scenario.

        Returns:
            List of dicts with keys ``name``, ``key``, ``description``,
            ``difficulty``, and ``steps``.
        """
        result: list[dict[str, Any]] = []
        for key, cls in self.SCENARIOS.items():
            scenario = cls()
            result.append({
                "key": key,
                "name": scenario.name,
                "description": scenario.description,
                "difficulty": scenario.difficulty,
                "steps": len(scenario.kill_chain),
            })
        return result

    def run_scenario(self, name: str) -> ChainResult:
        """Run a single scenario by its short key.

        Args:
            name: One of the keys in :pyattr:`SCENARIOS`.

        Returns:
            The :class:`ChainResult` for the completed scenario.

        Raises:
            ValueError: If *name* is not a registered scenario key.
        """
        if name not in self.SCENARIOS:
            raise ValueError(
                f"Unknown scenario '{name}'. "
                f"Available: {list(self.SCENARIOS.keys())}"
            )
        scenario = self.SCENARIOS[name]()
        return scenario.run(self._logger)

    def run_all(self) -> list[ChainResult]:
        """Run every registered scenario in order.

        Returns:
            A list of :class:`ChainResult` objects, one per scenario.
        """
        results: list[ChainResult] = []
        for key in self.SCENARIOS:
            results.append(self.run_scenario(key))
        return results
