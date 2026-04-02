"""
CyberSim6 - Incident Response Engine
NIST SP 800-61 guided incident response workflow.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from cybersim.core.logging_engine import CyberSimLogger


class IRPhase(Enum):
    PREPARATION = "preparation"
    IDENTIFICATION = "identification"
    CONTAINMENT = "containment"
    ERADICATION = "eradication"
    RECOVERY = "recovery"
    LESSONS_LEARNED = "lessons_learned"


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# Map severity to maximum response time in minutes (SLA)
SLA_TARGETS = {
    Severity.CRITICAL: 15,
    Severity.HIGH: 30,
    Severity.MEDIUM: 60,
    Severity.LOW: 240,
    Severity.INFO: 480,
}

# Attack type classification keywords
ATTACK_SIGNATURES = {
    "ddos": {"keywords": ["ddos", "flood", "syn_flood", "http_flood", "rate"], "severity": Severity.HIGH, "mitre": "T1498/T1499"},
    "sqli": {"keywords": ["sqli", "sql", "injection", "union", "blind"], "severity": Severity.CRITICAL, "mitre": "T1190"},
    "xss": {"keywords": ["xss", "script", "reflected", "stored", "dom"], "severity": Severity.HIGH, "mitre": "T1204"},
    "bruteforce": {"keywords": ["bruteforce", "brute_force", "dictionary", "login_failed"], "severity": Severity.MEDIUM, "mitre": "T1110"},
    "phishing": {"keywords": ["phishing", "credential", "campaign"], "severity": Severity.HIGH, "mitre": "T1566"},
    "ransomware": {"keywords": ["ransomware", "encrypt", "ransom", "locked"], "severity": Severity.CRITICAL, "mitre": "T1486"},
}

# Remediation playbooks per attack type
PLAYBOOKS = {
    "ddos": {
        "containment": ["Enable rate limiting on affected endpoints", "Activate WAF DDoS rules", "Block offending source IPs", "Enable traffic scrubbing"],
        "eradication": ["Analyze traffic patterns for bot signatures", "Update firewall rules with identified patterns", "Verify no backdoor was installed during attack"],
        "recovery": ["Gradually restore normal rate limits", "Monitor for attack resumption", "Verify service availability and performance"],
    },
    "sqli": {
        "containment": ["Disable affected endpoints immediately", "Activate WAF SQL injection rules", "Revoke compromised database sessions", "Isolate affected database"],
        "eradication": ["Patch vulnerable queries with parameterized statements", "Audit all SQL queries for injection vectors", "Check for exfiltrated data", "Rotate database credentials"],
        "recovery": ["Re-enable endpoints with patched code", "Run integrity checks on database", "Monitor for new injection attempts", "Verify data integrity"],
    },
    "xss": {
        "containment": ["Enable Content-Security-Policy headers", "Activate WAF XSS rules", "Sanitize stored malicious content", "Invalidate affected user sessions"],
        "eradication": ["Implement input validation on all endpoints", "Add output encoding", "Remove stored XSS payloads from database", "Audit all user-facing endpoints"],
        "recovery": ["Deploy sanitized application", "Clear browser caches via headers", "Monitor for new XSS attempts", "Verify CSP effectiveness"],
    },
    "bruteforce": {
        "containment": ["Lock targeted accounts temporarily", "Enable CAPTCHA on login", "Block source IPs with excessive failures", "Enable account lockout policy"],
        "eradication": ["Force password reset on targeted accounts", "Implement progressive delays", "Audit for compromised accounts", "Check for credential stuffing patterns"],
        "recovery": ["Unlock accounts after password reset", "Monitor login patterns", "Verify MFA enrollment", "Check for unauthorized access during attack window"],
    },
    "phishing": {
        "containment": ["Block phishing URLs at proxy/firewall", "Quarantine phishing emails", "Disable compromised credentials", "Alert affected users"],
        "eradication": ["Take down phishing infrastructure", "Reset all potentially compromised passwords", "Scan for malware from phishing links", "Update email filters"],
        "recovery": ["Restore user access with new credentials", "Conduct user awareness training", "Monitor for follow-up attacks", "Verify email filter effectiveness"],
    },
    "ransomware": {
        "containment": ["Isolate affected systems immediately", "Disable network shares", "Preserve forensic evidence", "Identify encryption scope"],
        "eradication": ["Remove ransomware binary and persistence", "Scan all systems for indicators of compromise", "Patch exploitation vector", "Verify backup integrity"],
        "recovery": ["Restore from clean backups", "Rebuild compromised systems", "Gradually reconnect to network", "Monitor for re-infection"],
    },
}


@dataclass
class TimelineEntry:
    """Single entry in the incident timeline."""
    timestamp: datetime
    phase: IRPhase
    action: str
    details: str = ""
    automated: bool = False


@dataclass
class Incident:
    """Represents a security incident under investigation."""
    incident_id: str = ""
    attack_types: list[str] = field(default_factory=list)
    severity: Severity = Severity.INFO
    mitre_techniques: list[str] = field(default_factory=list)
    affected_modules: list[str] = field(default_factory=list)
    total_events: int = 0
    attack_events: int = 0
    detection_events: int = 0
    start_time: datetime | None = None
    current_phase: IRPhase = IRPhase.PREPARATION
    timeline: list[TimelineEntry] = field(default_factory=list)
    sla_minutes: int = 15
    resolved: bool = False

    def elapsed_minutes(self) -> float:
        if not self.start_time:
            return 0.0
        delta = datetime.now(timezone.utc) - self.start_time
        return delta.total_seconds() / 60.0

    def sla_remaining(self) -> float:
        return max(0.0, self.sla_minutes - self.elapsed_minutes())

    def sla_breached(self) -> bool:
        return self.elapsed_minutes() > self.sla_minutes


class IncidentResponse:
    """NIST SP 800-61 guided incident response engine."""

    def __init__(self, logger: CyberSimLogger, events: list[dict] | None = None) -> None:
        self.logger = logger
        self.events = events or logger.events
        self.incident = Incident()

    def analyze(self) -> Incident:
        """Phase 1-2: Analyze events to identify and classify the incident."""
        self.incident.start_time = datetime.now(timezone.utc)
        self.incident.incident_id = f"IR-{int(time.time())}"
        self.incident.total_events = len(self.events)

        # Classify attack types from events
        attack_types_found: dict[str, int] = {}
        modules_seen: set[str] = set()

        for event in self.events:
            event_type = event.get("event_type", "").lower()
            module = event.get("module", "").lower()
            status = event.get("details", {}).get("status", "")
            modules_seen.add(module)

            if status == "warning" or "detected" in event_type or "attack" in event_type:
                self.incident.attack_events += 1

            if "detect" in event_type:
                self.incident.detection_events += 1

            for attack_name, sig in ATTACK_SIGNATURES.items():
                if any(kw in event_type or kw in module for kw in sig["keywords"]):
                    attack_types_found[attack_name] = attack_types_found.get(attack_name, 0) + 1

        self.incident.attack_types = sorted(attack_types_found, key=attack_types_found.get, reverse=True)
        self.incident.affected_modules = sorted(modules_seen)

        # Determine severity from worst attack type found
        if self.incident.attack_types:
            worst = Severity.INFO
            techniques: list[str] = []
            for at in self.incident.attack_types:
                sig = ATTACK_SIGNATURES[at]
                if list(Severity).index(sig["severity"]) < list(Severity).index(worst):
                    worst = sig["severity"]
                techniques.append(sig["mitre"])
            self.incident.severity = worst
            self.incident.mitre_techniques = techniques
            self.incident.sla_minutes = SLA_TARGETS[worst]

        self._add_timeline(IRPhase.IDENTIFICATION, "Incident classified",
                           f"Types: {', '.join(self.incident.attack_types) or 'none'} | "
                           f"Severity: {self.incident.severity.value} | "
                           f"Events: {self.incident.total_events}")

        self.incident.current_phase = IRPhase.IDENTIFICATION
        self.logger.log_event("ir_analysis_complete", "incident_response", {
            "incident_id": self.incident.incident_id,
            "attack_types": self.incident.attack_types,
            "severity": self.incident.severity.value,
            "status": "info",
        })

        return self.incident

    def get_playbook(self, phase: IRPhase) -> list[str]:
        """Get recommended actions for a given phase based on detected attack types."""
        actions: list[str] = []
        phase_key = {
            IRPhase.CONTAINMENT: "containment",
            IRPhase.ERADICATION: "eradication",
            IRPhase.RECOVERY: "recovery",
        }.get(phase)

        if not phase_key:
            return actions

        for attack_type in self.incident.attack_types:
            playbook = PLAYBOOKS.get(attack_type, {})
            phase_actions = playbook.get(phase_key, [])
            for action in phase_actions:
                if action not in actions:
                    actions.append(action)
        return actions

    def execute_phase(self, phase: IRPhase) -> list[str]:
        """Execute a phase of the IR workflow and return actions taken."""
        self.incident.current_phase = phase
        actions = self.get_playbook(phase)

        self._add_timeline(phase, f"Phase started: {phase.value}",
                           f"{len(actions)} actions planned")

        for action in actions:
            self._add_timeline(phase, action, automated=True)
            self.logger.log_event(f"ir_{phase.value}", "incident_response", {
                "action": action,
                "incident_id": self.incident.incident_id,
                "phase": phase.value,
                "status": "info",
            })

        self._add_timeline(phase, f"Phase completed: {phase.value}",
                           f"{len(actions)} actions executed")
        return actions

    def run(self) -> dict[str, Any]:
        """Run full IR workflow: analyze -> contain -> eradicate -> recover -> lessons learned."""
        # Phase 1-2: Identification
        self.analyze()

        if not self.incident.attack_types:
            return self._build_report()

        # Phase 3: Containment
        self.execute_phase(IRPhase.CONTAINMENT)

        # Phase 4: Eradication
        self.execute_phase(IRPhase.ERADICATION)

        # Phase 5: Recovery
        self.execute_phase(IRPhase.RECOVERY)

        # Phase 6: Lessons Learned
        self.incident.current_phase = IRPhase.LESSONS_LEARNED
        self.incident.resolved = True
        lessons = self._generate_lessons()
        self._add_timeline(IRPhase.LESSONS_LEARNED, "Post-incident review completed", lessons)

        self.logger.log_event("ir_complete", "incident_response", {
            "incident_id": self.incident.incident_id,
            "resolved": True,
            "phases_completed": 6,
            "sla_breached": self.incident.sla_breached(),
            "elapsed_minutes": round(self.incident.elapsed_minutes(), 2),
            "status": "info",
        })

        return self._build_report()

    def _generate_lessons(self) -> str:
        """Generate lessons learned summary."""
        lessons = []
        for at in self.incident.attack_types:
            sig = ATTACK_SIGNATURES.get(at, {})
            lessons.append(f"Attack '{at}' (MITRE {sig.get('mitre', 'N/A')}) successfully contained and eradicated")

        if self.incident.sla_breached():
            lessons.append(f"SLA BREACHED: Response took {self.incident.elapsed_minutes():.1f}min (target: {self.incident.sla_minutes}min)")
        else:
            lessons.append(f"SLA MET: Response completed in {self.incident.elapsed_minutes():.1f}min (target: {self.incident.sla_minutes}min)")

        lessons.append(f"Detection coverage: {self.incident.detection_events}/{self.incident.attack_events} attack events detected")
        return " | ".join(lessons)

    def _add_timeline(self, phase: IRPhase, action: str, details: str = "", automated: bool = False) -> None:
        self.incident.timeline.append(TimelineEntry(
            timestamp=datetime.now(timezone.utc),
            phase=phase,
            action=action,
            details=details,
            automated=automated,
        ))

    def _build_report(self) -> dict[str, Any]:
        return {
            "incident_id": self.incident.incident_id,
            "severity": self.incident.severity.value,
            "attack_types": self.incident.attack_types,
            "mitre_techniques": self.incident.mitre_techniques,
            "total_events": self.incident.total_events,
            "attack_events": self.incident.attack_events,
            "detection_events": self.incident.detection_events,
            "affected_modules": self.incident.affected_modules,
            "sla_minutes": self.incident.sla_minutes,
            "elapsed_minutes": round(self.incident.elapsed_minutes(), 2),
            "sla_breached": self.incident.sla_breached(),
            "resolved": self.incident.resolved,
            "phases_completed": len(set(e.phase for e in self.incident.timeline)),
            "actions_taken": len([e for e in self.incident.timeline if e.automated]),
            "timeline": [
                {
                    "timestamp": e.timestamp.isoformat(),
                    "phase": e.phase.value,
                    "action": e.action,
                    "details": e.details,
                }
                for e in self.incident.timeline
            ],
        }

    def generate_text_report(self) -> str:
        """Generate a formatted text report."""
        report = self._build_report()
        lines = [
            "",
            "  ╔══════════════════════════════════════════════════════════════════╗",
            "  ║              INCIDENT RESPONSE REPORT                           ║",
            "  ╚══════════════════════════════════════════════════════════════════╝",
            "",
            f"  Incident ID   : {report['incident_id']}",
            f"  Severity      : {report['severity'].upper()}",
            f"  Attack Types  : {', '.join(report['attack_types']) or 'none detected'}",
            f"  MITRE Techniques : {', '.join(report['mitre_techniques']) or 'N/A'}",
            f"  Total Events  : {report['total_events']}",
            f"  Attack Events : {report['attack_events']}",
            f"  Detections    : {report['detection_events']}",
            f"  SLA Target    : {report['sla_minutes']} min",
            f"  Elapsed       : {report['elapsed_minutes']} min",
            f"  SLA Status    : {'BREACHED' if report['sla_breached'] else 'MET'}",
            f"  Resolved      : {'Yes' if report['resolved'] else 'No'}",
            f"  Actions Taken : {report['actions_taken']}",
            "",
            "  Timeline:",
            "  " + "─" * 66,
        ]
        for entry in report["timeline"]:
            phase_tag = f"[{entry['phase']:<18}]"
            lines.append(f"    {phase_tag} {entry['action']}")
            if entry["details"]:
                lines.append(f"    {'':>20} {entry['details']}")
        lines.append("")
        return "\n".join(lines)
