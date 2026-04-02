"""
CyberSim6 - Digital Forensics Analyzer
Timeline reconstruction, hash verification, and chain of custody tracking.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cybersim.core.logging_engine import CyberSimLogger


@dataclass
class EvidenceItem:
    """A piece of digital evidence with chain of custody."""
    evidence_id: str
    source: str
    description: str
    sha256_hash: str
    collected_at: datetime
    collected_by: str = "CyberSim6 Forensics"
    chain_of_custody: list[dict[str, str]] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)

    def add_custody_entry(self, action: str, handler: str = "CyberSim6") -> None:
        self.chain_of_custody.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "handler": handler,
        })

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "source": self.source,
            "description": self.description,
            "sha256_hash": self.sha256_hash,
            "collected_at": self.collected_at.isoformat(),
            "collected_by": self.collected_by,
            "chain_of_custody": self.chain_of_custody,
            "tags": self.tags,
        }


@dataclass
class TimelineEvent:
    """A single event in the forensic timeline."""
    timestamp: str
    module: str
    event_type: str
    description: str
    severity: str = "info"
    indicators: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "module": self.module,
            "event_type": self.event_type,
            "description": self.description,
            "severity": self.severity,
            "indicators": self.indicators,
        }


class ForensicAnalyzer:
    """Digital forensics analysis engine for CyberSim6."""

    def __init__(self, logger: CyberSimLogger, events: list[dict] | None = None) -> None:
        self.logger = logger
        self.events = events or logger.events
        self.evidence: list[EvidenceItem] = []
        self.timeline: list[TimelineEvent] = []
        self._evidence_counter = 0

    # ── Timeline Reconstruction ────────────────────────────────────────

    def reconstruct_timeline(self) -> list[TimelineEvent]:
        """Reconstruct a chronological timeline from all events."""
        self.timeline.clear()

        for event in self.events:
            ts = event.get("timestamp", "")
            module = event.get("module", "unknown")
            event_type = event.get("event_type", "unknown")
            details = event.get("details", {})
            message = details.get("message", event_type)
            status = details.get("status", "info")

            # Determine indicators of compromise (IOC)
            iocs: list[str] = []
            if "detected" in event_type.lower():
                iocs.append("detection_trigger")
            if status == "warning":
                iocs.append("warning_status")
            if "attack" in event_type.lower():
                iocs.append("attack_activity")
            if "failed" in message.lower():
                iocs.append("failed_attempt")
            if any(kw in message.lower() for kw in ["injection", "xss", "flood", "brute"]):
                iocs.append("known_attack_pattern")

            severity = "info"
            if status == "warning" or iocs:
                severity = "warning"
            if "detected" in event_type and any(
                kw in event_type for kw in ["sqli", "xss", "ddos", "ransomware"]
            ):
                severity = "critical"

            self.timeline.append(TimelineEvent(
                timestamp=ts,
                module=module,
                event_type=event_type,
                description=message,
                severity=severity,
                indicators=iocs,
            ))

        # Sort by timestamp
        self.timeline.sort(key=lambda e: e.timestamp)

        self.logger.log_event("forensic_timeline_built", "forensics", {
            "total_events": len(self.timeline),
            "critical_events": sum(1 for e in self.timeline if e.severity == "critical"),
            "warning_events": sum(1 for e in self.timeline if e.severity == "warning"),
            "status": "info",
        })

        return self.timeline

    # ── Evidence Collection ────────────────────────────────────────────

    def collect_log_evidence(self, log_path: Path | None = None) -> EvidenceItem:
        """Collect event logs as forensic evidence with hash verification."""
        self._evidence_counter += 1
        evidence_id = f"EVD-{self._evidence_counter:04d}"

        # Serialize events for hashing
        content = json.dumps(self.events, indent=2, default=str)
        sha256 = hashlib.sha256(content.encode("utf-8")).hexdigest()

        source = str(log_path) if log_path else "in-memory event log"

        evidence = EvidenceItem(
            evidence_id=evidence_id,
            source=source,
            description=f"CyberSim6 session event log ({len(self.events)} events)",
            sha256_hash=sha256,
            collected_at=datetime.now(timezone.utc),
            tags=["event_log", "session_data"],
        )
        evidence.add_custody_entry("Evidence collected and hashed")

        self.evidence.append(evidence)
        return evidence

    def collect_file_evidence(self, file_path: Path) -> EvidenceItem | None:
        """Collect a file as forensic evidence with SHA-256 hash."""
        if not file_path.exists():
            return None

        self._evidence_counter += 1
        evidence_id = f"EVD-{self._evidence_counter:04d}"

        sha256 = hashlib.sha256(file_path.read_bytes()).hexdigest()

        evidence = EvidenceItem(
            evidence_id=evidence_id,
            source=str(file_path),
            description=f"File evidence: {file_path.name} ({file_path.stat().st_size} bytes)",
            sha256_hash=sha256,
            collected_at=datetime.now(timezone.utc),
            tags=["file_evidence", file_path.suffix.lstrip(".")],
        )
        evidence.add_custody_entry("File evidence collected and hashed")

        self.evidence.append(evidence)
        return evidence

    def verify_evidence_integrity(self, evidence: EvidenceItem) -> bool:
        """Verify that evidence has not been tampered with."""
        if evidence.source == "in-memory event log":
            content = json.dumps(self.events, indent=2, default=str)
            current_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
        else:
            path = Path(evidence.source)
            if not path.exists():
                return False
            current_hash = hashlib.sha256(path.read_bytes()).hexdigest()

        is_valid = current_hash == evidence.sha256_hash
        evidence.add_custody_entry(
            f"Integrity verification: {'PASSED' if is_valid else 'FAILED'}"
        )
        return is_valid

    # ── IOC Extraction ─────────────────────────────────────────────────

    def extract_iocs(self) -> dict[str, list[str]]:
        """Extract Indicators of Compromise from events."""
        iocs: dict[str, list[str]] = {
            "attack_types": [],
            "source_ips": [],
            "target_endpoints": [],
            "payloads": [],
            "timestamps_of_interest": [],
        }

        for event in self.events:
            event_type = event.get("event_type", "")
            details = event.get("details", {})

            # Attack types
            if "detected" in event_type:
                attack = event_type.replace("_detected", "").replace("detected_", "")
                if attack and attack not in iocs["attack_types"]:
                    iocs["attack_types"].append(attack)

            # Source IPs
            source_ip = details.get("source_ip", details.get("source", ""))
            if source_ip and source_ip not in iocs["source_ips"]:
                iocs["source_ips"].append(source_ip)

            # Endpoints
            endpoint = details.get("endpoint", details.get("url", ""))
            if endpoint and endpoint not in iocs["target_endpoints"]:
                iocs["target_endpoints"].append(endpoint)

            # Payloads (truncated)
            payload = details.get("sql", details.get("input", details.get("payload", "")))
            if payload:
                truncated = payload[:100]
                if truncated not in iocs["payloads"]:
                    iocs["payloads"].append(truncated)

            # Timestamps for critical events
            if details.get("status") == "warning":
                ts = event.get("timestamp", "")
                if ts and ts not in iocs["timestamps_of_interest"]:
                    iocs["timestamps_of_interest"].append(ts)

        return iocs

    # ── Analysis Report ────────────────────────────────────────────────

    def run(self) -> dict[str, Any]:
        """Run full forensic analysis."""
        timeline = self.reconstruct_timeline()
        self.collect_log_evidence()
        iocs = self.extract_iocs()

        report = {
            "timeline_events": len(timeline),
            "critical_events": sum(1 for e in timeline if e.severity == "critical"),
            "warning_events": sum(1 for e in timeline if e.severity == "warning"),
            "evidence_collected": len(self.evidence),
            "evidence_items": [e.to_dict() for e in self.evidence],
            "iocs": iocs,
            "timeline": [e.to_dict() for e in timeline],
        }

        self.logger.log_event("forensic_analysis_complete", "forensics", {
            "timeline_events": len(timeline),
            "evidence_items": len(self.evidence),
            "iocs_found": sum(len(v) for v in iocs.values()),
            "status": "info",
        })

        return report

    def generate_text_report(self) -> str:
        """Generate formatted text report."""
        report = self.run()
        lines = [
            "",
            "  ╔══════════════════════════════════════════════════════════════════╗",
            "  ║              DIGITAL FORENSIC ANALYSIS REPORT                   ║",
            "  ╚══════════════════════════════════════════════════════════════════╝",
            "",
            f"  Timeline Events  : {report['timeline_events']}",
            f"  Critical Events  : {report['critical_events']}",
            f"  Warning Events   : {report['warning_events']}",
            f"  Evidence Items   : {report['evidence_collected']}",
            "",
            "  Indicators of Compromise (IOC):",
            "  " + "─" * 50,
        ]

        iocs = report["iocs"]
        for category, items in iocs.items():
            if items:
                lines.append(f"    {category}:")
                for item in items[:10]:
                    lines.append(f"      - {item}")

        lines.extend([
            "",
            "  Evidence Chain of Custody:",
            "  " + "─" * 50,
        ])
        for ev in report["evidence_items"]:
            lines.append(f"    [{ev['evidence_id']}] {ev['description']}")
            lines.append(f"      SHA-256: {ev['sha256_hash'][:32]}...")
            for coc in ev["chain_of_custody"]:
                lines.append(f"      {coc['timestamp']}: {coc['action']}")

        lines.extend([
            "",
            "  Timeline (first 20 events):",
            "  " + "─" * 50,
        ])
        for event in report["timeline"][:20]:
            sev_tag = {"critical": "!!", "warning": "! ", "info": "  "}.get(event["severity"], "  ")
            lines.append(f"    {sev_tag} [{event['module']:<15}] {event['event_type']}")
            if event["indicators"]:
                lines.append(f"       IOC: {', '.join(event['indicators'])}")

        lines.append("")
        return "\n".join(lines)
