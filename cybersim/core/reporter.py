"""
CyberSim6 - Reporter
Generates summary reports from logged events.
"""

from collections import Counter
from cybersim.core.logging_engine import CyberSimLogger


def generate_summary(logger: CyberSimLogger) -> dict:
    """Generate a summary report from session events."""
    events = logger.events
    if not events:
        return {"total_events": 0}

    modules = Counter(e["module"] for e in events)
    event_types = Counter(e["event_type"] for e in events)
    statuses = Counter(e.get("status", "info") for e in events)

    return {
        "session_id": logger.session_id,
        "total_events": len(events),
        "time_range": {
            "start": events[0]["timestamp"],
            "end": events[-1]["timestamp"],
        },
        "events_by_module": dict(modules),
        "events_by_type": dict(event_types),
        "events_by_status": dict(statuses),
    }


def print_summary(logger: CyberSimLogger):
    """Print a formatted summary to console."""
    summary = generate_summary(logger)
    print("\n" + "=" * 50)
    print("  CyberSim6 - Session Summary")
    print("=" * 50)
    print(f"  Session ID : {summary.get('session_id', 'N/A')}")
    print(f"  Total Events: {summary['total_events']}")
    if summary["total_events"] > 0:
        print(f"  Time Range : {summary['time_range']['start']}")
        print(f"             -> {summary['time_range']['end']}")
        print("\n  Events by Module:")
        for mod, count in summary["events_by_module"].items():
            print(f"    {mod}: {count}")
        print("\n  Events by Status:")
        for status, count in summary["events_by_status"].items():
            print(f"    {status}: {count}")
    print("=" * 50 + "\n")
