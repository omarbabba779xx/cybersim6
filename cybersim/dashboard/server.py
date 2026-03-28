"""
CyberSim6 - Web Dashboard
Real-time visualization of attacks, detections, and logs.
"""

import json
import threading
import time
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import urlparse, parse_qs
from collections import Counter

from cybersim.core.anomaly_detection import AnomalyType, StatisticalDetector
from cybersim.core.audit_trail import AuditTrail
from cybersim.core.logging_engine import CyberSimLogger
from cybersim.core.pdf_report import MITRE_MAPPING
from cybersim.core.threat_score import ThreatScorer


def _parse_limit(value: str, default: int = 100, minimum: int = 1, maximum: int = 500) -> int:
    """Parse and clamp a query-string limit value."""
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return max(minimum, min(maximum, parsed))


_SEVERITY_MAP = {
    "info": 0.2,
    "warning": 0.55,
    "error": 0.85,
    "critical": 1.0,
}

_TACTIC_ORDER = {
    "Reconnaissance": 0,
    "Initial Access": 1,
    "Credential Access": 2,
    "Execution": 3,
    "Persistence": 4,
    "Defense Evasion": 5,
    "Discovery": 6,
    "Lateral Movement": 7,
    "Collection": 8,
    "Command and Control": 9,
    "Impact": 10,
}


def _canonical_module_key(module_name: str) -> str:
    """Map concrete runtime module IDs to stable module families."""
    normalized = str(module_name or "").lower()
    for key in MITRE_MAPPING:
        if key in normalized:
            return key
    if "scan" in normalized:
        return "scanner"
    if "honeypot" in normalized:
        return "honeypot"
    if "waf" in normalized or "firewall" in normalized:
        return "waf"
    return normalized or "unknown"


def _module_event_type(event: dict) -> str:
    """Reduce concrete event/module types to attack vs detection for scoring."""
    module_type = str(event.get("module_type", "")).lower()
    if "attack" in module_type:
        return "attack"
    if "detection" in module_type or "target" in module_type:
        return "detection"
    return "attack" if "attack" in str(event.get("event_type", "")).lower() else "detection"


def _event_status(event: dict) -> str:
    """Read the normalized event status."""
    details = event.get("details", {}) or {}
    return str(details.get("status") or event.get("status") or "info").lower()


def _safe_iso_to_ts(value: str) -> float:
    """Parse an ISO timestamp into a unix timestamp."""
    try:
        return datetime.fromisoformat(value).timestamp()
    except (TypeError, ValueError):
        return 0.0


def _bucketize_events(events: list[dict], bucket_seconds: int = 30) -> list[dict]:
    """Aggregate event counts into chronological time buckets."""
    buckets: dict[int, int] = {}
    for event in events:
        ts = _safe_iso_to_ts(event.get("timestamp"))
        bucket = int(ts // bucket_seconds) * bucket_seconds
        buckets[bucket] = buckets.get(bucket, 0) + 1

    series = []
    for bucket, count in sorted(buckets.items()):
        series.append({
            "timestamp": datetime.fromtimestamp(bucket).isoformat(),
            "count": count,
        })
    return series


def _build_soc_snapshot(events: list[dict]) -> dict:
    """Compute SOC-style metrics, incidents, anomalies and forensic integrity."""
    scorer = ThreatScorer(snapshot_interval_seconds=0)
    audit = AuditTrail()
    incidents = []

    for index, event in enumerate(events):
        family = _canonical_module_key(event.get("module"))
        status = _event_status(event)
        severity = _SEVERITY_MAP.get(status, 0.2)
        scorer.record_event(
            family,
            _module_event_type(event),
            severity,
            details=event.get("details", {}) or {},
        )
        audit.record(
            action=event.get("event_type", "event"),
            actor=event.get("source", "system"),
            module=family,
            details={
                "timestamp": event.get("timestamp"),
                "status": status,
                "message": (event.get("details", {}) or {}).get("message", ""),
            },
        )
        if status in {"warning", "error", "critical"}:
            incidents.append({
                "id": f"INC-{index + 1:04d}",
                "timestamp": event.get("timestamp"),
                "severity": status,
                "module": event.get("module"),
                "family": family,
                "event_type": event.get("event_type"),
                "message": (event.get("details", {}) or {}).get("message", event.get("event_type", "")),
                "source": event.get("source", "localhost"),
            })

    timeline = _bucketize_events(events, bucket_seconds=30)
    anomaly_detector = StatisticalDetector(
        window_size=max(20, len(timeline) or 1),
        learning_period=max(3, min(8, len(timeline) or 3)),
        z_threshold=2.0,
    )
    anomalies = []
    for bucket in timeline:
        result = anomaly_detector.observe(
            bucket["count"],
            features={"timestamp": bucket["timestamp"], "count": bucket["count"]},
        )
        if result.anomaly_type != AnomalyType.NORMAL:
            anomalies.append({
                "timestamp": bucket["timestamp"],
                "count": bucket["count"],
                "score": round(result.score, 3),
                "type": result.anomaly_type.value,
                "z_score": round(result.z_score, 3),
            })

    audit_valid, last_valid_index = audit.verify_chain()
    breakdown = {
        module: round(value, 2)
        for module, value in sorted(scorer.get_breakdown().items(), key=lambda item: item[1], reverse=True)
    }
    recent_incidents = list(reversed(incidents[-12:]))

    return {
        "threat_score": round(scorer.get_score(), 2),
        "threat_level": scorer.get_level().value,
        "incidents_open": len(incidents),
        "incidents": recent_incidents,
        "module_breakdown": breakdown,
        "anomalies": anomalies[-8:],
        "audit_trail": {
            "valid": audit_valid,
            "entries": len(events),
            "last_valid_index": last_valid_index,
        },
    }


def _build_attack_map(events: list[dict]) -> dict:
    """Build an ATT&CK-oriented summary from active events."""
    families = [_canonical_module_key(event.get("module")) for event in events]
    counts = Counter(family for family in families if family in MITRE_MAPPING)
    techniques = []
    tactics = Counter()
    seen_chain = set()
    kill_chain = []

    for family, count in sorted(counts.items(), key=lambda item: item[1], reverse=True):
        mapping = MITRE_MAPPING[family]
        tactics[mapping["tactic"]] += count
        techniques.append({
            "module": family,
            "count": count,
            "technique": mapping["technique"],
            "tactic": mapping["tactic"],
            "name": mapping["name"],
        })

    ordered_events = sorted(events, key=lambda event: _safe_iso_to_ts(event.get("timestamp")))
    for event in ordered_events:
        family = _canonical_module_key(event.get("module"))
        if family not in MITRE_MAPPING or family in seen_chain:
            continue
        mapping = MITRE_MAPPING[family]
        kill_chain.append({
            "module": family,
            "technique": mapping["technique"],
            "tactic": mapping["tactic"],
            "name": mapping["name"],
        })
        seen_chain.add(family)

    tactic_series = [
        {"tactic": tactic, "count": count}
        for tactic, count in sorted(tactics.items(), key=lambda item: _TACTIC_ORDER.get(item[0], 999))
    ]
    return {
        "techniques": techniques,
        "tactics": tactic_series,
        "kill_chain": kill_chain,
    }


class DashboardHandler(BaseHTTPRequestHandler):
    """HTTP handler for the dashboard."""

    logger: CyberSimLogger = None
    replay_mode: str = "live"
    replay_session_id: str | None = None
    replay_events: list[dict] = []
    replay_position: int = 0

    def log_message(self, format, *args):
        pass  # Suppress default access logs

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/" or path == "/dashboard":
            self._serve_dashboard()
        elif path == "/api/events":
            self._serve_events(parse_qs(parsed.query))
        elif path == "/api/stats":
            self._serve_stats()
        elif path == "/api/timeline":
            self._serve_timeline()
        elif path == "/api/soc":
            self._serve_soc()
        elif path == "/api/attack-map":
            self._serve_attack_map()
        elif path == "/api/replay/sessions":
            self._serve_replay_sessions()
        elif path == "/api/replay/state":
            self._serve_replay_state()
        elif path == "/api/replay/load":
            self._serve_replay_load(parse_qs(parsed.query))
        elif path == "/api/replay/step":
            self._serve_replay_step(parse_qs(parsed.query))
        elif path == "/api/replay/reset":
            self._serve_replay_reset()
        elif path == "/api/replay/live":
            self._serve_replay_live()
        else:
            self.send_error(404)

    def _serve_dashboard(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(DASHBOARD_HTML.encode("utf-8"))

    def _serve_events(self, params):
        events = self._get_active_events()
        module = params.get("module", [None])[0]
        limit = _parse_limit(params.get("limit", [100])[0])

        if module:
            events = [e for e in events if e["module"] == module]

        events = events[-limit:]

        self._send_json(events)

    def _serve_stats(self):
        events = self._get_active_events()
        handler_cls = type(self)

        modules = Counter(e["module"] for e in events)
        types = Counter(e["event_type"] for e in events)
        statuses = Counter(e.get("status", "info") for e in events)

        attacks = [e for e in events if "attack" in e.get("module_type", "")]
        detections = [e for e in events if "detection" in e.get("module_type", "")]

        stats = {
            "total_events": len(events),
            "total_attacks": len(attacks),
            "total_detections": len(detections),
            "session_id": self.logger.session_id if self.logger else "N/A",
            "events_by_module": dict(modules),
            "events_by_type": dict(types),
            "events_by_status": dict(statuses),
            "modules_active": list(modules.keys()),
            "mode": handler_cls.replay_mode,
            "replay_session_id": handler_cls.replay_session_id,
        }
        self._send_json(stats)

    def _serve_timeline(self):
        events = self._get_active_events()

        timeline = []
        for e in events[-200:]:
            timeline.append({
                "t": e["timestamp"],
                "module": e["module"],
                "type": e["event_type"],
                "status": e.get("status", "info"),
                "msg": e.get("details", {}).get("message", ""),
            })

        self._send_json(timeline)

    def _serve_soc(self):
        self._send_json(_build_soc_snapshot(self._get_active_events()))

    def _serve_attack_map(self):
        self._send_json(_build_attack_map(self._get_active_events()))

    def _serve_replay_sessions(self):
        sessions = []
        log_dir = Path(self.logger.log_dir) if self.logger else Path("./logs")
        for path in sorted(log_dir.glob("session_*.json")):
            try:
                with open(path, "r", encoding="utf-8") as handle:
                    events = json.load(handle)
            except (OSError, json.JSONDecodeError):
                continue
            session_id = path.stem.replace("session_", "", 1)
            sessions.append({
                "session_id": session_id,
                "events": len(events),
                "path": str(path),
            })
        self._send_json(sessions)

    def _serve_replay_state(self):
        handler_cls = type(self)
        total_events = len(handler_cls.replay_events)
        self._send_json({
            "mode": handler_cls.replay_mode,
            "session_id": handler_cls.replay_session_id,
            "position": handler_cls.replay_position,
            "total_events": total_events,
            "progress": round((handler_cls.replay_position / total_events) * 100, 2) if total_events else 0.0,
        })

    def _serve_replay_load(self, params):
        session_id = params.get("session", [None])[0]
        if not session_id:
            self.send_error(400, "Missing session")
            return

        log_dir = Path(self.logger.log_dir) if self.logger else Path("./logs")
        session_path = log_dir / f"session_{session_id}.json"
        if not session_path.exists():
            self.send_error(404, "Session not found")
            return

        with open(session_path, "r", encoding="utf-8") as handle:
            events = json.load(handle)

        handler_cls = type(self)
        handler_cls.replay_mode = "replay"
        handler_cls.replay_session_id = session_id
        handler_cls.replay_events = events
        handler_cls.replay_position = min(10, len(events))
        self._serve_replay_state()

    def _serve_replay_step(self, params):
        handler_cls = type(self)
        if handler_cls.replay_mode != "replay":
            self.send_error(400, "Replay mode is not active")
            return

        count = _parse_limit(params.get("count", [10])[0], default=10, minimum=1, maximum=100)
        handler_cls.replay_position = min(
            len(handler_cls.replay_events),
            handler_cls.replay_position + count,
        )
        self._serve_replay_state()

    def _serve_replay_reset(self):
        type(self).replay_position = 0
        self._serve_replay_state()

    def _serve_replay_live(self):
        handler_cls = type(self)
        handler_cls.replay_mode = "live"
        handler_cls.replay_session_id = None
        handler_cls.replay_events = []
        handler_cls.replay_position = 0
        self._serve_replay_state()

    def _get_active_events(self):
        handler_cls = type(self)
        if handler_cls.replay_mode == "replay":
            return handler_cls.replay_events[: handler_cls.replay_position]
        return self.logger.events if self.logger else []

    def _send_json(self, payload):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps(payload, ensure_ascii=False).encode("utf-8"))


class Dashboard:
    """Web dashboard for CyberSim6."""

    def __init__(self, port: int = 8888, logger: CyberSimLogger = None):
        self.port = port
        self.logger = logger or CyberSimLogger()
        self._server = None
        self._thread = None

    def start(self):
        DashboardHandler.logger = self.logger
        DashboardHandler.replay_mode = "live"
        DashboardHandler.replay_session_id = None
        DashboardHandler.replay_events = []
        DashboardHandler.replay_position = 0
        self._server = HTTPServer(("127.0.0.1", self.port), DashboardHandler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        print(f"[+] Dashboard running at http://127.0.0.1:{self.port}/dashboard")

    def stop(self):
        if self._server:
            self._server.shutdown()
            print("[+] Dashboard stopped.")


DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CyberSim6 — Threat Intelligence Dashboard</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;600;700&family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
:root {
  --bg:        #050810;
  --bg2:       #080c14;
  --card:      #0d1220;
  --card2:     #111828;
  --border:    #1a2236;
  --border2:   #243044;
  --neon:      #00ff41;
  --cyan:      #00d4ff;
  --red:       #ff0040;
  --orange:    #ff6b00;
  --yellow:    #ffd700;
  --purple:    #b44fff;
  --dim:       #3a4a66;
  --muted:     #6a7d99;
  --text:      #c8d8f0;
  --bright:    #e8f0ff;
  --glow-g:    0 0 20px rgba(0,255,65,0.4);
  --glow-c:    0 0 20px rgba(0,212,255,0.4);
  --glow-r:    0 0 20px rgba(255,0,64,0.4);
}

*,*::before,*::after{margin:0;padding:0;box-sizing:border-box}

html,body{
  height:100%;
  font-family:'Inter',sans-serif;
  background:var(--bg);
  color:var(--text);
  overflow-x:hidden;
}

/* ═══════════════ MATRIX RAIN ═══════════════ */
#matrix-canvas{
  position:fixed;top:0;left:0;width:100%;height:100%;
  z-index:0;opacity:0.04;pointer-events:none;
}

/* ═══════════════ SCANLINE OVERLAY ═══════════════ */
body::after{
  content:'';
  position:fixed;top:0;left:0;right:0;bottom:0;
  background:repeating-linear-gradient(
    0deg,transparent,transparent 2px,rgba(0,0,0,0.03) 2px,rgba(0,0,0,0.03) 4px
  );
  pointer-events:none;z-index:1;
}

.app{position:relative;z-index:2;min-height:100vh;display:flex;flex-direction:column;}

/* ═══════════════ HEADER ═══════════════ */
header{
  position:sticky;top:0;z-index:100;
  background:rgba(5,8,16,0.92);
  backdrop-filter:blur(24px);
  border-bottom:1px solid var(--border);
  padding:0 32px;
  height:64px;
  display:flex;align-items:center;justify-content:space-between;
}

.logo{display:flex;align-items:center;gap:14px;}

.logo-ascii{
  font-family:'JetBrains Mono',monospace;
  font-size:0.55rem;line-height:1.15;
  color:var(--neon);
  text-shadow:var(--glow-g);
  white-space:pre;
  animation:flicker 8s infinite;
}

@keyframes flicker{
  0%,95%,100%{opacity:1}
  96%{opacity:0.7}
  97%{opacity:1}
  98%{opacity:0.8}
  99%{opacity:1}
}

.logo-text{
  font-family:'JetBrains Mono',monospace;
  font-size:1.4rem;font-weight:700;
  background:linear-gradient(135deg,var(--neon),var(--cyan));
  -webkit-background-clip:text;-webkit-text-fill-color:transparent;
  letter-spacing:-0.5px;
}
.logo-text em{
  background:linear-gradient(135deg,var(--red),var(--orange));
  -webkit-background-clip:text;-webkit-text-fill-color:transparent;
  font-style:normal;
}

.header-right{display:flex;align-items:center;gap:16px;}

.pill{
  display:flex;align-items:center;gap:8px;
  background:var(--card);
  border:1px solid var(--border2);
  padding:6px 14px;border-radius:999px;
  font-family:'JetBrains Mono',monospace;
  font-size:0.72rem;color:var(--muted);
}

.dot-live{
  width:8px;height:8px;border-radius:50%;
  background:var(--neon);
  box-shadow:var(--glow-g);
  animation:beat 1.4s ease-in-out infinite;
}
@keyframes beat{0%,100%{transform:scale(1);opacity:1}50%{transform:scale(1.4);opacity:0.7}}

.refresh-ring{
  width:22px;height:22px;border-radius:50%;
  background:conic-gradient(var(--cyan) 0%, transparent 0%);
  transition:background 0.1s linear;
  display:flex;align-items:center;justify-content:center;
}
.refresh-ring-inner{width:14px;height:14px;border-radius:50%;background:var(--card);}

/* ═══════════════ MAIN ═══════════════ */
main{flex:1;padding:24px 32px;max-width:1600px;margin:0 auto;width:100%;}

/* ═══════════════ KPI GRID ═══════════════ */
.kpi-grid{
  display:grid;grid-template-columns:repeat(4,1fr);gap:16px;
  margin-bottom:24px;
}

.kpi{
  background:var(--card);
  border:1px solid var(--border);
  border-radius:16px;
  padding:20px 22px;
  position:relative;overflow:hidden;
  cursor:default;
  transition:transform 0.25s,box-shadow 0.25s,border-color 0.25s;
}
.kpi:hover{transform:translateY(-3px);}

.kpi::before{
  content:'';position:absolute;top:0;left:0;right:0;height:2px;
  border-radius:16px 16px 0 0;
}
.kpi.g::before{background:linear-gradient(90deg,var(--neon),var(--cyan));box-shadow:0 0 12px var(--neon);}
.kpi.r::before{background:linear-gradient(90deg,var(--red),var(--orange));box-shadow:0 0 12px var(--red);}
.kpi.c::before{background:linear-gradient(90deg,var(--cyan),var(--purple));box-shadow:0 0 12px var(--cyan);}
.kpi.p::before{background:linear-gradient(90deg,var(--purple),var(--red));box-shadow:0 0 12px var(--purple);}

.kpi:hover.g{border-color:rgba(0,255,65,0.3);box-shadow:0 8px 32px rgba(0,255,65,0.1);}
.kpi:hover.r{border-color:rgba(255,0,64,0.3);box-shadow:0 8px 32px rgba(255,0,64,0.1);}
.kpi:hover.c{border-color:rgba(0,212,255,0.3);box-shadow:0 8px 32px rgba(0,212,255,0.1);}
.kpi:hover.p{border-color:rgba(180,79,255,0.3);box-shadow:0 8px 32px rgba(180,79,255,0.1);}

.kpi-icon{font-size:1.4rem;margin-bottom:8px;display:block;}
.kpi-label{
  font-size:0.62rem;font-weight:600;text-transform:uppercase;
  letter-spacing:2px;color:var(--muted);margin-bottom:10px;
}
.kpi-value{
  font-family:'JetBrains Mono',monospace;
  font-size:2.6rem;font-weight:700;line-height:1;
  transition:color 0.3s;
}
.kpi.g .kpi-value{color:var(--neon);text-shadow:0 0 16px rgba(0,255,65,0.5);}
.kpi.r .kpi-value{color:var(--red);text-shadow:0 0 16px rgba(255,0,64,0.5);}
.kpi.c .kpi-value{color:var(--cyan);text-shadow:0 0 16px rgba(0,212,255,0.5);}
.kpi.p .kpi-value{color:var(--purple);text-shadow:0 0 16px rgba(180,79,255,0.5);}
.kpi-sub{font-size:0.7rem;color:var(--dim);margin-top:6px;font-family:'JetBrains Mono',monospace;}

/* ═══════════════ GRID LAYOUT ═══════════════ */
.grid-2{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:16px;}
.grid-3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:16px;margin-bottom:16px;}
.span2{grid-column:span 2;}

/* ═══════════════ PANEL ═══════════════ */
.panel{
  background:var(--card);
  border:1px solid var(--border);
  border-radius:16px;
  padding:20px 22px;
  display:flex;flex-direction:column;
}

.panel-hd{
  display:flex;align-items:center;justify-content:space-between;
  margin-bottom:16px;
}
.panel-title{
  font-size:0.7rem;font-weight:700;text-transform:uppercase;
  letter-spacing:2px;color:var(--muted);
  display:flex;align-items:center;gap:8px;
}
.panel-title .dot{
  width:6px;height:6px;border-radius:50%;background:var(--cyan);
  box-shadow:0 0 8px var(--cyan);
  animation:beat 2s infinite;
}
.panel-badge{
  font-size:0.65rem;font-family:'JetBrains Mono',monospace;
  padding:3px 10px;border-radius:999px;
  background:rgba(0,212,255,0.1);color:var(--cyan);border:1px solid rgba(0,212,255,0.2);
}

.panel-body{flex:1;overflow-y:auto;overflow-x:hidden;}
.panel-body::-webkit-scrollbar{width:3px;}
.panel-body::-webkit-scrollbar-thumb{background:var(--border2);border-radius:3px;}

/* ═══════════════ MODULE BARS ═══════════════ */
.bars{display:flex;flex-direction:column;gap:10px;}
.bar-row{display:flex;align-items:center;gap:10px;}
.bar-lbl{
  min-width:140px;max-width:140px;
  font-size:0.7rem;color:var(--muted);
  font-family:'JetBrains Mono',monospace;
  text-align:right;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;
}
.bar-track{
  flex:1;height:24px;
  background:rgba(26,34,54,0.8);
  border-radius:6px;overflow:hidden;
  border:1px solid var(--border);
}
.bar-fill{
  height:100%;border-radius:5px;
  display:flex;align-items:center;padding:0 8px;
  font-size:0.68rem;font-weight:600;color:rgba(255,255,255,0.95);
  font-family:'JetBrains Mono',monospace;
  transition:width 0.9s cubic-bezier(0.4,0,0.2,1);
  min-width:28px;
}
.b-ddos{background:linear-gradient(90deg,#ff0040,#cc0033);}
.b-sqli{background:linear-gradient(90deg,#ffd700,#cc9900);}
.b-bf  {background:linear-gradient(90deg,#00d4ff,#0099cc);}
.b-xss {background:linear-gradient(90deg,#b44fff,#8833cc);}
.b-phi {background:linear-gradient(90deg,#00ff41,#00cc33);}
.b-rns {background:linear-gradient(90deg,#ff6b00,#cc5500);}
.b-def {background:linear-gradient(90deg,var(--border2),var(--border));}
.b-info{background:linear-gradient(90deg,#00d4ff,#0099cc);}
.b-warn{background:linear-gradient(90deg,#ffd700,#cc9900);}
.b-err {background:linear-gradient(90deg,#ff0040,#cc0033);}

/* ═══════════════ THREAT METER ═══════════════ */
.threat-meters{display:flex;flex-direction:column;gap:14px;}
.threat-row{display:flex;flex-direction:column;gap:4px;}
.threat-lbl{
  display:flex;justify-content:space-between;align-items:center;
  font-size:0.7rem;font-family:'JetBrains Mono',monospace;
}
.threat-name{color:var(--text);}
.threat-pct{color:var(--muted);}
.threat-bar-track{
  height:8px;background:var(--bg2);border-radius:4px;overflow:hidden;
  border:1px solid var(--border);
}
.threat-bar-fill{
  height:100%;border-radius:3px;
  transition:width 1s cubic-bezier(0.4,0,0.2,1);
}

/* ═══════════════ CHART CONTAINER ═══════════════ */
.chart-wrap{position:relative;width:100%;height:200px;}
.chart-wrap canvas{max-height:200px;}

/* ═══════════════ EVENT TERMINAL ═══════════════ */
.terminal{
  background:var(--bg2);border:1px solid var(--border);
  border-radius:12px;overflow:hidden;
  font-family:'JetBrains Mono',monospace;
  max-height:320px;
}
.terminal-bar{
  display:flex;align-items:center;gap:8px;
  padding:10px 16px;
  background:rgba(26,34,54,0.8);
  border-bottom:1px solid var(--border);
}
.t-dot{width:10px;height:10px;border-radius:50%;}
.t-red{background:#ff5f57;}
.t-yellow{background:#ffbd2e;}
.t-green{background:#28c840;}
.terminal-title{
  flex:1;text-align:center;font-size:0.7rem;color:var(--muted);margin-left:8px;
}
.terminal-body{
  padding:12px 16px;
  overflow-y:auto;max-height:270px;
  font-size:0.72rem;line-height:1.7;
}
.terminal-body::-webkit-scrollbar{width:3px;}
.terminal-body::-webkit-scrollbar-thumb{background:var(--border2);}

.t-line{
  display:flex;align-items:baseline;gap:10px;
  padding:2px 0;
  border-bottom:1px solid rgba(26,34,54,0.5);
  transition:background 0.15s;
}
.t-line:hover{background:rgba(26,34,54,0.5);}
.t-time{color:var(--dim);min-width:72px;font-size:0.68rem;}
.t-badge{
  min-width:52px;text-align:center;
  padding:1px 6px;border-radius:3px;
  font-size:0.6rem;font-weight:600;text-transform:uppercase;
  letter-spacing:0.5px;
}
.tb-info   {background:rgba(0,212,255,0.1);color:var(--cyan);border:1px solid rgba(0,212,255,0.2);}
.tb-warning{background:rgba(255,215,0,0.1);color:var(--yellow);border:1px solid rgba(255,215,0,0.2);}
.tb-error  {background:rgba(255,0,64,0.12);color:var(--red);border:1px solid rgba(255,0,64,0.2);}
.t-mod{color:var(--neon);min-width:150px;font-size:0.68rem;}
.t-msg{color:var(--muted);flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}

/* ═══════════════ PULSE INDICATORS ═══════════════ */
.module-grid{
  display:grid;grid-template-columns:repeat(3,1fr);gap:10px;
}
.mod-card{
  background:var(--bg2);border:1px solid var(--border);
  border-radius:10px;padding:12px;
  display:flex;flex-direction:column;gap:6px;
  transition:border-color 0.3s,box-shadow 0.3s;
}
.mod-card.active-ddos{border-color:rgba(255,0,64,0.4);box-shadow:0 0 12px rgba(255,0,64,0.1);}
.mod-card.active-sqli{border-color:rgba(255,215,0,0.4);box-shadow:0 0 12px rgba(255,215,0,0.1);}
.mod-card.active-bf  {border-color:rgba(0,212,255,0.4);box-shadow:0 0 12px rgba(0,212,255,0.1);}
.mod-card.active-xss {border-color:rgba(180,79,255,0.4);box-shadow:0 0 12px rgba(180,79,255,0.1);}
.mod-card.active-phi {border-color:rgba(0,255,65,0.4);box-shadow:0 0 12px rgba(0,255,65,0.1);}
.mod-card.active-rns {border-color:rgba(255,107,0,0.4);box-shadow:0 0 12px rgba(255,107,0,0.1);}

.mod-top{display:flex;align-items:center;justify-content:space-between;}
.mod-name{font-size:0.68rem;font-weight:600;font-family:'JetBrains Mono',monospace;color:var(--text);}
.mod-status{
  font-size:0.6rem;padding:2px 7px;border-radius:999px;
  font-family:'JetBrains Mono',monospace;font-weight:600;
}
.ms-active{background:rgba(0,255,65,0.1);color:var(--neon);border:1px solid rgba(0,255,65,0.3);}
.ms-idle  {background:rgba(58,74,102,0.3);color:var(--dim);border:1px solid var(--border);}
.mod-count{font-size:1.2rem;font-weight:700;font-family:'JetBrains Mono',monospace;}
.mod-label{font-size:0.62rem;color:var(--dim);}

.soc-summary{
  display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin-bottom:12px;
}
.soc-chip,.replay-chip{
  background:var(--bg2);border:1px solid var(--border);border-radius:10px;
  padding:10px 12px;
}
.soc-chip .lbl,.replay-chip .lbl{
  font-size:0.62rem;color:var(--muted);text-transform:uppercase;letter-spacing:1px;
  font-family:'JetBrains Mono',monospace;
}
.soc-chip .val,.replay-chip .val{
  font-size:1.2rem;font-weight:700;font-family:'JetBrains Mono',monospace;color:var(--bright);
}
.incident-list,.attack-list,.replay-list,.killchain{
  display:flex;flex-direction:column;gap:8px;
}
.incident-item,.attack-item,.replay-item,.kill-step{
  background:var(--bg2);border:1px solid var(--border);border-radius:10px;padding:10px 12px;
}
.incident-top,.attack-top,.replay-top{
  display:flex;align-items:center;justify-content:space-between;gap:10px;margin-bottom:4px;
}
.incident-meta,.attack-meta,.replay-meta,.kill-meta{
  font-size:0.64rem;color:var(--muted);font-family:'JetBrains Mono',monospace;
}
.incident-msg,.attack-name,.replay-path,.kill-name{
  font-size:0.72rem;color:var(--text);line-height:1.5;
}
.sev-warning{color:var(--yellow);}
.sev-error,.sev-critical{color:var(--red);}
.sev-info{color:var(--cyan);}
.pill-btn{
  background:rgba(0,212,255,0.1);color:var(--cyan);border:1px solid rgba(0,212,255,0.25);
  border-radius:999px;padding:6px 10px;font-size:0.65rem;font-family:'JetBrains Mono',monospace;
  cursor:pointer;transition:all 0.2s;
}
.pill-btn:hover{background:rgba(0,212,255,0.18);}
.pill-btn.warn{color:var(--yellow);border-color:rgba(255,215,0,0.25);background:rgba(255,215,0,0.08);}
.pill-btn.danger{color:var(--red);border-color:rgba(255,0,64,0.25);background:rgba(255,0,64,0.08);}
.btn-row{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:12px;}
.replay-session-actions{display:flex;gap:8px;align-items:center;}
.killchain{position:relative;padding-left:14px;}
.kill-step{position:relative;}
.kill-step::before{
  content:'';position:absolute;left:-10px;top:18px;width:8px;height:8px;border-radius:50%;
  background:var(--neon);box-shadow:0 0 8px rgba(0,255,65,0.4);
}
.kill-step::after{
  content:'';position:absolute;left:-7px;top:26px;bottom:-16px;width:2px;background:rgba(0,255,65,0.18);
}
.kill-step:last-child::after{display:none;}

/* ═══════════════ FOOTER ═══════════════ */
footer{
  text-align:center;padding:16px 32px;
  border-top:1px solid var(--border);
  font-size:0.68rem;color:var(--dim);
  font-family:'JetBrains Mono',monospace;
  display:flex;align-items:center;justify-content:center;gap:16px;
}

/* ═══════════════ RESPONSIVE ═══════════════ */
@media(max-width:1100px){
  .kpi-grid{grid-template-columns:repeat(2,1fr);}
  .grid-2,.grid-3{grid-template-columns:1fr;}
  .span2{grid-column:span 1;}
  main{padding:16px;}
}
@media(max-width:600px){
  .kpi-grid{grid-template-columns:1fr 1fr;}
  header{padding:0 16px;}
  .logo-ascii{display:none;}
  .module-grid{grid-template-columns:repeat(2,1fr);}
}

/* COMMAND-SCALE VISUAL OVERRIDES */
body::before{
  content:'';
  position:fixed;
  inset:0;
  background:
    radial-gradient(circle at 12% 16%, rgba(0,212,255,0.12), transparent 28%),
    radial-gradient(circle at 86% 14%, rgba(180,79,255,0.14), transparent 26%),
    radial-gradient(circle at 50% 84%, rgba(0,255,65,0.08), transparent 34%);
  pointer-events:none;
  z-index:0;
}

header{
  padding:0 40px;
  height:78px;
  background:linear-gradient(180deg, rgba(5,8,16,0.96), rgba(5,8,16,0.84));
  box-shadow:0 14px 44px rgba(0,0,0,0.28);
}

.logo-text{
  font-size:1.55rem;
  letter-spacing:-0.8px;
}

main{
  padding:28px 36px 34px;
  max-width:1880px;
}

.hero-grid{
  display:grid;
  grid-template-columns:minmax(0,1.45fr) minmax(360px,0.95fr);
  gap:18px;
  margin-bottom:18px;
}

.hero-panel{
  position:relative;
  overflow:hidden;
  min-height:330px;
  border-radius:24px;
  padding:28px;
  background:linear-gradient(180deg, rgba(13,18,32,0.96), rgba(8,12,20,0.98));
  border:1px solid rgba(46,65,96,0.92);
  box-shadow:0 24px 80px rgba(0,0,0,0.26);
}

.hero-panel::before{
  content:'';
  position:absolute;
  inset:0 auto auto 0;
  width:100%;
  height:3px;
}

.hero-shell::before{
  background:linear-gradient(90deg, rgba(0,255,65,0.8), rgba(0,212,255,0.7), rgba(180,79,255,0.65));
  box-shadow:0 0 30px rgba(0,212,255,0.3);
}

.hero-side::before{
  background:linear-gradient(90deg, rgba(255,107,0,0.65), rgba(255,0,64,0.72), rgba(180,79,255,0.65));
  box-shadow:0 0 30px rgba(255,0,64,0.22);
}

.hero-kicker{
  display:inline-flex;
  align-items:center;
  gap:10px;
  margin-bottom:16px;
  padding:7px 12px;
  border-radius:999px;
  border:1px solid rgba(0,212,255,0.22);
  background:rgba(0,212,255,0.08);
  font-size:0.68rem;
  font-weight:700;
  letter-spacing:2px;
  text-transform:uppercase;
  color:var(--cyan);
  font-family:'JetBrains Mono',monospace;
}

.hero-title{
  max-width:860px;
  margin-bottom:14px;
  font-size:clamp(2.15rem,3.25vw,3.65rem);
  line-height:1.02;
  letter-spacing:-1.8px;
  color:var(--bright);
}

.hero-copy{
  max-width:780px;
  margin-bottom:22px;
  color:rgba(200,216,240,0.82);
  font-size:0.98rem;
  line-height:1.75;
}

.hero-status-row{
  display:flex;
  flex-wrap:wrap;
  gap:10px;
  margin-bottom:22px;
}

.hero-badge{
  display:flex;
  align-items:center;
  gap:10px;
  padding:10px 14px;
  border-radius:14px;
  background:rgba(5,8,16,0.58);
  border:1px solid rgba(36,48,68,0.95);
  color:var(--muted);
  font-size:0.72rem;
  font-family:'JetBrains Mono',monospace;
}

.hero-badge strong{
  color:var(--bright);
  font-size:0.76rem;
}

.hero-metrics{
  display:grid;
  grid-template-columns:repeat(4, minmax(0,1fr));
  gap:12px;
}

.hero-metric{
  padding:18px 18px 16px;
  border-radius:18px;
  border:1px solid rgba(36,48,68,0.95);
  background:
    linear-gradient(180deg, rgba(17,24,40,0.94), rgba(9,13,22,0.92));
  min-height:126px;
}

.hero-metric-label{
  margin-bottom:8px;
  color:var(--muted);
  font-size:0.68rem;
  font-weight:700;
  letter-spacing:1.6px;
  text-transform:uppercase;
  font-family:'JetBrains Mono',monospace;
}

.hero-metric-value{
  margin-bottom:8px;
  color:var(--bright);
  font-family:'JetBrains Mono',monospace;
  font-size:2.2rem;
  font-weight:700;
  line-height:1;
}

.hero-metric-sub{
  color:var(--dim);
  font-size:0.76rem;
  line-height:1.5;
}

.hero-side-grid{
  display:grid;
  grid-template-columns:repeat(2, minmax(0,1fr));
  gap:12px;
  height:calc(100% - 44px);
}

.hero-mini{
  display:flex;
  flex-direction:column;
  gap:10px;
  min-height:126px;
  padding:16px;
  border-radius:18px;
  border:1px solid rgba(36,48,68,0.95);
  background:rgba(5,8,16,0.52);
}

.hero-mini-wide{
  grid-column:span 2;
}

.hero-mini-label{
  color:var(--muted);
  font-size:0.68rem;
  font-weight:700;
  letter-spacing:1.6px;
  text-transform:uppercase;
  font-family:'JetBrains Mono',monospace;
}

.hero-mini-value{
  color:var(--bright);
  font-size:2.1rem;
  font-weight:700;
  line-height:1;
  font-family:'JetBrains Mono',monospace;
}

.hero-mini-meta{
  color:var(--dim);
  font-size:0.78rem;
  line-height:1.55;
}

.hero-list{
  display:flex;
  flex-direction:column;
  gap:8px;
}

.hero-list-item{
  display:flex;
  align-items:center;
  justify-content:space-between;
  gap:12px;
  padding:10px 12px;
  border-radius:12px;
  background:rgba(17,24,40,0.88);
  border:1px solid rgba(36,48,68,0.95);
  font-size:0.78rem;
  color:var(--text);
}

.hero-list-item strong{
  color:var(--cyan);
  font-family:'JetBrains Mono',monospace;
  font-size:0.72rem;
}

.hero-tags{
  display:flex;
  flex-wrap:wrap;
  gap:8px;
}

.hero-tag{
  display:inline-flex;
  align-items:center;
  gap:8px;
  padding:8px 10px;
  border-radius:999px;
  background:rgba(0,212,255,0.08);
  border:1px solid rgba(0,212,255,0.18);
  color:var(--cyan);
  font-size:0.72rem;
  font-family:'JetBrains Mono',monospace;
}

.hero-tag strong{
  color:var(--bright);
}

.hero-brief{
  color:rgba(200,216,240,0.84);
  font-size:0.84rem;
  line-height:1.68;
}

.kpi-grid{
  gap:18px;
  margin-bottom:18px;
}

.kpi{
  min-height:150px;
  padding:24px 24px 22px;
  border-radius:20px;
  background:linear-gradient(180deg, rgba(13,18,32,0.96), rgba(9,13,22,0.94));
}

.kpi-icon{
  font-size:1.55rem;
  margin-bottom:12px;
}

.kpi-label{
  font-size:0.66rem;
  letter-spacing:2.2px;
}

.kpi-value{
  font-size:3.15rem;
}

.kpi-sub{
  margin-top:10px;
}

.story-grid{
  display:grid;
  grid-template-columns:minmax(0,1.26fr) minmax(0,1fr);
  gap:18px;
  margin-bottom:18px;
}

.insight-grid{
  display:grid;
  grid-template-columns:minmax(0,0.94fr) minmax(0,0.94fr) minmax(0,1.12fr);
  gap:18px;
  margin-bottom:18px;
}

.command-grid{
  display:grid;
  grid-template-columns:minmax(0,1.05fr) minmax(0,1.12fr) minmax(0,0.93fr);
  gap:18px;
  margin-bottom:18px;
}

.panel{
  position:relative;
  overflow:hidden;
  min-height:330px;
  border-radius:20px;
  padding:24px 24px 22px;
  background:linear-gradient(180deg, rgba(13,18,32,0.96), rgba(9,13,22,0.94));
  box-shadow:0 18px 48px rgba(0,0,0,0.18);
}

.panel::after{
  content:'';
  position:absolute;
  inset:0 auto auto 0;
  width:100%;
  height:1px;
  background:linear-gradient(90deg, rgba(0,212,255,0.18), rgba(0,255,65,0.08), transparent);
}

.panel-xl{
  min-height:374px;
}

.panel-hd{
  margin-bottom:18px;
}

.panel-title{
  font-size:0.72rem;
  letter-spacing:2.4px;
}

.panel-badge{
  padding:4px 11px;
}

.chart-wrap{
  height:260px;
}

.chart-wrap canvas{
  max-height:260px;
}

.module-grid{
  grid-template-columns:repeat(2,1fr);
  gap:12px;
}

.mod-card{
  min-height:122px;
  padding:14px;
  border-radius:14px;
}

.mod-count{
  font-size:1.65rem;
}

.soc-summary{
  gap:12px;
  margin-bottom:14px;
}

.soc-chip,.replay-chip{
  padding:14px;
  border-radius:14px;
}

.soc-chip .val,.replay-chip .val{
  font-size:1.45rem;
}

.incident-item,.attack-item,.replay-item,.kill-step{
  padding:14px;
  border-radius:14px;
}

.terminal{
  margin-top:6px;
  max-height:420px;
  border-radius:18px;
  box-shadow:0 20px 52px rgba(0,0,0,0.22);
}

.terminal-body{
  max-height:360px;
  padding:14px 18px;
  font-size:0.76rem;
}

footer{
  padding:18px 36px;
}

@media(max-width:1450px){
  .hero-grid,.story-grid,.command-grid{
    grid-template-columns:1fr;
  }

  .hero-metrics{
    grid-template-columns:repeat(2, minmax(0,1fr));
  }

  .insight-grid{
    grid-template-columns:1fr 1fr;
  }
}

@media(max-width:1100px){
  main{
    padding:18px;
  }

  .insight-grid,.command-grid,.story-grid{
    grid-template-columns:1fr;
  }

  .module-grid{
    grid-template-columns:repeat(3,1fr);
  }
}

@media(max-width:760px){
  header{
    height:auto;
    padding:14px 16px;
    align-items:flex-start;
    gap:14px;
    flex-direction:column;
  }

  .header-right{
    width:100%;
    justify-content:flex-start;
    flex-wrap:wrap;
  }

  .hero-panel{
    padding:22px;
    min-height:auto;
  }

  .hero-title{
    font-size:2.15rem;
  }

  .hero-metrics,.hero-side-grid{
    grid-template-columns:1fr;
  }

  .hero-mini-wide{
    grid-column:span 1;
  }

  .module-grid{
    grid-template-columns:repeat(2,1fr);
  }
}

@media(max-width:600px){
  .kpi-grid,.hero-metrics,.hero-side-grid,.module-grid,.soc-summary{
    grid-template-columns:1fr;
  }

  .hero-mini-wide{
    grid-column:span 1;
  }
}
</style>
</head>
<body>
<canvas id="matrix-canvas"></canvas>

<div class="app">
<header>
  <div class="logo">
    <div class="logo-ascii">╔═╗┬ ┬┌┐ ┌─┐┬─┐
║  └┬┘├┴┐├┤ ├┬┘
╚═╝ ┴ └─┘└─┘┴└─</div>
    <div>
      <div class="logo-text">Cyber<em>Sim</em>6</div>
    </div>
  </div>
  <div class="header-right">
    <div class="pill"><div class="dot-live"></div><span id="sessionId">INITIALIZING...</span></div>
    <div class="pill">
      <div class="refresh-ring" id="refreshRing"><div class="refresh-ring-inner"></div></div>
      <span id="refreshTimer">2s</span>
    </div>
  </div>
</header>

<main>
  <section class="hero-grid">
    <section class="hero-panel hero-shell">
      <div class="hero-kicker">Cyber Defense War Room</div>
      <h1 class="hero-title">Live command, replay, triage and ATT&amp;CK correlation on one cinematic surface.</h1>
      <p class="hero-copy">
        A larger, more tactical command center for CyberSim6: real-time telemetry, forensic replay,
        analyst posture and campaign visibility brought together in a board that feels built for operations.
      </p>
      <div class="hero-status-row">
        <div class="hero-badge">Ops Mode <strong id="heroMode">LIVE</strong></div>
        <div class="hero-badge">Threat Level <strong id="heroThreatLevel">SAFE</strong></div>
        <div class="hero-badge">Replay Session <strong id="heroReplaySession">-</strong></div>
        <div class="hero-badge">Observed Techniques <strong id="heroTechniqueCount">0</strong></div>
      </div>
      <div class="hero-metrics">
        <div class="hero-metric">
          <div class="hero-metric-label">Threat Pressure</div>
          <div class="hero-metric-value" id="heroThreatScore">0.0</div>
          <div class="hero-metric-sub">composite live score</div>
        </div>
        <div class="hero-metric">
          <div class="hero-metric-label">Coverage</div>
          <div class="hero-metric-value" id="heroCoverage">0%</div>
          <div class="hero-metric-sub">core modules represented</div>
        </div>
        <div class="hero-metric">
          <div class="hero-metric-label">Kill Chain Depth</div>
          <div class="hero-metric-value" id="heroChainDepth">0</div>
          <div class="hero-metric-sub">mapped tactical stages</div>
        </div>
        <div class="hero-metric">
          <div class="hero-metric-label">Ops Tempo</div>
          <div class="hero-metric-value" id="heroTempo">LIVE</div>
          <div class="hero-metric-sub">replay progression or event volume</div>
        </div>
      </div>
    </section>

    <section class="hero-panel hero-side">
      <div class="panel-hd">
        <div class="panel-title"><span class="dot"></span>Battle Focus</div>
        <span class="panel-badge" id="heroFocusBadge">nominal</span>
      </div>
      <div class="hero-side-grid">
        <div class="hero-mini">
          <div class="hero-mini-label">Incident Pressure</div>
          <div class="hero-mini-value" id="heroPressure">0</div>
          <div class="hero-mini-meta" id="heroPressureMeta">No open incidents</div>
        </div>
        <div class="hero-mini">
          <div class="hero-mini-label">Telemetry Integrity</div>
          <div class="hero-mini-value" id="heroIntegrity">LOCKED</div>
          <div class="hero-mini-meta" id="heroIntegrityMeta">Audit chain verified</div>
        </div>
        <div class="hero-mini hero-mini-wide">
          <div class="hero-mini-label">Active Watchlist</div>
          <div class="hero-list" id="heroWatchlist"></div>
        </div>
        <div class="hero-mini hero-mini-wide">
          <div class="hero-mini-label">Dominant Modules</div>
          <div class="hero-tags" id="heroDominantModules"></div>
          <div class="hero-brief" id="heroBrief">Telemetry is online. Launch a replay or activate modules to illuminate the command surface.</div>
        </div>
      </div>
    </section>
  </section>

  <!-- KPI Row -->
  <div class="kpi-grid">
    <div class="kpi g">
      <span class="kpi-icon">📡</span>
      <div class="kpi-label">Total Events</div>
      <div class="kpi-value" id="kTotal">0</div>
      <div class="kpi-sub">all modules</div>
    </div>
    <div class="kpi r">
      <span class="kpi-icon">⚡</span>
      <div class="kpi-label">Attacks</div>
      <div class="kpi-value" id="kAttacks">0</div>
      <div class="kpi-sub">simulated</div>
    </div>
    <div class="kpi c">
      <span class="kpi-icon">🛡</span>
      <div class="kpi-label">Detections</div>
      <div class="kpi-value" id="kDetect">0</div>
      <div class="kpi-sub">threats caught</div>
    </div>
    <div class="kpi p">
      <span class="kpi-icon">🔬</span>
      <div class="kpi-label">Modules Active</div>
      <div class="kpi-value" id="kModules">0</div>
      <div class="kpi-sub" id="kModList">—</div>
    </div>
  </div>

  <!-- Row 1: Module bars + Charts -->
  <div class="story-grid">
    <div class="panel panel-xl">
      <div class="panel-hd">
        <div class="panel-title"><span class="dot"></span>Events by Module</div>
        <span class="panel-badge" id="bdgModules">0 modules</span>
      </div>
      <div class="panel-body" id="moduleChart"></div>
    </div>

    <div class="panel panel-xl">
      <div class="panel-hd">
        <div class="panel-title"><span class="dot"></span>Timeline (last 20 min)</div>
        <span class="panel-badge" id="bdgTimeline">live</span>
      </div>
      <div class="panel-body">
        <div class="chart-wrap"><canvas id="timelineChart"></canvas></div>
      </div>
    </div>
  </div>

  <!-- Row 2: Status bars + Doughnut + Module Cards -->
  <div class="insight-grid">
    <div class="panel">
      <div class="panel-hd">
        <div class="panel-title"><span class="dot"></span>By Status</div>
        <span class="panel-badge" id="bdgStatus">—</span>
      </div>
      <div class="panel-body" id="statusChart"></div>
    </div>

    <div class="panel">
      <div class="panel-hd">
        <div class="panel-title"><span class="dot"></span>Distribution</div>
        <span class="panel-badge">doughnut</span>
      </div>
      <div class="panel-body" style="display:flex;align-items:center;justify-content:center;">
        <div class="chart-wrap"><canvas id="doughnutChart"></canvas></div>
      </div>
    </div>

    <div class="panel">
      <div class="panel-hd">
        <div class="panel-title"><span class="dot"></span>Module Status</div>
        <span class="panel-badge" id="bdgModCards">6 modules</span>
      </div>
      <div class="panel-body">
        <div class="module-grid" id="moduleCards"></div>
      </div>
    </div>
  </div>

  <div class="command-grid">
    <div class="panel">
      <div class="panel-hd">
        <div class="panel-title"><span class="dot"></span>SOC Mode</div>
        <span class="panel-badge" id="bdgSoc">triage</span>
      </div>
      <div class="panel-body">
        <div class="soc-summary">
          <div class="soc-chip"><div class="lbl">Threat Score</div><div class="val" id="socThreatScore">0</div></div>
          <div class="soc-chip"><div class="lbl">Threat Level</div><div class="val" id="socThreatLevel">safe</div></div>
          <div class="soc-chip"><div class="lbl">Open Incidents</div><div class="val" id="socIncidentCount">0</div></div>
        </div>
        <div class="incident-list" id="socIncidents"></div>
      </div>
    </div>

    <div class="panel">
      <div class="panel-hd">
        <div class="panel-title"><span class="dot"></span>Replay &amp; Forensics</div>
        <span class="panel-badge" id="bdgReplay">live</span>
      </div>
      <div class="panel-body">
        <div class="btn-row">
          <button class="pill-btn" id="btnReplayToggle" type="button">Play Replay</button>
          <button class="pill-btn warn" id="btnReplayStep" type="button">Step +10</button>
          <button class="pill-btn" id="btnReplayReset" type="button">Reset</button>
          <button class="pill-btn danger" id="btnReplayLive" type="button">Back To Live</button>
        </div>
        <div class="soc-summary" style="margin-bottom:12px;">
          <div class="replay-chip"><div class="lbl">Mode</div><div class="val" id="replayMode">live</div></div>
          <div class="replay-chip"><div class="lbl">Session</div><div class="val" id="replaySession">-</div></div>
          <div class="replay-chip"><div class="lbl">Progress</div><div class="val" id="replayProgress">0%</div></div>
        </div>
        <div class="replay-list" id="replaySessions"></div>
      </div>
    </div>

    <div class="panel">
      <div class="panel-hd">
        <div class="panel-title"><span class="dot"></span>ATT&amp;CK Command Center</div>
        <span class="panel-badge" id="bdgAttackMap">matrix</span>
      </div>
      <div class="panel-body">
        <div class="attack-list" id="attackTechniques"></div>
        <div class="killchain" id="attackKillChain" style="margin-top:12px;"></div>
      </div>
    </div>
  </div>

  <!-- Terminal -->
  <div class="terminal" style="margin-bottom:24px;">
    <div class="terminal-bar">
      <div class="t-dot t-red"></div>
      <div class="t-dot t-yellow"></div>
      <div class="t-dot t-green"></div>
      <div class="terminal-title">root@cybersim6:~# tail -f /var/log/threats.log &nbsp;<span id="termCursor" style="animation:beat 1s infinite;color:var(--neon);">█</span></div>
    </div>
    <div class="terminal-body" id="termFeed"></div>
  </div>
</main>

<footer>
  <span>▸ CyberSim6 v1.0.0</span>
  <span>▸ EMSI Tanger — 4IIR 2025-2026</span>
  <span>▸ Framework: NIST/MITRE ATT&amp;CK</span>
  <span id="footerTime">▸ --:--:--</span>
</footer>
</div>

<script>
/* ════════════════════════════════════
   MATRIX RAIN
════════════════════════════════════ */
(function(){
  const canvas=document.getElementById('matrix-canvas');
  const ctx=canvas.getContext('2d');
  let W,H,cols,drops;
  const CHARS='アイウエオカキクケコサシスセソタチツテトナニヌネノハヒフヘホマミムメモヤユヨラリルレロワヲン01';
  function resize(){
    W=canvas.width=window.innerWidth;
    H=canvas.height=window.innerHeight;
    cols=Math.floor(W/16);
    drops=Array(cols).fill(1);
  }
  resize();
  window.addEventListener('resize',resize);
  function draw(){
    ctx.fillStyle='rgba(5,8,16,0.05)';
    ctx.fillRect(0,0,W,H);
    ctx.fillStyle='#00ff41';
    ctx.font='13px JetBrains Mono,monospace';
    for(let i=0;i<drops.length;i++){
      const c=CHARS[Math.floor(Math.random()*CHARS.length)];
      ctx.fillText(c,i*16,drops[i]*16);
      if(drops[i]*16>H&&Math.random()>0.975) drops[i]=0;
      drops[i]++;
    }
  }
  setInterval(draw,50);
})();

/* ════════════════════════════════════
   REFRESH RING
════════════════════════════════════ */
const REFRESH_MS=2000;
let _lastRefresh=Date.now();
function updateRing(){
  const elapsed=Date.now()-_lastRefresh;
  const pct=Math.min(elapsed/REFRESH_MS,1);
  const deg=Math.round(pct*360);
  const ring=document.getElementById('refreshRing');
  ring.style.background=`conic-gradient(var(--cyan) ${deg}deg, rgba(0,212,255,0.1) ${deg}deg)`;
  const rem=Math.ceil((REFRESH_MS-elapsed)/1000);
  document.getElementById('refreshTimer').textContent=rem+'s';
  document.getElementById('footerTime').textContent='▸ '+new Date().toLocaleTimeString();
}
setInterval(updateRing,100);

/* ════════════════════════════════════
   COLOR HELPERS
════════════════════════════════════ */
const MOD_MAP={
  ddos:'b-ddos',sqli:'b-sqli',bruteforce:'b-bf',
  xss:'b-xss',phishing:'b-phi',ransomware:'b-rns'
};
const MOD_CARD_MAP={
  ddos:{cls:'active-ddos',color:'#ff0040',name:'DDoS'},
  sqli:{cls:'active-sqli',color:'#ffd700',name:'SQLi'},
  bruteforce:{cls:'active-bf',color:'#00d4ff',name:'Brute Force'},
  xss:{cls:'active-xss',color:'#b44fff',name:'XSS'},
  phishing:{cls:'active-phi',color:'#00ff41',name:'Phishing'},
  ransomware:{cls:'active-rns',color:'#ff6b00',name:'Ransomware'},
};
const STATUS_MAP={info:'b-info',warning:'b-warn',error:'b-err'};

function escapeHtml(value){
  return String(value ?? '').replace(/[&<>"']/g, (char) => ({
    '&':'&amp;',
    '<':'&lt;',
    '>':'&gt;',
    '"':'&quot;',
    "'":'&#39;',
  }[char]));
}

function modClass(mod){
  for(const[k,v]of Object.entries(MOD_MAP)) if(mod.includes(k)) return v;
  return 'b-def';
}
function modKey(mod){
  for(const k of Object.keys(MOD_MAP)) if(mod.includes(k)) return k;
  return null;
}

/* ════════════════════════════════════
   COUNT-UP ANIMATION
════════════════════════════════════ */
const _prev={};
function countUp(id,target){
  const el=document.getElementById(id);
  if(!el) return;
  const from=_prev[id]||0;
  if(from===target){el.textContent=target;return;}
  const steps=20,diff=target-from;
  let step=0;
  const iv=setInterval(()=>{
    step++;
    el.textContent=Math.round(from+diff*(step/steps));
    if(step>=steps){clearInterval(iv);el.textContent=target;}
  },30);
  _prev[id]=target;
}

/* ════════════════════════════════════
   RENDER: MODULE BARS
════════════════════════════════════ */
function renderBars(containerId,data,classMap,badgeId){
  const el=document.getElementById(containerId);
  if(!el) return;
  const entries=Object.entries(data).sort((a,b)=>b[1]-a[1]);
  const max=Math.max(...entries.map(e=>e[1]),1);
  if(badgeId) document.getElementById(badgeId).textContent=entries.length+' types';
  let h='<div class="bars">';
  for(const[lbl,cnt]of entries){
    const pct=Math.max(cnt/max*100,3).toFixed(1);
    const cls=classMap(lbl);
    h+=`<div class="bar-row"><span class="bar-lbl">${escapeHtml(lbl)}</span>
    <div class="bar-track"><div class="bar-fill ${cls}" style="width:${pct}%">${cnt}</div></div></div>`;
  }
  h+='</div>';
  el.innerHTML=h;
}

/* ════════════════════════════════════
   CHART.JS INSTANCES
════════════════════════════════════ */
let timelineChart=null,doughnutChart=null;

const CHART_DEFAULTS={
  color:'rgba(200,216,240,0.7)',
  borderColor:'transparent',
};

function initCharts(){
  Chart.defaults.color=CHART_DEFAULTS.color;
  Chart.defaults.borderColor='rgba(26,34,54,0.8)';

  // Timeline line chart
  timelineChart=new Chart(document.getElementById('timelineChart'),{
    type:'line',
    data:{labels:[],datasets:[{
      label:'Events/min',data:[],
      borderColor:'#00d4ff',backgroundColor:'rgba(0,212,255,0.08)',
      borderWidth:2,pointRadius:3,pointBackgroundColor:'#00d4ff',
      fill:true,tension:0.4,
    }]},
    options:{
      responsive:true,maintainAspectRatio:false,
      plugins:{legend:{display:false}},
      scales:{
        x:{ticks:{font:{family:'JetBrains Mono',size:10},maxTicksLimit:6},grid:{color:'rgba(26,34,54,0.8)'}},
        y:{ticks:{font:{family:'JetBrains Mono',size:10}},grid:{color:'rgba(26,34,54,0.8)'},beginAtZero:true},
      },
      animation:{duration:600},
    },
  });

  // Doughnut
  doughnutChart=new Chart(document.getElementById('doughnutChart'),{
    type:'doughnut',
    data:{labels:[],datasets:[{data:[],
      backgroundColor:['#ff0040','#ffd700','#00d4ff','#b44fff','#00ff41','#ff6b00'],
      borderWidth:0,hoverOffset:6,
    }]},
    options:{
      responsive:true,maintainAspectRatio:false,
      plugins:{
        legend:{position:'right',labels:{font:{family:'JetBrains Mono',size:10},boxWidth:12,padding:12}},
      },
      animation:{duration:600},
    },
  });
}

/* ════════════════════════════════════
   MODULE CARDS
════════════════════════════════════ */
function renderModuleCards(eventsByModule){
  const el=document.getElementById('moduleCards');
  if(!el) return;
  const activeKeys=new Set(Object.keys(eventsByModule).map(k=>{
    for(const mk of Object.keys(MOD_CARD_MAP)) if(k.includes(mk)) return mk;
    return null;
  }).filter(Boolean));

  let h='';
  for(const[key,info]of Object.entries(MOD_CARD_MAP)){
    const isActive=activeKeys.has(key);
    const count=Object.entries(eventsByModule).filter(([k])=>k.includes(key)).reduce((s,[,v])=>s+v,0);
    const cls=isActive?'mod-card '+info.cls:'mod-card';
    const statusCls=isActive?'mod-status ms-active':'mod-status ms-idle';
    const statusTxt=isActive?'ACTIVE':'IDLE';
    const countStyle=isActive?`color:${info.color};text-shadow:0 0 12px ${info.color}66;`:'color:var(--dim);';
    h+=`<div class="${cls}">
      <div class="mod-top"><span class="mod-name">${info.name}</span><span class="${statusCls}">${statusTxt}</span></div>
      <div class="mod-count" style="${countStyle}">${count}</div>
      <div class="mod-label">events</div>
    </div>`;
  }
  el.innerHTML=h;
}

function topEntries(data,limit=4){
  return Object.entries(data||{}).sort((a,b)=>b[1]-a[1]).slice(0,limit);
}

function renderHero(stats,soc,attackMap,replayState){
  const mode=String((stats&&stats.mode)||'live').toUpperCase();
  const threatLevel=String((soc&&soc.threat_level)||'safe').toUpperCase();
  const threatScore=Number((soc&&soc.threat_score)||0);
  const incidentCount=Number((soc&&soc.incidents_open)||0);
  const techniques=(attackMap&&attackMap.techniques)||[];
  const killChain=(attackMap&&attackMap.kill_chain)||[];
  const auditTrail=(soc&&soc.audit_trail)||{};
  const modulesActive=((stats&&stats.modules_active)||[]).length;
  const moduleCoverage=Math.round((modulesActive/Object.keys(MOD_CARD_MAP).length)*100);
  const replayMode=(replayState&&replayState.mode)||'live';
  const replayProgress=Math.round((replayState&&replayState.progress)||0);
  const totalEvents=Number((stats&&stats.total_events)||0);
  const watchItems=[];

  document.getElementById('heroMode').textContent=mode;
  document.getElementById('heroThreatLevel').textContent=threatLevel;
  document.getElementById('heroReplaySession').textContent=(replayState&&replayState.session_id)||'-';
  document.getElementById('heroTechniqueCount').textContent=String(techniques.length);

  document.getElementById('heroThreatScore').textContent=threatScore.toFixed(1);
  document.getElementById('heroCoverage').textContent=`${moduleCoverage}%`;
  document.getElementById('heroChainDepth').textContent=String(killChain.length);
  document.getElementById('heroTempo').textContent=replayMode==='replay' ? `${replayProgress}%` : totalEvents.toLocaleString();

  document.getElementById('heroFocusBadge').textContent=incidentCount
    ? `${incidentCount} active incidents`
    : techniques.length
      ? `${techniques.length} observed techniques`
      : 'nominal';

  document.getElementById('heroPressure').textContent=String(incidentCount);
  document.getElementById('heroPressureMeta').textContent=incidentCount
    ? 'Analyst attention required'
    : 'No open incidents';

  document.getElementById('heroIntegrity').textContent=auditTrail.valid ? 'LOCKED' : 'CHECK';
  document.getElementById('heroIntegrityMeta').textContent=auditTrail.valid
    ? 'Audit chain verified'
    : 'Review telemetry integrity';

  const anomalies=(soc&&soc.anomalies)||[];
  if(anomalies.length){
    watchItems.push(...anomalies.slice(-3).reverse().map((item)=>({
      label:`Anomaly ${item.type||'spike'}`,
      value:`${item.count} evt`,
    })));
  }
  if(!watchItems.length){
    const incidents=(soc&&soc.incidents)||[];
    watchItems.push(...incidents.slice(0,3).map((item)=>({
      label:item.family||item.module||'incident',
      value:String(item.severity||'watch').toUpperCase(),
    })));
  }
  if(!watchItems.length){
    watchItems.push(...techniques.slice(0,3).map((item)=>({
      label:item.name,
      value:item.technique,
    })));
  }
  if(!watchItems.length){
    watchItems.push(
      {label:'Nominal traffic', value:'LIVE'},
      {label:'Awaiting incident chain', value:'IDLE'},
    );
  }

  const watchlist=document.getElementById('heroWatchlist');
  if(watchlist){
    watchlist.innerHTML=watchItems.slice(0,3).map((item)=>`
      <div class="hero-list-item">
        <span>${escapeHtml(item.label)}</span>
        <strong>${escapeHtml(item.value)}</strong>
      </div>
    `).join('');
  }

  const dominant=document.getElementById('heroDominantModules');
  if(dominant){
    const entries=topEntries((stats&&stats.events_by_module)||{},4);
    dominant.innerHTML=entries.length
      ? entries.map(([name,count])=>`<span class="hero-tag">${escapeHtml(name)} <strong>${count}</strong></span>`).join('')
      : '<span class="hero-tag">No modules <strong>idle</strong></span>';
  }

  const brief=document.getElementById('heroBrief');
  if(brief){
    let message='Telemetry is online. Launch a replay or activate modules to illuminate the command surface.';
    if(incidentCount){
      message=`${incidentCount} incident(s) are open with ${techniques.length} ATT&CK technique(s) observed. Prioritize triage and contain the dominant family first.`;
    }else if(replayMode==='replay'){
      message=`Replay session ${(replayState&&replayState.session_id)||'-'} is active at ${replayProgress}% progression. Use it to reconstruct the kill chain and validate detections.`;
    }else if(techniques.length){
      message=`Live telemetry is mapping ${techniques.length} technique(s) across ${killChain.length} kill-chain stage(s). The dashboard is now operating at campaign view.`;
    }
    brief.textContent=message;
  }
}

/* ════════════════════════════════════
   SOC MODE
════════════════════════════════════ */
let replayAutoAdvance=null;

function severityClass(level){
  return `sev-${String(level || 'info').toLowerCase()}`;
}

function renderSoc(data){
  document.getElementById('socThreatScore').textContent=data.threat_score.toFixed ? data.threat_score.toFixed(1) : data.threat_score;
  document.getElementById('socThreatLevel').textContent=String(data.threat_level || 'safe').toUpperCase();
  document.getElementById('socIncidentCount').textContent=data.incidents_open || 0;
  document.getElementById('bdgSoc').textContent=`${data.anomalies.length} anomalies`;
  const el=document.getElementById('socIncidents');
  if(!el) return;
  if(!data.incidents.length){
    el.innerHTML='<div class="incident-item"><div class="incident-msg">// no active incidents</div><div class="incident-meta">Threat telemetry nominal.</div></div>';
    return;
  }
  el.innerHTML=data.incidents.map((incident)=>`
    <div class="incident-item">
      <div class="incident-top">
        <span class="incident-meta">${escapeHtml(incident.id)} · ${escapeHtml(incident.family)}</span>
        <span class="incident-meta ${severityClass(incident.severity)}">${escapeHtml(incident.severity)}</span>
      </div>
      <div class="incident-msg">${escapeHtml(incident.message)}</div>
      <div class="incident-meta">${escapeHtml((incident.timestamp || '').replace('T',' ').slice(0,19))} · ${escapeHtml(incident.source || 'localhost')}</div>
    </div>
  `).join('');
}

/* ════════════════════════════════════
   REPLAY & FORENSICS
════════════════════════════════════ */
function setReplayAutoAdvance(active){
  if(replayAutoAdvance){
    clearInterval(replayAutoAdvance);
    replayAutoAdvance=null;
  }
  const btn=document.getElementById('btnReplayToggle');
  if(btn) btn.textContent=active?'Pause Replay':'Play Replay';
  if(!active) return;
  replayAutoAdvance=setInterval(async ()=>{
    const stateRes=await fetch('/api/replay/state');
    const state=await stateRes.json();
    if(state.mode!=='replay' || state.position>=state.total_events){
      setReplayAutoAdvance(false);
      return;
    }
    await fetch('/api/replay/step?count=8');
    refresh();
  }, 900);
}

async function replayLoad(sessionId){
  await fetch(`/api/replay/load?session=${encodeURIComponent(sessionId)}`);
  setReplayAutoAdvance(false);
  refresh();
}
async function replayStep(count=10){
  await fetch(`/api/replay/step?count=${count}`);
  refresh();
}
async function replayReset(){
  await fetch('/api/replay/reset');
  setReplayAutoAdvance(false);
  refresh();
}
async function replayLive(){
  await fetch('/api/replay/live');
  setReplayAutoAdvance(false);
  refresh();
}

function renderReplay(sessions,state){
  document.getElementById('bdgReplay').textContent=state.mode || 'live';
  document.getElementById('replayMode').textContent=String(state.mode || 'live').toUpperCase();
  document.getElementById('replaySession').textContent=state.session_id || '-';
  document.getElementById('replayProgress').textContent=`${Math.round(state.progress || 0)}%`;
  const list=document.getElementById('replaySessions');
  if(!list) return;
  if(!sessions.length){
    list.innerHTML='<div class="replay-item"><div class="replay-path">// no saved sessions found in logs/</div></div>';
    return;
  }
  list.innerHTML=sessions.slice(0,8).map((session)=>`
    <div class="replay-item">
      <div class="replay-top">
        <span class="replay-meta">${escapeHtml(session.session_id)}</span>
        <div class="replay-session-actions">
          <button class="pill-btn" type="button" onclick="replayLoad('${encodeURIComponent(session.session_id)}')">Load</button>
        </div>
      </div>
      <div class="replay-path">${escapeHtml(session.path)}</div>
      <div class="replay-meta">${session.events} events</div>
    </div>
  `).join('');
}

/* ════════════════════════════════════
   ATT&CK COMMAND CENTER
════════════════════════════════════ */
function renderAttackMap(data){
  document.getElementById('bdgAttackMap').textContent=`${data.techniques.length} techniques`;
  const attackEl=document.getElementById('attackTechniques');
  const chainEl=document.getElementById('attackKillChain');
  if(attackEl){
    attackEl.innerHTML=(data.techniques.length?data.techniques:[{module:'none',technique:'-',tactic:'No activity',name:'Awaiting telemetry',count:0}]).map((item)=>`
      <div class="attack-item">
        <div class="attack-top">
          <span class="attack-meta">${escapeHtml(item.module)} · ${escapeHtml(item.technique)}</span>
          <span class="attack-meta">${item.count}</span>
        </div>
        <div class="attack-name">${escapeHtml(item.name)}</div>
        <div class="attack-meta">${escapeHtml(item.tactic)}</div>
      </div>
    `).join('');
  }
  if(chainEl){
    chainEl.innerHTML=(data.kill_chain.length?data.kill_chain:[{module:'none',technique:'-',tactic:'No chain yet',name:'Waiting for replay or live events'}]).map((step)=>`
      <div class="kill-step">
        <div class="kill-name">${escapeHtml(step.name)}</div>
        <div class="kill-meta">${escapeHtml(step.module)} · ${escapeHtml(step.technique)} · ${escapeHtml(step.tactic)}</div>
      </div>
    `).join('');
  }
}

/* ════════════════════════════════════
   TERMINAL FEED
════════════════════════════════════ */
function renderTerminal(events){
  const el=document.getElementById('termFeed');
  if(!el) return;
  const recent=[...events].reverse().slice(0,80);
  let h='';
  for(const e of recent){
    const t=escapeHtml(e.timestamp?e.timestamp.split('T')[1].substring(0,8):'');
    const msg=escapeHtml((e.details&&e.details.message)||e.event_type);
    const st=escapeHtml((e.details&&e.details.status)||e.status||'info');
    const mod=escapeHtml(e.module);
    const bc={'info':'tb-info','warning':'tb-warning','error':'tb-error'}[st]||'tb-info';
    const prefix=st==='error'?'<span style="color:var(--red)">$</span>':st==='warning'?'<span style="color:var(--yellow)">!</span>':'<span style="color:var(--neon)">▸</span>';
    h+=`<div class="t-line">
      <span class="t-time">${t}</span>
      <span class="t-badge ${bc}">${st}</span>
      <span class="t-mod">${mod}</span>
      <span class="t-msg">${prefix} ${msg}</span>
    </div>`;
  }
  el.innerHTML=h||'<span style="color:var(--dim)">// awaiting events...</span>';
}

/* ════════════════════════════════════
   TIMELINE UPDATE
════════════════════════════════════ */
const timelineBuckets=[];
let lastBucketTime=null;

function updateTimeline(events){
  if(!timelineChart) return;
  const now=new Date();
  const bucketKey=now.getMinutes()+':'+Math.floor(now.getSeconds()/10)*10;
  if(lastBucketTime!==bucketKey){
    lastBucketTime=bucketKey;
    const lbl=now.getHours().toString().padStart(2,'0')+':'+now.getMinutes().toString().padStart(2,'0');
    timelineBuckets.push({label:lbl,count:events.length});
    if(timelineBuckets.length>20) timelineBuckets.shift();
    timelineChart.data.labels=timelineBuckets.map(b=>b.label);
    timelineChart.data.datasets[0].data=timelineBuckets.map(b=>b.count);
    timelineChart.update('none');
  }
}

/* ════════════════════════════════════
   DOUGHNUT UPDATE
════════════════════════════════════ */
function updateDoughnut(eventsByModule){
  if(!doughnutChart) return;
  const entries=Object.entries(eventsByModule).sort((a,b)=>b[1]-a[1]).slice(0,6);
  doughnutChart.data.labels=entries.map(([k])=>k);
  doughnutChart.data.datasets[0].data=entries.map(([,v])=>v);
  doughnutChart.update('none');
}

/* ════════════════════════════════════
   MAIN REFRESH LOOP
════════════════════════════════════ */
async function refresh(){
  try{
    const[sRes,eRes,socRes,mapRes,replaySessionsRes,replayStateRes]=await Promise.all([
      fetch('/api/stats'),
      fetch('/api/events?limit=200'),
      fetch('/api/soc'),
      fetch('/api/attack-map'),
      fetch('/api/replay/sessions'),
      fetch('/api/replay/state'),
    ]);
    const stats=await sRes.json();
    const events=await eRes.json();
    const soc=await socRes.json();
    const attackMap=await mapRes.json();
    const replaySessions=await replaySessionsRes.json();
    const replayState=await replayStateRes.json();

    // KPIs
    document.getElementById('sessionId').textContent=`SID:${stats.session_id} · ${String(stats.mode || 'live').toUpperCase()}`;
    countUp('kTotal',stats.total_events);
    countUp('kAttacks',stats.total_attacks);
    countUp('kDetect',stats.total_detections);
    countUp('kModules',stats.modules_active.length);
    document.getElementById('kModList').textContent=stats.modules_active.slice(0,3).join(' · ')||'—';
    document.getElementById('bdgTimeline').textContent=stats.mode || 'live';

    // Module badge
    document.getElementById('bdgModules').textContent=Object.keys(stats.events_by_module).length+' modules';

    // Bar charts
    renderBars('moduleChart',stats.events_by_module,modClass,'');
    renderBars('statusChart',stats.events_by_status,s=>STATUS_MAP[s]||'b-def','bdgStatus');

    // Module cards
    renderModuleCards(stats.events_by_module);

    // Charts
    updateTimeline(events);
    updateDoughnut(stats.events_by_module);

    // Terminal
    renderTerminal(events);

    // Command center
    renderHero(stats,soc,attackMap,replayState);
    renderSoc(soc);
    renderReplay(replaySessions,replayState);
    renderAttackMap(attackMap);

    _lastRefresh=Date.now();
  }catch(e){
    document.getElementById('sessionId').textContent='DISCONNECTED';
  }
}

document.getElementById('btnReplayToggle').addEventListener('click', async () => {
  const stateRes=await fetch('/api/replay/state');
  const state=await stateRes.json();
  if(state.mode!=='replay'){
    const sessionsRes=await fetch('/api/replay/sessions');
    const sessions=await sessionsRes.json();
    if(sessions.length){
      await replayLoad(sessions[0].session_id);
      setReplayAutoAdvance(true);
    }
    return;
  }
  setReplayAutoAdvance(!replayAutoAdvance);
});
document.getElementById('btnReplayStep').addEventListener('click',()=>replayStep(10));
document.getElementById('btnReplayReset').addEventListener('click',()=>replayReset());
document.getElementById('btnReplayLive').addEventListener('click',()=>replayLive());

initCharts();
refresh();
setInterval(refresh,REFRESH_MS);
</script>
</body>
</html>"""
