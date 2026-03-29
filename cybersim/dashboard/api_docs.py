"""
CyberSim6 - Dashboard REST API Documentation

OpenAPI 3.0 specification and local interactive docs for the CyberSim6 dashboard endpoints.
"""

from cybersim import __version__

OPENAPI_SPEC: dict = {
    "openapi": "3.0.3",
    "info": {
        "title": "CyberSim6 Dashboard API",
        "description": (
            "REST API for the CyberSim6 Threat Intelligence Dashboard. "
            "Provides real-time access to security events, SOC metrics, "
            "MITRE ATT&CK mapping, timeline data, and session replay controls."
        ),
        "version": __version__,
        "contact": {
            "name": "CyberSim6 Team",
        },
        "license": {
            "name": "MIT",
        },
    },
    "servers": [
        {
            "url": "http://127.0.0.1:8888",
            "description": "Local development server",
        },
    ],
    "tags": [
        {"name": "dashboard", "description": "Dashboard HTML interface"},
        {"name": "events", "description": "Security event retrieval and filtering"},
        {"name": "stats", "description": "Aggregate statistics for the current session"},
        {"name": "timeline", "description": "Chronological event timeline"},
        {"name": "soc", "description": "SOC snapshot with threat scoring, incidents, and anomalies"},
        {"name": "attack-map", "description": "MITRE ATT&CK technique and tactic mapping"},
        {"name": "replay", "description": "Session replay controls (load, step, reset, live)"},
        {"name": "docs", "description": "API documentation"},
    ],
    "paths": {
        "/": {
            "get": {
                "tags": ["dashboard"],
                "summary": "Serve the dashboard UI",
                "description": "Returns the full HTML page for the CyberSim6 Threat Intelligence Dashboard.",
                "operationId": "getDashboard",
                "responses": {
                    "200": {
                        "description": "Dashboard HTML page",
                        "content": {
                            "text/html": {
                                "schema": {"type": "string"},
                            },
                        },
                    },
                },
            },
        },
        "/dashboard": {
            "get": {
                "tags": ["dashboard"],
                "summary": "Serve the dashboard UI (alias)",
                "description": "Alias for /. Returns the same dashboard HTML page.",
                "operationId": "getDashboardAlias",
                "responses": {
                    "200": {
                        "description": "Dashboard HTML page",
                        "content": {
                            "text/html": {
                                "schema": {"type": "string"},
                            },
                        },
                    },
                },
            },
        },
        "/api/events": {
            "get": {
                "tags": ["events"],
                "summary": "List security events",
                "description": (
                    "Retrieve security events from the current session or replay. "
                    "Supports filtering by module and limiting the result count."
                ),
                "operationId": "getEvents",
                "parameters": [
                    {
                        "name": "module",
                        "in": "query",
                        "required": False,
                        "description": "Filter events by module name.",
                        "schema": {"type": "string"},
                        "example": "xss",
                    },
                    {
                        "name": "limit",
                        "in": "query",
                        "required": False,
                        "description": "Maximum number of events to return (1-500, default 100).",
                        "schema": {"type": "integer", "default": 100, "minimum": 1, "maximum": 500},
                    },
                ],
                "responses": {
                    "200": {
                        "description": "Array of event objects",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "array",
                                    "items": {"$ref": "#/components/schemas/Event"},
                                },
                                "example": [
                                    {
                                        "timestamp": "2026-03-28T10:00:00",
                                        "module": "xss",
                                        "module_type": "attack",
                                        "event_type": "xss_injection",
                                        "source": "192.168.1.10",
                                        "status": "warning",
                                        "details": {"message": "Reflected XSS detected in search param"},
                                    },
                                ],
                            },
                        },
                    },
                },
            },
        },
        "/api/stats": {
            "get": {
                "tags": ["stats"],
                "summary": "Get aggregate statistics",
                "description": (
                    "Returns aggregate counts and breakdowns for the current session, "
                    "including totals by module, event type, and status."
                ),
                "operationId": "getStats",
                "responses": {
                    "200": {
                        "description": "Session statistics",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/Stats"},
                                "example": {
                                    "total_events": 42,
                                    "total_attacks": 18,
                                    "total_detections": 24,
                                    "session_id": "abc123",
                                    "events_by_module": {"xss": 10, "phishing": 8},
                                    "events_by_type": {"xss_injection": 10},
                                    "events_by_status": {"info": 20, "warning": 15, "error": 7},
                                    "modules_active": ["xss", "phishing"],
                                    "mode": "live",
                                    "replay_session_id": None,
                                },
                            },
                        },
                    },
                },
            },
        },
        "/api/timeline": {
            "get": {
                "tags": ["timeline"],
                "summary": "Get event timeline",
                "description": "Returns the last 200 events in a compact timeline format for charting.",
                "operationId": "getTimeline",
                "responses": {
                    "200": {
                        "description": "Array of timeline entries",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "array",
                                    "items": {"$ref": "#/components/schemas/TimelineEntry"},
                                },
                                "example": [
                                    {
                                        "t": "2026-03-28T10:00:00",
                                        "module": "xss",
                                        "type": "xss_injection",
                                        "status": "warning",
                                        "msg": "Reflected XSS detected",
                                    },
                                ],
                            },
                        },
                    },
                },
            },
        },
        "/api/soc": {
            "get": {
                "tags": ["soc"],
                "summary": "Get SOC snapshot",
                "description": (
                    "Computes and returns a SOC-style snapshot including threat score, "
                    "threat level, open incidents, module breakdown, anomalies, and audit trail integrity."
                ),
                "operationId": "getSocSnapshot",
                "responses": {
                    "200": {
                        "description": "SOC snapshot data",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/SocSnapshot"},
                                "example": {
                                    "threat_score": 0.65,
                                    "threat_level": "high",
                                    "incidents_open": 5,
                                    "incidents": [],
                                    "module_breakdown": {"xss": 0.45, "phishing": 0.20},
                                    "anomalies": [],
                                    "audit_trail": {
                                        "valid": True,
                                        "entries": 42,
                                        "last_valid_index": 41,
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
        "/api/attack-map": {
            "get": {
                "tags": ["attack-map"],
                "summary": "Get MITRE ATT&CK mapping",
                "description": (
                    "Returns MITRE ATT&CK technique and tactic mapping for current events, "
                    "including a reconstructed kill chain."
                ),
                "operationId": "getAttackMap",
                "responses": {
                    "200": {
                        "description": "ATT&CK mapping data",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/AttackMap"},
                                "example": {
                                    "techniques": [
                                        {
                                            "module": "xss",
                                            "count": 10,
                                            "technique": "T1189",
                                            "tactic": "Initial Access",
                                            "name": "Drive-by Compromise",
                                        },
                                    ],
                                    "tactics": [{"tactic": "Initial Access", "count": 10}],
                                    "kill_chain": [],
                                },
                            },
                        },
                    },
                },
            },
        },
        "/api/replay/sessions": {
            "get": {
                "tags": ["replay"],
                "summary": "List available replay sessions",
                "description": "Returns a list of saved session log files available for replay.",
                "operationId": "getReplaySessions",
                "responses": {
                    "200": {
                        "description": "Array of available sessions",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "array",
                                    "items": {"$ref": "#/components/schemas/ReplaySession"},
                                },
                                "example": [
                                    {
                                        "session_id": "20260328_100000",
                                        "events": 150,
                                        "path": "logs/session_20260328_100000.json",
                                    },
                                ],
                            },
                        },
                    },
                },
            },
        },
        "/api/replay/state": {
            "get": {
                "tags": ["replay"],
                "summary": "Get current replay state",
                "description": "Returns the current replay mode, position, and progress.",
                "operationId": "getReplayState",
                "responses": {
                    "200": {
                        "description": "Current replay state",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/ReplayState"},
                                "example": {
                                    "mode": "replay",
                                    "session_id": "20260328_100000",
                                    "position": 30,
                                    "total_events": 150,
                                    "progress": 20.0,
                                },
                            },
                        },
                    },
                },
            },
        },
        "/api/replay/load": {
            "get": {
                "tags": ["replay"],
                "summary": "Load a session for replay",
                "description": "Loads a saved session by ID and enters replay mode. Position starts at min(10, total_events).",
                "operationId": "loadReplaySession",
                "parameters": [
                    {
                        "name": "session",
                        "in": "query",
                        "required": True,
                        "description": "Session ID to load for replay.",
                        "schema": {"type": "string"},
                        "example": "20260328_100000",
                    },
                ],
                "responses": {
                    "200": {
                        "description": "Replay state after loading the session",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/ReplayState"},
                            },
                        },
                    },
                    "400": {
                        "description": "Missing session parameter",
                    },
                    "404": {
                        "description": "Session not found",
                    },
                },
            },
        },
        "/api/replay/step": {
            "get": {
                "tags": ["replay"],
                "summary": "Step forward in replay",
                "description": "Advance the replay position by a given number of events (default 10, max 100).",
                "operationId": "stepReplay",
                "parameters": [
                    {
                        "name": "count",
                        "in": "query",
                        "required": False,
                        "description": "Number of events to step forward (1-100, default 10).",
                        "schema": {"type": "integer", "default": 10, "minimum": 1, "maximum": 100},
                    },
                ],
                "responses": {
                    "200": {
                        "description": "Replay state after stepping",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/ReplayState"},
                            },
                        },
                    },
                    "400": {
                        "description": "Replay mode is not active",
                    },
                },
            },
        },
        "/api/replay/reset": {
            "get": {
                "tags": ["replay"],
                "summary": "Reset replay position",
                "description": "Resets the replay position back to 0.",
                "operationId": "resetReplay",
                "responses": {
                    "200": {
                        "description": "Replay state after reset",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/ReplayState"},
                            },
                        },
                    },
                },
            },
        },
        "/api/replay/live": {
            "get": {
                "tags": ["replay"],
                "summary": "Switch to live mode",
                "description": "Exits replay mode and switches back to live event streaming.",
                "operationId": "switchToLive",
                "responses": {
                    "200": {
                        "description": "Replay state after switching to live",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/ReplayState"},
                            },
                        },
                    },
                },
            },
        },
        "/api/docs": {
            "get": {
                "tags": ["docs"],
                "summary": "Interactive API docs",
                "description": "Serves a local interactive documentation page for exploring the API.",
                "operationId": "getSwaggerUI",
                "responses": {
                    "200": {
                        "description": "Interactive API documentation HTML page",
                        "content": {
                            "text/html": {
                                "schema": {"type": "string"},
                            },
                        },
                    },
                },
            },
        },
        "/api/openapi.json": {
            "get": {
                "tags": ["docs"],
                "summary": "OpenAPI specification",
                "description": "Returns the OpenAPI 3.0 JSON specification for this API.",
                "operationId": "getOpenAPISpec",
                "responses": {
                    "200": {
                        "description": "OpenAPI 3.0 specification",
                        "content": {
                            "application/json": {
                                "schema": {"type": "object"},
                            },
                        },
                    },
                },
            },
        },
    },
    "components": {
        "schemas": {
            "Event": {
                "type": "object",
                "properties": {
                    "timestamp": {"type": "string", "format": "date-time", "description": "ISO 8601 timestamp"},
                    "module": {"type": "string", "description": "Source module (e.g. xss, phishing, scanner)"},
                    "module_type": {"type": "string", "description": "Module category (attack or detection)"},
                    "event_type": {"type": "string", "description": "Specific event type identifier"},
                    "source": {"type": "string", "description": "Source IP or hostname"},
                    "status": {"type": "string", "enum": ["info", "warning", "error", "critical"]},
                    "details": {
                        "type": "object",
                        "properties": {
                            "message": {"type": "string"},
                            "status": {"type": "string"},
                        },
                    },
                },
            },
            "Stats": {
                "type": "object",
                "properties": {
                    "total_events": {"type": "integer"},
                    "total_attacks": {"type": "integer"},
                    "total_detections": {"type": "integer"},
                    "session_id": {"type": "string"},
                    "events_by_module": {"type": "object", "additionalProperties": {"type": "integer"}},
                    "events_by_type": {"type": "object", "additionalProperties": {"type": "integer"}},
                    "events_by_status": {"type": "object", "additionalProperties": {"type": "integer"}},
                    "modules_active": {"type": "array", "items": {"type": "string"}},
                    "mode": {"type": "string", "enum": ["live", "replay"]},
                    "replay_session_id": {"type": "string", "nullable": True},
                },
            },
            "TimelineEntry": {
                "type": "object",
                "properties": {
                    "t": {"type": "string", "format": "date-time", "description": "Timestamp"},
                    "module": {"type": "string"},
                    "type": {"type": "string", "description": "Event type"},
                    "status": {"type": "string"},
                    "msg": {"type": "string", "description": "Event message"},
                },
            },
            "SocSnapshot": {
                "type": "object",
                "properties": {
                    "threat_score": {"type": "number", "format": "float", "description": "Overall threat score (0-1)"},
                    "threat_level": {"type": "string", "description": "Threat level label"},
                    "incidents_open": {"type": "integer"},
                    "incidents": {
                        "type": "array",
                        "items": {"$ref": "#/components/schemas/Incident"},
                    },
                    "module_breakdown": {
                        "type": "object",
                        "additionalProperties": {"type": "number"},
                        "description": "Per-module threat score breakdown",
                    },
                    "anomalies": {
                        "type": "array",
                        "items": {"$ref": "#/components/schemas/Anomaly"},
                    },
                    "audit_trail": {"$ref": "#/components/schemas/AuditTrailStatus"},
                },
            },
            "Incident": {
                "type": "object",
                "properties": {
                    "id": {"type": "string", "description": "Incident ID (e.g. INC-0001)"},
                    "timestamp": {"type": "string", "format": "date-time"},
                    "severity": {"type": "string", "enum": ["warning", "error", "critical"]},
                    "module": {"type": "string"},
                    "family": {"type": "string"},
                    "event_type": {"type": "string"},
                    "message": {"type": "string"},
                    "source": {"type": "string"},
                },
            },
            "Anomaly": {
                "type": "object",
                "properties": {
                    "timestamp": {"type": "string", "format": "date-time"},
                    "count": {"type": "integer"},
                    "score": {"type": "number", "format": "float"},
                    "type": {"type": "string"},
                    "z_score": {"type": "number", "format": "float"},
                },
            },
            "AuditTrailStatus": {
                "type": "object",
                "properties": {
                    "valid": {"type": "boolean", "description": "Whether the audit chain is valid"},
                    "entries": {"type": "integer", "description": "Total audit entries"},
                    "last_valid_index": {"type": "integer"},
                },
            },
            "AttackMap": {
                "type": "object",
                "properties": {
                    "techniques": {
                        "type": "array",
                        "items": {"$ref": "#/components/schemas/Technique"},
                    },
                    "tactics": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "tactic": {"type": "string"},
                                "count": {"type": "integer"},
                            },
                        },
                    },
                    "kill_chain": {
                        "type": "array",
                        "items": {"$ref": "#/components/schemas/Technique"},
                    },
                },
            },
            "Technique": {
                "type": "object",
                "properties": {
                    "module": {"type": "string"},
                    "count": {"type": "integer"},
                    "technique": {"type": "string", "description": "MITRE technique ID (e.g. T1189)"},
                    "tactic": {"type": "string", "description": "MITRE tactic name"},
                    "name": {"type": "string", "description": "Technique display name"},
                },
            },
            "ReplaySession": {
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                    "events": {"type": "integer", "description": "Number of events in session"},
                    "path": {"type": "string", "description": "Path to session log file"},
                },
            },
            "ReplayState": {
                "type": "object",
                "properties": {
                    "mode": {"type": "string", "enum": ["live", "replay"]},
                    "session_id": {"type": "string", "nullable": True},
                    "position": {"type": "integer", "description": "Current event position"},
                    "total_events": {"type": "integer"},
                    "progress": {"type": "number", "format": "float", "description": "Progress percentage (0-100)"},
                },
            },
        },
    },
}


def get_openapi_spec() -> dict:
    """Return the OpenAPI 3.0 specification as a Python dictionary."""
    return OPENAPI_SPEC


def serve_swagger_ui(handler) -> None:
    """Serve the local API documentation page via the given HTTP request handler.

    Args:
        handler: A BaseHTTPRequestHandler instance used to write the response.
    """
    html = _SWAGGER_HTML
    handler.send_response(200)
    handler.send_header("Content-Type", "text/html; charset=utf-8")
    handler.end_headers()
    handler.wfile.write(html.encode("utf-8"))


_SWAGGER_HTML = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CyberSim6 API Documentation</title>
<style>
  :root {
    color-scheme: dark;
    --bg: #0d1117;
    --panel: #111827;
    --panel-border: #1f2937;
    --text: #e5e7eb;
    --muted: #9ca3af;
    --accent: #38bdf8;
    --accent-soft: rgba(56, 189, 248, 0.16);
    --success: #22c55e;
    --warning: #f59e0b;
  }

  * {
    box-sizing: border-box;
  }

  body {
    margin: 0;
    font-family: "Segoe UI", Tahoma, Geneva, Verdana, sans-serif;
    background:
      radial-gradient(circle at top, rgba(56, 189, 248, 0.12), transparent 32%),
      linear-gradient(180deg, #0b1220 0%, var(--bg) 100%);
    color: var(--text);
  }

  .shell {
    max-width: 1180px;
    margin: 0 auto;
    padding: 32px 20px 64px;
  }

  .hero {
    padding: 24px;
    border: 1px solid var(--panel-border);
    border-radius: 18px;
    background: rgba(17, 24, 39, 0.9);
    box-shadow: 0 20px 50px rgba(0, 0, 0, 0.25);
  }

  .eyebrow {
    display: inline-block;
    margin-bottom: 12px;
    padding: 6px 10px;
    border-radius: 999px;
    background: var(--accent-soft);
    color: var(--accent);
    font-size: 12px;
    font-weight: 700;
    letter-spacing: 0.08em;
    text-transform: uppercase;
  }

  h1 {
    margin: 0 0 8px;
    font-size: clamp(28px, 4vw, 42px);
  }

  .hero p {
    margin: 0;
    color: var(--muted);
    line-height: 1.6;
    max-width: 780px;
  }

  .meta {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 12px;
    margin-top: 20px;
  }

  .meta-card {
    padding: 14px 16px;
    border-radius: 14px;
    background: rgba(15, 23, 42, 0.88);
    border: 1px solid var(--panel-border);
  }

  .meta-card strong {
    display: block;
    margin-bottom: 4px;
    color: #f8fafc;
    font-size: 14px;
  }

  .meta-card span {
    color: var(--muted);
    font-size: 13px;
  }

  #swagger-ui {
    display: grid;
    gap: 16px;
    margin-top: 24px;
  }

  .status {
    padding: 16px 18px;
    border-radius: 14px;
    border: 1px solid var(--panel-border);
    background: rgba(15, 23, 42, 0.88);
    color: var(--muted);
  }

  .endpoint {
    overflow: hidden;
    border: 1px solid var(--panel-border);
    border-radius: 16px;
    background: rgba(17, 24, 39, 0.92);
  }

  .endpoint summary {
    list-style: none;
    display: flex;
    align-items: center;
    gap: 12px;
    cursor: pointer;
    padding: 18px 20px;
  }

  .endpoint summary::-webkit-details-marker {
    display: none;
  }

  .method {
    min-width: 62px;
    text-align: center;
    padding: 6px 10px;
    border-radius: 999px;
    background: rgba(34, 197, 94, 0.16);
    color: var(--success);
    font-weight: 700;
    font-size: 12px;
    letter-spacing: 0.08em;
  }

  .path {
    font-family: Consolas, "Courier New", monospace;
    color: #f8fafc;
    font-size: 15px;
  }

  .summary {
    color: var(--muted);
    font-size: 14px;
  }

  .endpoint-body {
    padding: 0 20px 20px;
    color: var(--muted);
    line-height: 1.6;
  }

  .endpoint-body h3 {
    margin: 18px 0 8px;
    color: #f8fafc;
    font-size: 15px;
  }

  .tag-list,
  .server-list,
  .parameter-list,
  .response-list {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
  }

  .pill,
  .param,
  .response {
    padding: 7px 10px;
    border-radius: 999px;
    background: rgba(15, 23, 42, 0.92);
    border: 1px solid var(--panel-border);
    font-size: 13px;
  }

  .response code,
  .param code,
  .server-list code {
    font-family: Consolas, "Courier New", monospace;
  }

  .empty {
    color: var(--muted);
    font-style: italic;
  }

  .footer-note {
    margin-top: 12px;
    color: var(--warning);
    font-size: 13px;
  }
</style>
</head>
<body>
<main class="shell">
  <section class="hero">
    <span class="eyebrow">Local API Explorer</span>
    <h1>CyberSim6 API Documentation</h1>
    <p>
      This page is rendered entirely from local assets and fetches its schema from
      <code>/api/openapi.json</code>. It gives you a quick interactive overview of
      the dashboard API without relying on external CDNs.
    </p>
    <div class="meta" id="meta"></div>
  </section>

  <section id="swagger-ui">
    <div class="status">Loading local API documentation...</div>
  </section>
</main>

<script>
function createElement(tag, className, text) {
  const el = document.createElement(tag);
  if (className) {
    el.className = className;
  }
  if (text !== undefined) {
    el.textContent = text;
  }
  return el;
}

function createMetaCard(title, value) {
  const card = createElement("div", "meta-card");
  card.appendChild(createElement("strong", "", title));
  card.appendChild(createElement("span", "", value));
  return card;
}

function renderMeta(spec) {
  const meta = document.getElementById("meta");
  meta.innerHTML = "";
  meta.appendChild(createMetaCard("Version", spec.info.version));
  meta.appendChild(createMetaCard("OpenAPI", spec.openapi));
  meta.appendChild(createMetaCard("Endpoints", String(Object.keys(spec.paths || {}).length)));
  meta.appendChild(createMetaCard("Tags", String((spec.tags || []).length)));
}

function renderParameters(parameters) {
  if (!parameters || parameters.length === 0) {
    return createElement("p", "empty", "No query parameters documented.");
  }

  const list = createElement("div", "parameter-list");
  parameters.forEach((param) => {
    const item = createElement("div", "param");
    item.innerHTML = "<code>" + param.name + "</code> in " + param.in + (param.required ? " (required)" : "");
    list.appendChild(item);
  });
  return list;
}

function renderResponses(responses) {
  const entries = Object.entries(responses || {});
  if (entries.length === 0) {
    return createElement("p", "empty", "No responses documented.");
  }

  const list = createElement("div", "response-list");
  entries.forEach(([code, details]) => {
    const item = createElement("div", "response");
    item.innerHTML = "<code>" + code + "</code> " + (details.description || "");
    list.appendChild(item);
  });
  return list;
}

function renderOperation(path, method, operation) {
  const wrapper = document.createElement("details");
  wrapper.className = "endpoint";

  const summary = document.createElement("summary");
  summary.appendChild(createElement("span", "method", method.toUpperCase()));
  summary.appendChild(createElement("span", "path", path));
  summary.appendChild(createElement("span", "summary", operation.summary || ""));
  wrapper.appendChild(summary);

  const body = createElement("div", "endpoint-body");
  body.appendChild(createElement("p", "", operation.description || "No description provided."));

  body.appendChild(createElement("h3", "", "Tags"));
  const tagList = createElement("div", "tag-list");
  (operation.tags || []).forEach((tag) => {
    tagList.appendChild(createElement("span", "pill", tag));
  });
  body.appendChild(tagList.childElementCount ? tagList : createElement("p", "empty", "No tags."));

  body.appendChild(createElement("h3", "", "Parameters"));
  body.appendChild(renderParameters(operation.parameters));

  body.appendChild(createElement("h3", "", "Responses"));
  body.appendChild(renderResponses(operation.responses));
  wrapper.appendChild(body);

  return wrapper;
}

function renderSpec(spec) {
  renderMeta(spec);
  const root = document.getElementById("swagger-ui");
  root.innerHTML = "";

  const serverBox = createElement("div", "status");
  serverBox.appendChild(createElement("strong", "", "Servers"));
  const serverList = createElement("div", "server-list");
  (spec.servers || []).forEach((server) => {
    const item = createElement("span", "pill");
    item.innerHTML = "<code>" + server.url + "</code> " + (server.description || "");
    serverList.appendChild(item);
  });
  serverBox.appendChild(serverList.childElementCount ? serverList : createElement("p", "empty", "No servers documented."));
  root.appendChild(serverBox);

  Object.entries(spec.paths || {}).forEach(([path, methods]) => {
    Object.entries(methods).forEach(([method, operation]) => {
      root.appendChild(renderOperation(path, method, operation));
    });
  });

  const note = createElement("p", "footer-note", "OpenAPI source: /api/openapi.json");
  root.appendChild(note);
}

async function loadSpec() {
  const response = await fetch("/api/openapi.json", { headers: { "Accept": "application/json" } });
  if (!response.ok) {
    throw new Error("Unable to load OpenAPI spec (" + response.status + ")");
  }
  const spec = await response.json();
  renderSpec(spec);
}

loadSpec().catch((error) => {
  const root = document.getElementById("swagger-ui");
  root.innerHTML = "";
  const status = createElement("div", "status");
  status.textContent = "Failed to load API docs: " + error.message;
  root.appendChild(status);
});
</script>
</body>
</html>
"""
