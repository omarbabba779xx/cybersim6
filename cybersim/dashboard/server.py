"""
CyberSim6 - Web Dashboard
Real-time visualization of attacks, detections, and logs.
"""

import json
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from collections import Counter

from cybersim.core.logging_engine import CyberSimLogger


class DashboardHandler(BaseHTTPRequestHandler):
    """HTTP handler for the dashboard."""

    logger: CyberSimLogger = None

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
        else:
            self.send_error(404)

    def _serve_dashboard(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(DASHBOARD_HTML.encode("utf-8"))

    def _serve_events(self, params):
        events = self.logger.events if self.logger else []
        module = params.get("module", [None])[0]
        limit = int(params.get("limit", [100])[0])

        if module:
            events = [e for e in events if e["module"] == module]

        events = events[-limit:]

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps(events, ensure_ascii=False).encode("utf-8"))

    def _serve_stats(self):
        events = self.logger.events if self.logger else []

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
        }

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps(stats, ensure_ascii=False).encode("utf-8"))

    def _serve_timeline(self):
        events = self.logger.events if self.logger else []

        timeline = []
        for e in events[-200:]:
            timeline.append({
                "t": e["timestamp"],
                "module": e["module"],
                "type": e["event_type"],
                "status": e.get("status", "info"),
                "msg": e.get("details", {}).get("message", ""),
            })

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps(timeline, ensure_ascii=False).encode("utf-8"))


class Dashboard:
    """Web dashboard for CyberSim6."""

    def __init__(self, port: int = 8888, logger: CyberSimLogger = None):
        self.port = port
        self.logger = logger or CyberSimLogger()
        self._server = None
        self._thread = None

    def start(self):
        DashboardHandler.logger = self.logger
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
  <div class="grid-2" style="margin-bottom:16px;">
    <div class="panel">
      <div class="panel-hd">
        <div class="panel-title"><span class="dot"></span>Events by Module</div>
        <span class="panel-badge" id="bdgModules">0 modules</span>
      </div>
      <div class="panel-body" id="moduleChart"></div>
    </div>

    <div class="panel">
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
  <div class="grid-3" style="margin-bottom:16px;">
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
    h+=`<div class="bar-row"><span class="bar-lbl">${lbl}</span>
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

/* ════════════════════════════════════
   TERMINAL FEED
════════════════════════════════════ */
function renderTerminal(events){
  const el=document.getElementById('termFeed');
  if(!el) return;
  const recent=[...events].reverse().slice(0,80);
  let h='';
  for(const e of recent){
    const t=e.timestamp?e.timestamp.split('T')[1].substring(0,8):'';
    const msg=(e.details&&e.details.message)||e.event_type;
    const st=(e.details&&e.details.status)||e.status||'info';
    const bc={'info':'tb-info','warning':'tb-warning','error':'tb-error'}[st]||'tb-info';
    const prefix=st==='error'?'<span style="color:var(--red)">$</span>':st==='warning'?'<span style="color:var(--yellow)">!</span>':'<span style="color:var(--neon)">▸</span>';
    h+=`<div class="t-line">
      <span class="t-time">${t}</span>
      <span class="t-badge ${bc}">${st}</span>
      <span class="t-mod">${e.module}</span>
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
    const[sRes,eRes]=await Promise.all([fetch('/api/stats'),fetch('/api/events?limit=200')]);
    const stats=await sRes.json();
    const events=await eRes.json();

    // KPIs
    document.getElementById('sessionId').textContent='SID:'+stats.session_id;
    countUp('kTotal',stats.total_events);
    countUp('kAttacks',stats.total_attacks);
    countUp('kDetect',stats.total_detections);
    countUp('kModules',stats.modules_active.length);
    document.getElementById('kModList').textContent=stats.modules_active.slice(0,3).join(' · ')||'—';

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

    _lastRefresh=Date.now();
  }catch(e){
    document.getElementById('sessionId').textContent='DISCONNECTED';
  }
}

initCharts();
refresh();
setInterval(refresh,REFRESH_MS);
</script>
</body>
</html>"""
