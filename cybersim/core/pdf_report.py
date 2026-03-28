"""
Report Generator -- Professional HTML security assessment report.

Generates a standalone HTML file with embedded CSS, charts (SVG), and analysis.
Can be opened in any browser and printed to PDF.
Only uses Python standard library modules.
"""

from __future__ import annotations

import html
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cybersim.core.logging_engine import CyberSimLogger
from cybersim.core.reporter import generate_summary

# ---------------------------------------------------------------------------
# MITRE ATT&CK mapping
# ---------------------------------------------------------------------------

MITRE_MAPPING: dict[str, dict[str, str]] = {
    "ddos": {
        "technique": "T1498",
        "tactic": "Impact",
        "name": "Network Denial of Service",
    },
    "sqli": {
        "technique": "T1190",
        "tactic": "Initial Access",
        "name": "Exploit Public-Facing Application",
    },
    "xss": {
        "technique": "T1189",
        "tactic": "Initial Access",
        "name": "Drive-by Compromise",
    },
    "bruteforce": {
        "technique": "T1110",
        "tactic": "Credential Access",
        "name": "Brute Force",
    },
    "phishing": {
        "technique": "T1566",
        "tactic": "Initial Access",
        "name": "Phishing",
    },
    "ransomware": {
        "technique": "T1486",
        "tactic": "Impact",
        "name": "Data Encrypted for Impact",
    },
}

# ---------------------------------------------------------------------------
# Colour palette
# ---------------------------------------------------------------------------

_PALETTE = [
    "#00d4ff",  # cyan
    "#ff6b6b",  # red
    "#51cf66",  # green
    "#fcc419",  # yellow
    "#845ef7",  # purple
    "#ff922b",  # orange
    "#20c997",  # teal
    "#e64980",  # pink
]

_SEVERITY_COLORS: dict[str, str] = {
    "info": "#00d4ff",
    "warning": "#fcc419",
    "error": "#ff6b6b",
    "critical": "#e64980",
}


def _esc(text: Any) -> str:
    """HTML-escape arbitrary text."""
    return html.escape(str(text))


def _canonical_module_key(module_name: str) -> str:
    """Normalize concrete module names into report families when possible."""
    normalized = str(module_name).lower()
    for key in MITRE_MAPPING:
        if key in normalized:
            return key
    return normalized


# ===================================================================
# ReportGenerator
# ===================================================================


class ReportGenerator:
    """Generate professional cybersecurity assessment reports.

    The output is a single self-contained HTML file (no external
    dependencies) that can be opened in any browser and printed to PDF
    via the browser's built-in *Print -> Save as PDF* feature.

    Parameters
    ----------
    logger:
        A :class:`CyberSimLogger` instance containing the events to
        report on.
    session_id:
        Override session identifier shown in the header.  When *None*,
        the logger's own ``session_id`` is used.
    """

    def __init__(self, logger: CyberSimLogger, session_id: str | None = None) -> None:
        self.logger = logger
        self.session_id = session_id or logger.session_id
        self.events: list[dict[str, Any]] = logger.events
        self.summary: dict[str, Any] = generate_summary(logger)
        self.generated_at = datetime.now(timezone.utc).isoformat()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate(self, output_path: str | None = None) -> str:
        """Generate the full HTML report and write it to *output_path*.

        Parameters
        ----------
        output_path:
            Destination file path.  When *None* the file is written
            to the logger's ``log_dir`` as
            ``report_<session_id>.html``.

        Returns
        -------
        str
            Absolute path of the generated file.
        """
        if output_path is None:
            output_path = str(
                self.logger.log_dir / f"report_{self.session_id}.html"
            )

        sections = [
            self._build_header(),
            self._build_executive_summary(),
            self._build_module_analysis(),
            self._build_timeline_chart(),
            self._build_attack_distribution(),
            self._build_mitre_mapping(),
            self._build_recommendations(),
            self._build_footer(),
        ]

        body = "\n".join(sections)
        full_html = self._wrap_html(body)

        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        Path(output_path).write_text(full_html, encoding="utf-8")
        return str(Path(output_path).resolve())

    # ------------------------------------------------------------------
    # Section builders
    # ------------------------------------------------------------------

    def _build_header(self) -> str:
        """Report header with branding, title, date, session info."""
        return f"""
        <header class="report-header">
          <div class="header-brand">
            <svg class="logo" width="48" height="48" viewBox="0 0 48 48">
              <defs>
                <linearGradient id="logoGrad" x1="0%" y1="0%" x2="100%" y2="100%">
                  <stop offset="0%" style="stop-color:#00d4ff"/>
                  <stop offset="100%" style="stop-color:#845ef7"/>
                </linearGradient>
              </defs>
              <circle cx="24" cy="24" r="22" fill="none" stroke="url(#logoGrad)"
                      stroke-width="3"/>
              <path d="M24 10 L24 38 M16 18 L32 18 M14 26 L34 26 M18 34 L30 34"
                    stroke="url(#logoGrad)" stroke-width="2" fill="none"
                    stroke-linecap="round"/>
            </svg>
            <div>
              <h1 class="header-title">CyberSim6</h1>
              <p class="header-subtitle">Security Assessment Report</p>
            </div>
          </div>
          <div class="header-meta">
            <span class="meta-item"><strong>Session:</strong> {_esc(self.session_id)}</span>
            <span class="meta-item"><strong>Generated:</strong> {_esc(self.generated_at)}</span>
          </div>
        </header>"""

    def _build_executive_summary(self) -> str:
        """High-level findings: total events, threat level, key metrics."""
        total = self.summary.get("total_events", 0)
        modules = self.summary.get("events_by_module", {})
        statuses = self.summary.get("events_by_status", {})

        error_count = statuses.get("error", 0) + statuses.get("critical", 0)
        warning_count = statuses.get("warning", 0)

        if error_count > 5:
            threat_level, threat_color = "CRITICAL", "#e64980"
        elif error_count > 0:
            threat_level, threat_color = "HIGH", "#ff6b6b"
        elif warning_count > 0:
            threat_level, threat_color = "MEDIUM", "#fcc419"
        else:
            threat_level, threat_color = "LOW", "#51cf66"

        time_range = self.summary.get("time_range", {})
        start_time = time_range.get("start", "N/A")
        end_time = time_range.get("end", "N/A")

        cards = f"""
        <div class="metric-card">
          <div class="metric-value">{total}</div>
          <div class="metric-label">Total Events</div>
        </div>
        <div class="metric-card">
          <div class="metric-value">{len(modules)}</div>
          <div class="metric-label">Modules Active</div>
        </div>
        <div class="metric-card">
          <div class="metric-value" style="color:{threat_color}">{threat_level}</div>
          <div class="metric-label">Threat Level</div>
        </div>
        <div class="metric-card">
          <div class="metric-value">{error_count}</div>
          <div class="metric-label">Errors / Critical</div>
        </div>
        <div class="metric-card">
          <div class="metric-value">{warning_count}</div>
          <div class="metric-label">Warnings</div>
        </div>"""

        return f"""
        <section class="section">
          <h2 class="section-title">Executive Summary</h2>
          <div class="metric-grid">{cards}</div>
          <table class="info-table">
            <tr><td><strong>Session ID</strong></td><td>{_esc(self.session_id)}</td></tr>
            <tr><td><strong>Time Range</strong></td>
                <td>{_esc(start_time)} &mdash; {_esc(end_time)}</td></tr>
            <tr><td><strong>Total Events</strong></td><td>{total}</td></tr>
          </table>
        </section>"""

    def _build_module_analysis(self) -> str:
        """Per-module breakdown with event counts, findings, severity."""
        modules = self.summary.get("events_by_module", {})
        if not modules:
            return """
            <section class="section">
              <h2 class="section-title">Module Analysis</h2>
              <p class="muted">No module events recorded.</p>
            </section>"""

        rows: list[str] = []
        for mod, count in sorted(modules.items(), key=lambda x: -x[1]):
            mod_events = [e for e in self.events if e["module"] == mod]
            statuses = Counter(e.get("status", "info") for e in mod_events)
            types = Counter(e.get("module_type", "unknown") for e in mod_events)

            severity_badges = " ".join(
                f'<span class="badge" style="background:{_SEVERITY_COLORS.get(s, "#666")}">'
                f"{_esc(s)}: {c}</span>"
                for s, c in statuses.items()
            )
            type_str = ", ".join(f"{t} ({c})" for t, c in types.items())

            rows.append(f"""
            <tr>
              <td class="module-name">{_esc(mod)}</td>
              <td>{count}</td>
              <td>{_esc(type_str)}</td>
              <td>{severity_badges}</td>
            </tr>""")

        return f"""
        <section class="section">
          <h2 class="section-title">Module Analysis</h2>
          <table class="data-table">
            <thead>
              <tr>
                <th>Module</th><th>Events</th><th>Type(s)</th><th>Severity</th>
              </tr>
            </thead>
            <tbody>{"".join(rows)}</tbody>
          </table>
        </section>"""

    def _build_timeline_chart(self) -> str:
        """SVG timeline chart of events over time."""
        if not self.events:
            return """
            <section class="section">
              <h2 class="section-title">Event Timeline</h2>
              <p class="muted">No events to display.</p>
            </section>"""

        # Bucket events by minute
        buckets: Counter[str] = Counter()
        for ev in self.events:
            ts = ev.get("timestamp", "")[:16]  # YYYY-MM-DDTHH:MM
            buckets[ts] += 1

        labels = sorted(buckets.keys())
        values = [buckets[label] for label in labels]
        max_val = max(values) if values else 1

        chart_w, chart_h = 700, 220
        margin_left, margin_bottom = 50, 60
        usable_w = chart_w - margin_left - 10
        usable_h = chart_h - margin_bottom - 20

        n = len(labels)
        bar_w = max(4, min(40, usable_w // max(n, 1) - 2))
        spacing = usable_w / max(n, 1)

        bars: list[str] = []
        x_labels: list[str] = []
        for i, (label, val) in enumerate(zip(labels, values)):
            h = (val / max_val) * usable_h if max_val else 0
            x = margin_left + i * spacing + (spacing - bar_w) / 2
            y = chart_h - margin_bottom - h
            bars.append(
                f'<rect x="{x:.1f}" y="{y:.1f}" width="{bar_w}" '
                f'height="{h:.1f}" fill="#00d4ff" rx="2" opacity="0.85"/>'
            )
            # Shortened label (HH:MM)
            short = label[-5:] if len(label) >= 5 else label
            lx = margin_left + i * spacing + spacing / 2
            x_labels.append(
                f'<text x="{lx:.1f}" y="{chart_h - margin_bottom + 18}" '
                f'text-anchor="middle" class="chart-label" '
                f'transform="rotate(-45,{lx:.1f},{chart_h - margin_bottom + 18})">'
                f"{_esc(short)}</text>"
            )

        # Y-axis ticks
        y_ticks: list[str] = []
        for i in range(5):
            val = int(max_val * i / 4)
            y = chart_h - margin_bottom - (i / 4) * usable_h
            y_ticks.append(
                f'<text x="{margin_left - 8}" y="{y:.1f}" '
                f'text-anchor="end" dominant-baseline="middle" '
                f'class="chart-label">{val}</text>'
            )
            y_ticks.append(
                f'<line x1="{margin_left}" y1="{y:.1f}" '
                f'x2="{chart_w - 10}" y2="{y:.1f}" '
                f'stroke="#333" stroke-dasharray="4,4"/>'
            )

        svg = (
            f'<svg viewBox="0 0 {chart_w} {chart_h}" '
            f'class="chart-svg" preserveAspectRatio="xMidYMid meet">'
            + "".join(y_ticks)
            + "".join(bars)
            + "".join(x_labels)
            + "</svg>"
        )

        return f"""
        <section class="section">
          <h2 class="section-title">Event Timeline</h2>
          <div class="chart-container">{svg}</div>
        </section>"""

    def _build_attack_distribution(self) -> str:
        """SVG bar chart of attacks by module."""
        modules = self.summary.get("events_by_module", {})
        if not modules:
            return """
            <section class="section">
              <h2 class="section-title">Attack Distribution</h2>
              <p class="muted">No data available.</p>
            </section>"""

        sorted_mods = sorted(modules.items(), key=lambda x: -x[1])
        max_val = max(v for _, v in sorted_mods) if sorted_mods else 1

        chart_w, chart_h = 600, max(180, len(sorted_mods) * 40 + 40)
        bar_h = 26
        spacing = 38
        margin_left = 130

        bars: list[str] = []
        for i, (mod, count) in enumerate(sorted_mods):
            w = ((count / max_val) * (chart_w - margin_left - 60)) if max_val else 0
            y = 20 + i * spacing
            color = _PALETTE[i % len(_PALETTE)]
            bars.append(
                f'<text x="{margin_left - 10}" y="{y + bar_h / 2 + 1}" '
                f'text-anchor="end" dominant-baseline="middle" '
                f'class="chart-label">{_esc(mod)}</text>'
            )
            bars.append(
                f'<rect x="{margin_left}" y="{y}" width="{w:.1f}" '
                f'height="{bar_h}" fill="{color}" rx="4" opacity="0.9"/>'
            )
            bars.append(
                f'<text x="{margin_left + w + 8:.1f}" y="{y + bar_h / 2 + 1}" '
                f'dominant-baseline="middle" class="chart-value">{count}</text>'
            )

        svg = (
            f'<svg viewBox="0 0 {chart_w} {chart_h}" '
            f'class="chart-svg" preserveAspectRatio="xMidYMid meet">'
            + "".join(bars)
            + "</svg>"
        )

        return f"""
        <section class="section">
          <h2 class="section-title">Attack Distribution</h2>
          <div class="chart-container">{svg}</div>
        </section>"""

    def _build_mitre_mapping(self) -> str:
        """Table mapping each observed module to MITRE ATT&CK techniques."""
        modules = self.summary.get("events_by_module", {})
        observed = {_canonical_module_key(name) for name in modules.keys()}
        # Also include all known mappings for reference
        all_keys = sorted(set(MITRE_MAPPING.keys()) | observed)

        rows: list[str] = []
        for key in all_keys:
            mapping = MITRE_MAPPING.get(key)
            if mapping is None:
                rows.append(
                    f"<tr><td>{_esc(key)}</td>"
                    f"<td colspan='3' class='muted'>No MITRE mapping defined</td>"
                    f"<td>{'Yes' if key in observed else 'No'}</td></tr>"
                )
            else:
                obs_class = "observed-yes" if key in observed else "observed-no"
                rows.append(
                    f"<tr class='{obs_class}'>"
                    f"<td>{_esc(key)}</td>"
                    f"<td><code>{_esc(mapping['technique'])}</code></td>"
                    f"<td>{_esc(mapping['tactic'])}</td>"
                    f"<td>{_esc(mapping['name'])}</td>"
                    f"<td>{'Yes' if key in observed else 'No'}</td></tr>"
                )

        return f"""
        <section class="section">
          <h2 class="section-title">MITRE ATT&amp;CK Mapping</h2>
          <table class="data-table mitre-table">
            <thead>
              <tr>
                <th>Module</th><th>Technique</th><th>Tactic</th>
                <th>Name</th><th>Observed</th>
              </tr>
            </thead>
            <tbody>{"".join(rows)}</tbody>
          </table>
        </section>"""

    def _build_recommendations(self) -> str:
        """Security recommendations based on findings (NIST SP 800-61)."""
        modules = self.summary.get("events_by_module", {})
        observed = {_canonical_module_key(name) for name in modules.keys()}

        recs: list[str] = []

        # Always include general recommendations
        recs.append(self._rec_card(
            "Incident Response Plan",
            "Establish and maintain an incident response plan aligned with "
            "NIST SP 800-61 Rev. 2. Ensure all team members are trained on "
            "escalation procedures.",
            "general",
        ))

        if "ddos" in observed:
            recs.append(self._rec_card(
                "DDoS Mitigation",
                "Deploy rate-limiting and traffic scrubbing at the network edge. "
                "Consider CDN-based DDoS protection services. Monitor baseline "
                "traffic patterns to detect volumetric anomalies early.",
                "high",
            ))

        if "sqli" in observed:
            recs.append(self._rec_card(
                "SQL Injection Prevention",
                "Use parameterised queries and prepared statements for all "
                "database interactions. Deploy a Web Application Firewall (WAF) "
                "with up-to-date rule sets. Conduct regular code reviews.",
                "critical",
            ))

        if "xss" in observed:
            recs.append(self._rec_card(
                "Cross-Site Scripting Defence",
                "Implement Content Security Policy (CSP) headers. Sanitise and "
                "encode all user-supplied output. Use framework-level auto-escaping.",
                "high",
            ))

        if "bruteforce" in observed:
            recs.append(self._rec_card(
                "Brute Force Protection",
                "Enforce account lockout policies after repeated failed attempts. "
                "Implement multi-factor authentication (MFA). Monitor "
                "authentication logs for anomalous patterns.",
                "high",
            ))

        if "phishing" in observed:
            recs.append(self._rec_card(
                "Phishing Awareness",
                "Conduct regular phishing simulation exercises. Deploy email "
                "filtering with DMARC, DKIM, and SPF. Educate users on "
                "recognising suspicious emails and links.",
                "high",
            ))

        if "ransomware" in observed:
            recs.append(self._rec_card(
                "Ransomware Resilience",
                "Maintain offline, tested backups following the 3-2-1 rule. "
                "Segment networks to limit lateral movement. Keep all systems "
                "patched and restrict macro execution.",
                "critical",
            ))

        recs.append(self._rec_card(
            "Continuous Monitoring",
            "Implement centralized log aggregation and SIEM correlation. "
            "Establish alerting thresholds aligned with NIST SP 800-61 "
            "severity classifications.",
            "general",
        ))

        return f"""
        <section class="section">
          <h2 class="section-title">Recommendations (NIST SP 800-61)</h2>
          <div class="rec-grid">{"".join(recs)}</div>
        </section>"""

    def _build_footer(self) -> str:
        """Disclaimer, generation info."""
        return f"""
        <footer class="report-footer">
          <p><strong>Disclaimer:</strong> This report was automatically generated
          by CyberSim6 for educational and training purposes only. The findings
          reflect simulated attack and detection scenarios and should not be
          treated as a substitute for a professional penetration test or
          security audit.</p>
          <p class="footer-meta">
            Report generated on {_esc(self.generated_at)} &bull;
            Session {_esc(self.session_id)} &bull;
            CyberSim6 &copy; {datetime.now().year}
          </p>
        </footer>"""

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _rec_card(title: str, description: str, severity: str) -> str:
        """Render a single recommendation card."""
        color_map = {
            "critical": "#e64980",
            "high": "#ff6b6b",
            "medium": "#fcc419",
            "general": "#00d4ff",
        }
        color = color_map.get(severity, "#00d4ff")
        return (
            f'<div class="rec-card" style="border-left:4px solid {color}">'
            f'<h3 class="rec-title">{_esc(title)}</h3>'
            f'<span class="rec-severity" style="color:{color}">'
            f"{_esc(severity.upper())}</span>"
            f"<p>{_esc(description)}</p></div>"
        )

    def _wrap_html(self, body: str) -> str:
        """Wrap section HTML in a full HTML document with embedded CSS."""
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>CyberSim6 Report &mdash; {_esc(self.session_id)}</title>
<style>
{_CSS}
</style>
</head>
<body>
<div class="container">
{body}
</div>
</body>
</html>"""


# ===================================================================
# Embedded CSS
# ===================================================================

_CSS = r"""
/* --- Reset & Base ------------------------------------------------- */
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
body{
  font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,
    "Helvetica Neue",Arial,sans-serif;
  background:#0d1117;
  color:#c9d1d9;
  line-height:1.6;
  -webkit-print-color-adjust:exact;
  print-color-adjust:exact;
}
.container{max-width:960px;margin:0 auto;padding:32px 24px}

/* --- Header ------------------------------------------------------- */
.report-header{
  display:flex;justify-content:space-between;align-items:center;
  flex-wrap:wrap;gap:16px;
  padding:24px 32px;margin-bottom:32px;
  background:linear-gradient(135deg,#161b22 0%,#0d1117 100%);
  border:1px solid #30363d;border-radius:12px;
}
.header-brand{display:flex;align-items:center;gap:16px}
.header-title{
  font-size:1.8rem;font-weight:700;
  background:linear-gradient(90deg,#00d4ff,#845ef7);
  -webkit-background-clip:text;-webkit-text-fill-color:transparent;
  background-clip:text;
}
.header-subtitle{font-size:.95rem;color:#8b949e}
.header-meta{display:flex;flex-direction:column;gap:4px;font-size:.85rem;color:#8b949e}
.meta-item strong{color:#c9d1d9}
.logo{flex-shrink:0}

/* --- Sections ----------------------------------------------------- */
.section{
  background:#161b22;border:1px solid #30363d;border-radius:12px;
  padding:28px 32px;margin-bottom:24px;
}
.section-title{
  font-size:1.25rem;font-weight:600;margin-bottom:20px;
  padding-bottom:10px;border-bottom:2px solid #30363d;
  color:#e6edf3;
}

/* --- Metric cards ------------------------------------------------- */
.metric-grid{
  display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));
  gap:16px;margin-bottom:20px;
}
.metric-card{
  background:#0d1117;border:1px solid #30363d;border-radius:10px;
  padding:18px;text-align:center;
}
.metric-value{font-size:1.6rem;font-weight:700;color:#00d4ff}
.metric-label{font-size:.8rem;color:#8b949e;margin-top:4px}

/* --- Tables ------------------------------------------------------- */
.info-table{width:100%;border-collapse:collapse}
.info-table td{padding:8px 12px;border-bottom:1px solid #21262d}
.info-table td:first-child{width:160px;color:#8b949e}

.data-table{width:100%;border-collapse:collapse;font-size:.9rem}
.data-table th{
  text-align:left;padding:10px 12px;
  background:#0d1117;color:#8b949e;font-weight:600;
  border-bottom:2px solid #30363d;
}
.data-table td{padding:10px 12px;border-bottom:1px solid #21262d}
.data-table tbody tr:hover{background:#1c2128}
.module-name{font-weight:600;color:#58a6ff}
.badge{
  display:inline-block;padding:2px 8px;border-radius:12px;
  font-size:.75rem;color:#fff;margin:2px;
}
.observed-yes td{color:#c9d1d9}
.observed-no td{color:#484f58}
.mitre-table code{
  background:#0d1117;padding:2px 6px;border-radius:4px;
  font-size:.85rem;color:#ff7b72;
}

/* --- Charts ------------------------------------------------------- */
.chart-container{
  background:#0d1117;border:1px solid #21262d;border-radius:10px;
  padding:20px;overflow-x:auto;
}
.chart-svg{width:100%;height:auto}
.chart-label{fill:#8b949e;font-size:11px;font-family:inherit}
.chart-value{fill:#c9d1d9;font-size:12px;font-weight:600;font-family:inherit}

/* --- Recommendations ---------------------------------------------- */
.rec-grid{display:flex;flex-direction:column;gap:16px}
.rec-card{
  background:#0d1117;border:1px solid #21262d;border-radius:8px;
  padding:16px 20px;
}
.rec-title{font-size:1rem;font-weight:600;color:#e6edf3;margin-bottom:4px}
.rec-severity{font-size:.75rem;font-weight:700;display:inline-block;margin-bottom:8px}
.rec-card p{font-size:.9rem;color:#8b949e}

/* --- Footer ------------------------------------------------------- */
.report-footer{
  margin-top:32px;padding:20px 28px;
  background:#161b22;border:1px solid #30363d;border-radius:12px;
  font-size:.82rem;color:#8b949e;
}
.report-footer p{margin-bottom:8px}
.footer-meta{text-align:center;color:#484f58;font-size:.78rem}

/* --- Utility ------------------------------------------------------ */
.muted{color:#484f58;font-style:italic}

/* --- Print -------------------------------------------------------- */
@media print{
  body{background:#fff;color:#1a1a1a}
  .container{max-width:100%;padding:0}
  .report-header,.section,.report-footer{
    border-color:#ddd;background:#fff;
    break-inside:avoid;
  }
  .metric-card{background:#f6f8fa;border-color:#ddd}
  .chart-container{background:#f6f8fa;border-color:#ddd}
  .data-table th{background:#f6f8fa}
  .section-title{border-color:#ddd;color:#1a1a1a}
  .metric-value{color:#0969da}
  .header-title{-webkit-text-fill-color:#0969da;color:#0969da}
  .rec-card{background:#f6f8fa;border-color:#ddd}
  .report-footer{background:#f6f8fa}
}
"""
