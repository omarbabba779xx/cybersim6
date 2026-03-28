"""
CyberSim6 - Honeypot Module
Fake vulnerable services that attract and log attacker behavior.

Deploys decoy services: fake login, fake API, fake admin panel, fake database
error, fake file endpoints.  All interactions are logged for forensic analysis
and attacker profiling.
"""

from __future__ import annotations

import json
import threading
import time
from collections import Counter
from dataclasses import dataclass, field
from enum import Enum
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Any

from cybersim.core.logging_engine import CyberSimLogger


# ---------------------------------------------------------------------------
# Trap definition
# ---------------------------------------------------------------------------

@dataclass
class HoneypotTrap:
    """Single honeypot trap configuration.

    Attributes:
        name: Human-readable label for the trap.
        path: URL path that triggers this trap.
        response_code: HTTP status code to return.
        response_body: Body payload returned to the attacker.
        trap_type: Category — one of ``"login"``, ``"api"``, ``"admin"``,
                   ``"error"``, ``"file"``, ``"banner"``.
    """

    name: str
    path: str
    response_code: int
    response_body: str
    trap_type: str  # "login", "api", "admin", "error", "file", "banner"


# ---------------------------------------------------------------------------
# Default traps
# ---------------------------------------------------------------------------

DEFAULT_TRAPS: list[HoneypotTrap] = [
    HoneypotTrap(
        name="Fake Login",
        path="/admin/login",
        response_code=200,
        response_body=(
            "<!DOCTYPE html><html><head><title>Admin Login</title></head>"
            "<body><h1>Admin Panel</h1>"
            '<form method="POST" action="/admin/login">'
            '<input name="username" type="text" placeholder="Username">'
            '<input name="password" type="password" placeholder="Password">'
            "<button type=\"submit\">Login</button></form></body></html>"
        ),
        trap_type="login",
    ),
    HoneypotTrap(
        name="Fake API",
        path="/api/v1/users",
        response_code=200,
        response_body=json.dumps(
            {
                "users": [
                    {"id": 1, "name": "admin", "role": "superuser"},
                    {"id": 2, "name": "operator", "role": "staff"},
                ]
            }
        ),
        trap_type="api",
    ),
    HoneypotTrap(
        name="Fake phpMyAdmin",
        path="/phpmyadmin/",
        response_code=200,
        response_body=(
            "<!DOCTYPE html><html><head><title>phpMyAdmin</title></head>"
            "<body><h1>phpMyAdmin 4.9.7</h1>"
            "<p>Welcome to phpMyAdmin</p></body></html>"
        ),
        trap_type="admin",
    ),
    HoneypotTrap(
        name="Fake .env",
        path="/.env",
        response_code=200,
        response_body=(
            "APP_NAME=MyApp\nAPP_ENV=production\n"
            "DB_HOST=127.0.0.1\nDB_DATABASE=myapp\n"
            "DB_USERNAME=root\nDB_PASSWORD=changeme123\n"
            "SECRET_KEY=abc123secret\n"
        ),
        trap_type="file",
    ),
    HoneypotTrap(
        name="Fake wp-admin",
        path="/wp-admin/",
        response_code=200,
        response_body=(
            "<!DOCTYPE html><html><head><title>WordPress Admin</title></head>"
            "<body><h1>WordPress Dashboard</h1>"
            "<p>Welcome, admin</p></body></html>"
        ),
        trap_type="admin",
    ),
    HoneypotTrap(
        name="SQL Error",
        path="/search",
        response_code=500,
        response_body=(
            "MySQL Error: You have an error in your SQL syntax; "
            "check the manual that corresponds to your MySQL server version "
            "for the right syntax to use near '' at line 1"
        ),
        trap_type="error",
    ),
    HoneypotTrap(
        name="Fake SSH Banner",
        path="/ssh",
        response_code=200,
        response_body="SSH-2.0-OpenSSH_7.4",
        trap_type="banner",
    ),
    HoneypotTrap(
        name="Fake Backup",
        path="/backup.sql.gz",
        response_code=200,
        response_body="fake-backup-data-blob",
        trap_type="file",
    ),
]


# ---------------------------------------------------------------------------
# Threat levels
# ---------------------------------------------------------------------------

class ThreatLevel(str, Enum):
    """Threat level classification for correlated attacker activity."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


# ---------------------------------------------------------------------------
# Attack correlator
# ---------------------------------------------------------------------------

# Known attack payload signatures used for threat escalation.
_ATTACK_SIGNATURES: list[str] = [
    "' OR ",
    "1=1",
    "<script",
    "UNION SELECT",
    "../",
    "etc/passwd",
    "cmd=",
    "exec(",
    "wget ",
    "curl ",
    "nc ",
    "base64",
    "eval(",
]


@dataclass
class _IPProfile:
    """Internal mutable profile for a single source IP."""

    interactions: list[dict[str, Any]] = field(default_factory=list)
    traps_visited: set[str] = field(default_factory=set)
    trap_types_visited: set[str] = field(default_factory=set)
    first_seen: float = 0.0
    last_seen: float = 0.0
    payload_hits: int = 0


class AttackCorrelator:
    """Cross-trap attack correlation engine.

    Tracks interactions per source IP across all honeypot traps and detects
    multi-stage attack patterns such as reconnaissance sweeps, brute-force
    attempts, and lateral movement.

    Thread-safe: all public methods acquire an internal lock.

    Args:
        traps: The list of :class:`HoneypotTrap` entries used by the server
               so the correlator can map paths to trap metadata.
        fast_threshold: Maximum seconds between two consecutive interactions
                        from the same IP to be considered *automated*.
                        Defaults to ``2.0``.
        brute_force_threshold: Minimum number of interactions with the *same*
                               trap path from the same IP to flag brute-force
                               behaviour.  Defaults to ``5``.
    """

    def __init__(
        self,
        traps: list[HoneypotTrap] | None = None,
        *,
        fast_threshold: float = 2.0,
        brute_force_threshold: int = 5,
    ) -> None:
        self._traps = list(traps or DEFAULT_TRAPS)
        self._trap_map: dict[str, HoneypotTrap] = {t.path: t for t in self._traps}
        self._profiles: dict[str, _IPProfile] = {}
        self._lock = threading.RLock()
        self._fast_threshold = fast_threshold
        self._brute_force_threshold = brute_force_threshold

    # -- recording -----------------------------------------------------------

    def record(self, interaction: dict[str, Any]) -> None:
        """Record a single interaction for correlation.

        This is intended to be called by the honeypot server on every trap
        hit so that the correlator can build per-IP profiles incrementally.

        Args:
            interaction: A dict as produced by the honeypot handler, with at
                         least ``source_ip``, ``timestamp``, ``path``,
                         ``method``, and optionally ``body``.
        """
        ip = interaction["source_ip"]
        ts = interaction["timestamp"]
        path = interaction["path"].split("?")[0]

        with self._lock:
            prof = self._profiles.get(ip)
            if prof is None:
                prof = _IPProfile(first_seen=ts, last_seen=ts)
                self._profiles[ip] = prof

            prof.interactions.append(interaction)
            prof.last_seen = max(prof.last_seen, ts)
            prof.first_seen = min(prof.first_seen, ts)
            prof.traps_visited.add(path)

            trap = self._trap_map.get(path)
            if trap is not None:
                prof.trap_types_visited.add(trap.trap_type)

            # Check payload for known attack signatures
            body = interaction.get("body", "")
            if body and any(sig.lower() in body.lower() for sig in _ATTACK_SIGNATURES):
                prof.payload_hits += 1

    # -- threat assessment ---------------------------------------------------

    def _threat_level_for(self, prof: _IPProfile) -> ThreatLevel:
        """Compute the threat level for a single IP profile.

        The base level comes from the number of unique trap paths visited:
        - 1 trap   -> LOW
        - 2-3 traps -> MEDIUM
        - 4-5 traps -> HIGH
        - 6+ traps  -> CRITICAL

        The level is then escalated (never downgraded) when:
        - Interactions happen faster than *fast_threshold* (automated tool).
        - Payloads contain known attack signatures.
        """
        n_traps = len(prof.traps_visited)

        if n_traps >= 6:
            level = ThreatLevel.CRITICAL
        elif n_traps >= 4:
            level = ThreatLevel.HIGH
        elif n_traps >= 2:
            level = ThreatLevel.MEDIUM
        else:
            level = ThreatLevel.LOW

        # Escalate for speed (automated tooling)
        if len(prof.interactions) >= 2:
            duration = prof.last_seen - prof.first_seen
            avg_interval = duration / (len(prof.interactions) - 1) if len(prof.interactions) > 1 else duration
            if avg_interval <= self._fast_threshold and avg_interval >= 0:
                level = self._escalate(level)

        # Escalate for malicious payloads
        if prof.payload_hits > 0:
            level = self._escalate(level)

        return level

    @staticmethod
    def _escalate(level: ThreatLevel) -> ThreatLevel:
        """Move one step up in the threat scale (capped at CRITICAL)."""
        order = [ThreatLevel.LOW, ThreatLevel.MEDIUM, ThreatLevel.HIGH, ThreatLevel.CRITICAL]
        idx = order.index(level)
        return order[min(idx + 1, len(order) - 1)]

    # -- pattern detection ---------------------------------------------------

    def detect_recon(self, ip: str) -> bool:
        """Return *True* if *ip* exhibits reconnaissance behaviour.

        Reconnaissance is defined as an attacker visiting **3 or more**
        distinct trap paths, suggesting a systematic scan across multiple
        services.
        """
        with self._lock:
            prof = self._profiles.get(ip)
            if prof is None:
                return False
            return len(prof.traps_visited) >= 3

    def detect_brute_force(self, ip: str) -> bool:
        """Return *True* if *ip* is brute-forcing a single trap.

        Brute-force is flagged when the same trap path is hit at least
        *brute_force_threshold* times from the same IP.
        """
        with self._lock:
            prof = self._profiles.get(ip)
            if prof is None:
                return False
            path_counts: Counter[str] = Counter()
            for ix in prof.interactions:
                path_counts[ix["path"].split("?")[0]] += 1
            return any(c >= self._brute_force_threshold for c in path_counts.values())

    def detect_lateral_movement(self, ip: str) -> bool:
        """Return *True* if *ip* probes different service *types*.

        Lateral movement is defined as interacting with **2 or more**
        distinct trap types (e.g. ``login`` + ``api`` + ``admin``).
        """
        with self._lock:
            prof = self._profiles.get(ip)
            if prof is None:
                return False
            return len(prof.trap_types_visited) >= 2

    # -- timelines and reports -----------------------------------------------

    def get_attack_timeline(self, ip: str) -> list[dict[str, Any]]:
        """Return a chronological list of trap interactions for *ip*.

        Each entry is a dict with keys ``timestamp``, ``path``, ``method``,
        and ``trap_type`` (or ``"unknown"`` for non-trap paths).
        """
        with self._lock:
            prof = self._profiles.get(ip)
            if prof is None:
                return []
            timeline: list[dict[str, Any]] = []
            for ix in sorted(prof.interactions, key=lambda x: x["timestamp"]):
                clean_path = ix["path"].split("?")[0]
                trap = self._trap_map.get(clean_path)
                timeline.append({
                    "timestamp": ix["timestamp"],
                    "path": ix["path"],
                    "method": ix["method"],
                    "trap_type": trap.trap_type if trap else "unknown",
                })
            return timeline

    def get_threat_report(self) -> dict[str, Any]:
        """Return a comprehensive cross-trap threat report.

        Returns:
            Dictionary with keys:

            - ``total_ips`` — number of distinct source IPs observed.
            - ``threats`` — mapping of IP to threat detail dict containing
              ``threat_level``, ``traps_visited``, ``trap_types``,
              ``interaction_count``, ``first_seen``, ``last_seen``,
              ``is_recon``, ``is_brute_force``, ``is_lateral_movement``,
              and ``timeline``.
        """
        with self._lock:
            ips = list(self._profiles.keys())

        threats: dict[str, Any] = {}
        for ip in ips:
            with self._lock:
                prof = self._profiles[ip]
                level = self._threat_level_for(prof)
                threats[ip] = {
                    "threat_level": level.value,
                    "traps_visited": sorted(prof.traps_visited),
                    "trap_types": sorted(prof.trap_types_visited),
                    "interaction_count": len(prof.interactions),
                    "first_seen": prof.first_seen,
                    "last_seen": prof.last_seen,
                    "is_recon": len(prof.traps_visited) >= 3,
                    "is_brute_force": any(
                        c >= self._brute_force_threshold
                        for c in Counter(
                            ix["path"].split("?")[0] for ix in prof.interactions
                        ).values()
                    ),
                    "is_lateral_movement": len(prof.trap_types_visited) >= 2,
                    "timeline": self.get_attack_timeline(ip),
                }

        return {
            "total_ips": len(threats),
            "threats": threats,
        }

    def get_top_threats(self, n: int = 5) -> list[dict[str, Any]]:
        """Return the *n* most dangerous IPs, sorted by threat severity.

        Sorting priority: threat level (CRITICAL > HIGH > MEDIUM > LOW),
        then by number of interactions (descending).

        Returns:
            List of dicts with ``ip`` plus the same fields as in
            :meth:`get_threat_report` threats entries.
        """
        report = self.get_threat_report()
        level_order = {
            ThreatLevel.LOW.value: 0,
            ThreatLevel.MEDIUM.value: 1,
            ThreatLevel.HIGH.value: 2,
            ThreatLevel.CRITICAL.value: 3,
        }
        items = [
            {"ip": ip, **detail}
            for ip, detail in report["threats"].items()
        ]
        items.sort(
            key=lambda x: (level_order.get(x["threat_level"], 0), x["interaction_count"]),
            reverse=True,
        )
        return items[:n]


# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------

class _HoneypotHandler(BaseHTTPRequestHandler):
    """Internal HTTP request handler for the honeypot server.

    Class-level attributes are injected by :class:`HoneypotServer` before
    the ``HTTPServer`` is started.
    """

    traps: list[HoneypotTrap] = []
    logger: CyberSimLogger | None = None
    interactions: list[dict[str, Any]] = []
    lock: threading.Lock = threading.Lock()
    correlator: AttackCorrelator | None = None

    # -- helpers -------------------------------------------------------------

    def _record_interaction(self, method: str, path: str, body: str = "") -> None:
        """Log an interaction from any HTTP method."""
        headers = {k: v for k, v in self.headers.items()}
        entry: dict[str, Any] = {
            "timestamp": time.time(),
            "source_ip": self.client_address[0],
            "source_port": self.client_address[1],
            "method": method,
            "path": path,
            "headers": headers,
            "body": body,
        }
        with self.lock:
            self.interactions.append(entry)

        if self.correlator is not None:
            self.correlator.record(entry)

        if self.logger:
            self.logger.log_event(
                module="honeypot",
                module_type="detection",
                event_type="honeypot_interaction",
                details={
                    "source": self.client_address[0],
                    "method": method,
                    "path": path,
                    "message": (
                        f"Honeypot hit: {method} {path} from "
                        f"{self.client_address[0]}"
                    ),
                    "status": "warning",
                },
            )

    def _find_trap(self, path: str) -> HoneypotTrap | None:
        """Return the first trap whose path matches the request path."""
        # Strip query string for matching
        clean = path.split("?")[0]
        for trap in self.traps:
            if clean == trap.path:
                return trap
        return None

    def _respond_trap(self, trap: HoneypotTrap) -> None:
        """Send the trap's canned response."""
        content_type = "text/html"
        if trap.trap_type == "api":
            content_type = "application/json"
        elif trap.trap_type in ("file", "banner"):
            content_type = "text/plain"

        self.send_response(trap.response_code)
        self.send_header("Content-Type", content_type)
        self.send_header("Server", "Apache/2.4.41 (Ubuntu)")
        self.end_headers()
        self.wfile.write(trap.response_body.encode())

    def _respond_default(self) -> None:
        """Return a generic 404 that still looks realistic."""
        self.send_response(404)
        self.send_header("Content-Type", "text/html")
        self.send_header("Server", "Apache/2.4.41 (Ubuntu)")
        self.end_headers()
        self.wfile.write(
            b"<!DOCTYPE html><html><body>"
            b"<h1>404 Not Found</h1>"
            b"<p>The requested URL was not found on this server.</p>"
            b"</body></html>"
        )

    # -- HTTP verbs ----------------------------------------------------------

    def do_GET(self) -> None:
        """Handle GET requests."""
        self._record_interaction("GET", self.path)
        trap = self._find_trap(self.path)
        if trap:
            self._respond_trap(trap)
        else:
            self._respond_default()

    def do_POST(self) -> None:
        """Handle POST requests."""
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode() if content_length else ""
        self._record_interaction("POST", self.path, body)
        trap = self._find_trap(self.path)
        if trap:
            self._respond_trap(trap)
        else:
            self._respond_default()

    def do_PUT(self) -> None:
        """Handle PUT requests."""
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode() if content_length else ""
        self._record_interaction("PUT", self.path, body)
        self._respond_default()

    def do_DELETE(self) -> None:
        """Handle DELETE requests."""
        self._record_interaction("DELETE", self.path)
        self._respond_default()

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        """Suppress default stderr logging."""
        pass


# ---------------------------------------------------------------------------
# Honeypot server wrapper
# ---------------------------------------------------------------------------

class HoneypotServer:
    """HTTP server disguised as a vulnerable application.

    Listens on *host*:*port* and responds to requests using pre-configured
    :class:`HoneypotTrap` entries.  Every interaction is recorded for later
    analysis.

    Args:
        logger: :class:`CyberSimLogger` instance for event recording.
        host: Bind address.  Defaults to ``127.0.0.1``.
        port: Bind port.  Defaults to ``9090``.
        traps: Optional list of custom traps.  If *None*, :data:`DEFAULT_TRAPS`
               are used.
    """

    DEFAULT_TRAPS = DEFAULT_TRAPS

    def __init__(
        self,
        logger: CyberSimLogger,
        host: str = "127.0.0.1",
        port: int = 9090,
        traps: list[HoneypotTrap] | None = None,
    ) -> None:
        self.logger = logger
        self.host = host
        self.port = port
        self.traps: list[HoneypotTrap] = list(traps or DEFAULT_TRAPS)
        self._server: HTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._interactions: list[dict[str, Any]] = []
        self._lock = threading.Lock()
        self.correlator = AttackCorrelator(traps=self.traps)

    # -- lifecycle -----------------------------------------------------------

    def start(self) -> None:
        """Start the honeypot server in a background daemon thread."""
        # Inject state into handler class
        _HoneypotHandler.traps = self.traps
        _HoneypotHandler.logger = self.logger
        _HoneypotHandler.interactions = self._interactions
        _HoneypotHandler.lock = self._lock
        _HoneypotHandler.correlator = self.correlator

        self._server = HTTPServer((self.host, self.port), _HoneypotHandler)
        self._thread = threading.Thread(
            target=self._server.serve_forever, daemon=True
        )
        self._thread.start()

        self.logger.log_event(
            module="honeypot",
            module_type="detection",
            event_type="honeypot_started",
            details={
                "host": self.host,
                "port": self.port,
                "traps": len(self.traps),
                "message": (
                    f"Honeypot started on http://{self.host}:{self.port} "
                    f"with {len(self.traps)} traps"
                ),
            },
        )

    def stop(self) -> None:
        """Shut down the honeypot server gracefully."""
        if self._server:
            self._server.shutdown()
            self.logger.log_event(
                module="honeypot",
                module_type="detection",
                event_type="honeypot_stopped",
                details={
                    "total_interactions": len(self._interactions),
                    "message": (
                        f"Honeypot stopped. "
                        f"Total interactions: {len(self._interactions)}"
                    ),
                },
            )

    # -- trap management -----------------------------------------------------

    def add_trap(self, trap: HoneypotTrap) -> None:
        """Add a custom trap at runtime.

        Args:
            trap: The :class:`HoneypotTrap` to register.
        """
        self.traps.append(trap)

    # -- data access ---------------------------------------------------------

    def get_interactions(self) -> list[dict[str, Any]]:
        """Return a copy of all recorded interactions.

        Returns:
            List of interaction dicts with keys: ``timestamp``, ``source_ip``,
            ``source_port``, ``method``, ``path``, ``headers``, ``body``.
        """
        with self._lock:
            return list(self._interactions)

    def get_attacker_profile(self) -> dict[str, Any]:
        """Build a summary profile of observed attacker behaviour.

        Returns:
            Dictionary with keys ``unique_ips``, ``total_interactions``,
            ``methods_used``, ``paths_targeted``, ``first_seen``,
            ``last_seen``, ``per_ip``.
        """
        with self._lock:
            interactions = list(self._interactions)

        if not interactions:
            return {
                "unique_ips": 0,
                "total_interactions": 0,
                "methods_used": [],
                "paths_targeted": [],
                "first_seen": None,
                "last_seen": None,
                "per_ip": {},
            }

        ips: Counter[str] = Counter()
        methods: Counter[str] = Counter()
        paths: Counter[str] = Counter()
        per_ip: dict[str, dict[str, Any]] = {}

        for ix in interactions:
            ip = ix["source_ip"]
            ips[ip] += 1
            methods[ix["method"]] += 1
            paths[ix["path"]] += 1
            entry = per_ip.setdefault(
                ip,
                {"count": 0, "methods": set(), "paths": set(), "first": ix["timestamp"], "last": ix["timestamp"]},
            )
            entry["count"] += 1
            entry["methods"].add(ix["method"])
            entry["paths"].add(ix["path"])
            entry["last"] = max(entry["last"], ix["timestamp"])
            entry["first"] = min(entry["first"], ix["timestamp"])

        # Serialise sets for JSON-friendliness
        for v in per_ip.values():
            v["methods"] = sorted(v["methods"])
            v["paths"] = sorted(v["paths"])

        return {
            "unique_ips": len(ips),
            "total_interactions": len(interactions),
            "methods_used": sorted(methods.keys()),
            "paths_targeted": [p for p, _ in paths.most_common()],
            "first_seen": interactions[0]["timestamp"],
            "last_seen": interactions[-1]["timestamp"],
            "per_ip": per_ip,
        }

    def get_stats(self) -> dict[str, Any]:
        """Return aggregate statistics about honeypot activity.

        Returns:
            Dictionary with keys ``total_interactions``, ``unique_ips``,
            ``by_method``, ``by_path``, ``by_trap_type``, ``traps_hit``,
            ``traps_missed``.
        """
        with self._lock:
            interactions = list(self._interactions)

        by_method: Counter[str] = Counter()
        by_path: Counter[str] = Counter()
        unique_ips: set[str] = set()
        traps_hit: set[str] = set()

        trap_paths = {t.path for t in self.traps}
        trap_type_map = {t.path: t.trap_type for t in self.traps}
        by_trap_type: Counter[str] = Counter()

        for ix in interactions:
            by_method[ix["method"]] += 1
            by_path[ix["path"]] += 1
            unique_ips.add(ix["source_ip"])
            clean_path = ix["path"].split("?")[0]
            if clean_path in trap_paths:
                traps_hit.add(clean_path)
                by_trap_type[trap_type_map[clean_path]] += 1

        return {
            "total_interactions": len(interactions),
            "unique_ips": len(unique_ips),
            "by_method": dict(by_method),
            "by_path": dict(by_path),
            "by_trap_type": dict(by_trap_type),
            "traps_hit": len(traps_hit),
            "traps_missed": len(trap_paths - traps_hit),
        }


# ---------------------------------------------------------------------------
# Honeypot log analyser
# ---------------------------------------------------------------------------

class HoneypotAnalyzer:
    """Analyse honeypot interaction logs to identify attack patterns.

    Args:
        logger: :class:`CyberSimLogger` instance for event recording.
    """

    # Path patterns that indicate specific attacker intent
    _SCANNER_PATHS = {
        "/.env", "/wp-admin/", "/phpmyadmin/", "/backup.sql.gz",
        "/ssh", "/.git/config", "/robots.txt", "/sitemap.xml",
    }
    _EXPLOIT_PATHS = {"/search", "/api/v1/users", "/admin/login"}

    def __init__(self, logger: CyberSimLogger) -> None:
        self.logger = logger

    def analyze_interactions(self, interactions: list[dict[str, Any]]) -> dict[str, Any]:
        """Produce a structured analysis report from raw interactions.

        Args:
            interactions: List of interaction dicts as returned by
                :meth:`HoneypotServer.get_interactions`.

        Returns:
            Dictionary with keys ``total``, ``unique_ips``, ``timeline``,
            ``path_frequency``, ``method_frequency``, ``classification``,
            ``ioc``.
        """
        if not interactions:
            return {
                "total": 0,
                "unique_ips": 0,
                "timeline": [],
                "path_frequency": {},
                "method_frequency": {},
                "classification": "none",
                "ioc": self.generate_ioc([]),
            }

        ips: set[str] = set()
        path_freq: Counter[str] = Counter()
        method_freq: Counter[str] = Counter()
        timeline: list[dict[str, Any]] = []

        for ix in interactions:
            ips.add(ix["source_ip"])
            path_freq[ix["path"]] += 1
            method_freq[ix["method"]] += 1
            timeline.append(
                {
                    "time": ix["timestamp"],
                    "ip": ix["source_ip"],
                    "action": f"{ix['method']} {ix['path']}",
                }
            )

        classification = self.classify_attacker(interactions)
        ioc = self.generate_ioc(interactions)

        report = {
            "total": len(interactions),
            "unique_ips": len(ips),
            "timeline": timeline,
            "path_frequency": dict(path_freq.most_common()),
            "method_frequency": dict(method_freq),
            "classification": classification,
            "ioc": ioc,
        }

        self.logger.log_event(
            module="honeypot_analyzer",
            module_type="detection",
            event_type="analysis_complete",
            details={
                "total": report["total"],
                "classification": classification,
                "message": (
                    f"Honeypot analysis complete: {report['total']} "
                    f"interactions, classified as '{classification}'"
                ),
            },
        )

        return report

    def classify_attacker(self, interactions: list[dict[str, Any]]) -> str:
        """Classify attacker behaviour into a category.

        Heuristics:
        * **scanner** — Many different paths targeted quickly (breadth-first
          reconnaissance).
        * **bot** — Repetitive requests to the same path with minimal
          variation.
        * **apt** — Multi-stage behaviour: reconnaissance *and* targeted
          exploitation paths, or POST bodies present.
        * **manual** — Low volume, varied timing, possible human operator.

        Args:
            interactions: Raw interaction list.

        Returns:
            One of ``"scanner"``, ``"bot"``, ``"apt"``, ``"manual"``,
            or ``"none"``.
        """
        if not interactions:
            return "none"

        unique_paths = {ix["path"].split("?")[0] for ix in interactions}
        methods = {ix["method"] for ix in interactions}
        has_post = "POST" in methods
        total = len(interactions)

        scanner_hits = unique_paths & self._SCANNER_PATHS
        exploit_hits = unique_paths & self._EXPLOIT_PATHS

        # APT: both recon and exploitation, or POST with varied paths
        if scanner_hits and exploit_hits and has_post:
            return "apt"

        # Scanner: many unique paths, mostly GET
        if len(unique_paths) >= 4 and total >= 4:
            return "scanner"

        # Bot: repetitive — low path diversity, high volume
        if total >= 5 and len(unique_paths) <= 2:
            return "bot"

        # Manual: low volume
        if total <= 3:
            return "manual"

        return "scanner"

    def generate_ioc(self, interactions: list[dict[str, Any]]) -> dict[str, Any]:
        """Generate Indicators of Compromise from honeypot interactions.

        Args:
            interactions: Raw interaction list.

        Returns:
            Dictionary with keys ``ip_addresses``, ``user_agents``,
            ``paths_accessed``, ``payloads``, ``timestamps``.
        """
        ips: set[str] = set()
        user_agents: set[str] = set()
        paths: set[str] = set()
        payloads: list[str] = []
        timestamps: list[float] = []

        for ix in interactions:
            ips.add(ix["source_ip"])
            ua = ix.get("headers", {}).get("User-Agent", "")
            if ua:
                user_agents.add(ua)
            paths.add(ix["path"])
            if ix.get("body"):
                payloads.append(ix["body"])
            timestamps.append(ix["timestamp"])

        return {
            "ip_addresses": sorted(ips),
            "user_agents": sorted(user_agents),
            "paths_accessed": sorted(paths),
            "payloads": payloads,
            "timestamps": sorted(timestamps),
        }
