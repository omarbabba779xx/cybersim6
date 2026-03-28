"""
CyberSim6 - Web Application Firewall Engine
Inspects HTTP requests for SQLi, XSS, path traversal, rate-limit abuse,
and suspicious user-agents.  Designed to sit as a reverse-proxy in front
of vulnerable training applications.

Classes:
    WAFSeverity  -- Enum of rule severity levels.
    WAFAction    -- Enum of possible rule actions (block / allow / log).
    WAFRule      -- A single inspection rule with a compiled regex pattern.
    WAFResult    -- Outcome of inspecting one HTTP request.
    WebApplicationFirewall -- Main WAF engine that aggregates rules and stats.
    WAFServer    -- HTTP reverse-proxy server that delegates to the engine.
"""

from __future__ import annotations

import enum
import http.server
import re
import threading
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any

from cybersim.core.logging_engine import CyberSimLogger
from cybersim.sqli.detection import SQLI_PATTERNS
from cybersim.xss.detection import XSS_PATTERNS


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class WAFSeverity(enum.Enum):
    """Severity level assigned to a WAF rule."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class WAFAction(enum.Enum):
    """Action a rule may trigger on match."""
    BLOCK = "block"
    ALLOW = "allow"
    LOG = "log"


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class WAFRule:
    """Single WAF rule with a compiled regex pattern.

    Attributes:
        name:        Human-readable rule identifier.
        pattern:     Compiled regular expression to test against request data.
        action:      What to do when the pattern matches.
        severity:    How severe this class of attack is.
        category:    High-level category (e.g. ``"sqli"``, ``"xss"``).
        description: Extended explanation shown in logs and the block page.
        enabled:     Toggle to temporarily disable a rule without removing it.
    """

    name: str
    pattern: re.Pattern[str]
    action: WAFAction
    severity: WAFSeverity
    category: str
    description: str = ""
    enabled: bool = True


@dataclass
class WAFResult:
    """Outcome of inspecting a single HTTP request.

    Attributes:
        allowed:          ``True`` when the request may proceed.
        matched_rules:    List of :class:`WAFRule` objects that fired.
        action:           Final action taken (block / allow / log).
        block_reason:     Short explanation if the request was blocked.
        details:          Mapping of extra context (e.g. matched text).
    """

    allowed: bool
    matched_rules: list[WAFRule] = field(default_factory=list)
    action: WAFAction = WAFAction.ALLOW
    block_reason: str = ""
    details: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Blocked-page HTML template
# ---------------------------------------------------------------------------

BLOCKED_PAGE_HTML = """\
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>403 Forbidden &mdash; CyberSim6 WAF</title>
  <style>
    *{margin:0;padding:0;box-sizing:border-box}
    body{font-family:'Segoe UI',system-ui,sans-serif;background:#0f172a;
         color:#e2e8f0;display:flex;align-items:center;justify-content:center;
         min-height:100vh}
    .card{background:#1e293b;border:1px solid #334155;border-radius:12px;
          padding:2.5rem;max-width:520px;text-align:center;box-shadow:
          0 4px 24px rgba(0,0,0,.4)}
    .icon{font-size:3rem;margin-bottom:.75rem}
    h1{font-size:1.5rem;margin-bottom:.5rem;color:#f87171}
    p{line-height:1.6;color:#94a3b8;margin-bottom:.75rem}
    .reason{background:#0f172a;border:1px solid #334155;border-radius:8px;
            padding:.75rem 1rem;font-family:monospace;font-size:.85rem;
            color:#fbbf24;word-break:break-all}
    .footer{margin-top:1.25rem;font-size:.75rem;color:#475569}
  </style>
</head>
<body>
  <div class="card">
    <div class="icon">&#x1f6e1;</div>
    <h1>403 &mdash; Request Blocked</h1>
    <p>The Web Application Firewall detected a potential attack in your
       request and has blocked it for security reasons.</p>
    <div class="reason">{reason}</div>
    <p class="footer">CyberSim6 WAF &bull; Educational Security Platform</p>
  </div>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# Path traversal patterns
# ---------------------------------------------------------------------------

PATH_TRAVERSAL_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\.\./|\.\.\\", re.IGNORECASE), "Directory traversal (../)"),
    (re.compile(r"%2e%2e[/%5c]", re.IGNORECASE), "URL-encoded traversal"),
    (re.compile(r"/etc/(passwd|shadow|hosts)", re.IGNORECASE), "Sensitive file access"),
    (re.compile(r"(cmd|command)\.(exe|com)", re.IGNORECASE), "Windows command execution"),
    (re.compile(r"/proc/self/", re.IGNORECASE), "Linux proc access"),
]


# ---------------------------------------------------------------------------
# XXE (XML External Entity) patterns
# ---------------------------------------------------------------------------

XXE_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"<!ENTITY", re.IGNORECASE), "XML external entity declaration"),
    (re.compile(r"SYSTEM\s+[\"']", re.IGNORECASE), "SYSTEM keyword in XML entity"),
    (re.compile(r"file://", re.IGNORECASE), "file:// protocol in XML"),
    (re.compile(r"<!DOCTYPE\s+\w+\s+\[", re.IGNORECASE), "DOCTYPE with internal subset"),
    (re.compile(r"xmlns:xi=", re.IGNORECASE), "XInclude namespace declaration"),
    (re.compile(r"expect://", re.IGNORECASE), "expect:// protocol in XML"),
    (re.compile(r"php://filter", re.IGNORECASE), "php://filter wrapper"),
]


# ---------------------------------------------------------------------------
# Authentication bypass patterns
# ---------------------------------------------------------------------------

AUTH_BYPASS_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"admin\s*'\s*--", re.IGNORECASE), "Admin comment bypass (admin'--)"),
    (re.compile(r"'\s*OR\s+1\s*=\s*1", re.IGNORECASE), "OR 1=1 authentication bypass"),
    (re.compile(r"'\s*OR\s+'[^']*'\s*=\s*'[^']*'", re.IGNORECASE), "OR string equality bypass"),
    (re.compile(r"admin\s*'#", re.IGNORECASE), "Admin hash comment bypass"),
    (re.compile(r"'\s*OR\s+true", re.IGNORECASE), "OR true bypass"),
    (re.compile(r"token=['\"]?null['\"]?|token=undefined", re.IGNORECASE), "Token manipulation (null/undefined)"),
]


# ---------------------------------------------------------------------------
# Command injection patterns
# ---------------------------------------------------------------------------

COMMAND_INJECTION_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r";\s*(ls|cat|whoami|id|uname|pwd|wget|curl)\b", re.IGNORECASE), "Semicolon command chain"),
    (re.compile(r"\|\s*(ls|cat|whoami|id|uname|pwd|wget|curl)\b", re.IGNORECASE), "Pipe command injection"),
    (re.compile(r"&&\s*(ls|cat|whoami|id|uname|pwd|wget|curl)\b", re.IGNORECASE), "AND command chain"),
    (re.compile(r"`[^`]+`"), "Backtick command substitution"),
    (re.compile(r"\$\([^)]+\)"), "Dollar-paren command substitution"),
    (re.compile(r"\|\|\s*(ls|cat|whoami|id|uname|pwd|wget|curl)\b", re.IGNORECASE), "OR command chain"),
    (re.compile(r"/bin/(sh|bash|zsh|dash|csh)\b", re.IGNORECASE), "Direct shell invocation"),
    (re.compile(r"\bnc\s+-[elp]", re.IGNORECASE), "Netcat reverse shell"),
]


# ---------------------------------------------------------------------------
# SSRF (Server-Side Request Forgery) patterns
# ---------------------------------------------------------------------------

SSRF_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"(^|[=&?])url=https?://(127\.\d+\.\d+\.\d+|localhost)", re.IGNORECASE), "SSRF to localhost"),
    (re.compile(r"(^|[=&?])url=https?://10\.\d+\.\d+\.\d+", re.IGNORECASE), "SSRF to 10.x private network"),
    (re.compile(r"(^|[=&?])url=https?://192\.168\.\d+\.\d+", re.IGNORECASE), "SSRF to 192.168.x private network"),
    (re.compile(r"(^|[=&?])url=https?://172\.(1[6-9]|2\d|3[01])\.\d+\.\d+", re.IGNORECASE), "SSRF to 172.16-31.x private network"),
    (re.compile(r"(^|[=&?])url=https?://169\.254\.\d+\.\d+", re.IGNORECASE), "SSRF to link-local/metadata endpoint"),
    (re.compile(r"(^|[=&?])url=https?://0\.0\.0\.0", re.IGNORECASE), "SSRF to 0.0.0.0"),
    (re.compile(r"(^|[=&?])url=file://", re.IGNORECASE), "SSRF via file:// protocol"),
    (re.compile(r"(^|[=&?])url=https?://\[::1?\]", re.IGNORECASE), "SSRF to IPv6 loopback"),
]


# ---------------------------------------------------------------------------
# CSRF detection helpers (header-based, not pattern-matched on body)
# ---------------------------------------------------------------------------

# Methods that require CSRF protection
CSRF_PROTECTED_METHODS = {"POST", "PUT", "DELETE", "PATCH"}


# ---------------------------------------------------------------------------
# Suspicious user-agents
# ---------------------------------------------------------------------------

SUSPICIOUS_USER_AGENTS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"sqlmap", re.IGNORECASE), "sqlmap scanner"),
    (re.compile(r"nikto", re.IGNORECASE), "Nikto scanner"),
    (re.compile(r"nmap", re.IGNORECASE), "Nmap scanner"),
    (re.compile(r"dirbuster", re.IGNORECASE), "DirBuster scanner"),
    (re.compile(r"gobuster", re.IGNORECASE), "GoBuster scanner"),
    (re.compile(r"wfuzz", re.IGNORECASE), "WFuzz scanner"),
    (re.compile(r"masscan", re.IGNORECASE), "Masscan scanner"),
    (re.compile(r"zgrab", re.IGNORECASE), "ZGrab scanner"),
    (re.compile(r"hydra", re.IGNORECASE), "Hydra brute-forcer"),
]


# ---------------------------------------------------------------------------
# WebApplicationFirewall
# ---------------------------------------------------------------------------

class WebApplicationFirewall:
    """Main WAF engine.

    Aggregates built-in and custom rules, inspects HTTP requests, enforces
    rate limits, and tracks statistics.

    Args:
        logger:  :class:`CyberSimLogger` instance for event recording.
        config:  Optional configuration dict.  Recognised keys:

            * ``rate_limit_requests`` (int) -- Max requests per window (default 100).
            * ``rate_limit_window``   (int) -- Window length in seconds (default 60).
            * ``whitelist_ips``       (list[str]) -- IPs that bypass all rules.
            * ``blacklist_ips``       (list[str]) -- IPs that are always blocked.
            * ``enabled``             (bool) -- Global on/off switch (default True).
    """

    MODULE_NAME = "waf_engine"
    MODULE_TYPE = "detection"

    def __init__(self, logger: CyberSimLogger, config: dict[str, Any] | None = None) -> None:
        self.logger = logger
        self.config = config or {}

        # Rule storage
        self._rules: list[WAFRule] = []
        self._load_builtin_rules()

        # Rate limiting state  {ip: [timestamp, ...]}
        self._request_log: dict[str, list[float]] = {}
        self._rate_limit_requests: int = self.config.get("rate_limit_requests", 100)
        self._rate_limit_window: int = self.config.get("rate_limit_window", 60)

        # IP lists
        self._whitelist_ips: set[str] = set(self.config.get("whitelist_ips", []))
        self._blacklist_ips: set[str] = set(self.config.get("blacklist_ips", []))

        # Global toggle
        self._enabled: bool = self.config.get("enabled", True)

        # Statistics
        self._stats: dict[str, int] = {
            "total_requests": 0,
            "blocked": 0,
            "allowed": 0,
            "sqli_blocked": 0,
            "xss_blocked": 0,
            "path_traversal_blocked": 0,
            "rate_limit_blocked": 0,
            "user_agent_blocked": 0,
            "blacklist_blocked": 0,
            "custom_rule_blocked": 0,
            "csrf_blocked": 0,
            "xxe_blocked": 0,
            "auth_bypass_blocked": 0,
            "command_injection_blocked": 0,
            "ssrf_blocked": 0,
        }
        self._lock = threading.Lock()

    # -- Rule loading -------------------------------------------------------

    def _load_builtin_rules(self) -> None:
        """Populate the rule list from the existing CyberSim6 pattern sets."""

        # SQL Injection rules (from sqli/detection.py)
        for pattern, description in SQLI_PATTERNS:
            self._rules.append(WAFRule(
                name=f"sqli_{description.lower().replace(' ', '_')}",
                pattern=pattern,
                action=WAFAction.BLOCK,
                severity=WAFSeverity.HIGH,
                category="sqli",
                description=description,
            ))

        # XSS rules (from xss/detection.py)
        for pattern, description in XSS_PATTERNS:
            self._rules.append(WAFRule(
                name=f"xss_{description.lower().replace(' ', '_')}",
                pattern=pattern,
                action=WAFAction.BLOCK,
                severity=WAFSeverity.HIGH,
                category="xss",
                description=description,
            ))

        # Path traversal rules
        for pattern, description in PATH_TRAVERSAL_PATTERNS:
            self._rules.append(WAFRule(
                name=f"traversal_{description.lower().replace(' ', '_')}",
                pattern=pattern,
                action=WAFAction.BLOCK,
                severity=WAFSeverity.CRITICAL,
                category="path_traversal",
                description=description,
            ))

        # XXE rules
        for pattern, description in XXE_PATTERNS:
            self._rules.append(WAFRule(
                name=f"xxe_{description.lower().replace(' ', '_')}",
                pattern=pattern,
                action=WAFAction.BLOCK,
                severity=WAFSeverity.CRITICAL,
                category="xxe",
                description=description,
            ))

        # Authentication bypass rules
        for pattern, description in AUTH_BYPASS_PATTERNS:
            self._rules.append(WAFRule(
                name=f"auth_{description.lower().replace(' ', '_')}",
                pattern=pattern,
                action=WAFAction.BLOCK,
                severity=WAFSeverity.CRITICAL,
                category="auth_bypass",
                description=description,
            ))

        # Command injection rules
        for pattern, description in COMMAND_INJECTION_PATTERNS:
            self._rules.append(WAFRule(
                name=f"cmdi_{description.lower().replace(' ', '_')}",
                pattern=pattern,
                action=WAFAction.BLOCK,
                severity=WAFSeverity.CRITICAL,
                category="command_injection",
                description=description,
            ))

        # SSRF rules
        for pattern, description in SSRF_PATTERNS:
            self._rules.append(WAFRule(
                name=f"ssrf_{description.lower().replace(' ', '_')}",
                pattern=pattern,
                action=WAFAction.BLOCK,
                severity=WAFSeverity.HIGH,
                category="ssrf",
                description=description,
            ))

        # Suspicious user-agent rules
        for pattern, description in SUSPICIOUS_USER_AGENTS:
            self._rules.append(WAFRule(
                name=f"ua_{description.lower().replace(' ', '_')}",
                pattern=pattern,
                action=WAFAction.BLOCK,
                severity=WAFSeverity.MEDIUM,
                category="user_agent",
                description=description,
            ))

    # -- Public API ---------------------------------------------------------

    def add_rule(self, rule: WAFRule) -> None:
        """Register a custom WAF rule.

        Args:
            rule: :class:`WAFRule` to add to the inspection chain.
        """
        self._rules.append(rule)
        self._log("rule_added", {
            "message": f"Custom rule added: {rule.name}",
            "rule_name": rule.name,
            "category": rule.category,
            "status": "info",
        })

    def inspect_request(
        self,
        method: str = "GET",
        path: str = "/",
        headers: dict[str, str] | None = None,
        body: str = "",
        source_ip: str = "127.0.0.1",
    ) -> WAFResult:
        """Inspect an incoming HTTP request against all active rules.

        Args:
            method:    HTTP method (GET, POST, ...).
            path:      Request path (may include query string).
            headers:   Request headers as a flat dict.
            body:      Request body (for POST/PUT).
            source_ip: IP address of the client.

        Returns:
            :class:`WAFResult` with the inspection outcome.
        """
        headers = headers or {}

        with self._lock:
            self._stats["total_requests"] += 1

        # Bypass if WAF is disabled
        if not self._enabled:
            with self._lock:
                self._stats["allowed"] += 1
            return WAFResult(allowed=True)

        # Whitelist check
        if source_ip in self._whitelist_ips:
            with self._lock:
                self._stats["allowed"] += 1
            self._log("request_whitelisted", {
                "message": f"Whitelisted IP {source_ip} bypassed WAF",
                "source": source_ip,
                "path": path,
                "status": "info",
            })
            return WAFResult(allowed=True, details={"reason": "whitelisted_ip"})

        # Blacklist check
        if source_ip in self._blacklist_ips:
            with self._lock:
                self._stats["blocked"] += 1
                self._stats["blacklist_blocked"] += 1
            self._log("request_blacklisted", {
                "message": f"Blacklisted IP {source_ip} blocked",
                "source": source_ip,
                "path": path,
                "status": "warning",
            })
            return WAFResult(
                allowed=False,
                action=WAFAction.BLOCK,
                block_reason=f"Blacklisted IP: {source_ip}",
            )

        # Rate limiting
        rate_result = self._check_rate_limit(source_ip)
        if rate_result is not None:
            return rate_result

        # CSRF protection: check state-changing requests for valid tokens/headers
        csrf_result = self._check_csrf(method, path, headers, body, source_ip)
        if csrf_result is not None:
            return csrf_result

        # Build the text blob to inspect (path + decoded query + body + headers)
        decoded_path = urllib.parse.unquote(path)
        inspect_text = f"{method} {decoded_path} {body}"

        # Also inspect individual header values
        user_agent = headers.get("User-Agent", headers.get("user-agent", ""))

        # Evaluate rules
        matched_rules: list[WAFRule] = []

        for rule in self._rules:
            if not rule.enabled:
                continue

            # User-agent rules only check the UA header
            if rule.category == "user_agent":
                if rule.pattern.search(user_agent):
                    matched_rules.append(rule)
                continue

            # All other rules inspect the combined text
            if rule.pattern.search(inspect_text):
                matched_rules.append(rule)

        # Determine outcome -- any BLOCK rule wins
        block_rules = [r for r in matched_rules if r.action == WAFAction.BLOCK]
        if block_rules:
            top_rule = max(block_rules, key=lambda r: list(WAFSeverity).index(r.severity))
            reason = f"[{top_rule.category.upper()}] {top_rule.description}"

            # Update stats
            with self._lock:
                self._stats["blocked"] += 1
                self._increment_category_stat(top_rule.category)

            self._log("request_blocked", {
                "message": f"BLOCKED {method} {path} -- {reason}",
                "source": source_ip,
                "path": path,
                "method": method,
                "rule": top_rule.name,
                "category": top_rule.category,
                "severity": top_rule.severity.value,
                "status": "warning",
            })

            return WAFResult(
                allowed=False,
                matched_rules=matched_rules,
                action=WAFAction.BLOCK,
                block_reason=reason,
                details={"top_rule": top_rule.name, "source_ip": source_ip},
            )

        # Request is clean
        with self._lock:
            self._stats["allowed"] += 1

        self._log("request_allowed", {
            "message": f"ALLOWED {method} {path}",
            "source": source_ip,
            "path": path,
            "method": method,
            "status": "info",
        })

        return WAFResult(allowed=True, matched_rules=matched_rules)

    def get_stats(self) -> dict[str, int]:
        """Return a snapshot of the current WAF statistics.

        Returns:
            Dictionary with keys: ``total_requests``, ``blocked``,
            ``allowed``, and per-category block counts.
        """
        with self._lock:
            return dict(self._stats)

    def reset_stats(self) -> None:
        """Zero all counters."""
        with self._lock:
            for key in self._stats:
                self._stats[key] = 0

    def get_blocked_page(self, reason: str) -> str:
        """Render the 403 block page HTML with the given reason.

        Args:
            reason: Explanation text inserted into the template.

        Returns:
            Complete HTML string ready to be sent as the response body.
        """
        import html as _html
        return BLOCKED_PAGE_HTML.replace("{reason}", _html.escape(reason))

    # -- CSRF protection ----------------------------------------------------

    def _check_csrf(
        self,
        method: str,
        path: str,
        headers: dict[str, str],
        body: str,
        source_ip: str,
    ) -> WAFResult | None:
        """Check state-changing requests for CSRF indicators.

        Blocks POST/PUT/DELETE/PATCH requests that are missing both a CSRF
        token (in body or header) and a valid Origin/Referer header.  This
        is intentionally conservative: a request is only blocked when *all*
        of the indicators are absent.

        Returns:
            A blocking :class:`WAFResult` if CSRF protection fails, else ``None``.
        """
        if method.upper() not in CSRF_PROTECTED_METHODS:
            return None

        # Check for CSRF token in body or custom header
        has_csrf_token = (
            "csrf_token" in body.lower()
            or "csrf-token" in body.lower()
            or "_token" in body.lower()
            or "X-CSRF-Token" in headers
            or "x-csrf-token" in headers
            or "X-XSRF-TOKEN" in headers
            or "x-xsrf-token" in headers
        )

        # Check for valid Origin or Referer header
        has_origin = bool(headers.get("Origin") or headers.get("origin"))
        has_referer = bool(headers.get("Referer") or headers.get("referer"))

        if not has_csrf_token and not has_origin and not has_referer:
            reason = "[CSRF] Missing CSRF token and Origin/Referer headers"
            with self._lock:
                self._stats["blocked"] += 1
                self._stats["csrf_blocked"] += 1

            self._log("request_blocked", {
                "message": f"BLOCKED {method} {path} -- {reason}",
                "source": source_ip,
                "path": path,
                "method": method,
                "category": "csrf",
                "severity": "high",
                "status": "warning",
            })

            return WAFResult(
                allowed=False,
                action=WAFAction.BLOCK,
                block_reason=reason,
                details={"category": "csrf", "source_ip": source_ip},
            )

        return None

    # -- Rate limiting ------------------------------------------------------

    def _check_rate_limit(self, source_ip: str) -> WAFResult | None:
        """Enforce per-IP rate limiting.

        Returns:
            A blocking :class:`WAFResult` if the limit is exceeded, else ``None``.
        """
        now = time.time()
        window_start = now - self._rate_limit_window

        with self._lock:
            timestamps = self._request_log.setdefault(source_ip, [])
            # Prune old entries
            timestamps[:] = [t for t in timestamps if t > window_start]
            timestamps.append(now)

            if len(timestamps) > self._rate_limit_requests:
                self._stats["blocked"] += 1
                self._stats["rate_limit_blocked"] += 1
                self._log("rate_limit_exceeded", {
                    "message": f"Rate limit exceeded for {source_ip} "
                               f"({len(timestamps)}/{self._rate_limit_requests} "
                               f"in {self._rate_limit_window}s)",
                    "source": source_ip,
                    "count": len(timestamps),
                    "limit": self._rate_limit_requests,
                    "status": "warning",
                })
                return WAFResult(
                    allowed=False,
                    action=WAFAction.BLOCK,
                    block_reason=f"Rate limit exceeded ({len(timestamps)}"
                                 f"/{self._rate_limit_requests} requests "
                                 f"in {self._rate_limit_window}s)",
                )
        return None

    # -- Internal helpers ---------------------------------------------------

    def _increment_category_stat(self, category: str) -> None:
        """Bump the per-category block counter (caller holds *_lock*)."""
        mapping = {
            "sqli": "sqli_blocked",
            "xss": "xss_blocked",
            "path_traversal": "path_traversal_blocked",
            "user_agent": "user_agent_blocked",
            "csrf": "csrf_blocked",
            "xxe": "xxe_blocked",
            "auth_bypass": "auth_bypass_blocked",
            "command_injection": "command_injection_blocked",
            "ssrf": "ssrf_blocked",
        }
        key = mapping.get(category, "custom_rule_blocked")
        self._stats[key] = self._stats.get(key, 0) + 1

    def _log(self, event_type: str, details: dict[str, Any]) -> None:
        """Emit a structured log event through the CyberSim logger."""
        self.logger.log_event(
            module=self.MODULE_NAME,
            module_type=self.MODULE_TYPE,
            event_type=event_type,
            details=details,
        )


# ---------------------------------------------------------------------------
# WAFServer -- HTTP reverse-proxy with WAF inspection
# ---------------------------------------------------------------------------

class _WAFRequestHandler(http.server.BaseHTTPRequestHandler):
    """HTTP request handler that delegates inspection to a :class:`WebApplicationFirewall`."""

    # Quieten default logging to stderr
    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        pass

    # -- Shared request processing ------------------------------------------

    def _handle(self) -> None:
        """Common handler for all HTTP methods."""
        waf: WebApplicationFirewall = self.server.waf  # type: ignore[attr-defined]
        backend: str = self.server.backend_url  # type: ignore[attr-defined]

        # Read body for POST / PUT
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8", errors="replace") if content_length else ""

        # Flatten headers
        headers = {k: v for k, v in self.headers.items()}

        # Derive source IP
        source_ip = self.client_address[0] if self.client_address else "0.0.0.0"

        result = waf.inspect_request(
            method=self.command,
            path=self.path,
            headers=headers,
            body=body,
            source_ip=source_ip,
        )

        if not result.allowed:
            # Send 403 block page
            page = waf.get_blocked_page(result.block_reason).encode("utf-8")
            self.send_response(403)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(page)))
            self.end_headers()
            self.wfile.write(page)
            return

        # Forward to backend
        try:
            target_url = backend.rstrip("/") + self.path
            req = urllib.request.Request(
                target_url,
                data=body.encode("utf-8") if body else None,
                headers=headers,
                method=self.command,
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                resp_body = resp.read()
                self.send_response(resp.status)
                for key, val in resp.getheaders():
                    if key.lower() not in ("transfer-encoding", "connection"):
                        self.send_header(key, val)
                self.end_headers()
                self.wfile.write(resp_body)
        except Exception as exc:
            error_msg = f"Backend error: {exc}"
            self.send_response(502)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(error_msg.encode("utf-8"))

    # Map all common HTTP verbs to the shared handler
    do_GET = _handle
    do_POST = _handle
    do_PUT = _handle
    do_DELETE = _handle
    do_PATCH = _handle
    do_HEAD = _handle
    do_OPTIONS = _handle


class WAFServer(http.server.HTTPServer):
    """HTTP reverse-proxy server with :class:`WebApplicationFirewall` inspection.

    Args:
        listen_addr: ``(host, port)`` tuple for the listening socket.
        waf:         Configured :class:`WebApplicationFirewall` instance.
        backend_url: Origin server URL to forward clean requests to
                     (e.g. ``"http://127.0.0.1:8080"``).
    """

    def __init__(
        self,
        listen_addr: tuple[str, int],
        waf: WebApplicationFirewall,
        backend_url: str = "http://127.0.0.1:8080",
    ) -> None:
        self.waf = waf
        self.backend_url = backend_url
        super().__init__(listen_addr, _WAFRequestHandler)

    def start(self) -> threading.Thread:
        """Start the server in a background daemon thread.

        Returns:
            The :class:`threading.Thread` running the server.
        """
        thread = threading.Thread(target=self.serve_forever, daemon=True)
        thread.start()
        self.waf._log("server_started", {
            "message": f"WAF server listening on {self.server_address}",
            "backend": self.backend_url,
            "status": "info",
        })
        return thread

    def shutdown(self) -> None:  # type: ignore[override]
        """Gracefully stop the server."""
        super().shutdown()
        self.waf._log("server_stopped", {
            "message": "WAF server stopped",
            "status": "info",
        })
