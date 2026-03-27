"""
CyberSim6 - Port Scanner Module
Nmap-like localhost port scanner.

Scans TCP ports, detects services, grabs banners.
Safety: localhost only, configurable port range.

Uses TCP connect scanning with concurrent threads for speed,
service detection via a known-ports dictionary, and banner
grabbing by reading the first bytes from open ports.
"""

from __future__ import annotations

import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Any, Callable

from cybersim.core.base_module import BaseModule
from cybersim.core.logging_engine import CyberSimLogger
from cybersim.core.safety import SafetyError, validate_target_ip


# ---------------------------------------------------------------------------
# Well-known ports and their typical services
# ---------------------------------------------------------------------------

COMMON_PORTS: dict[int, str] = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    993: "IMAPS",
    995: "POP3S",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
    8888: "HTTP-Alt",
    27017: "MongoDB",
}

#: The "top 100" ports most commonly found open on hosts.  Derived from
#: Nmap's ``nmap-services`` frequency list (trimmed for brevity).
TOP_100_PORTS: list[int] = sorted(
    {
        7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110,
        111, 113, 119, 135, 139, 143, 144, 179, 199, 389, 427, 443, 444,
        445, 465, 513, 514, 515, 543, 544, 548, 554, 587, 631, 646, 873,
        990, 993, 995, 1025, 1026, 1027, 1028, 1029, 1110, 1433, 1720,
        1723, 1755, 1900, 2000, 2001, 2049, 2121, 2717, 3000, 3128,
        3306, 3389, 3986, 4899, 5000, 5009, 5051, 5060, 5101, 5190,
        5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001, 6646, 7070,
        8000, 8008, 8009, 8080, 8081, 8443, 8888, 9100, 9999, 10000,
        32768, 49152, 49153, 49154, 49155, 49156, 49157,
    }
)


# ---------------------------------------------------------------------------
# Scan result data class
# ---------------------------------------------------------------------------

@dataclass
class ScanResult:
    """Result of scanning a single TCP port.

    Attributes:
        port: The scanned port number.
        state: One of ``"open"``, ``"closed"``, or ``"filtered"``.
        service: Detected service name (empty string if unknown).
        banner: Raw banner text grabbed from the port (empty string if none).
        response_time: Round-trip time in seconds for the connect attempt.
    """

    port: int
    state: str = "closed"
    service: str = ""
    banner: str = ""
    response_time: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        """Serialise the result to a plain dictionary."""
        return {
            "port": self.port,
            "state": self.state,
            "service": self.service,
            "banner": self.banner,
            "response_time": round(self.response_time, 4),
        }


# ---------------------------------------------------------------------------
# Port Scanner (attack / recon module)
# ---------------------------------------------------------------------------

class PortScanner(BaseModule):
    """TCP connect-scan port scanner limited to localhost targets.

    Inherits from :class:`BaseModule` and enforces the safety constraint
    that only loopback addresses may be scanned.

    Args:
        config: Module configuration dict.  Recognised keys:

            * ``target`` (str) -- IP or hostname to scan (default ``"127.0.0.1"``).
            * ``timeout`` (float) -- Per-port connect timeout in seconds (default ``1.0``).
        logger: Shared :class:`CyberSimLogger` instance.
        target: Override for ``config["target"]``.
        timeout: Override for ``config["timeout"]``.
    """

    MODULE_TYPE = "attack"
    MODULE_NAME = "port_scanner"

    def __init__(
        self,
        config: dict[str, Any] | None = None,
        logger: CyberSimLogger | None = None,
        target: str = "127.0.0.1",
        timeout: float = 1.0,
    ) -> None:
        config = config or {}
        self.target: str = config.get("target", target)
        self.timeout: float = config.get("timeout", timeout)
        self._results: list[ScanResult] = []
        # BaseModule.__init__ calls _validate_safety
        super().__init__(config, logger or CyberSimLogger(session_id="scanner"))

    # -- safety -------------------------------------------------------------

    def _validate_safety(self) -> None:
        """Block any non-localhost target."""
        validate_target_ip(self.target)

    # -- single port --------------------------------------------------------

    def scan_port(self, port: int) -> ScanResult:
        """Scan a single TCP port on the configured target.

        Args:
            port: Port number (1-65535).

        Returns:
            A :class:`ScanResult` with state, service, banner, and timing.
        """
        result = ScanResult(port=port)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        start = time.perf_counter()
        try:
            sock.connect((self.target, port))
            elapsed = time.perf_counter() - start
            result.state = "open"
            result.response_time = elapsed
            result.service = self.detect_service(port)
            result.banner = self._grab_banner_from_socket(sock)
        except socket.timeout:
            result.state = "filtered"
            result.response_time = time.perf_counter() - start
        except (ConnectionRefusedError, OSError):
            result.state = "closed"
            result.response_time = time.perf_counter() - start
        finally:
            sock.close()
        return result

    # -- range scan ---------------------------------------------------------

    def scan_range(
        self,
        start: int = 1,
        end: int = 1024,
        threads: int = 50,
        progress_callback: Callable[[int, int], None] | None = None,
    ) -> list[ScanResult]:
        """Scan a contiguous range of ports concurrently.

        Args:
            start: First port (inclusive).
            end: Last port (inclusive).
            threads: Maximum number of concurrent threads.
            progress_callback: Optional ``(completed, total)`` callback.

        Returns:
            List of :class:`ScanResult` objects sorted by port number.
        """
        self._validate_safety()
        ports = list(range(start, end + 1))
        total = len(ports)
        results: list[ScanResult] = []
        completed = 0

        self.log_event("scan_started", {
            "target": self.target,
            "port_range": f"{start}-{end}",
            "threads": threads,
        })

        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(self.scan_port, p): p for p in ports}
            for future in as_completed(futures):
                result = future.result()
                results.append(result)
                completed += 1
                if progress_callback is not None:
                    progress_callback(completed, total)

        results.sort(key=lambda r: r.port)
        self._results = results

        open_ports = [r for r in results if r.state == "open"]
        self.log_event("scan_completed", {
            "target": self.target,
            "ports_scanned": total,
            "open_ports": len(open_ports),
        })
        return results

    # -- convenience scans --------------------------------------------------

    def scan_common(self) -> list[ScanResult]:
        """Scan only the well-known ports defined in :data:`COMMON_PORTS`.

        Returns:
            List of :class:`ScanResult` objects sorted by port number.
        """
        self._validate_safety()
        results: list[ScanResult] = []
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(self.scan_port, p): p for p in COMMON_PORTS}
            for future in as_completed(futures):
                results.append(future.result())
        results.sort(key=lambda r: r.port)
        self._results = results
        return results

    def quick_scan(self) -> list[ScanResult]:
        """Scan the top 100 most common ports.

        Returns:
            List of :class:`ScanResult` objects sorted by port number.
        """
        self._validate_safety()
        results: list[ScanResult] = []
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = {executor.submit(self.scan_port, p): p for p in TOP_100_PORTS}
            for future in as_completed(futures):
                results.append(future.result())
        results.sort(key=lambda r: r.port)
        self._results = results
        return results

    # -- accessors ----------------------------------------------------------

    def get_open_ports(self) -> list[ScanResult]:
        """Return only the open-port results from the last scan."""
        return [r for r in self._results if r.state == "open"]

    # -- service / banner ---------------------------------------------------

    def detect_service(self, port: int) -> str:
        """Return the service name associated with *port*, or ``""``."""
        return COMMON_PORTS.get(port, "")

    def grab_banner(self, port: int, timeout: float | None = None) -> str:
        """Open a fresh connection to *port* and read a banner.

        Args:
            port: Port number to connect to.
            timeout: Socket timeout (defaults to ``self.timeout``).

        Returns:
            The banner string, or ``""`` on failure.
        """
        self._validate_safety()
        timeout = timeout if timeout is not None else self.timeout
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            sock.connect((self.target, port))
            return self._grab_banner_from_socket(sock)
        except (socket.timeout, ConnectionRefusedError, OSError):
            return ""
        finally:
            sock.close()

    # -- BaseModule interface -----------------------------------------------

    def run(self, **kwargs: Any) -> None:
        """Run a scan using parameters from *config* or *kwargs*.

        Keyword Args:
            start (int): First port (default 1).
            end (int): Last port (default 1024).
            threads (int): Concurrency (default 50).
        """
        self._running = True
        start = kwargs.get("start", self.config.get("start", 1))
        end = kwargs.get("end", self.config.get("end", 1024))
        threads = kwargs.get("threads", self.config.get("threads", 50))
        self.scan_range(start, end, threads)
        self._running = False

    def stop(self) -> None:
        """Signal the scanner to stop."""
        self._running = False

    # -- private helpers ----------------------------------------------------

    @staticmethod
    def _grab_banner_from_socket(sock: socket.socket, max_bytes: int = 1024) -> str:
        """Read up to *max_bytes* from an already-connected socket.

        Returns:
            Decoded banner text, or ``""`` if nothing could be read.
        """
        try:
            sock.settimeout(0.5)
            data = sock.recv(max_bytes)
            return data.decode("utf-8", errors="replace").strip()
        except (socket.timeout, OSError):
            return ""


# ---------------------------------------------------------------------------
# Port-scan detector (blue-team / detection module)
# ---------------------------------------------------------------------------

class PortScanDetector(BaseModule):
    """Detect port-scanning activity by monitoring connection patterns.

    Records incoming connection attempts and raises an alert when the
    number of distinct ports touched by a single source exceeds a
    threshold within a sliding time window.

    Args:
        config: Module configuration dict.  Recognised keys:

            * ``threshold`` (int) -- Distinct-port count that triggers an
              alert (default ``20``).
            * ``window`` (int) -- Sliding window size in seconds (default
              ``10``).
        logger: Shared :class:`CyberSimLogger` instance.
        threshold: Override for ``config["threshold"]``.
        window: Override for ``config["window"]``.
    """

    MODULE_TYPE = "detection"
    MODULE_NAME = "port_scan_detector"

    def __init__(
        self,
        config: dict[str, Any] | None = None,
        logger: CyberSimLogger | None = None,
        threshold: int = 20,
        window: int = 10,
    ) -> None:
        config = config or {}
        self.threshold: int = config.get("threshold", threshold)
        self.window: int = config.get("window", window)
        # source_ip -> list of (timestamp, port)
        self._connections: dict[str, list[tuple[float, int]]] = {}
        super().__init__(config, logger or CyberSimLogger(session_id="scan_detector"))

    def _validate_safety(self) -> None:
        """No external targets needed for the detector -- always safe."""
        pass

    # -- public API ---------------------------------------------------------

    def record_connection(self, port: int, source_ip: str = "127.0.0.1") -> None:
        """Record an incoming connection attempt.

        Args:
            port: Destination port that was touched.
            source_ip: Source IP address of the connector.
        """
        now = time.time()
        self._connections.setdefault(source_ip, []).append((now, port))

    def check_scan(self, source_ip: str | None = None) -> dict[str, Any]:
        """Analyse recorded connections and determine if a scan is underway.

        Args:
            source_ip: If given, check only this source.  Otherwise check
                all recorded sources and return the worst offender.

        Returns:
            Dictionary with keys:

            * ``is_scan`` (bool)
            * ``ports_touched`` (int) -- distinct ports in the window
            * ``source`` (str) -- source IP responsible
            * ``threshold`` (int) -- configured threshold
            * ``window`` (int) -- configured window in seconds
        """
        now = time.time()
        sources = [source_ip] if source_ip else list(self._connections.keys())

        worst: dict[str, Any] = {
            "is_scan": False,
            "ports_touched": 0,
            "source": "",
            "threshold": self.threshold,
            "window": self.window,
        }

        for src in sources:
            entries = self._connections.get(src, [])
            # Keep only entries inside the sliding window
            recent = [(ts, p) for ts, p in entries if now - ts <= self.window]
            self._connections[src] = recent
            distinct_ports = len({p for _, p in recent})

            if distinct_ports > worst["ports_touched"]:
                worst["ports_touched"] = distinct_ports
                worst["source"] = src
                worst["is_scan"] = distinct_ports >= self.threshold

        if worst["is_scan"]:
            self.log_event("port_scan_detected", {
                "source": worst["source"],
                "ports_touched": worst["ports_touched"],
                "threshold": self.threshold,
                "window": self.window,
                "status": "critical",
            })

        return worst

    # -- BaseModule interface -----------------------------------------------

    def run(self, **kwargs: Any) -> None:
        """Start the detector (monitoring mode)."""
        self._running = True

    def stop(self) -> None:
        """Stop the detector."""
        self._running = False
