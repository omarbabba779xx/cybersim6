"""Tests for the Port Scanner module."""

import socket
import threading
import time

import pytest

from cybersim.core.logging_engine import CyberSimLogger
from cybersim.core.safety import SafetyError
from cybersim.scanner.port_scanner import (
    COMMON_PORTS,
    PortScanner,
    PortScanDetector,
    ScanResult,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _start_temp_server() -> tuple[socket.socket, int]:
    """Bind a TCP server on an ephemeral port and start listening.

    Returns:
        (server_socket, port) -- caller must close the socket when done.
    """
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    return srv, port


def _make_scanner(**kwargs) -> PortScanner:
    logger = CyberSimLogger(session_id="test_scanner")
    return PortScanner(config={}, logger=logger, **kwargs)


# ---------------------------------------------------------------------------
# PortScanner tests
# ---------------------------------------------------------------------------

class TestPortScanner:
    """Unit tests for :class:`PortScanner`."""

    def test_scan_closed_port_returns_closed(self):
        """Scanning a port with nothing listening should return 'closed'."""
        scanner = _make_scanner(timeout=0.3)
        # Port 1 is almost never open on localhost
        result = scanner.scan_port(1)
        assert isinstance(result, ScanResult)
        assert result.state in ("closed", "filtered")
        assert result.port == 1

    def test_scan_open_port_returns_open(self):
        """Scanning a port with an active listener should return 'open'."""
        srv, port = _start_temp_server()
        try:
            scanner = _make_scanner(timeout=1.0)
            result = scanner.scan_port(port)
            assert result.state == "open"
            assert result.port == port
            assert result.response_time > 0
        finally:
            srv.close()

    def test_common_ports_dict_exists_and_populated(self):
        """The COMMON_PORTS mapping should contain well-known entries."""
        assert isinstance(COMMON_PORTS, dict)
        assert len(COMMON_PORTS) > 10
        assert COMMON_PORTS[80] == "HTTP"
        assert COMMON_PORTS[22] == "SSH"
        assert COMMON_PORTS[443] == "HTTPS"

    def test_service_detection(self):
        """detect_service should return the correct service name."""
        scanner = _make_scanner()
        assert scanner.detect_service(80) == "HTTP"
        assert scanner.detect_service(22) == "SSH"
        assert scanner.detect_service(443) == "HTTPS"
        assert scanner.detect_service(99999) == ""

    def test_safety_blocks_non_localhost(self):
        """Creating a scanner aimed at an external IP must raise SafetyError."""
        with pytest.raises(SafetyError):
            _make_scanner(target="8.8.8.8")

    def test_safety_blocks_external_hostname(self):
        """Creating a scanner aimed at an external hostname must raise SafetyError."""
        with pytest.raises(SafetyError):
            _make_scanner(target="example.com")

    def test_scan_result_structure(self):
        """ScanResult.to_dict should contain all expected keys."""
        result = ScanResult(port=80, state="open", service="HTTP",
                            banner="Apache", response_time=0.0012)
        d = result.to_dict()
        assert set(d.keys()) == {"port", "state", "service", "banner", "response_time"}
        assert d["port"] == 80
        assert d["state"] == "open"
        assert d["service"] == "HTTP"
        assert d["banner"] == "Apache"

    def test_scan_range_returns_sorted_results(self):
        """scan_range should return results sorted by port number."""
        srv, port = _start_temp_server()
        try:
            scanner = _make_scanner(timeout=0.2)
            start = max(1, port - 2)
            end = port + 2
            results = scanner.scan_range(start=start, end=end, threads=5)
            ports = [r.port for r in results]
            assert ports == sorted(ports)
            assert len(results) == end - start + 1
        finally:
            srv.close()

    def test_get_open_ports_filters_correctly(self):
        """get_open_ports should return only results with state 'open'."""
        srv, port = _start_temp_server()
        try:
            scanner = _make_scanner(timeout=0.2)
            scanner.scan_range(start=port, end=port + 2, threads=3)
            open_results = scanner.get_open_ports()
            assert all(r.state == "open" for r in open_results)
            assert any(r.port == port for r in open_results)
        finally:
            srv.close()

    def test_progress_callback_invoked(self):
        """The progress callback should be called for every port scanned."""
        scanner = _make_scanner(timeout=0.1)
        progress_calls: list[tuple[int, int]] = []
        scanner.scan_range(start=1, end=5, threads=5,
                           progress_callback=lambda c, t: progress_calls.append((c, t)))
        assert len(progress_calls) == 5
        assert all(t == 5 for _, t in progress_calls)


# ---------------------------------------------------------------------------
# PortScanDetector tests
# ---------------------------------------------------------------------------

class TestPortScanDetector:
    """Unit tests for :class:`PortScanDetector`."""

    def setup_method(self) -> None:
        self.logger = CyberSimLogger(session_id="test_scan_detector")
        self.detector = PortScanDetector(
            config={}, logger=self.logger, threshold=20, window=10
        )

    def test_scan_detected_above_threshold(self):
        """Touching >= threshold distinct ports should flag a scan."""
        for port in range(1, 25):
            self.detector.record_connection(port, "10.0.0.1")
        result = self.detector.check_scan()
        assert result["is_scan"] is True
        assert result["ports_touched"] >= 20
        assert result["source"] == "10.0.0.1"

    def test_no_scan_below_threshold(self):
        """Touching fewer than threshold distinct ports should not flag a scan."""
        for port in range(1, 6):
            self.detector.record_connection(port, "10.0.0.1")
        result = self.detector.check_scan()
        assert result["is_scan"] is False
        assert result["ports_touched"] == 5

    def test_events_logged_on_scan_detection(self):
        """A port_scan_detected event should be logged when threshold is exceeded."""
        for port in range(1, 30):
            self.detector.record_connection(port, "10.0.0.1")
        self.detector.check_scan()
        events = self.logger.get_events(event_type="port_scan_detected")
        assert len(events) > 0

    def test_check_scan_specific_source(self):
        """check_scan with a specific source_ip should inspect only that source."""
        for port in range(1, 25):
            self.detector.record_connection(port, "attacker")
        for port in range(1, 3):
            self.detector.record_connection(port, "benign")

        result_attacker = self.detector.check_scan(source_ip="attacker")
        assert result_attacker["is_scan"] is True

        result_benign = self.detector.check_scan(source_ip="benign")
        assert result_benign["is_scan"] is False
