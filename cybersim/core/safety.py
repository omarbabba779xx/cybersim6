"""
CyberSim6 - Safety Guard Framework
Ensures all simulations stay within sandbox boundaries.
"""

import ipaddress
import socket
from pathlib import Path


ALLOWED_TARGETS = {"127.0.0.1", "localhost", "::1", "0.0.0.0"}
SANDBOX_MARKER = ".cybersim_sandbox"


class SafetyError(Exception):
    """Raised when a safety constraint is violated."""
    pass


def validate_target_ip(target: str):
    """Ensure target resolves to a loopback address only."""
    try:
        resolved = socket.gethostbyname(target)
        addr = ipaddress.ip_address(resolved)
        if not addr.is_loopback:
            raise SafetyError(
                f"BLOCKED: Target {target} ({resolved}) is not a loopback address. "
                "CyberSim6 only operates on localhost targets."
            )
    except socket.gaierror:
        raise SafetyError(f"BLOCKED: Cannot resolve hostname '{target}'.")


def validate_sandbox_directory(path: Path):
    """Ensure directory is a designated sandbox (contains marker file)."""
    path = Path(path)
    if not path.exists():
        raise SafetyError(f"BLOCKED: Sandbox directory '{path}' does not exist.")
    marker = path / SANDBOX_MARKER
    if not marker.exists():
        raise SafetyError(
            f"BLOCKED: Directory '{path}' is not a designated sandbox. "
            f"Missing marker file: {SANDBOX_MARKER}. "
            "Run 'python sandbox/setup_sandbox.py' first."
        )


def validate_file_in_sandbox(filepath: Path, sandbox_root: Path):
    """Ensure file path resolves inside sandbox root (prevents path traversal)."""
    resolved = Path(filepath).resolve()
    sandbox_resolved = Path(sandbox_root).resolve()
    if not str(resolved).startswith(str(sandbox_resolved)):
        raise SafetyError(
            f"BLOCKED: File '{filepath}' resolves outside sandbox '{sandbox_root}'. "
            "Path traversal attempt detected."
        )


def validate_url_localhost(url: str):
    """Ensure URL targets localhost only."""
    from urllib.parse import urlparse
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    if hostname not in ALLOWED_TARGETS:
        try:
            validate_target_ip(hostname)
        except SafetyError:
            raise SafetyError(
                f"BLOCKED: URL '{url}' does not target localhost. "
                "CyberSim6 only operates on local targets."
            )
