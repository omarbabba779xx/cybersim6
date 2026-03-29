"""
CyberSim6 - Safety Guard Framework
Ensures all simulations stay within sandbox boundaries.

Seven-layer safety model:
    1. IP validation (loopback only)
    2. Sandbox marker file check
    3. Anti-path-traversal via ``resolve()``
    4. Ransomware file-count / size limits
    5. Interactive confirmation before encryption
    6. Non-destructive defaults
    7. Blocked system directories
"""

from __future__ import annotations

import ipaddress
import socket
from pathlib import Path


LOOPBACK_TARGETS: set[str] = {"127.0.0.1", "localhost", "::1"}  # nosec B104
SANDBOX_MARKER: str = ".cybersim_sandbox"


class SafetyError(Exception):
    """Raised when a safety constraint is violated."""
    pass


def validate_target_ip(target: str) -> None:
    """Ensure *target* resolves to a loopback address only.

    Raises:
        SafetyError: If the target is external or unresolvable.
    """
    try:
        literal = ipaddress.ip_address(target)
        addresses = [literal]
    except ValueError:
        try:
            infos = socket.getaddrinfo(target, None)
        except socket.gaierror:
            raise SafetyError(f"BLOCKED: Cannot resolve hostname '{target}'.")

        addresses = []
        for info in infos:
            resolved = info[4][0]
            try:
                addresses.append(ipaddress.ip_address(resolved))
            except ValueError:
                continue

        if not addresses:
            raise SafetyError(f"BLOCKED: Cannot resolve hostname '{target}'.")

    for addr in addresses:
        if not addr.is_loopback:
            raise SafetyError(
                f"BLOCKED: Target {target} ({addr}) is not a loopback address. "
                "CyberSim6 only operates on localhost targets."
            )


def validate_sandbox_directory(path: Path) -> None:
    """Ensure directory is a designated sandbox (contains marker file).

    Raises:
        SafetyError: If the directory does not exist or lacks the marker.
    """
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


def validate_file_in_sandbox(filepath: Path, sandbox_root: Path) -> None:
    """Ensure *filepath* resolves inside *sandbox_root* (prevents path traversal).

    Raises:
        SafetyError: If the resolved path escapes the sandbox root.
    """
    resolved = Path(filepath).resolve()
    sandbox_resolved = Path(sandbox_root).resolve()
    try:
        resolved.relative_to(sandbox_resolved)
    except ValueError:
        raise SafetyError(
            f"BLOCKED: File '{filepath}' resolves outside sandbox '{sandbox_root}'. "
            "Path traversal attempt detected."
        )


def validate_url_localhost(url: str) -> None:
    """Ensure *url* targets localhost only.

    Raises:
        SafetyError: If the URL hostname is not a loopback address.
    """
    from urllib.parse import urlparse
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    if not hostname:
        raise SafetyError(
            f"BLOCKED: URL '{url}' is missing a hostname. "
            "CyberSim6 only operates on local targets."
        )

    try:
        validate_target_ip(hostname)
    except SafetyError as exc:
        if hostname in LOOPBACK_TARGETS:
            raise
        raise SafetyError(
            f"BLOCKED: URL '{url}' does not target localhost. "
            "CyberSim6 only operates on local targets."
        ) from exc
