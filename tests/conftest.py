"""
CyberSim6 - Pytest Configuration
Shared fixtures for all test modules.
"""

import pytest
from pathlib import Path

from cybersim.core.logging_engine import CyberSimLogger


@pytest.fixture
def logger(tmp_path):
    """Provide a fresh logger instance for each test."""
    return CyberSimLogger(log_dir=tmp_path, session_id="test")


@pytest.fixture
def sandbox(tmp_path):
    """Provide a sandbox directory with marker file."""
    marker = tmp_path / ".cybersim_sandbox"
    marker.write_text("CyberSim6 test sandbox")

    # Create dummy files
    for i in range(3):
        (tmp_path / f"doc{i}.txt").write_text(f"Test document {i}")
    (tmp_path / "data.csv").write_text("col1,col2\na,b\nc,d")

    return tmp_path
