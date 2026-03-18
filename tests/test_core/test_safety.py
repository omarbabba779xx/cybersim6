"""Tests for cybersim.core.safety module."""

import pytest
from pathlib import Path

from cybersim.core.safety import (
    SafetyError,
    validate_target_ip,
    validate_sandbox_directory,
    validate_file_in_sandbox,
    validate_url_localhost,
)


class TestValidateTargetIP:
    def test_loopback_allowed(self):
        validate_target_ip("127.0.0.1")

    def test_localhost_allowed(self):
        validate_target_ip("localhost")

    def test_external_ip_blocked(self):
        with pytest.raises(SafetyError, match="not a loopback"):
            validate_target_ip("8.8.8.8")

    def test_unresolvable_blocked(self):
        with pytest.raises(SafetyError, match="Cannot resolve"):
            validate_target_ip("this.host.does.not.exist.invalid")


class TestValidateSandbox:
    def test_valid_sandbox(self, tmp_path):
        (tmp_path / ".cybersim_sandbox").write_text("marker")
        validate_sandbox_directory(tmp_path)

    def test_missing_marker(self, tmp_path):
        with pytest.raises(SafetyError, match="not a designated sandbox"):
            validate_sandbox_directory(tmp_path)

    def test_nonexistent_dir(self):
        with pytest.raises(SafetyError, match="does not exist"):
            validate_sandbox_directory(Path("/nonexistent_dir_xyz"))


class TestValidateFileInSandbox:
    def test_file_inside_sandbox(self, tmp_path):
        test_file = tmp_path / "test.txt"
        test_file.write_text("hello")
        validate_file_in_sandbox(test_file, tmp_path)

    def test_path_traversal_blocked(self, tmp_path):
        outside_file = tmp_path.parent / "outside.txt"
        with pytest.raises(SafetyError, match="resolves outside sandbox"):
            validate_file_in_sandbox(outside_file, tmp_path)


class TestValidateURLLocalhost:
    def test_localhost_url_allowed(self):
        validate_url_localhost("http://127.0.0.1:8080")

    def test_localhost_name_allowed(self):
        validate_url_localhost("http://localhost:9090/login")

    def test_external_url_blocked(self):
        with pytest.raises(SafetyError, match="does not target localhost"):
            validate_url_localhost("http://example.com/login")
