"""Tests for Ransomware module (safety guard, detection, entropy)."""

import pytest

from cybersim.core.logging_engine import CyberSimLogger
from cybersim.core.safety import SafetyError
from cybersim.ransomware.safety_guard import RansomwareSafetyGuard
from cybersim.ransomware.detection import RansomwareDetector, calculate_entropy


class TestCalculateEntropy:
    def test_zero_entropy_uniform(self):
        data = bytes([0] * 100)
        assert calculate_entropy(data) == 0.0

    def test_high_entropy_random(self):
        import os
        data = os.urandom(1024)
        entropy = calculate_entropy(data)
        assert entropy > 7.0

    def test_low_entropy_text(self):
        data = b"hello world " * 100
        entropy = calculate_entropy(data)
        assert entropy < 4.0

    def test_empty_data(self):
        assert calculate_entropy(b"") == 0.0


class TestRansomwareSafetyGuard:
    def test_valid_sandbox(self, tmp_path):
        (tmp_path / ".cybersim_sandbox").write_text("marker")
        guard = RansomwareSafetyGuard(sandbox_dir=tmp_path)
        assert guard.sandbox_dir == tmp_path.resolve()

    def test_missing_marker(self, tmp_path):
        with pytest.raises(SafetyError):
            RansomwareSafetyGuard(sandbox_dir=tmp_path)

    def test_can_encrypt_valid_file(self, tmp_path):
        (tmp_path / ".cybersim_sandbox").write_text("marker")
        test_file = tmp_path / "test.txt"
        test_file.write_text("hello")
        guard = RansomwareSafetyGuard(sandbox_dir=tmp_path)
        assert guard.can_encrypt(test_file) is True

    def test_blocked_extension(self, tmp_path):
        (tmp_path / ".cybersim_sandbox").write_text("marker")
        test_file = tmp_path / "test.exe"
        test_file.write_text("hello")
        guard = RansomwareSafetyGuard(sandbox_dir=tmp_path)
        with pytest.raises(SafetyError, match="Extension"):
            guard.can_encrypt(test_file)

    def test_max_files_limit(self, tmp_path):
        (tmp_path / ".cybersim_sandbox").write_text("marker")
        guard = RansomwareSafetyGuard(sandbox_dir=tmp_path, max_files=2)
        guard._encrypted_count = 2
        test_file = tmp_path / "test.txt"
        test_file.write_text("hello")
        with pytest.raises(SafetyError, match="Max encrypted"):
            guard.can_encrypt(test_file)

    def test_pre_run_check_all_valid(self, tmp_path):
        (tmp_path / ".cybersim_sandbox").write_text("marker")
        files = []
        for i in range(3):
            f = tmp_path / f"test{i}.txt"
            f.write_text(f"content {i}")
            files.append(f)
        guard = RansomwareSafetyGuard(sandbox_dir=tmp_path)
        assert guard.pre_run_check(files) is True

    def test_pre_run_check_exceeds_max(self, tmp_path):
        (tmp_path / ".cybersim_sandbox").write_text("marker")
        files = [tmp_path / f"f{i}.txt" for i in range(100)]
        guard = RansomwareSafetyGuard(sandbox_dir=tmp_path, max_files=5)
        with pytest.raises(SafetyError, match="exceeds max"):
            guard.pre_run_check(files)


class TestRansomwareDetector:
    def test_clean_directory(self, tmp_path):
        (tmp_path / ".cybersim_sandbox").write_text("marker")
        (tmp_path / "test.txt").write_text("hello world")
        logger = CyberSimLogger(session_id="test_rw")
        detector = RansomwareDetector(config={}, logger=logger)
        result = detector.scan_directory(tmp_path)
        assert result["is_compromised"] is False
        assert result["encrypted_files"] == []

    def test_detect_encrypted_files(self, tmp_path):
        (tmp_path / ".cybersim_sandbox").write_text("marker")
        (tmp_path / "test.txt.locked").write_bytes(b"\x00" * 100)
        (tmp_path / "RANSOM_NOTE.txt").write_text("pay up")
        logger = CyberSimLogger(session_id="test_rw")
        detector = RansomwareDetector(config={}, logger=logger)
        result = detector.scan_directory(tmp_path)
        assert result["is_compromised"] is True
        assert len(result["encrypted_files"]) == 1
        assert len(result["ransom_notes"]) == 1
