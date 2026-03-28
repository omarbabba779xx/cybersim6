"""Edge case tests for ransomware detection — entropy, large files, key rotation."""
import math
import pytest
from cybersim.ransomware.detection import calculate_entropy, _entropy_cached, RansomwareDetector
from cybersim.core.logging_engine import CyberSimLogger
import tempfile
from pathlib import Path


@pytest.fixture
def detector():
    return RansomwareDetector(config={}, logger=CyberSimLogger())


class TestShannonEntropy:
    def test_empty_data_returns_zero(self):
        assert calculate_entropy(b"") == 0.0

    def test_single_byte_zero_entropy(self):
        # All same bytes → zero entropy
        assert calculate_entropy(b"\x00" * 100) == pytest.approx(0.0, abs=1e-9)

    def test_two_equal_bytes_entropy(self):
        # 50% / 50% → entropy = 1.0
        data = b"\x00\xff" * 100
        entropy = calculate_entropy(data)
        assert entropy == pytest.approx(1.0, abs=0.01)

    def test_uniform_random_high_entropy(self):
        # 256 distinct bytes → maximum entropy ~8.0
        data = bytes(range(256)) * 10
        entropy = calculate_entropy(data)
        assert entropy > 7.9

    def test_text_low_entropy(self):
        # English text has entropy ~4-5
        text = b"the quick brown fox jumps over the lazy dog " * 20
        entropy = calculate_entropy(text)
        assert entropy < 7.0

    def test_encrypted_like_high_entropy(self):
        import os
        random_data = os.urandom(4096)
        entropy = calculate_entropy(random_data)
        assert entropy > 7.0  # random bytes ≈ max entropy

    def test_large_file_chunked(self):
        # Should handle data larger than 4KB chunk
        data = bytes(range(256)) * 100  # 25600 bytes
        entropy = calculate_entropy(data)
        assert entropy > 7.5

    def test_entropy_cached_consistent(self):
        chunk = bytes(range(256))
        e1 = _entropy_cached(chunk)
        e2 = _entropy_cached(chunk)
        assert e1 == e2

    def test_entropy_threshold_detection(self, detector):
        """Files with entropy > 7.5 should be flagged."""
        with tempfile.TemporaryDirectory() as tmpdir:
            p = Path(tmpdir)
            # Create sandbox marker
            (p / ".cybersim_sandbox").touch()
            # Deterministic high-entropy file (uniform byte distribution)
            (p / "encrypted.locked").write_bytes(bytes(range(256)) * 2)
            # Low entropy file (normal text)
            (p / "normal.txt").write_bytes(b"hello world " * 100)

            results = detector.scan_directory(p)
            assert any(f["name"] == "encrypted.locked" for f in results["high_entropy_files"])

    def test_small_data_no_chunking(self):
        data = b"AAAA"
        entropy = calculate_entropy(data)
        assert entropy == 0.0

    def test_entropy_is_float(self):
        assert isinstance(calculate_entropy(b"test data"), float)


class TestRansomwareScanDirectory:
    def test_detects_locked_extension(self, detector):
        with tempfile.TemporaryDirectory() as tmpdir:
            p = Path(tmpdir)
            (p / "file.txt.locked").write_bytes(b"encrypted")
            (p / "normal.txt").write_bytes(b"normal text")
            results = detector.scan_directory(p)
            assert "file.txt.locked" in results["encrypted_files"]

    def test_detects_ransom_note(self, detector):
        with tempfile.TemporaryDirectory() as tmpdir:
            p = Path(tmpdir)
            (p / "README_RANSOM.txt").write_bytes(b"pay here")
            results = detector.scan_directory(p)
            assert "README_RANSOM.txt" in results["ransom_notes"]

    def test_empty_directory(self, detector):
        with tempfile.TemporaryDirectory() as tmpdir:
            results = detector.scan_directory(tmpdir)
            assert results["total_files"] == 0
            assert results["is_compromised"] is False

    def test_is_compromised_flag(self, detector):
        with tempfile.TemporaryDirectory() as tmpdir:
            p = Path(tmpdir)
            (p / "data.locked").write_bytes(b"x")
            results = detector.scan_directory(p)
            assert results["is_compromised"] is True

    def test_clean_directory_not_compromised(self, detector):
        with tempfile.TemporaryDirectory() as tmpdir:
            p = Path(tmpdir)
            (p / "report.pdf").write_bytes(b"normal pdf content " * 50)
            (p / "notes.txt").write_bytes(b"meeting notes")
            results = detector.scan_directory(p)
            assert results["is_compromised"] is False
