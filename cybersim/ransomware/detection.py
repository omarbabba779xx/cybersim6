"""
CyberSim6 - Ransomware Detection Module
Monitors filesystem for ransomware indicators:
- Rapid file extension changes
- High entropy in files (encrypted content)
- Mass file modifications in short time
"""

import math
import time
from pathlib import Path
from collections import Counter
from functools import lru_cache

from cybersim.core.base_module import BaseModule
from cybersim.core.safety import validate_sandbox_directory


@lru_cache(maxsize=512)
def _entropy_cached(chunk: bytes) -> float:
    """Cached Shannon entropy calculation for identical chunks."""
    counter = Counter(chunk)
    length = len(chunk)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in counter.values()
        if count > 0
    )


def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of data. High entropy = likely encrypted.

    Uses chunk-level caching to avoid recomputing entropy for repeated blocks
    (common in encrypted files with repeated padding).
    """
    if not data:
        return 0.0
    # Process in 4KB chunks and average — enables cache hits on repeated blocks
    chunk_size = 4096
    if len(data) <= chunk_size:
        return _entropy_cached(bytes(data))
    entropies = [_entropy_cached(bytes(data[i:i + chunk_size]))
                 for i in range(0, len(data), chunk_size)]
    return sum(entropies) / len(entropies)


class RansomwareDetector(BaseModule):
    """Detects ransomware activity by monitoring filesystem changes."""

    MODULE_TYPE = "detection"
    MODULE_NAME = "ransomware_detector"

    ENTROPY_THRESHOLD = 7.5  # Encrypted files typically have entropy > 7.5 (max is 8.0)

    def _validate_safety(self):
        watch_dir = Path(self.config.get("sandbox_dir", "./sandbox/test_files"))
        validate_sandbox_directory(watch_dir)

    def scan_directory(self, directory: Path, encrypted_ext: str = ".locked") -> dict:
        """
        Scan a directory for ransomware indicators.

        Returns:
            dict with detection results
        """
        directory = Path(directory)
        results = {
            "total_files": 0,
            "encrypted_files": [],
            "high_entropy_files": [],
            "ransom_notes": [],
            "is_compromised": False,
        }

        for filepath in directory.iterdir():
            if not filepath.is_file():
                continue
            results["total_files"] += 1

            # Check for encrypted extension
            if filepath.suffix == encrypted_ext:
                results["encrypted_files"].append(filepath.name)

            # Check for ransom notes
            if "ransom" in filepath.name.lower() or "readme" in filepath.name.lower():
                results["ransom_notes"].append(filepath.name)

            # Check file entropy
            try:
                data = filepath.read_bytes()
                if len(data) > 0:
                    entropy = calculate_entropy(data)
                    if entropy > self.ENTROPY_THRESHOLD:
                        results["high_entropy_files"].append({
                            "name": filepath.name,
                            "entropy": round(entropy, 4),
                        })
            except (PermissionError, OSError):
                pass

        # Determine if compromised
        if results["encrypted_files"] or results["ransom_notes"]:
            results["is_compromised"] = True
            self.log_event("ransomware_detected", {
                "message": f"RANSOMWARE DETECTED in {directory}: "
                           f"{len(results['encrypted_files'])} encrypted files, "
                           f"{len(results['ransom_notes'])} ransom notes",
                "encrypted_count": len(results["encrypted_files"]),
                "ransom_notes": results["ransom_notes"],
                "status": "warning",
            })

        return results

    def run(self, watch_dir: str = None, duration: int = 60,
            interval: float = 3.0, **kwargs):
        """
        Continuously monitor a directory for ransomware indicators.

        Args:
            watch_dir: Directory to monitor
            duration: Monitoring duration in seconds
            interval: Scan interval in seconds
        """
        watch_dir = Path(watch_dir or self.config.get("sandbox_dir", "./sandbox/test_files"))

        self._running = True
        self.log_event("detection_started", {
            "message": f"Ransomware detection started on {watch_dir}",
            "status": "info",
        })

        prev_files = set()
        start = time.time()

        while self._running and (time.time() - start) < duration:
            current_files = set(f.name for f in watch_dir.iterdir() if f.is_file())

            # Check for new files
            new_files = current_files - prev_files
            removed_files = prev_files - current_files

            if new_files:
                locked_new = [f for f in new_files if f.endswith(".locked")]
                if locked_new:
                    self.log_event("suspicious_activity", {
                        "message": f"New encrypted files detected: {locked_new}",
                        "new_encrypted": locked_new,
                        "status": "warning",
                    })

            if removed_files:
                self.log_event("file_changes", {
                    "message": f"Files removed: {removed_files}",
                    "removed": list(removed_files),
                    "status": "info",
                })

            prev_files = current_files
            self.scan_directory(watch_dir)

            time.sleep(interval)

        self._running = False
        self.log_event("detection_stopped", {
            "message": "Ransomware detection stopped.",
            "status": "info",
        })

    def stop(self):
        self._running = False
