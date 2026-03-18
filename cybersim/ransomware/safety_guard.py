"""
CyberSim6 - Ransomware Safety Guard
Multi-layer safety mechanism for the ransomware simulation module.
Prevents any operation outside the designated sandbox.
"""

from pathlib import Path
from cybersim.core.safety import (
    SafetyError,
    validate_sandbox_directory,
    validate_file_in_sandbox,
)

MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB


class RansomwareSafetyGuard:
    """Enforces safety constraints for the ransomware module."""

    def __init__(self, sandbox_dir: Path, max_files: int = 50,
                 allowed_extensions: list = None):
        self.sandbox_dir = Path(sandbox_dir).resolve()
        self.max_files = max_files
        self.allowed_extensions = set(allowed_extensions or [
            ".txt", ".csv", ".doc", ".pdf",
        ])
        self._encrypted_count = 0

        # Validate sandbox exists and has marker
        validate_sandbox_directory(self.sandbox_dir)

        # Block system directories
        blocked = [
            Path.home(),
            Path("/"),
            Path("C:/"),
            Path("C:/Windows"),
            Path("C:/Program Files"),
        ]
        for b in blocked:
            try:
                if self.sandbox_dir == b.resolve():
                    raise SafetyError(
                        f"BLOCKED: Cannot use system directory '{b}' as sandbox."
                    )
            except (OSError, ValueError):
                continue

    def can_encrypt(self, filepath: Path) -> bool:
        """Check if a single file is safe to encrypt."""
        filepath = Path(filepath)

        # Must be inside sandbox
        validate_file_in_sandbox(filepath, self.sandbox_dir)

        # Must exist and be a file
        if not filepath.exists() or not filepath.is_file():
            raise SafetyError(f"BLOCKED: '{filepath}' is not a valid file.")

        # Check extension
        if filepath.suffix.lower() not in self.allowed_extensions:
            raise SafetyError(
                f"BLOCKED: Extension '{filepath.suffix}' not in allowed list: "
                f"{self.allowed_extensions}"
            )

        # Check file size
        if filepath.stat().st_size > MAX_FILE_SIZE:
            raise SafetyError(
                f"BLOCKED: File '{filepath}' exceeds max size ({MAX_FILE_SIZE} bytes)."
            )

        # Check count limit
        if self._encrypted_count >= self.max_files:
            raise SafetyError(
                f"BLOCKED: Max encrypted file count reached ({self.max_files})."
            )

        return True

    def pre_run_check(self, file_list: list) -> bool:
        """
        Validate ALL files before encrypting ANY (atomic check).
        If any file fails validation, none will be encrypted.
        """
        if len(file_list) > self.max_files:
            raise SafetyError(
                f"BLOCKED: File list ({len(file_list)}) exceeds max ({self.max_files})."
            )

        for filepath in file_list:
            self.can_encrypt(filepath)

        return True

    def record_encryption(self):
        """Record that a file has been encrypted."""
        self._encrypted_count += 1
