"""
CyberSim6 - Ransomware Decryptor
Decrypts files encrypted by the ransomware simulator.
Verifies integrity using SHA-256 checksums.
"""

import hashlib
import json
from pathlib import Path

from Crypto.Cipher import AES  # nosec B413
from Crypto.Util.Padding import unpad  # nosec B413

from cybersim.core.base_module import BaseModule
from cybersim.core.safety import validate_sandbox_directory, validate_file_in_sandbox


class RansomwareDecryptor(BaseModule):
    """Decrypts files encrypted by the CyberSim6 ransomware module."""

    MODULE_TYPE = "remediation"
    MODULE_NAME = "ransomware_decrypt"

    def _validate_safety(self):
        sandbox_dir = self.config.get("sandbox_dir", "./sandbox/test_files")
        validate_sandbox_directory(Path(sandbox_dir))

    def run(self, sandbox_dir: str = None, key_file: str = None, **kwargs):
        """
        Decrypt files in the sandbox.

        Args:
            sandbox_dir: Path to sandbox directory
            key_file: Path to decryption key file
        """
        sandbox_dir = Path(sandbox_dir or self.config.get("sandbox_dir", "./sandbox/test_files"))
        encrypted_ext = self.config.get("encrypted_extension", ".locked")

        validate_sandbox_directory(sandbox_dir)

        # Load key
        key_path = Path(key_file) if key_file else sandbox_dir / "decryption.key"
        if not key_path.exists():
            self.log_event("error", {
                "message": f"Key file not found: {key_path}",
                "status": "error",
            })
            return

        key_data = json.loads(key_path.read_text())
        key = bytes.fromhex(key_data["key"])
        iv = bytes.fromhex(key_data["iv"])

        # Load manifest for integrity checks
        manifest_path = sandbox_dir / "encryption_manifest.json"
        manifest = {}
        if manifest_path.exists():
            manifest_data = json.loads(manifest_path.read_text())
            manifest = {f["encrypted_name"]: f for f in manifest_data.get("files", [])}

        # Find encrypted files
        encrypted_files = list(sandbox_dir.glob(f"*{encrypted_ext}"))
        if not encrypted_files:
            self.log_event("no_files", {
                "message": "No encrypted files found in sandbox.",
                "status": "info",
            })
            return

        self._running = True
        self.log_event("decryption_started", {
            "message": f"Decrypting {len(encrypted_files)} files in {sandbox_dir}",
            "status": "info",
        })

        decrypted_count = 0
        integrity_ok = 0
        integrity_fail = 0

        for enc_path in encrypted_files:
            if not self._running:
                break

            validate_file_in_sandbox(enc_path, sandbox_dir)

            try:
                encrypted_data = enc_path.read_bytes()

                # Decrypt
                cipher = AES.new(key, AES.MODE_CBC, iv)
                decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)

                # Restore original filename (remove .locked suffix)
                original_name = enc_path.name
                for ext_to_remove in [encrypted_ext]:
                    if original_name.endswith(ext_to_remove):
                        original_name = original_name[:-len(ext_to_remove)]
                        break

                original_path = sandbox_dir / original_name
                original_path.write_bytes(decrypted_data)

                # Integrity check
                decrypted_hash = hashlib.sha256(decrypted_data).hexdigest()
                file_manifest = manifest.get(enc_path.name, {})
                expected_hash = file_manifest.get("original_hash")

                if expected_hash:
                    if decrypted_hash == expected_hash:
                        integrity_ok += 1
                        integrity_status = "VERIFIED"
                    else:
                        integrity_fail += 1
                        integrity_status = "MISMATCH"
                else:
                    integrity_status = "NO_REFERENCE"

                # Remove encrypted file
                enc_path.unlink()
                decrypted_count += 1

                self.log_event("file_decrypted", {
                    "message": f"Decrypted: {enc_path.name} -> {original_name} [{integrity_status}]",
                    "encrypted_file": enc_path.name,
                    "restored_file": original_name,
                    "integrity": integrity_status,
                    "status": "info",
                })

            except Exception as e:
                self.log_event("error", {
                    "message": f"Failed to decrypt {enc_path.name}: {e}",
                    "status": "error",
                })

        # Clean up key and manifest files
        for cleanup_file in [key_path, manifest_path, sandbox_dir / "RANSOM_NOTE.txt"]:
            if cleanup_file.exists():
                cleanup_file.unlink()

        self._running = False
        self.log_event("decryption_completed", {
            "message": f"Decryption complete. {decrypted_count} files restored. "
                       f"Integrity: {integrity_ok} OK, {integrity_fail} failed.",
            "decrypted_count": decrypted_count,
            "integrity_ok": integrity_ok,
            "integrity_fail": integrity_fail,
            "status": "info",
        })

        return {
            "decrypted_count": decrypted_count,
            "integrity_ok": integrity_ok,
            "integrity_fail": integrity_fail,
        }

    def stop(self):
        self._running = False
