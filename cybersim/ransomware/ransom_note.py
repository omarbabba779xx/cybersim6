"""
CyberSim6 - Ransom Note Generator
Creates a simulated ransom note for educational purposes.
"""

from pathlib import Path


RANSOM_NOTE_TEMPLATE = """
================================================================================
                    *** YOUR FILES HAVE BEEN ENCRYPTED ***
================================================================================

  All your important files have been encrypted using AES-256 military-grade
  encryption. Without the decryption key, your files cannot be recovered.

  Files encrypted: {file_count}
  Encryption algorithm: AES-256-CBC

  To recover your files, you must:
  1. Send 0.5 BTC to wallet: 1CyB3rS1m6FaK3WaLL3tAdDr3sS
  2. Send proof of payment to: ransom@fake-cybersim6.invalid
  3. Wait for decryption key delivery

  WARNING: Do not attempt to decrypt files manually.
  WARNING: Do not contact law enforcement.
  WARNING: You have 72 hours before the key is destroyed.

================================================================================
  *** THIS IS A SIMULATION - EDUCATIONAL PURPOSE ONLY ***
  *** CyberSim6 Project - EMSI Tanger 4IIR ***
  *** No real data was harmed. All files are fictitious. ***
  *** Decryption key is stored locally in: decryption.key ***
  *** Run the decryptor to restore all files. ***
================================================================================
"""


def generate_ransom_note(sandbox_dir: Path, file_count: int):
    """Generate a simulated ransom note in the sandbox directory."""
    sandbox_dir = Path(sandbox_dir)
    note_path = sandbox_dir / "RANSOM_NOTE.txt"
    note_content = RANSOM_NOTE_TEMPLATE.format(file_count=file_count)
    note_path.write_text(note_content, encoding="utf-8")
    print(f"[!] Ransom note created: {note_path}")
    return note_path
