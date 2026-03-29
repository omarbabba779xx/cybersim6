"""Round-trip tests for ransomware encryption and decryption."""

from __future__ import annotations

from cybersim.ransomware.decryptor import RansomwareDecryptor
from cybersim.ransomware.encryptor import RansomwareSimulator


def test_ransomware_roundtrip_restores_files(logger, sandbox):
    original_contents = {
        path.name: path.read_text(encoding="utf-8")
        for path in sandbox.iterdir()
        if path.is_file() and path.suffix in {".txt", ".csv"}
    }

    encryptor = RansomwareSimulator(
        config={
            "sandbox_dir": str(sandbox),
            "encrypted_extension": ".locked",
            "keep_originals": False,
        },
        logger=logger,
    )
    encrypt_result = encryptor.run(confirm=False)

    assert encrypt_result["encrypted_count"] == len(original_contents)
    assert any(sandbox.glob("*.locked"))
    assert (sandbox / "RANSOM_NOTE.txt").exists()
    assert (sandbox / "decryption.key").exists()

    decryptor = RansomwareDecryptor(
        config={"sandbox_dir": str(sandbox), "encrypted_extension": ".locked"},
        logger=logger,
    )
    decrypt_result = decryptor.run()

    restored_contents = {
        path.name: path.read_text(encoding="utf-8")
        for path in sandbox.iterdir()
        if path.is_file() and path.suffix in {".txt", ".csv"}
    }

    assert decrypt_result["decrypted_count"] == len(original_contents)
    assert decrypt_result["integrity_fail"] == 0
    assert restored_contents == original_contents
    assert not any(sandbox.glob("*.locked"))
    assert not (sandbox / "RANSOM_NOTE.txt").exists()
    assert not (sandbox / "decryption.key").exists()
