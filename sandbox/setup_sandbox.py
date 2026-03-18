"""
CyberSim6 - Sandbox Setup
Creates the isolated test environment with marker file and dummy files.
"""

import sys
from pathlib import Path

SANDBOX_DIR = Path(__file__).parent / "test_files"
MARKER_FILE = ".cybersim_sandbox"

DUMMY_FILES = {
    "document1.txt": "This is a confidential report about Q4 revenue projections.\nAll data is fictional and for testing purposes only.\n",
    "document2.txt": "Meeting notes from 2026-01-15.\nTopics discussed: budget review, hiring plan.\nThis is dummy content for CyberSim6 testing.\n",
    "spreadsheet.csv": "name,department,salary\nAlice,Engineering,75000\nBob,Marketing,65000\nCharlie,Sales,70000\n",
    "notes.txt": "Personal notes - fictional data.\nPassword reminder: use a strong password manager.\nThis file is part of CyberSim6 sandbox.\n",
    "report.txt": "Annual Security Audit Report (FICTIONAL)\nDate: 2026-03-01\nFindings: 3 critical, 5 medium, 12 low\nAll data generated for CyberSim6 testing.\n",
}


def setup():
    """Create sandbox environment with marker and test files."""
    SANDBOX_DIR.mkdir(parents=True, exist_ok=True)

    # Create marker file
    marker = SANDBOX_DIR / MARKER_FILE
    marker.write_text(
        "This directory is a CyberSim6 sandbox environment.\n"
        "Files here are FICTIONAL and used for attack simulation testing.\n"
        "DO NOT place real files in this directory.\n"
    )
    print(f"[+] Created sandbox marker: {marker}")

    # Create dummy files
    for filename, content in DUMMY_FILES.items():
        filepath = SANDBOX_DIR / filename
        filepath.write_text(content, encoding="utf-8")
        print(f"[+] Created test file: {filepath}")

    print(f"\n[OK] Sandbox ready at: {SANDBOX_DIR.resolve()}")
    print(f"     {len(DUMMY_FILES)} test files created.")


def clean():
    """Remove all files from sandbox (except marker)."""
    if not SANDBOX_DIR.exists():
        print("[-] Sandbox directory does not exist.")
        return
    count = 0
    for f in SANDBOX_DIR.iterdir():
        if f.name != MARKER_FILE:
            f.unlink()
            count += 1
    print(f"[OK] Cleaned {count} files from sandbox.")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "clean":
        clean()
    else:
        setup()
