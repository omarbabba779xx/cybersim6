"""Cross-platform helpers used by the Makefile."""

from __future__ import annotations

import argparse
import re
import shutil
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent


def show_help() -> None:
    """Render Makefile target help without depending on grep/awk."""
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    pattern = re.compile(r"^([a-zA-Z_-]+):.*?## (.+)$")
    for line in makefile.splitlines():
        match = pattern.match(line)
        if match:
            name, description = match.groups()
            print(f"  {name:<15} {description}")


def clean() -> None:
    """Remove local caches and build artifacts."""
    directories = ["build", "dist", ".pytest_cache", "htmlcov"]
    for relative in directories:
        path = ROOT / relative
        if path.exists():
            shutil.rmtree(path)

    for path in ROOT.glob("*.egg-info"):
        if path.is_dir():
            shutil.rmtree(path)

    for path in ROOT.rglob("__pycache__"):
        if path.is_dir():
            shutil.rmtree(path)

    for path in ROOT.rglob("*.pyc"):
        if path.is_file():
            path.unlink()

    print("  Cleaned.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Project helper tasks")
    parser.add_argument("command", choices=["help", "clean"])
    args = parser.parse_args()

    if args.command == "help":
        show_help()
    else:
        clean()


if __name__ == "__main__":
    main()
