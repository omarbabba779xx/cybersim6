"""Repository metadata consistency checks."""

from __future__ import annotations

from pathlib import Path
import re

from cybersim import __version__
from cybersim.dashboard.api_docs import OPENAPI_SPEC
from cybersim.dashboard.server import DASHBOARD_HTML


def test_project_version_is_consistent():
    pyproject_text = Path("pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r'^version = "([^"]+)"$', pyproject_text, flags=re.MULTILINE)

    assert match is not None
    assert match.group(1) == __version__
    assert OPENAPI_SPEC["info"]["version"] == __version__


def test_dashboard_html_exposes_runtime_version():
    assert __version__ in DASHBOARD_HTML
    assert "__CYBERSIM_VERSION__" not in DASHBOARD_HTML
