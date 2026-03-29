"""Repository metadata consistency checks."""

from __future__ import annotations

from pathlib import Path
import tomllib

from cybersim import __version__
from cybersim.dashboard.api_docs import OPENAPI_SPEC
from cybersim.dashboard.server import DASHBOARD_HTML


def test_project_version_is_consistent():
    pyproject = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))

    assert pyproject["project"]["version"] == __version__
    assert OPENAPI_SPEC["info"]["version"] == __version__


def test_dashboard_html_exposes_runtime_version():
    assert __version__ in DASHBOARD_HTML
    assert "__CYBERSIM_VERSION__" not in DASHBOARD_HTML
