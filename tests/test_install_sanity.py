"""v0.1 fresh-venv install ship-gate: `pip install -e ".[dev]"` must leave the
test suite collectable.

Three checks:
  1. The [dev] extra pulls every runtime dep the test suite imports at
     collection time (httpx, pyyaml, casket.*).
  2. `pytest --collect-only -q tests/` returns zero ERROR lines.
  3. pyproject.toml's [dev] extra still declares httpx and pyyaml
     (pure-parse regression guard).

Skippable via `pytest -m "not install_sanity"`. Runs in the full v0.1 suite.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent


def _pip_install_editable_dev() -> None:
    """Idempotent reinstall of the project's [dev] extra."""
    subprocess.run(
        [sys.executable, "-m", "pip", "install", "-e", ".[dev]", "--quiet"],
        check=True, cwd=str(REPO_ROOT),
    )


@pytest.mark.install_sanity
def test_dev_extra_pulls_runtime_deps():
    """After `pip install -e ".[dev]"`, every module the test suite imports
    at collection time must resolve without ModuleNotFoundError."""
    _pip_install_editable_dev()
    # Runtime deps declared in [project.dependencies] and re-listed in [dev].
    import httpx  # noqa: F401
    import yaml  # noqa: F401
    # Every casket.* module transitively imported by the test suite.
    import casket  # noqa: F401
    import casket.cli  # noqa: F401
    import casket.scanner  # noqa: F401
    import casket.rules  # noqa: F401
    import casket.checks  # noqa: F401
    import casket.checks.creds  # noqa: F401
    import casket.checks.cves  # noqa: F401
    import casket.checks.misconfig  # noqa: F401
    # Version sanity: casket.__version__ must match pyproject.toml.
    assert casket.__version__ == "1.0.0"


@pytest.mark.install_sanity
def test_collect_only_returns_zero_errors():
    """`pytest --collect-only tests/` must show zero ERROR lines and >= 540 collected."""
    _pip_install_editable_dev()
    # Use -p no:ini to suppress addopts=-q so the summary line appears.
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-p", "no:ini", "tests/"],
        capture_output=True, text=True, cwd=str(REPO_ROOT),
    )
    error_lines = [
        line for line in proc.stdout.splitlines() + proc.stderr.splitlines()
        if line.startswith("ERROR ")
    ]
    assert not error_lines, (
        f"pytest collection reported {len(error_lines)} ERRORs "
        f"(see `pytest --collect-only tests/` for the list): "
        f"{error_lines[:3]}"
    )
    # The test suite collected at least 540 items (current is 547; allow slack).
    collected_match = re.search(r"(\d+) tests? collected", proc.stdout)
    assert collected_match, f"could not parse 'tests collected' line from:\n{proc.stdout}"
    collected = int(collected_match.group(1))
    assert collected >= 540, f"only {collected} tests collected; expected >= 540"


@pytest.mark.install_sanity
def test_pyproject_declares_runtime_deps_in_dev_extra():
    """pyproject.toml's [project.optional-dependencies].dev must list httpx and pyyaml.

    Pure-parse test — no subprocess. Catches the regression where a future
    edit trims [dev] back to just pytest, breaking fresh-venv test collection.
    """
    pyproject = (REPO_ROOT / "pyproject.toml").read_text()
    # Find the [project.optional-dependencies] block.
    m = re.search(
        r"\[project\.optional-dependencies\](.*?)(?=\n\[|\Z)",
        pyproject, re.DOTALL,
    )
    assert m, "no [project.optional-dependencies] block found in pyproject.toml"
    block = m.group(1)
    assert "httpx" in block, (
        "[project.optional-dependencies] does not declare httpx — "
        "the dev extra is incomplete; tests will fail to import httpx at collection"
    )
    assert "pyyaml" in block, (
        "[project.optional-dependencies] does not declare pyyaml — "
        "the dev extra is incomplete; tests will fail to import yaml at collection"
    )
