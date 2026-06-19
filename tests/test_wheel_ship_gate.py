"""Wheel-ship-gate contract for casket.

Pins the v1.0 wheel-install contract (this is the BRIDGE between
casket-001-dev-extra-recovery's editable-install contract and the
casket-003 v1.0 RELEASE packet's release-cut).

All tests are gated behind @pytest.mark.ship_gate. The fast inner-loop
is `pytest -q -m "not ship_gate"`. The full suite (including ship_gate)
is the v1.0 release gate.

The tests build the wheel into dist/, create a fresh venv in a tempdir,
install the wheel + runtime deps, and assert the CLI works from the
fresh venv. This is the "what `pip install casket` followed by
`casket --help` looks like" contract.

Reference: oracle-002 / blight-001 / omen-002 shipped this exact
shape on other necromancer tools (see done/ for those packets).
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path

import pytest

# Pin to the v0.1 version (bridge pins current state; casket-003
# will flip this to "1.0.0" in a separate packet).
EXPECTED_VERSION = "0.1.0"

# 12 non-__init__ public modules at the top of casket/. Verified
# live at this wake: `ls casket/*.py | grep -v __init__` returns
# cli.py, compare.py, epss.py, findings.py, oci.py, osv.py,
# podman_mode.py, remote_mode.py, rules.py, scanner.py, summary.py,
# vex.py — 12 entries.
_PUBLIC_MODULES = (
    "casket",
    "casket.cli",
    "casket.scanner",
    "casket.findings",
    "casket.compare",
    "casket.summary",
    "casket.oci",
    "casket.osv",
    "casket.podman_mode",
    "casket.remote_mode",
    "casket.epss",
    "casket.vex",
)


def _project_root() -> Path:
    return Path(__file__).resolve().parent.parent


def _pyproject_version() -> str:
    """Read pyproject.toml [project].version verbatim."""
    with open(_project_root() / "pyproject.toml", "rb") as fh:
        return tomllib.load(fh)["project"]["version"]


def _build_wheel() -> Path:
    """Run `python -m build --wheel --sdist` in a subprocess.

    Returns the wheel path in dist/. Assumes the build module is on
    sys.path (in the project venv, `pip install build` is in [dev]).
    """
    root = _project_root()
    subprocess.run(
        [sys.executable, "-m", "build", "--wheel", "--sdist"],
        cwd=root, check=True, capture_output=True, text=True,
    )
    wheel = list((root / "dist").glob(f"casket-{EXPECTED_VERSION}-py3-none-any.whl"))
    assert wheel, f"wheel not found in dist/ after build (expected casket-{EXPECTED_VERSION}-*.whl)"
    return wheel[0]


@pytest.fixture(scope="module")
def fresh_venv_with_wheel():
    """Create a fresh venv, install wheel + runtime deps, return venv path.

    Module-scoped so we build once for all 7 ship_gate tests. The
    venv is created in a tempdir that is auto-cleaned at test-end.
    """
    tmpdir = Path(tempfile.mkdtemp(prefix="casket-ship-gate-"))
    venv = tmpdir / "venv"
    subprocess.run(
        [sys.executable, "-m", "venv", str(venv)], check=True, capture_output=True
    )
    pip = venv / "bin" / "pip"
    # Install the wheel first (--no-deps to force explicit dep install).
    wheel = _build_wheel()
    subprocess.run(
        [str(pip), "install", str(wheel), "--no-deps"], check=True, capture_output=True
    )
    # Install the runtime deps declared in [project].dependencies.
    subprocess.run(
        [str(pip), "install", "httpx>=0.27", "pyyaml>=6.0"],
        check=True, capture_output=True,
    )
    yield venv
    shutil.rmtree(tmpdir, ignore_errors=True)


@pytest.mark.ship_gate
def test_wheel_builds_cleanly():
    """`python -m build --wheel --sdist` exits 0 and produces wheel+sdist."""
    root = _project_root()
    # Force a rebuild so we observe the artifact from this test.
    subprocess.run(
        [sys.executable, "-m", "build", "--wheel", "--sdist"],
        cwd=root, check=True, capture_output=True, text=True,
    )
    wheels = list((root / "dist").glob(f"casket-{EXPECTED_VERSION}-py3-none-any.whl"))
    sdists = list((root / "dist").glob(f"casket-{EXPECTED_VERSION}.tar.gz"))
    assert len(wheels) == 1, f"expected 1 wheel, got {len(wheels)}"
    assert len(sdists) == 1, f"expected 1 sdist, got {len(sdists)}"
    assert wheels[0].stat().st_size > 50_000, "wheel is suspiciously small"


@pytest.mark.ship_gate
def test_wheel_installs_into_fresh_venv(fresh_venv_with_wheel):
    """`pip install <wheel>` into a fresh venv leaves `casket` importable."""
    venv = fresh_venv_with_wheel
    py = venv / "bin" / "python"
    result = subprocess.run(
        [str(py), "-c", "import casket; print(casket.__file__)"],
        check=True, capture_output=True, text=True,
    )
    assert "casket/__init__.py" in result.stdout, (
        f"casket did not resolve to expected path: {result.stdout!r}"
    )


@pytest.mark.ship_gate
def test_wheel_version_importable_in_fresh_venv(fresh_venv_with_wheel):
    """`casket.__version__` matches `pyproject.toml [project].version` from fresh venv."""
    venv = fresh_venv_with_wheel
    py = venv / "bin" / "python"
    result = subprocess.run(
        [str(py), "-c", "import casket; print(casket.__version__)"],
        check=True, capture_output=True, text=True,
    )
    assert result.stdout.strip() == EXPECTED_VERSION, (
        f"version mismatch: stdout={result.stdout!r}, expected={EXPECTED_VERSION!r}"
    )
    # And the project root's pyproject.toml matches too.
    assert _pyproject_version() == EXPECTED_VERSION, (
        f"pyproject.toml version={_pyproject_version()!r} != {EXPECTED_VERSION!r}"
    )


@pytest.mark.ship_gate
def test_installed_wheel_public_api(fresh_venv_with_wheel):
    """All 12 non-__init__ public modules import from the fresh-venv wheel."""
    venv = fresh_venv_with_wheel
    py = venv / "bin" / "python"
    code = (
        "import importlib;"
        "mods = ['casket', 'casket.cli', 'casket.scanner', 'casket.findings', "
        "'casket.compare', 'casket.summary', 'casket.oci', 'casket.osv', "
        "'casket.podman_mode', 'casket.remote_mode', 'casket.epss', 'casket.vex'];"
        "[importlib.import_module(m) for m in mods];"
        "print(len(mods))"
    )
    result = subprocess.run(
        [str(py), "-c", code], check=True, capture_output=True, text=True,
    )
    assert result.stdout.strip() == str(len(_PUBLIC_MODULES)), (
        f"expected {len(_PUBLIC_MODULES)} imports, got {result.stdout!r}"
    )


@pytest.mark.ship_gate
def test_installed_wheel_checks_registry_smoke(fresh_venv_with_wheel):
    """`casket.checks.REGISTRY` exposes exactly creds/cves/misconfig from fresh venv."""
    venv = fresh_venv_with_wheel
    py = venv / "bin" / "python"
    code = (
        "from casket.checks import REGISTRY, ALL_CHECKS;"
        "import json;"
        "print(json.dumps({'reg': sorted(REGISTRY.keys()), 'all': ALL_CHECKS}))"
    )
    result = subprocess.run(
        [str(py), "-c", code], check=True, capture_output=True, text=True,
    )
    import json as _json
    payload = _json.loads(result.stdout.strip())
    assert payload["reg"] == ["creds", "cves", "misconfig"], (
        f"REGISTRY keys mismatch: {payload['reg']!r}"
    )
    assert payload["all"] == ["creds", "cves", "misconfig"], (
        f"ALL_CHECKS mismatch: {payload['all']!r}"
    )


@pytest.mark.ship_gate
def test_installed_wheel_help_exits_zero(fresh_venv_with_wheel):
    """`casket --help` exits 0 from fresh venv and lists key flag choices."""
    venv = fresh_venv_with_wheel
    cli = venv / "bin" / "casket"
    result = subprocess.run(
        [str(cli), "--help"], check=True, capture_output=True, text=True,
    )
    assert "--mode {tarball,podman,remote}" in result.stdout, (
        f"--help missing --mode choices: {result.stdout[:500]!r}"
    )
    assert "--checks {creds,cves,misconfig,all}" in result.stdout, (
        f"--help missing --checks choices: {result.stdout[:500]!r}"
    )
    assert "--format {json,h1md,sarif}" in result.stdout, (
        f"--help missing --format choices: {result.stdout[:500]!r}"
    )


@pytest.mark.ship_gate
def test_installed_wheel_check_categories_validate(fresh_venv_with_wheel):
    """`--checks` accepts each of creds/cves/misconfig/all via argparse."""
    venv = fresh_venv_with_wheel
    cli = venv / "bin" / "casket"
    for check in ("creds", "cves", "misconfig", "all"):
        # Use --help to surface the choices without triggering network/image-load.
        result = subprocess.run(
            [str(cli), "--checks", check, "--help"],
            check=True, capture_output=True, text=True,
        )
        assert "--checks" in result.stdout, (
            f"--checks {check!r} did not parse (--help exited 0 but stdout missing --checks: "
            f"{result.stdout[:300]!r})"
        )
