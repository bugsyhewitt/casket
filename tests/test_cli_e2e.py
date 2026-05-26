"""End-to-end CLI smoke tests (criteria 2, 3, 4, 5, 8).

One E2E per mode:
  - tarball: real fixture
  - podman:  mocked subprocess
  - remote:  local fixture registry server
"""

from __future__ import annotations

import json
import shutil
import subprocess

import pytest

from casket.cli import build_parser, main
from tests.conftest import fixture_path
from tests.test_remote_mode import fixture_registry  # noqa: F401  (fixture)


# ---- criterion 2: --help surface ------------------------------------------

def test_help_lists_required_flags(capsys):
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["--help"])
    out = capsys.readouterr().out
    for token in ["--image", "--mode", "--checks", "--format"]:
        assert token in out
    assert "tarball" in out and "podman" in out and "remote" in out
    assert "creds" in out and "cves" in out and "misconfig" in out
    assert "json" in out and "h1md" in out


# ---- criterion 3: creds JSON shape ----------------------------------------

def test_e2e_tarball_creds_json(capsys):
    rc = main([
        "--image", fixture_path("leaky-image.tar"),
        "--mode", "tarball",
        "--checks", "creds",
        "--format", "json",
    ])
    assert rc == 1  # findings present -> exit 1
    payload = json.loads(capsys.readouterr().out)
    creds_findings = [f for f in payload["findings"] if f["category"] == "creds"]
    assert creds_findings
    f = creds_findings[0]
    assert f["category"] == "creds"
    assert "layer_sha" in f and f["layer_sha"].startswith("sha256:")
    assert "path_in_layer" in f


# ---- criterion 4: cve JSON shape ------------------------------------------

def test_e2e_tarball_cves_json(capsys, _isolate_osv_cache):
    # Seed the cache the CLI will load (via CASKET_OSV_CACHE env).
    from casket.osv import OSVClient

    seed = OSVClient(cache_path=_isolate_osv_cache)
    seed.seed(
        "PyPI",
        "requests",
        "2.19.0",
        [{"id": "GHSA-x", "aliases": ["CVE-2018-18074"],
          "summary": "auth leak", "database_specific": {"severity": "MEDIUM"}}],
    )

    rc = main([
        "--image", fixture_path("old-package.tar"),
        "--mode", "tarball",
        "--checks", "cves",
        "--format", "json",
        "--offline",
    ])
    assert rc == 1
    payload = json.loads(capsys.readouterr().out)
    cve_findings = [f for f in payload["findings"] if f["category"] == "cve"]
    assert cve_findings
    f = cve_findings[0]
    assert f["cve_id"] == "CVE-2018-18074"
    assert f["package"] == "requests"
    assert f["installed_version"] == "2.19.0"


# ---- criterion 5: misconfig running_as_root ------------------------------

def test_e2e_tarball_misconfig_root(capsys):
    rc = main([
        "--image", fixture_path("rootuser-image.tar"),
        "--mode", "tarball",
        "--checks", "misconfig",
        "--format", "json",
    ])
    assert rc == 1
    payload = json.loads(capsys.readouterr().out)
    misc = [f for f in payload["findings"] if f["category"] == "misconfig"]
    rules = {f["rule"] for f in misc}
    assert "running_as_root" in rules


# ---- criterion 8: podman mode E2E (mocked) --------------------------------

def test_e2e_podman_mode_mocked(capsys, monkeypatch):
    fixture = fixture_path("leaky-image.tar")
    monkeypatch.setattr(shutil, "which", lambda _b: "/usr/bin/podman")

    def fake_run(cmd, capture_output=True, text=True):
        out_path = cmd[cmd.index("-o") + 1]
        shutil.copyfile(fixture, out_path)

        class _P:
            returncode = 0
            stdout = stderr = ""

        return _P()

    monkeypatch.setattr(subprocess, "run", fake_run)
    rc = main([
        "--image", "localhost/leaky:latest",
        "--mode", "podman",
        "--checks", "creds",
        "--format", "json",
    ])
    assert rc == 1
    payload = json.loads(capsys.readouterr().out)
    assert any(f["category"] == "creds" for f in payload["findings"])


# ---- criterion 8: remote mode E2E (local server) --------------------------

def test_e2e_remote_mode_local_server(capsys, fixture_registry):  # noqa: F811
    ref = f"{fixture_registry}/library/leaky:1.0"
    rc = main([
        "--image", ref,
        "--mode", "remote",
        "--checks", "all",
        "--format", "json",
        "--offline",
    ])
    assert rc == 1
    payload = json.loads(capsys.readouterr().out)
    cats = {f["category"] for f in payload["findings"]}
    # remote fixture has a planted token (creds) and User root (misconfig).
    assert "creds" in cats
    assert "misconfig" in cats


# ---- h1md format smoke -----------------------------------------------------

def test_h1md_format_renders(capsys):
    rc = main([
        "--image", fixture_path("rootuser-image.tar"),
        "--mode", "tarball",
        "--checks", "misconfig",
        "--format", "h1md",
    ])
    assert rc == 1
    out = capsys.readouterr().out
    assert out.startswith("# casket scan report")
    assert "running as root" in out.lower() or "root" in out.lower()


# ---- clean exit code -------------------------------------------------------

def test_missing_image_exit_code(capsys):
    rc = main([
        "--image", "/no/such/image.tar",
        "--mode", "tarball",
        "--checks", "all",
    ])
    assert rc == 2
    err = capsys.readouterr().err
    assert "not found" in err
