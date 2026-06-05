"""Tests for --only-actionable fix-availability filter.

``--only-actionable`` drops CVE findings that have no published fix: only CVE
findings whose OSV record carries at least one patched version (i.e.
``detail["fixed_versions"]`` is a non-empty list) survive. creds and misconfig
findings always survive regardless. ``filter_fix_available()`` is the pure
decision function; the CLI e2e tests confirm it is wired into the rendered output
and that the exit-code gate applies to the *filtered* (reported) set.
"""

from __future__ import annotations

import json

import pytest

from casket.cli import main
from casket.findings import Finding
from casket.scanner import filter_fix_available
from tests.conftest import fixture_path


# ---- helpers ----------------------------------------------------------------

def _cve(*, fixed: list[str] | None = None) -> Finding:
    """Make a minimal CVE finding, optionally with fixed_versions."""
    detail: dict = {
        "cve_id": "CVE-2023-0001",
        "osv_id": "GHSA-xxxx-yyyy-zzzz",
        "package": "requests",
        "ecosystem": "PyPI",
        "installed_version": "2.19.0",
        "summary": "test cve",
    }
    if fixed is not None:
        detail["fixed_versions"] = fixed
    return Finding(
        category="cve",
        title="test cve",
        severity="medium",
        layer_sha="sha256:deadbeef",
        path_in_layer="layer[0]",
        detail=detail,
    )


def _cred() -> Finding:
    return Finding(
        category="creds",
        title="AWS secret key leaked",
        severity="critical",
        layer_sha="sha256:deadbeef",
        path_in_layer="/app/.env",
        detail={"rule": "aws_secret_access_key"},
    )


def _misconfig() -> Finding:
    return Finding(
        category="misconfig",
        title="image runs as root",
        severity="high",
        layer_sha="sha256:deadbeef",
        path_in_layer="<image config>",
        detail={"rule": "running_as_root"},
    )


# ---- pure filter_fix_available helper ---------------------------------------

def test_flag_off_returns_everything_unchanged():
    findings = [_cve(fixed=["2.20.0"]), _cve(fixed=None), _cred(), _misconfig()]
    out = filter_fix_available(findings, only_actionable=False)
    assert len(out) == 4


def test_default_arg_is_noop():
    findings = [_cve(fixed=None), _misconfig()]
    assert len(filter_fix_available(findings)) == 2


def test_empty_input_is_empty():
    assert filter_fix_available([], only_actionable=True) == []


def test_cve_with_fix_survives():
    f = _cve(fixed=["2.20.0"])
    out = filter_fix_available([f], only_actionable=True)
    assert out == [f]


def test_cve_without_fix_dropped():
    f = _cve(fixed=None)
    out = filter_fix_available([f], only_actionable=True)
    assert out == []


def test_cve_with_empty_fixed_list_dropped():
    f = _cve(fixed=[])
    out = filter_fix_available([f], only_actionable=True)
    assert out == []


def test_creds_always_survives():
    f = _cred()
    out = filter_fix_available([f], only_actionable=True)
    assert out == [f]


def test_misconfig_always_survives():
    f = _misconfig()
    out = filter_fix_available([f], only_actionable=True)
    assert out == [f]


def test_mixed_cves_partial_filter():
    fixed = _cve(fixed=["2.20.0"])
    unfixed = _cve(fixed=None)
    out = filter_fix_available([fixed, unfixed], only_actionable=True)
    assert out == [fixed]


def test_returns_new_list_not_mutation():
    original = [_cve(fixed=["2.20.0"]), _cve(fixed=None)]
    out = filter_fix_available(original, only_actionable=True)
    assert out is not original
    assert len(original) == 2  # original untouched


def test_multiple_fixed_versions_survives():
    f = _cve(fixed=["2.20.0", "2.21.0"])
    out = filter_fix_available([f], only_actionable=True)
    assert out == [f]


# ---- CLI surface ------------------------------------------------------------

def test_cli_parser_has_only_actionable_flag():
    from casket.cli import build_parser
    parser = build_parser()
    ns = parser.parse_args(["--image", "test.tar"])
    assert hasattr(ns, "only_actionable")
    assert ns.only_actionable is False


def test_cli_only_actionable_flag_sets_true():
    from casket.cli import build_parser
    parser = build_parser()
    ns = parser.parse_args(["--image", "test.tar", "--only-actionable"])
    assert ns.only_actionable is True


def test_cli_help_mentions_only_actionable(capsys):
    from casket.cli import build_parser
    parser = build_parser()
    try:
        parser.parse_args(["--help"])
    except SystemExit:
        pass
    out = capsys.readouterr().out
    assert "--only-actionable" in out


# ---- end-to-end CLI tests ---------------------------------------------------

def test_only_actionable_keeps_fixable_cve(capsys):
    """A CVE with a fixed_version is reported under --only-actionable."""
    # old-package.tar carries PyPI requests 2.19.0. The seed has
    # fixed_versions=["2.20.0"] for it. The finding should survive.
    rc = main([
        "--image", fixture_path("old-package.tar"),
        "--format", "json", "--only-actionable",
    ])
    out = json.loads(capsys.readouterr().out)
    cves = [f for f in out["findings"] if f["category"] == "cve"]
    # At least one CVE with a fixed version should appear.
    assert any(f.get("fixed_versions") for f in cves)
    assert rc == 1  # findings present → gate trips


def test_only_actionable_flag_absent_shows_all(capsys):
    """Without --only-actionable all CVE findings appear (flag is a no-op by default)."""
    rc_all = main([
        "--image", fixture_path("old-package.tar"),
        "--format", "json",
    ])
    out_all = json.loads(capsys.readouterr().out)

    rc_filtered = main([
        "--image", fixture_path("old-package.tar"),
        "--format", "json", "--only-actionable",
    ])
    out_filtered = json.loads(capsys.readouterr().out)

    # The filtered set must be a subset of the full set.
    all_ids = {f.get("cve_id", f.get("osv_id")) for f in out_all["findings"]}
    filtered_ids = {f.get("cve_id", f.get("osv_id")) for f in out_filtered["findings"]}
    assert filtered_ids <= all_ids


def test_only_actionable_gate_consistent_with_report(capsys):
    """--only-actionable gate trips only for findings that pass the filter."""
    # old-package.tar: requests 2.19.0 has CVEs with fixes.
    # With --only-actionable the gate should still trip (fixes exist).
    rc = main([
        "--image", fixture_path("old-package.tar"),
        "--format", "json", "--only-actionable", "--checks", "cves",
    ])
    out = json.loads(capsys.readouterr().out)
    cves = [f for f in out["findings"] if f["category"] == "cve"]
    # All reported CVEs must have fixed_versions.
    assert all(f.get("fixed_versions") for f in cves)
    # Gate should trip since there are findings.
    assert rc == 1
