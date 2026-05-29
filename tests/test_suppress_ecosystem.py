"""Tests for --suppress-ecosystem report filtering.

``--suppress-ecosystem`` prunes CVE findings from operator-named OSV ecosystems
(e.g. hide all Debian OS-package CVEs to focus on application dependencies) —
unlike ``--fail-on``, which gates only the build's exit code, it shapes what
casket *reports*. ``filter_by_ecosystem()`` is the pure decision function; the
CLI e2e tests confirm it's wired into the rendered output and that the exit-code
gate applies to the *filtered* (reported) set.
"""

from __future__ import annotations

import json

import pytest

from casket.cli import build_parser, main
from casket.findings import Finding
from casket.scanner import filter_by_ecosystem
from tests.conftest import fixture_path


def _cve(ecosystem: str | None, *, severity: str = "high") -> Finding:
    detail: dict[str, object] = {"cve_id": f"CVE-{ecosystem or 'x'}", "package": "p"}
    if ecosystem is not None:
        detail["ecosystem"] = ecosystem
    return Finding(
        category="cve",
        title=f"{ecosystem} cve",
        severity=severity,
        layer_sha="sha256:deadbeef",
        path_in_layer="usr/lib/x",
        detail=detail,
    )


def _misconfig() -> Finding:
    return Finding(
        category="misconfig",
        title="running as root",
        severity="high",
        layer_sha="sha256:cafef00d",
        path_in_layer="<image config>",
        detail={"rule": "running_as_root"},
    )


def _ecos(findings: list[Finding]) -> list[str | None]:
    return [f.detail.get("ecosystem") for f in findings]


# ---- pure filter_by_ecosystem helper --------------------------------------

def test_none_returns_everything_unchanged():
    findings = [_cve("Debian"), _cve("PyPI"), _misconfig()]
    out = filter_by_ecosystem(findings, None)
    assert _ecos(out) == ["Debian", "PyPI", None]


def test_empty_set_is_a_noop():
    findings = [_cve("Debian"), _cve("PyPI")]
    assert _ecos(filter_by_ecosystem(findings, set())) == ["Debian", "PyPI"]


def test_default_arg_reports_everything():
    findings = [_cve("Alpine")]
    assert _ecos(filter_by_ecosystem(findings)) == ["Alpine"]


def test_suppresses_named_ecosystem():
    findings = [_cve("Debian"), _cve("PyPI")]
    out = filter_by_ecosystem(findings, {"Debian"})
    assert _ecos(out) == ["PyPI"]


def test_match_is_case_insensitive():
    # operator needn't remember OSV's exact capitalisation
    findings = [_cve("Debian"), _cve("Red Hat")]
    out = filter_by_ecosystem(findings, {"debian", "red hat"})
    assert out == []


def test_suppresses_multiple_ecosystems():
    findings = [_cve("Debian"), _cve("Alpine"), _cve("PyPI")]
    out = filter_by_ecosystem(findings, {"Debian", "Alpine"})
    assert _ecos(out) == ["PyPI"]


def test_non_cve_findings_always_survive():
    # misconfig carries no ecosystem and is never about package identity
    findings = [_misconfig(), _cve("Debian")]
    out = filter_by_ecosystem(findings, {"Debian"})
    assert out == [findings[0]]  # the misconfig, not the suppressed CVE


def test_cve_without_ecosystem_is_kept():
    # an ecosystem-less CVE can't be matched -> never silently hidden
    findings = [_cve(None), _cve("Debian")]
    out = filter_by_ecosystem(findings, {"Debian"})
    assert out == [findings[0]]


def test_returns_a_new_list_not_the_input():
    findings = [_cve("PyPI")]
    out = filter_by_ecosystem(findings, None)
    assert out is not findings


def test_empty_input_is_empty():
    assert filter_by_ecosystem([], {"Debian"}) == []


# ---- CLI surface ----------------------------------------------------------

def test_parser_default_suppress_ecosystem_is_none():
    parser = build_parser()
    args = parser.parse_args(["--image", "x.tar"])
    assert args.suppress_ecosystem is None


def test_parser_suppress_ecosystem_is_repeatable():
    parser = build_parser()
    args = parser.parse_args(
        ["--image", "x.tar", "--suppress-ecosystem", "Debian",
         "--suppress-ecosystem", "Alpine"]
    )
    assert args.suppress_ecosystem == ["Debian", "Alpine"]


def test_help_lists_suppress_ecosystem(capsys):
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["--help"])
    assert "--suppress-ecosystem" in capsys.readouterr().out


# ---- CLI e2e: filtering against a real fixture ----------------------------
#
# old-package.tar ships requests 2.19.0 (PyPI). Seeding the OSV cache (offline)
# makes the cves check emit one PyPI CVE finding; --suppress-ecosystem PyPI must
# empty the report and flip the gate to clean.


def _seed_requests_cve(_isolate_osv_cache):
    from casket.osv import OSVClient

    seed = OSVClient(cache_path=_isolate_osv_cache)
    seed.seed(
        "PyPI",
        "requests",
        "2.19.0",
        [
            {
                "id": "GHSA-x",
                "aliases": ["CVE-2018-18074"],
                "summary": "auth leak",
                "database_specific": {"severity": "MEDIUM"},
            }
        ],
    )


def test_e2e_without_suppress_reports_the_cve(capsys, _isolate_osv_cache):
    _seed_requests_cve(_isolate_osv_cache)
    rc = main(
        [
            "--image", fixture_path("old-package.tar"),
            "--mode", "tarball",
            "--checks", "cves",
            "--format", "json",
            "--offline",
        ]
    )
    payload = json.loads(capsys.readouterr().out)
    cves = [f for f in payload["findings"] if f["category"] == "cve"]
    assert any(f["ecosystem"] == "PyPI" for f in cves)
    assert rc == 1  # finding present -> gate trips


def test_e2e_suppress_pypi_empties_report_and_gate_passes(
    capsys, _isolate_osv_cache
):
    _seed_requests_cve(_isolate_osv_cache)
    rc = main(
        [
            "--image", fixture_path("old-package.tar"),
            "--mode", "tarball",
            "--checks", "cves",
            "--format", "json",
            "--offline",
            "--suppress-ecosystem", "PyPI",
        ]
    )
    payload = json.loads(capsys.readouterr().out)
    assert not [f for f in payload["findings"] if f["category"] == "cve"]
    # finding_count reflects the filtered report
    assert payload["finding_count"] == len(payload["findings"])
    assert rc == 0  # nothing left to fail on


def test_e2e_suppress_is_case_insensitive(capsys, _isolate_osv_cache):
    _seed_requests_cve(_isolate_osv_cache)
    rc = main(
        [
            "--image", fixture_path("old-package.tar"),
            "--mode", "tarball",
            "--checks", "cves",
            "--format", "json",
            "--offline",
            "--suppress-ecosystem", "pypi",  # lower-case still matches "PyPI"
        ]
    )
    payload = json.loads(capsys.readouterr().out)
    assert not [f for f in payload["findings"] if f["category"] == "cve"]
    assert rc == 0


def test_e2e_suppress_other_ecosystem_keeps_the_cve(capsys, _isolate_osv_cache):
    # suppressing an ecosystem the image doesn't have leaves the PyPI CVE intact
    _seed_requests_cve(_isolate_osv_cache)
    rc = main(
        [
            "--image", fixture_path("old-package.tar"),
            "--mode", "tarball",
            "--checks", "cves",
            "--format", "json",
            "--offline",
            "--suppress-ecosystem", "Debian",
        ]
    )
    payload = json.loads(capsys.readouterr().out)
    cves = [f for f in payload["findings"] if f["category"] == "cve"]
    assert any(f["ecosystem"] == "PyPI" for f in cves)
    assert rc == 1  # the CVE survives -> gate still trips
