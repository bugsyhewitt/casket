"""Tests for VEX (Vulnerability Exploitability eXchange) suppression.

casket consumes an OpenVEX document (``--vex FILE.json``) and drops CVE
findings the operator has triaged as ``not_affected`` or ``fixed`` — the same
"suppress known-not-affected noise" capability every mature scanner ships
(Trivy/Grype VEX, GitHub dismissals). Like the other report filters
(``--min-severity`` / ``--min-epss``) it shapes the *reported* set before the
exit-code gate / ``--compare`` diff, so a triaged-away CVE neither shows up nor
trips the gate, and creds/misconfig findings are never pruned by it.

The parsing layer (``casket.vex``) turns an OpenVEX JSON document into the set
of suppressed vulnerability identifiers; the filter (``scanner.filter_by_vex``)
matches a CVE finding against that set by *any* of its ids (headline CVE, OSV
id, or any alias) so a VEX statement written against the CVE still suppresses a
finding whose OSV headline is a GHSA, and vice-versa.
"""

from __future__ import annotations

import json

import pytest

from casket.cli import build_parser, main
from casket.findings import Finding
from casket.scanner import filter_by_vex
from casket.vex import VEXError, load_vex, parse_vex
from tests.conftest import fixture_path


# --- parse_vex: OpenVEX document -> suppression set -----------------------


def test_parse_collects_not_affected_and_fixed():
    doc = json.dumps(
        {
            "@context": "https://openvex.dev/ns/v0.2.0",
            "statements": [
                {"vulnerability": {"name": "CVE-1"}, "status": "not_affected"},
                {"vulnerability": {"name": "CVE-2"}, "status": "fixed"},
            ],
        }
    )
    assert parse_vex(doc) == {"CVE-1", "CVE-2"}


def test_parse_ignores_affected_and_under_investigation():
    # affected / under_investigation are NOT suppressing: the operator is
    # telling us to keep showing them.
    doc = json.dumps(
        {
            "statements": [
                {"vulnerability": {"name": "CVE-1"}, "status": "affected"},
                {
                    "vulnerability": {"name": "CVE-2"},
                    "status": "under_investigation",
                },
                {"vulnerability": {"name": "CVE-3"}, "status": "not_affected"},
            ]
        }
    )
    assert parse_vex(doc) == {"CVE-3"}


def test_parse_accepts_bare_string_vulnerability():
    doc = json.dumps(
        {"statements": [{"vulnerability": "CVE-9", "status": "not_affected"}]}
    )
    assert parse_vex(doc) == {"CVE-9"}


def test_parse_skips_malformed_statements_without_raising():
    doc = json.dumps(
        {
            "statements": [
                "not-an-object",
                {"status": "not_affected"},  # no vulnerability
                {"vulnerability": {"name": "CVE-1"}},  # no status
                {"vulnerability": {"name": 42}, "status": "not_affected"},  # bad id
                {"vulnerability": {"name": "  "}, "status": "fixed"},  # blank id
                {"vulnerability": {"name": "CVE-OK"}, "status": "not_affected"},
            ]
        }
    )
    assert parse_vex(doc) == {"CVE-OK"}


def test_parse_empty_statements_is_empty_set():
    assert parse_vex(json.dumps({"statements": []})) == set()


def test_parse_invalid_json_raises_vexerror():
    with pytest.raises(VEXError):
        parse_vex("{not json")


def test_parse_non_object_raises_vexerror():
    with pytest.raises(VEXError):
        parse_vex(json.dumps(["a", "list"]))


def test_parse_missing_statements_raises_vexerror():
    with pytest.raises(VEXError):
        parse_vex(json.dumps({"@context": "x"}))


def test_load_vex_reads_file(tmp_path):
    p = tmp_path / "vex.json"
    p.write_text(
        json.dumps(
            {"statements": [{"vulnerability": "CVE-7", "status": "fixed"}]}
        )
    )
    assert load_vex(str(p)) == {"CVE-7"}


def test_load_vex_missing_file_raises_filenotfound():
    with pytest.raises(FileNotFoundError):
        load_vex("/no/such/vex.json")


# --- filter_by_vex: drop suppressed CVE findings ---------------------------


def _cve(cve_id, *, osv_id=None, aliases=None):
    detail = {"cve_id": cve_id, "package": "pkg", "installed_version": "1.0"}
    if osv_id is not None:
        detail["osv_id"] = osv_id
    if aliases is not None:
        detail["aliases"] = aliases
    return Finding(
        category="cve",
        title=f"pkg 1.0: {cve_id}",
        severity="high",
        layer_sha="sha256:layer",
        path_in_layer="usr/lib/pkg",
        detail=detail,
    )


def _misconfig():
    return Finding(
        category="misconfig",
        title="running as root",
        severity="high",
        layer_sha="sha256:cfg",
        path_in_layer="<image config>",
        detail={"rule": "running_as_root", "user": "root"},
    )


def test_filter_none_is_noop():
    findings = [_cve("CVE-1"), _misconfig()]
    assert filter_by_vex(findings, None) == findings


def test_filter_empty_set_is_noop():
    findings = [_cve("CVE-1"), _misconfig()]
    out = filter_by_vex(findings, set())
    assert out == findings


def test_filter_drops_suppressed_cve_by_headline_id():
    findings = [_cve("CVE-1"), _cve("CVE-2")]
    out = filter_by_vex(findings, {"CVE-1"})
    assert [f.detail["cve_id"] for f in out] == ["CVE-2"]


def test_filter_matches_on_osv_id():
    # VEX names the GHSA; the finding's headline is a CVE but its osv_id matches.
    findings = [_cve("CVE-1", osv_id="GHSA-x")]
    assert filter_by_vex(findings, {"GHSA-x"}) == []


def test_filter_matches_on_alias():
    # VEX names a distro id that only appears in the finding's alias list.
    findings = [_cve("CVE-1", aliases=["CVE-1", "DSA-9999-1"])]
    assert filter_by_vex(findings, {"DSA-9999-1"}) == []


def test_filter_never_drops_non_cve_findings():
    mc = _misconfig()
    # Even if a misconfig somehow shared an id with a suppressed vuln, VEX is a
    # CVE-triage format and must not touch creds/misconfig.
    out = filter_by_vex([mc], {"running_as_root", "CVE-1"})
    assert out == [mc]


def test_filter_keeps_unsuppressed_cve():
    findings = [_cve("CVE-keep")]
    assert filter_by_vex(findings, {"CVE-other"}) == findings


# --- CLI wiring ------------------------------------------------------------


def test_help_mentions_vex(capsys):
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["--help"])
    assert "--vex" in capsys.readouterr().out


def test_cli_missing_vex_file_exits_2(capsys):
    rc = main(
        [
            "--image",
            fixture_path("old-package.tar"),
            "--mode",
            "tarball",
            "--checks",
            "cves",
            "--offline",
            "--vex",
            "/no/such/vex.json",
        ]
    )
    assert rc == 2
    assert "VEX file not found" in capsys.readouterr().err


def test_cli_malformed_vex_file_exits_2(capsys, tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{not valid json")
    rc = main(
        [
            "--image",
            fixture_path("old-package.tar"),
            "--mode",
            "tarball",
            "--checks",
            "cves",
            "--offline",
            "--vex",
            str(bad),
        ]
    )
    assert rc == 2
    assert "failed to read VEX file" in capsys.readouterr().err


# --- CLI e2e: suppress a real CVE finding ----------------------------------
#
# old-package.tar ships requests 2.19.0; seeding the OSV cache (autouse env)
# makes the cves check emit one CVE finding offline. A VEX file marking that
# CVE not_affected must empty the report and flip the gate to clean.


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


def test_e2e_without_vex_reports_the_cve(capsys, _isolate_osv_cache):
    _seed_requests_cve(_isolate_osv_cache)
    rc = main(
        [
            "--image",
            fixture_path("old-package.tar"),
            "--mode",
            "tarball",
            "--checks",
            "cves",
            "--format",
            "json",
            "--offline",
        ]
    )
    payload = json.loads(capsys.readouterr().out)
    cves = [f for f in payload["findings"] if f["category"] == "cve"]
    assert any(f["cve_id"] == "CVE-2018-18074" for f in cves)
    assert rc == 1  # finding present -> gate trips


def test_e2e_vex_suppresses_the_cve_and_gate_passes(
    capsys, _isolate_osv_cache, tmp_path
):
    _seed_requests_cve(_isolate_osv_cache)
    vex = tmp_path / "vex.json"
    vex.write_text(
        json.dumps(
            {
                "@context": "https://openvex.dev/ns/v0.2.0",
                "statements": [
                    {
                        "vulnerability": {"name": "CVE-2018-18074"},
                        "status": "not_affected",
                    }
                ],
            }
        )
    )
    rc = main(
        [
            "--image",
            fixture_path("old-package.tar"),
            "--mode",
            "tarball",
            "--checks",
            "cves",
            "--format",
            "json",
            "--offline",
            "--vex",
            str(vex),
        ]
    )
    payload = json.loads(capsys.readouterr().out)
    # the requests CVE is suppressed; the report (and gate) clear
    assert all(
        f["cve_id"] != "CVE-2018-18074"
        for f in payload["findings"]
        if f["category"] == "cve"
    )
    assert payload["finding_count"] == len(payload["findings"])
    assert rc == 0  # nothing left to fail on


def test_e2e_vex_matches_on_alias(capsys, _isolate_osv_cache, tmp_path):
    # The finding's headline id is CVE-2018-18074 but its OSV id is GHSA-x; a
    # VEX statement naming GHSA-x (the OSV id, not the headline) must suppress it.
    _seed_requests_cve(_isolate_osv_cache)
    vex = tmp_path / "vex.json"
    vex.write_text(
        json.dumps(
            {"statements": [{"vulnerability": "GHSA-x", "status": "fixed"}]}
        )
    )
    rc = main(
        [
            "--image",
            fixture_path("old-package.tar"),
            "--mode",
            "tarball",
            "--checks",
            "cves",
            "--format",
            "json",
            "--offline",
            "--vex",
            str(vex),
        ]
    )
    payload = json.loads(capsys.readouterr().out)
    assert not [f for f in payload["findings"] if f["category"] == "cve"]
    assert rc == 0
