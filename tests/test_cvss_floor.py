"""Tests for --cvss-floor report filtering.

``--cvss-floor`` prunes CVE findings whose numeric CVSS base score is below
the operator's threshold — a finer knob than ``--min-severity``'s band floor
(a 7.0 and a 9.8 are both ``high``). ``filter_by_cvss_floor()`` is the pure
decision function; the CLI e2e tests confirm it's wired into the rendered
output and that the exit-code gate applies to the *filtered* (reported) set.
"""

from __future__ import annotations

import json

import pytest

from casket.cli import build_parser, main
from casket.findings import Finding
from casket.scanner import filter_by_cvss_floor
from tests.conftest import fixture_path


def _cve(score: float | None, *, severity: str = "high") -> Finding:
    detail: dict[str, object] = {"cve_id": f"CVE-{score}", "package": "p"}
    if score is not None:
        detail["cvss_score"] = score
    return Finding(
        category="cve",
        title=f"cve@{score}",
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


def _creds() -> Finding:
    return Finding(
        category="creds",
        title="AWS key",
        severity="critical",
        layer_sha="sha256:beefcafe",
        path_in_layer="app/.env",
        detail={"rule": "aws_secret_access_key"},
    )


def _scores(findings: list[Finding]) -> list[object]:
    return [f.detail.get("cvss_score") for f in findings]


# ---- pure filter_by_cvss_floor helper -------------------------------------

def test_none_returns_everything_unchanged():
    findings = [_cve(9.8), _cve(5.0), _cve(None), _misconfig()]
    out = filter_by_cvss_floor(findings, None)
    assert _scores(out) == [9.8, 5.0, None, None]


def test_default_arg_reports_everything():
    findings = [_cve(3.1), _cve(9.0)]
    assert _scores(filter_by_cvss_floor(findings)) == [3.1, 9.0]


def test_floor_keeps_at_or_above_threshold():
    findings = [_cve(9.8), _cve(7.5), _cve(7.4), _cve(0.0)]
    out = filter_by_cvss_floor(findings, 7.5)
    assert _scores(out) == [9.8, 7.5]  # 7.4 dropped, 0.0 dropped


def test_floor_at_zero_keeps_every_scored_cve():
    # 0.0 is the info-band floor and a valid CVSS score; an explicit floor of
    # 0.0 must keep every CVE that carries any score (only unscored CVEs drop).
    findings = [_cve(0.0), _cve(5.0), _cve(None)]
    out = filter_by_cvss_floor(findings, 0.0)
    assert _scores(out) == [0.0, 5.0]  # the unscored CVE is pruned


def test_floor_at_ten_keeps_only_perfect_scores():
    findings = [_cve(10.0), _cve(9.9), _cve(9.8)]
    out = filter_by_cvss_floor(findings, 10.0)
    assert _scores(out) == [10.0]


def test_unscored_cve_dropped_by_explicit_floor():
    # matches --min-epss posture: an explicit numeric bar requires a number
    findings = [_cve(None), _cve(8.0)]
    out = filter_by_cvss_floor(findings, 7.0)
    assert _scores(out) == [8.0]


def test_non_cve_findings_always_survive():
    # creds/misconfig have no CVSS score and a different class of problem
    findings = [_misconfig(), _creds(), _cve(2.0)]
    out = filter_by_cvss_floor(findings, 7.0)
    assert out == [findings[0], findings[1]]  # only the low-CVSS CVE drops


def test_int_score_is_accepted_as_a_number():
    # OSV records sometimes round to whole numbers; bool is a subclass of int
    # but cvss scores are floats in practice — exercise the int branch directly.
    cve = _cve(None)
    cve.detail["cvss_score"] = 8  # plain int
    out = filter_by_cvss_floor([cve], 7.5)
    assert out == [cve]


def test_non_numeric_score_is_pruned_under_floor():
    # a malformed score must not silently pass an explicit floor
    cve = _cve(None)
    cve.detail["cvss_score"] = "9.8"  # stringly-typed; not a number
    out = filter_by_cvss_floor([cve], 7.0)
    assert out == []


def test_returns_a_new_list_not_the_input():
    findings = [_cve(5.0)]
    out = filter_by_cvss_floor(findings, None)
    assert out is not findings


def test_empty_input_is_empty():
    assert filter_by_cvss_floor([], 5.0) == []


# ---- argparse type validation ---------------------------------------------

def test_parser_default_cvss_floor_is_none():
    parser = build_parser()
    args = parser.parse_args(["--image", "x.tar"])
    assert args.cvss_floor is None


def test_parser_accepts_in_range_floor():
    parser = build_parser()
    args = parser.parse_args(["--image", "x.tar", "--cvss-floor", "7.5"])
    assert args.cvss_floor == 7.5


def test_parser_accepts_boundary_values():
    parser = build_parser()
    args = parser.parse_args(["--image", "x.tar", "--cvss-floor", "0.0"])
    assert args.cvss_floor == 0.0
    args = parser.parse_args(["--image", "x.tar", "--cvss-floor", "10.0"])
    assert args.cvss_floor == 10.0


def test_parser_rejects_above_ten(capsys):
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["--image", "x.tar", "--cvss-floor", "10.1"])
    err = capsys.readouterr().err
    assert "CVSS floor" in err or "cvss-floor" in err


def test_parser_rejects_negative(capsys):
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["--image", "x.tar", "--cvss-floor", "-0.1"])
    assert "CVSS floor" in capsys.readouterr().err


def test_parser_rejects_non_numeric(capsys):
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["--image", "x.tar", "--cvss-floor", "high"])
    assert "invalid CVSS floor" in capsys.readouterr().err


def test_help_lists_cvss_floor(capsys):
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["--help"])
    assert "--cvss-floor" in capsys.readouterr().out


# ---- CLI e2e: filtering against a real fixture ----------------------------
#
# old-package.tar ships requests 2.19.0 (PyPI). Seeding the OSV cache (offline)
# with a CVSS v3.1 vector that scores 6.1 makes the cves check emit a CVE
# finding carrying ``cvss_score: 6.1``. --cvss-floor 7.0 must prune it (the
# numeric score is below the floor) and flip the gate to clean; --cvss-floor
# 5.0 keeps it and the gate trips.


def _seed_requests_cve_with_cvss(_isolate_osv_cache):
    """Seed the OSV cache with a CVSS-scored advisory for requests 2.19.0.

    The vector below scores 6.1 under CVSS v3.1 — high enough to be ``medium``
    in the casket band map, well below ``high``. That gives us a non-trivial
    floor (7.0) that prunes and a permissive floor (5.0) that keeps.
    """
    from casket.osv import OSVClient

    seed = OSVClient(cache_path=_isolate_osv_cache)
    seed.seed(
        "PyPI",
        "requests",
        "2.19.0",
        [
            {
                "id": "GHSA-x84v-xcm2-53pg",
                "aliases": ["CVE-2018-18074"],
                "summary": "auth leak",
                "severity": [
                    {
                        "type": "CVSS_V3",
                        "score": (
                            "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
                        ),
                    }
                ],
            }
        ],
    )


def test_e2e_without_cvss_floor_reports_the_cve(capsys, _isolate_osv_cache):
    _seed_requests_cve_with_cvss(_isolate_osv_cache)
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
    assert cves and cves[0]["cvss_score"] == 6.1
    assert rc == 1  # finding present -> gate trips


def test_e2e_cvss_floor_above_score_prunes_and_gate_passes(
    capsys, _isolate_osv_cache
):
    _seed_requests_cve_with_cvss(_isolate_osv_cache)
    rc = main(
        [
            "--image", fixture_path("old-package.tar"),
            "--mode", "tarball",
            "--checks", "cves",
            "--format", "json",
            "--offline",
            "--cvss-floor", "7.0",  # the seeded CVE scores 6.1 -> pruned
        ]
    )
    payload = json.loads(capsys.readouterr().out)
    assert not [f for f in payload["findings"] if f["category"] == "cve"]
    # finding_count reflects the filtered report
    assert payload["finding_count"] == len(payload["findings"])
    assert rc == 0  # nothing left to fail on


def test_e2e_cvss_floor_below_score_keeps_finding(capsys, _isolate_osv_cache):
    _seed_requests_cve_with_cvss(_isolate_osv_cache)
    rc = main(
        [
            "--image", fixture_path("old-package.tar"),
            "--mode", "tarball",
            "--checks", "cves",
            "--format", "json",
            "--offline",
            "--cvss-floor", "5.0",  # the seeded CVE scores 6.1 -> survives
        ]
    )
    payload = json.loads(capsys.readouterr().out)
    cves = [f for f in payload["findings"] if f["category"] == "cve"]
    assert cves and cves[0]["cvss_score"] == 6.1
    assert rc == 1  # the CVE survives -> gate still trips
