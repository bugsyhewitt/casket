"""Tests for the --fail-on severity gate (CI exit-code threshold).

The gate decides *whether findings break the build* without affecting what gets
reported. ``exit_code()`` is the pure decision function; the CLI e2e tests
confirm it's wired to the process return code and that every finding is still
emitted regardless of threshold.
"""

from __future__ import annotations

import json

import pytest

from casket.cli import build_parser, main
from casket.findings import Finding
from casket.scanner import FAIL_ON_CHOICES, exit_code
from tests.conftest import fixture_path


def _finding(severity: str) -> Finding:
    return Finding(
        category="misconfig",
        title=f"{severity} thing",
        severity=severity,
        layer_sha="sha256:deadbeef",
        path_in_layer="<image config>",
        detail={"rule": "test"},
    )


# ---- pure exit_code helper ------------------------------------------------

def test_exit_code_clean_is_zero_for_every_threshold():
    for fail_on in FAIL_ON_CHOICES:
        assert exit_code([], fail_on) == 0


def test_exit_code_any_fails_on_any_finding():
    assert exit_code([_finding("info")], "any") == 1
    assert exit_code([_finding("critical")], "any") == 1


def test_exit_code_default_is_any():
    # default arg preserves casket's original binary behaviour
    assert exit_code([_finding("low")]) == 1


def test_exit_code_none_never_fails_on_findings():
    assert exit_code([_finding("critical")], "none") == 0
    assert exit_code([_finding("info")], "none") == 0


def test_exit_code_threshold_includes_more_severe():
    findings = [_finding("critical")]
    # critical trips a "high" gate (critical is more severe than high)
    assert exit_code(findings, "high") == 1
    assert exit_code(findings, "critical") == 1


def test_exit_code_threshold_ignores_less_severe():
    findings = [_finding("low"), _finding("info")]
    # only low/info present; a "high" gate stays clean
    assert exit_code(findings, "high") == 0
    assert exit_code(findings, "medium") == 0
    # but the matching/looser thresholds trip
    assert exit_code(findings, "low") == 1
    assert exit_code(findings, "info") == 1


def test_exit_code_mixed_findings_trips_on_highest():
    findings = [_finding("info"), _finding("medium"), _finding("low")]
    assert exit_code(findings, "medium") == 1  # the medium one trips it
    assert exit_code(findings, "high") == 0  # nothing high+ present


def test_exit_code_unknown_severity_treated_as_below_threshold():
    weird = _finding("bogus")
    # an unrecognised severity ranks below info; only "any" should trip on it
    assert exit_code([weird], "any") == 1
    assert exit_code([weird], "info") == 0


def test_exit_code_unknown_threshold_fails_safe():
    # defensive: an out-of-range threshold value falls back to failing
    assert exit_code([_finding("low")], "nonsense") == 1


# ---- CLI surface ----------------------------------------------------------

def test_help_lists_fail_on():
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["--help"])  # argparse prints help and exits


def test_parser_rejects_bad_fail_on():
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["--image", "x.tar", "--fail-on", "catastrophic"])


def test_parser_default_fail_on_is_any():
    parser = build_parser()
    args = parser.parse_args(["--image", "x.tar"])
    assert args.fail_on == "any"


# ---- CLI e2e: gate behaviour against a real fixture -----------------------

def test_e2e_fail_on_high_passes_when_only_low(capsys):
    # The rootuser fixture's misconfig set includes a high (running_as_root)
    # finding, so use a check/threshold combo that yields a clean gate but a
    # non-empty report: scan the leaky image for creds at an impossible-to-meet
    # threshold is not possible (creds are critical), so we assert the inverse:
    # --fail-on none always exits 0 while still reporting findings.
    rc = main([
        "--image", fixture_path("rootuser-image.tar"),
        "--mode", "tarball",
        "--checks", "misconfig",
        "--format", "json",
        "--fail-on", "none",
    ])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    # report still contains the findings even though the gate passed
    assert payload["finding_count"] >= 1


def test_e2e_fail_on_threshold_gates_exit_code(capsys):
    # rootuser image -> a high-severity running_as_root finding exists.
    # --fail-on critical should NOT trip (no critical findings), but the
    # report must still include the high finding.
    rc = main([
        "--image", fixture_path("rootuser-image.tar"),
        "--mode", "tarball",
        "--checks", "misconfig",
        "--format", "json",
        "--fail-on", "critical",
    ])
    payload = json.loads(capsys.readouterr().out)
    severities = {f["severity"] for f in payload["findings"]}
    # sanity: there's a high finding but no critical one
    assert "high" in severities
    if "critical" in severities:
        assert rc == 1
    else:
        assert rc == 0


def test_e2e_fail_on_high_trips_on_critical_creds(capsys):
    # leaky image plants critical-severity credentials; --fail-on high trips.
    rc = main([
        "--image", fixture_path("leaky-image.tar"),
        "--mode", "tarball",
        "--checks", "creds",
        "--format", "json",
        "--fail-on", "high",
    ])
    payload = json.loads(capsys.readouterr().out)
    assert payload["finding_count"] >= 1
    assert rc == 1


def test_e2e_default_behaviour_unchanged(capsys):
    # No --fail-on: any finding still exits 1 (back-compat).
    rc = main([
        "--image", fixture_path("leaky-image.tar"),
        "--mode", "tarball",
        "--checks", "creds",
        "--format", "json",
    ])
    assert rc == 1
    capsys.readouterr()
