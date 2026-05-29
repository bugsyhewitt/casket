"""Tests for --suppress-severity band filtering.

``--suppress-severity`` mutes findings at *exactly* the named severity band(s) —
where ``--min-severity`` is a floor (keep at-or-above one threshold), this drops
the named level(s) alone, so the two knobs together carve out any arbitrary
severity range (e.g. keep critical/high + info, drop the busy medium/low
middle). ``filter_by_severity_band()`` is the pure decision function; the CLI
e2e tests confirm it's wired into the rendered output and that the exit-code gate
applies to the *filtered* (reported) set.
"""

from __future__ import annotations

import json

import pytest

from casket.cli import build_parser, main
from casket.findings import Finding
from casket.scanner import (
    SUPPRESS_SEVERITY_CHOICES,
    exit_code,
    filter_by_severity_band,
)
from tests.conftest import fixture_path


def _finding(severity: str, *, category: str = "misconfig") -> Finding:
    return Finding(
        category=category,
        title=f"{severity} thing",
        severity=severity,
        layer_sha="sha256:deadbeef",
        path_in_layer="<image config>",
        detail={"rule": "test"},
    )


def _severities(findings: list[Finding]) -> list[str]:
    return [f.severity for f in findings]


# ---- pure filter_by_severity_band helper ----------------------------------

def test_none_returns_everything_unchanged():
    findings = [_finding("critical"), _finding("low"), _finding("info")]
    out = filter_by_severity_band(findings, None)
    assert _severities(out) == ["critical", "low", "info"]


def test_empty_set_is_a_noop():
    findings = [_finding("high"), _finding("medium")]
    assert _severities(filter_by_severity_band(findings, set())) == ["high", "medium"]


def test_default_arg_is_noop():
    findings = [_finding("low"), _finding("info")]
    assert _severities(filter_by_severity_band(findings)) == ["low", "info"]


def test_empty_input_is_empty():
    assert filter_by_severity_band([], {"high"}) == []


def test_single_band_mutes_only_that_level():
    findings = [_finding("critical"), _finding("high"), _finding("medium")]
    out = filter_by_severity_band(findings, {"high"})
    assert _severities(out) == ["critical", "medium"]


def test_multiple_bands_mute_each_named_level():
    # the motivating case --min-severity cannot express: keep critical/high AND
    # info, drop the busy medium/low middle.
    findings = [
        _finding("critical"),
        _finding("high"),
        _finding("medium"),
        _finding("low"),
        _finding("info"),
    ]
    out = filter_by_severity_band(findings, {"medium", "low"})
    assert _severities(out) == ["critical", "high", "info"]


def test_upper_band_mute_keeps_critical_and_info():
    # mute high (a band --min-severity can't isolate) while keeping critical+info
    findings = [_finding("critical"), _finding("high"), _finding("info")]
    out = filter_by_severity_band(findings, {"high"})
    assert _severities(out) == ["critical", "info"]


def test_applies_across_all_categories():
    findings = [
        _finding("high", category="cve"),
        _finding("high", category="creds"),
        _finding("high", category="misconfig"),
        _finding("low", category="cve"),
    ]
    out = filter_by_severity_band(findings, {"high"})
    # every category's high finding is muted; only the low cve survives
    assert [f.category for f in out] == ["cve"]
    assert _severities(out) == ["low"]


def test_unknown_severity_finding_always_survives():
    weird = _finding("bogus")
    # an unrecognised severity is never in the (validated) suppress set, so the
    # band filter never silently hides it
    assert filter_by_severity_band([weird], {"high", "low"}) == [weird]


def test_suppress_every_band_empties_report():
    findings = [_finding(s) for s in SUPPRESS_SEVERITY_CHOICES]
    out = filter_by_severity_band(findings, set(SUPPRESS_SEVERITY_CHOICES))
    assert out == []


def test_returns_a_new_list_not_the_input():
    findings = [_finding("high")]
    out = filter_by_severity_band(findings, None)
    assert out is not findings


# ---- CLI surface ----------------------------------------------------------

def test_parser_default_suppress_severity_is_none():
    parser = build_parser()
    args = parser.parse_args(["--image", "x.tar"])
    assert args.suppress_severity is None


def test_parser_appends_repeatable():
    parser = build_parser()
    args = parser.parse_args([
        "--image", "x.tar",
        "--suppress-severity", "medium",
        "--suppress-severity", "low",
    ])
    assert args.suppress_severity == ["medium", "low"]


def test_parser_rejects_bad_band():
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["--image", "x.tar", "--suppress-severity", "catastrophic"])


def test_help_lists_suppress_severity(capsys):
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["--help"])
    assert "--suppress-severity" in capsys.readouterr().out


# ---- CLI e2e: filtering against a real fixture ----------------------------
#
# rootuser-image's misconfig set spans high (running_as_root, SSH sensitive
# port) and medium (suspicious_env API_TOKEN) — ideal for proving the band
# filter keeps and drops the right levels and that the gate sees the filtered
# set.

def test_e2e_no_flag_reports_both_bands(capsys):
    rc = main([
        "--image", fixture_path("rootuser-image.tar"),
        "--mode", "tarball",
        "--checks", "misconfig",
        "--format", "json",
    ])
    payload = json.loads(capsys.readouterr().out)
    severities = {f["severity"] for f in payload["findings"]}
    assert {"high", "medium"} <= severities
    assert rc == 1


def test_e2e_suppress_medium_keeps_high(capsys):
    rc = main([
        "--image", fixture_path("rootuser-image.tar"),
        "--mode", "tarball",
        "--checks", "misconfig",
        "--format", "json",
        "--suppress-severity", "medium",
    ])
    payload = json.loads(capsys.readouterr().out)
    severities = {f["severity"] for f in payload["findings"]}
    assert "high" in severities  # high band survives
    assert "medium" not in severities  # medium band muted
    # finding_count reflects the filtered (reported) set
    assert payload["finding_count"] == len(payload["findings"])
    assert rc == 1  # a high finding remains -> gate still trips


def test_e2e_suppress_high_band_only(capsys):
    # mute the high band while leaving medium — something --min-severity (a
    # floor) cannot do (it would have to drop medium to drop high).
    rc = main([
        "--image", fixture_path("rootuser-image.tar"),
        "--mode", "tarball",
        "--checks", "misconfig",
        "--format", "json",
        "--suppress-severity", "high",
    ])
    payload = json.loads(capsys.readouterr().out)
    severities = {f["severity"] for f in payload["findings"]}
    assert severities == {"medium"}  # only the medium band remains
    assert rc == 1  # a medium finding remains -> gate trips on "any"


def test_e2e_suppress_both_bands_empties_and_gate_passes(capsys):
    rc = main([
        "--image", fixture_path("rootuser-image.tar"),
        "--mode", "tarball",
        "--checks", "misconfig",
        "--format", "json",
        "--suppress-severity", "high",
        "--suppress-severity", "medium",
    ])
    payload = json.loads(capsys.readouterr().out)
    assert payload["finding_count"] == 0
    assert payload["findings"] == []
    # gate runs on the filtered (now-empty) set -> clean build
    assert rc == 0


def test_e2e_band_and_min_severity_compose(capsys):
    # --min-severity high (floor: keep high+) THEN --suppress-severity high
    # (mute the high band) leaves nothing — proves the two knobs compose as
    # independent stages on the reported set.
    rc = main([
        "--image", fixture_path("rootuser-image.tar"),
        "--mode", "tarball",
        "--checks", "misconfig",
        "--format", "json",
        "--min-severity", "high",
        "--suppress-severity", "high",
    ])
    payload = json.loads(capsys.readouterr().out)
    assert payload["finding_count"] == 0
    assert rc == 0
