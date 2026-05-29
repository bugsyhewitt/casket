"""Tests for --min-severity report filtering.

``--min-severity`` prunes what casket *reports* (unlike ``--fail-on``, which
gates only the build's exit code). ``filter_by_severity()`` is the pure decision
function; the CLI e2e tests confirm it's wired into the rendered output and that
the exit-code gate applies to the *filtered* (reported) set.
"""

from __future__ import annotations

import json

import pytest

from casket.cli import build_parser, main
from casket.findings import Finding
from casket.scanner import (
    MIN_SEVERITY_CHOICES,
    exit_code,
    filter_by_severity,
)
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


def _severities(findings: list[Finding]) -> list[str]:
    return [f.severity for f in findings]


# ---- pure filter_by_severity helper ---------------------------------------

def test_filter_all_returns_everything_unchanged():
    findings = [_finding("critical"), _finding("low"), _finding("info")]
    out = filter_by_severity(findings, "all")
    assert _severities(out) == ["critical", "low", "info"]


def test_filter_default_is_all():
    findings = [_finding("low"), _finding("info")]
    # default arg preserves casket's original report-everything behaviour
    assert _severities(filter_by_severity(findings)) == ["low", "info"]


def test_filter_empty_input_is_empty_for_every_choice():
    for choice in MIN_SEVERITY_CHOICES:
        assert filter_by_severity([], choice) == []


def test_filter_keeps_at_or_above_threshold():
    findings = [
        _finding("critical"),
        _finding("high"),
        _finding("medium"),
        _finding("low"),
        _finding("info"),
    ]
    out = filter_by_severity(findings, "high")
    assert _severities(out) == ["critical", "high"]


def test_filter_medium_drops_low_and_info():
    findings = [_finding("medium"), _finding("low"), _finding("info")]
    out = filter_by_severity(findings, "medium")
    assert _severities(out) == ["medium"]


def test_filter_info_keeps_all_known_severities():
    findings = [
        _finding("critical"),
        _finding("high"),
        _finding("medium"),
        _finding("low"),
        _finding("info"),
    ]
    out = filter_by_severity(findings, "info")
    assert len(out) == 5


def test_filter_critical_keeps_only_critical():
    findings = [_finding("critical"), _finding("high"), _finding("medium")]
    out = filter_by_severity(findings, "critical")
    assert _severities(out) == ["critical"]


def test_filter_returns_a_new_list_not_the_input():
    findings = [_finding("high")]
    out = filter_by_severity(findings, "all")
    assert out is not findings  # caller can mutate without surprising the source


def test_filter_unknown_severity_finding_dropped_by_threshold():
    weird = _finding("bogus")
    # an unrecognised severity ranks below info -> dropped by any threshold,
    # kept only under "all"
    assert filter_by_severity([weird], "all") == [weird]
    assert filter_by_severity([weird], "info") == []


def test_filter_unknown_threshold_keeps_everything():
    # defensive: an out-of-range threshold must not silently hide all findings
    findings = [_finding("low"), _finding("info")]
    assert _severities(filter_by_severity(findings, "nonsense")) == ["low", "info"]


# ---- CLI surface ----------------------------------------------------------

def test_parser_default_min_severity_is_all():
    parser = build_parser()
    args = parser.parse_args(["--image", "x.tar"])
    assert args.min_severity == "all"


def test_parser_rejects_bad_min_severity():
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["--image", "x.tar", "--min-severity", "catastrophic"])


def test_help_lists_min_severity(capsys):
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["--help"])
    assert "--min-severity" in capsys.readouterr().out


# ---- CLI e2e: filtering against a real fixture ----------------------------
#
# rootuser-image declares USER root (high running_as_root) AND exposes 22/tcp
# (low exposed_port), so its misconfig set spans two severities — ideal for
# proving the filter both keeps and drops.

def test_e2e_min_severity_all_reports_both_severities(capsys):
    rc = main([
        "--image", fixture_path("rootuser-image.tar"),
        "--mode", "tarball",
        "--checks", "misconfig",
        "--format", "json",
    ])
    payload = json.loads(capsys.readouterr().out)
    severities = {f["severity"] for f in payload["findings"]}
    assert {"high", "low"} <= severities  # both present without filtering
    assert rc == 1


def test_e2e_min_severity_high_drops_low_findings(capsys):
    rc = main([
        "--image", fixture_path("rootuser-image.tar"),
        "--mode", "tarball",
        "--checks", "misconfig",
        "--format", "json",
        "--min-severity", "high",
    ])
    payload = json.loads(capsys.readouterr().out)
    severities = {f["severity"] for f in payload["findings"]}
    assert "high" in severities  # the root finding survives
    assert "low" not in severities  # the exposed-port finding is suppressed
    # finding_count reflects the filtered report, not the pre-filter total
    assert payload["finding_count"] == len(payload["findings"])
    assert rc == 1  # a high finding remains, so the gate still trips


def test_e2e_min_severity_critical_suppresses_all_and_gate_passes(capsys):
    # No critical misconfig exists on this image; filtering to critical empties
    # the report, and the exit-code gate (run on the filtered set) goes clean.
    rc = main([
        "--image", fixture_path("rootuser-image.tar"),
        "--mode", "tarball",
        "--checks", "misconfig",
        "--format", "json",
        "--min-severity", "critical",
    ])
    payload = json.loads(capsys.readouterr().out)
    assert payload["finding_count"] == 0
    assert payload["findings"] == []
    # gate applies to the reported (now-empty) set -> clean build
    assert rc == 0


def test_e2e_min_severity_filters_before_gate_consistency(capsys):
    # The reported set and the gated set must agree: with only a high finding
    # remaining after --min-severity high, --fail-on critical sees nothing to
    # trip on (the high is reported but below the *fail* threshold).
    rc = main([
        "--image", fixture_path("rootuser-image.tar"),
        "--mode", "tarball",
        "--checks", "misconfig",
        "--format", "json",
        "--min-severity", "high",
        "--fail-on", "critical",
    ])
    payload = json.loads(capsys.readouterr().out)
    severities = {f["severity"] for f in payload["findings"]}
    assert severities == {"high"}  # low dropped, high kept
    assert rc == 0  # no critical -> gate clean
