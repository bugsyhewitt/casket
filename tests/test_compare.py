"""Tests for --compare diff mode.

``--compare`` diffs the current scan against a previous casket JSON report and
classifies every finding as added / removed / changed / unchanged, gating the
build's exit code on *new* findings (regressions). The pure functions in
``casket.compare`` are data-in/data-out (no network, no I/O beyond the baseline
file the CLI loads), so they're tested directly; the CLI e2e tests confirm the
wiring, the diff output, and the regression gate against real fixtures.
"""

from __future__ import annotations

import json

import pytest

from casket.cli import build_parser, main
from casket.compare import (
    diff_reports,
    finding_fingerprint,
    load_baseline_report,
    regression_count,
    render_diff_json,
)
from tests.conftest import fixture_path


def _cve(cve_id="CVE-2018-18074", package="requests", version="2.19.0",
         severity="high", layer="sha256:aaa", osv_id=None, summary="x"):
    return {
        "category": "cve",
        "title": f"{package} {version}: {cve_id}",
        "severity": severity,
        "layer_sha": layer,
        "path_in_layer": f"{package}.dist-info/METADATA",
        "cve_id": cve_id,
        "osv_id": osv_id or cve_id,
        "package": package,
        "ecosystem": "PyPI",
        "installed_version": version,
        "summary": summary,
    }


def _creds(rule="aws_secret_key", path="app/.env", severity="critical",
           layer="sha256:bbb"):
    return {
        "category": "creds",
        "title": "AWS secret key",
        "severity": severity,
        "layer_sha": layer,
        "path_in_layer": path,
        "rule": rule,
    }


def _misconfig(rule="exposed_port", port=22, severity="low",
               layer="sha256:ccc"):
    return {
        "category": "misconfig",
        "title": "exposed port",
        "severity": severity,
        "layer_sha": layer,
        "path_in_layer": "<image config>",
        "rule": rule,
        "port": port,
    }


def _report(findings, image="img:latest"):
    return {
        "tool": "casket",
        "image": image,
        "finding_count": len(findings),
        "findings": findings,
    }


# ---- finding_fingerprint --------------------------------------------------

def test_fingerprint_ignores_layer_sha():
    # A rebuild yields fresh layer digests for identical content; the
    # fingerprint must be stable across them.
    a = _cve(layer="sha256:aaa")
    b = _cve(layer="sha256:zzz")
    assert finding_fingerprint(a) == finding_fingerprint(b)


def test_fingerprint_ignores_severity_and_summary():
    a = _cve(severity="high", summary="old text")
    b = _cve(severity="critical", summary="new text")
    assert finding_fingerprint(a) == finding_fingerprint(b)


def test_fingerprint_ignores_layer_command():
    a = _cve()
    b = dict(_cve(), layer_command="RUN pip install requests")
    assert finding_fingerprint(a) == finding_fingerprint(b)


def test_fingerprint_distinguishes_cve_id():
    assert finding_fingerprint(_cve(cve_id="CVE-1")) != finding_fingerprint(
        _cve(cve_id="CVE-2")
    )


def test_fingerprint_distinguishes_package_version():
    assert finding_fingerprint(_cve(version="1.0")) != finding_fingerprint(
        _cve(version="2.0")
    )


def test_fingerprint_creds_keyed_on_rule_and_path():
    assert finding_fingerprint(_creds(path="a/.env")) != finding_fingerprint(
        _creds(path="b/.env")
    )
    assert finding_fingerprint(_creds(rule="r1")) != finding_fingerprint(
        _creds(rule="r2")
    )


def test_fingerprint_misconfig_keyed_on_rule_and_salient_value():
    assert finding_fingerprint(_misconfig(port=22)) != finding_fingerprint(
        _misconfig(port=80)
    )


def test_fingerprint_fallback_category():
    odd = {"category": "weird", "title": "T", "path_in_layer": "p"}
    # Doesn't crash, and is stable.
    assert finding_fingerprint(odd) == finding_fingerprint(dict(odd))


# ---- diff_reports ---------------------------------------------------------

def test_diff_added_finding_is_a_regression():
    base = _report([_cve(cve_id="CVE-OLD")])
    cur = _report([_cve(cve_id="CVE-OLD"), _cve(cve_id="CVE-NEW")])
    diff = diff_reports(base, cur)
    assert diff["summary"] == {"added": 1, "removed": 0, "changed": 0, "unchanged": 1}
    assert diff["added"][0]["cve_id"] == "CVE-NEW"
    assert regression_count(diff) == 1


def test_diff_removed_finding():
    base = _report([_cve(cve_id="CVE-A"), _cve(cve_id="CVE-B")])
    cur = _report([_cve(cve_id="CVE-A")])
    diff = diff_reports(base, cur)
    assert diff["summary"]["removed"] == 1
    assert diff["removed"][0]["cve_id"] == "CVE-B"
    assert regression_count(diff) == 0  # removals are not regressions


def test_diff_changed_severity_is_not_added_or_removed():
    base = _report([_cve(severity="medium")])
    cur = _report([_cve(severity="critical")])
    diff = diff_reports(base, cur)
    assert diff["summary"] == {
        "added": 0, "removed": 0, "changed": 1, "unchanged": 0,
    }
    entry = diff["changed"][0]
    assert entry["from_severity"] == "medium"
    assert entry["to_severity"] == "critical"
    assert entry["finding"]["severity"] == "critical"
    # A re-score is intentionally NOT a regression for the gate.
    assert regression_count(diff) == 0


def test_diff_unchanged_across_rebuild_layer_digests():
    # Same logical finding, different layer digest (rebuild) -> unchanged.
    base = _report([_cve(layer="sha256:old")])
    cur = _report([_cve(layer="sha256:new")])
    diff = diff_reports(base, cur)
    assert diff["summary"] == {
        "added": 0, "removed": 0, "changed": 0, "unchanged": 1,
    }


def test_diff_identical_reports_all_unchanged():
    findings = [_cve(), _creds(), _misconfig()]
    diff = diff_reports(_report(findings), _report(findings))
    assert diff["summary"] == {
        "added": 0, "removed": 0, "changed": 0, "unchanged": 3,
    }
    assert regression_count(diff) == 0


def test_diff_empty_baseline_makes_everything_added():
    cur = _report([_cve(), _creds()])
    diff = diff_reports(_report([]), cur)
    assert diff["summary"]["added"] == 2
    assert regression_count(diff) == 2


def test_diff_empty_current_makes_everything_removed():
    base = _report([_cve(), _creds()])
    diff = diff_reports(base, _report([]))
    assert diff["summary"]["removed"] == 2
    assert regression_count(diff) == 0


def test_diff_mixed_add_remove_change():
    base = _report([
        _cve(cve_id="CVE-STABLE", severity="high"),
        _cve(cve_id="CVE-FIXED"),
        _cve(cve_id="CVE-RESCORED", severity="low"),
    ])
    cur = _report([
        _cve(cve_id="CVE-STABLE", severity="high"),
        _cve(cve_id="CVE-RESCORED", severity="critical"),
        _cve(cve_id="CVE-BRANDNEW"),
    ])
    diff = diff_reports(base, cur)
    assert diff["summary"] == {
        "added": 1, "removed": 1, "changed": 1, "unchanged": 1,
    }
    assert diff["added"][0]["cve_id"] == "CVE-BRANDNEW"
    assert diff["removed"][0]["cve_id"] == "CVE-FIXED"
    assert diff["changed"][0]["finding"]["cve_id"] == "CVE-RESCORED"


def test_diff_carries_image_refs():
    diff = diff_reports(_report([], image="base:1"), _report([], image="cur:2"))
    assert diff["baseline_image"] == "base:1"
    assert diff["current_image"] == "cur:2"
    assert diff["tool"] == "casket" and diff["diff"] is True


def test_diff_missing_findings_key_degrades_gracefully():
    # A baseline object missing 'findings' (treated as empty) -> all added.
    diff = diff_reports({}, _report([_cve()]))
    assert diff["summary"]["added"] == 1


def test_render_diff_json_roundtrips():
    diff = diff_reports(_report([_cve()]), _report([_cve(), _creds()]))
    parsed = json.loads(render_diff_json(diff))
    assert parsed["summary"]["added"] == 1
    assert parsed["diff"] is True


# ---- load_baseline_report -------------------------------------------------

def test_load_baseline_report_ok(tmp_path):
    p = tmp_path / "base.json"
    p.write_text(json.dumps(_report([_cve()])), encoding="utf-8")
    data = load_baseline_report(str(p))
    assert data["findings"][0]["cve_id"] == "CVE-2018-18074"


def test_load_baseline_report_rejects_non_report(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text(json.dumps({"not": "a report"}), encoding="utf-8")
    with pytest.raises(ValueError):
        load_baseline_report(str(p))


def test_load_baseline_report_rejects_non_object(tmp_path):
    p = tmp_path / "list.json"
    p.write_text(json.dumps([1, 2, 3]), encoding="utf-8")
    with pytest.raises(ValueError):
        load_baseline_report(str(p))


# ---- CLI surface ----------------------------------------------------------

def test_parser_compare_defaults_none():
    args = build_parser().parse_args(["--image", "x.tar"])
    assert args.compare is None


def test_help_lists_compare(capsys):
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["--help"])
    assert "--compare" in capsys.readouterr().out


# ---- CLI e2e: diff against a real fixture ---------------------------------

def _scan_json(capsys, image, checks="misconfig"):
    rc = main([
        "--image", fixture_path(image),
        "--mode", "tarball",
        "--checks", checks,
        "--format", "json",
    ])
    out = capsys.readouterr().out
    return rc, json.loads(out)


def test_e2e_compare_same_image_no_regression(capsys, tmp_path):
    # Scan once, save the report, then compare a re-scan of the SAME image:
    # every finding is unchanged, so the diff gate stays clean (exit 0).
    _rc, report = _scan_json(capsys, "rootuser-image.tar")
    base = tmp_path / "baseline.json"
    base.write_text(json.dumps(report), encoding="utf-8")

    rc = main([
        "--image", fixture_path("rootuser-image.tar"),
        "--mode", "tarball",
        "--checks", "misconfig",
        "--compare", str(base),
    ])
    diff = json.loads(capsys.readouterr().out)
    assert diff["diff"] is True
    assert diff["summary"]["added"] == 0
    assert diff["summary"]["removed"] == 0
    assert diff["summary"]["unchanged"] > 0
    assert rc == 0  # no new findings -> clean build


def test_e2e_compare_empty_baseline_flags_regressions(capsys, tmp_path):
    # An empty baseline: every current finding is new -> exit 1.
    base = tmp_path / "empty.json"
    base.write_text(
        json.dumps({"tool": "casket", "image": "x", "finding_count": 0,
                    "findings": []}),
        encoding="utf-8",
    )
    rc = main([
        "--image", fixture_path("rootuser-image.tar"),
        "--mode", "tarball",
        "--checks", "misconfig",
        "--compare", str(base),
    ])
    diff = json.loads(capsys.readouterr().out)
    assert diff["summary"]["added"] > 0
    assert diff["added"]  # the new findings are listed
    assert rc == 1  # regressions -> gate trips


def test_e2e_compare_min_severity_applied_before_diff(capsys, tmp_path):
    # --min-severity high prunes the low exposed-port finding from BOTH the
    # baseline-equivalent set and the current scan, so the diff only ever sees
    # high+ findings. Comparing the high-only current scan against an empty
    # baseline flags exactly the high finding(s), not the suppressed low one.
    base = tmp_path / "empty.json"
    base.write_text(
        json.dumps({"tool": "casket", "image": "x", "findings": []}),
        encoding="utf-8",
    )
    rc = main([
        "--image", fixture_path("rootuser-image.tar"),
        "--mode", "tarball",
        "--checks", "misconfig",
        "--min-severity", "high",
        "--compare", str(base),
    ])
    diff = json.loads(capsys.readouterr().out)
    sevs = {f["severity"] for f in diff["added"]}
    assert "low" not in sevs  # suppressed before diffing
    assert "high" in sevs
    assert rc == 1


def test_e2e_compare_missing_baseline_file(capsys):
    rc = main([
        "--image", fixture_path("rootuser-image.tar"),
        "--mode", "tarball",
        "--checks", "misconfig",
        "--compare", "/no/such/baseline.json",
    ])
    assert rc == 2
    assert "baseline report not found" in capsys.readouterr().err


def test_e2e_compare_malformed_baseline_file(capsys, tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{ not json", encoding="utf-8")
    rc = main([
        "--image", fixture_path("rootuser-image.tar"),
        "--mode", "tarball",
        "--checks", "misconfig",
        "--compare", str(bad),
    ])
    assert rc == 2
    assert "failed to read baseline" in capsys.readouterr().err
