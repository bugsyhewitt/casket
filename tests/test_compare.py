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
    render_diff_h1md,
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


# ---- render_diff_h1md (unit) ---------------------------------------------

def test_h1md_empty_diff_has_no_section_bodies():
    diff = diff_reports(_report([]), _report([]))
    text = render_diff_h1md(diff)
    assert text.startswith("# casket scan diff")
    # Summary line present with all-zero counts.
    assert "added `0`" in text
    assert "removed `0`" in text
    assert "changed `0`" in text
    assert "unchanged `0`" in text
    # Each section degrades gracefully when empty.
    assert "## Added (0)" in text
    assert "_No new findings._" in text
    assert "## Removed (0)" in text
    assert "## Changed (0)" in text
    assert "## Unchanged (0)" in text


def test_h1md_added_cve_renders_one_liner():
    cur = _report([_cve(cve_id="CVE-NEW", package="requests",
                        version="2.19.0", severity="critical")])
    diff = diff_reports(_report([]), cur)
    text = render_diff_h1md(diff)
    assert "## Added (1)" in text
    assert "**[CRITICAL]**" in text
    assert "`CVE-NEW`" in text
    assert "`requests@2.19.0`" in text
    assert "[PyPI]" in text


def test_h1md_added_sorted_worst_severity_first():
    cur = _report([
        _cve(cve_id="CVE-LOW", severity="low"),
        _cve(cve_id="CVE-CRIT", severity="critical"),
        _cve(cve_id="CVE-MED", severity="medium"),
    ])
    text = render_diff_h1md(diff_reports(_report([]), cur))
    # Worst severity bullet must appear before the others in the Added section.
    added_section = text.split("## Added", 1)[1].split("## Removed", 1)[0]
    pos_crit = added_section.index("CVE-CRIT")
    pos_med = added_section.index("CVE-MED")
    pos_low = added_section.index("CVE-LOW")
    assert pos_crit < pos_med < pos_low


def test_h1md_removed_section_renders_findings():
    base = _report([_cve(cve_id="CVE-FIXED", package="urllib3",
                         version="1.0", severity="high")])
    diff = diff_reports(base, _report([]))
    text = render_diff_h1md(diff)
    assert "## Removed (1)" in text
    assert "`CVE-FIXED`" in text
    assert "`urllib3@1.0`" in text


def test_h1md_changed_shows_from_to_arrow():
    base = _report([_cve(cve_id="CVE-X", severity="medium")])
    cur = _report([_cve(cve_id="CVE-X", severity="critical")])
    text = render_diff_h1md(diff_reports(base, cur))
    assert "## Changed (1)" in text
    # The bullet must call out the severity movement, not just the new band.
    assert "**[MEDIUM -> CRITICAL]**" in text
    assert "`CVE-X`" in text


def test_h1md_creds_finding_renders_rule_and_path():
    diff = diff_reports(
        _report([]),
        _report([_creds(rule="aws_secret_key", path="app/.env",
                        severity="critical")]),
    )
    text = render_diff_h1md(diff)
    assert "**[CRITICAL]**" in text
    assert "`aws_secret_key`" in text
    assert "`app/.env`" in text


def test_h1md_misconfig_renders_salient_detail():
    diff = diff_reports(
        _report([]),
        _report([_misconfig(rule="exposed_port", port=22, severity="low")]),
    )
    text = render_diff_h1md(diff)
    assert "`exposed_port`" in text
    assert "port=`22`" in text


def test_h1md_unchanged_collapses_to_count_line():
    # A diff with only unchanged findings: the Markdown summary should NOT
    # spam them as bullets — only show the count.
    findings = [_cve(cve_id="CVE-A"), _cve(cve_id="CVE-B"), _cve(cve_id="CVE-C")]
    text = render_diff_h1md(diff_reports(_report(findings), _report(findings)))
    assert "## Unchanged (3)" in text
    assert "3 finding(s) carry over from the baseline unchanged" in text
    # The unchanged findings must NOT be re-listed as bullets (the diff is
    # about deltas, not the stable wall).
    unchanged_section = text.split("## Unchanged", 1)[1]
    for cve in ("CVE-A", "CVE-B", "CVE-C"):
        assert cve not in unchanged_section


def test_h1md_carries_image_refs():
    diff = diff_reports(_report([], image="base:1"), _report([], image="cur:2"))
    text = render_diff_h1md(diff)
    assert "`base:1`" in text
    assert "`cur:2`" in text


def test_h1md_mixed_buckets_summary_counts_match():
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
    text = render_diff_h1md(diff_reports(base, cur))
    assert (
        "added `1`, removed `1`, changed `1`, unchanged `1`" in text
    )
    assert "CVE-BRANDNEW" in text
    assert "CVE-FIXED" in text
    assert "CVE-RESCORED" in text


def test_h1md_handles_missing_optional_fields():
    # A degraded finding missing several keys must still render without crashing.
    diff = diff_reports(
        _report([]),
        _report([{"category": "cve", "severity": "high"}]),
    )
    text = render_diff_h1md(diff)
    assert "## Added (1)" in text
    assert "**[HIGH]**" in text


# ---- CLI surface for --diff-format ---------------------------------------

def test_parser_diff_format_default_json():
    args = build_parser().parse_args(["--image", "x.tar"])
    assert args.diff_format == "json"


def test_parser_diff_format_accepts_h1md():
    args = build_parser().parse_args(
        ["--image", "x.tar", "--compare", "b.json", "--diff-format", "h1md"]
    )
    assert args.diff_format == "h1md"


def test_parser_diff_format_rejects_unknown(capsys):
    with pytest.raises(SystemExit):
        build_parser().parse_args(
            ["--image", "x.tar", "--diff-format", "xml"]
        )
    assert "invalid choice" in capsys.readouterr().err


def test_help_lists_diff_format(capsys):
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["--help"])
    assert "--diff-format" in capsys.readouterr().out


# ---- CLI e2e: --compare + --diff-format h1md -----------------------------

def test_e2e_compare_diff_format_h1md_emits_markdown(capsys, tmp_path):
    # Empty baseline: every current finding is a regression. With --diff-format
    # h1md the output is Markdown (not JSON) and lists the new findings.
    base = tmp_path / "empty.json"
    base.write_text(
        json.dumps({"tool": "casket", "image": "x", "findings": []}),
        encoding="utf-8",
    )
    rc = main([
        "--image", fixture_path("rootuser-image.tar"),
        "--mode", "tarball",
        "--checks", "misconfig",
        "--compare", str(base),
        "--diff-format", "h1md",
    ])
    out = capsys.readouterr().out
    # h1md, not JSON — must not parse as JSON, must start with the diff header.
    assert out.startswith("# casket scan diff")
    with pytest.raises(json.JSONDecodeError):
        json.loads(out)
    assert "## Added" in out
    # Regression gate is identical across formats: new findings -> exit 1.
    assert rc == 1


def test_e2e_compare_diff_format_default_stays_json(capsys, tmp_path):
    # Backward compatibility: omitting --diff-format keeps the canonical JSON
    # diff output that existing --compare consumers depend on.
    _rc, report = _scan_json(capsys, "rootuser-image.tar")
    base = tmp_path / "baseline.json"
    base.write_text(json.dumps(report), encoding="utf-8")

    rc = main([
        "--image", fixture_path("rootuser-image.tar"),
        "--mode", "tarball",
        "--checks", "misconfig",
        "--compare", str(base),
    ])
    out = capsys.readouterr().out
    parsed = json.loads(out)  # still valid JSON
    assert parsed["diff"] is True
    assert rc == 0


def test_e2e_compare_diff_format_h1md_same_image_clean(capsys, tmp_path):
    # h1md against the same image: no regressions, exit 0, and the Markdown
    # shows the empty-Added "no new findings" line.
    _rc, report = _scan_json(capsys, "rootuser-image.tar")
    base = tmp_path / "baseline.json"
    base.write_text(json.dumps(report), encoding="utf-8")

    rc = main([
        "--image", fixture_path("rootuser-image.tar"),
        "--mode", "tarball",
        "--checks", "misconfig",
        "--compare", str(base),
        "--diff-format", "h1md",
    ])
    out = capsys.readouterr().out
    assert out.startswith("# casket scan diff")
    assert "## Added (0)" in out
    assert "_No new findings._" in out
    assert rc == 0
