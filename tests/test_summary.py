"""Tests for the --output-json-summary dashboard / metric-aggregation output.

Covers the pure ``build_summary`` aggregation (histograms, top-N CVE preview,
scan_stats surfacing, filter-set respect), the JSON serialization, the CLI
flag end-to-end (filter / --stats / --fail-on / --compare-conflict / --help),
and that the default (flag absent) output is byte-for-byte unchanged.
"""

from __future__ import annotations

import json

import pytest

from casket.cli import build_parser, main
from casket.findings import Finding
from casket.scanner import component_stats
from casket.summary import (
    DEFAULT_TOP_CVES,
    build_summary,
    render_summary_json,
)
from tests.conftest import fixture_path


# ---- Test helpers ---------------------------------------------------------


def _mk(category, severity, **detail):
    return Finding(
        category=category,
        title=detail.pop("title", "t"),
        severity=severity,
        layer_sha=detail.pop("layer_sha", "sha256:x"),
        path_in_layer=detail.pop("path_in_layer", "p"),
        detail=detail,
    )


class _NoPkgImage:
    layers: list = []


# ---- build_summary: shape and stable top-level keys -----------------------


def test_build_summary_carries_tool_version_image_and_count():
    summary = build_summary([], image="img.tar")
    assert summary["tool"] == "casket"
    assert isinstance(summary["version"], str) and summary["version"]
    assert summary["image"] == "img.tar"
    assert summary["finding_count"] == 0


def test_build_summary_finding_count_matches_filtered_set():
    findings = [_mk("cve", "high", cve_id="CVE-1"), _mk("creds", "medium")]
    summary = build_summary(findings, image="img")
    assert summary["finding_count"] == 2


# ---- by_severity histogram ------------------------------------------------


def test_build_summary_severity_histogram_spans_all_categories():
    # A severity histogram is cross-category (creds + cve + misconfig).
    findings = [
        _mk("cve", "critical"),
        _mk("creds", "high"),
        _mk("misconfig", "high"),
        _mk("misconfig", "low"),
    ]
    summary = build_summary(findings, image="img")
    assert summary["by_severity"] == {"critical": 1, "high": 2, "low": 1}


def test_build_summary_severity_histogram_ordered_most_severe_first():
    findings = [
        _mk("cve", "info"),
        _mk("cve", "critical"),
        _mk("cve", "medium"),
    ]
    summary = build_summary(findings, image="img")
    assert list(summary["by_severity"].items()) == [
        ("critical", 1), ("medium", 1), ("info", 1),
    ]


def test_build_summary_severity_unknown_bucketed_last():
    findings = [_mk("misconfig", "weird"), _mk("cve", "high")]
    summary = build_summary(findings, image="img")
    assert list(summary["by_severity"].items()) == [
        ("high", 1), ("unknown", 1),
    ]


def test_build_summary_severity_histogram_empty_when_no_findings():
    summary = build_summary([], image="img")
    assert summary["by_severity"] == {}


# ---- by_category histogram ------------------------------------------------


def test_build_summary_category_histogram_counts_each_category():
    findings = [
        _mk("cve", "high"), _mk("cve", "low"), _mk("cve", "info"),
        _mk("creds", "high"),
        _mk("misconfig", "medium"), _mk("misconfig", "low"),
    ]
    summary = build_summary(findings, image="img")
    # Ordered by descending count then name.
    assert list(summary["by_category"].items()) == [
        ("cve", 3), ("misconfig", 2), ("creds", 1),
    ]


def test_build_summary_category_histogram_empty_when_no_findings():
    summary = build_summary([], image="img")
    assert summary["by_category"] == {}


# ---- by_ecosystem (CVE-only) histogram -----------------------------------


def test_build_summary_ecosystem_histogram_counts_only_cve_findings():
    # creds and misconfig carry no ecosystem; they must not be counted.
    findings = [
        _mk("cve", "high", ecosystem="Debian"),
        _mk("cve", "high", ecosystem="Debian"),
        _mk("cve", "low", ecosystem="PyPI"),
        _mk("creds", "high"),
        _mk("misconfig", "medium"),
    ]
    summary = build_summary(findings, image="img")
    assert list(summary["by_ecosystem"].items()) == [
        ("Debian", 2), ("PyPI", 1),
    ]


def test_build_summary_ecosystem_missing_bucketed_unknown_not_dropped():
    # A CVE with no ecosystem field must not silently disappear.
    findings = [
        _mk("cve", "high", ecosystem="PyPI"),
        _mk("cve", "high"),  # no ecosystem detail key
    ]
    summary = build_summary(findings, image="img")
    assert summary["by_ecosystem"] == {"PyPI": 1, "unknown": 1}


def test_build_summary_ecosystem_empty_when_no_cve_findings():
    findings = [_mk("creds", "high"), _mk("misconfig", "medium")]
    summary = build_summary(findings, image="img")
    assert summary["by_ecosystem"] == {}


# ---- scan_stats surfacing -------------------------------------------------


def test_build_summary_omits_inventory_keys_when_scan_stats_absent():
    # Absence is distinguishable from "no packages": the operator did not pass
    # --stats, so we omit the inventory keys entirely rather than report 0.
    summary = build_summary([], image="img")
    assert "total_components" not in summary
    assert "vulnerable_components" not in summary
    assert "components_by_ecosystem" not in summary


def test_build_summary_surfaces_inventory_counts_when_scan_stats_supplied():
    stats = {
        "total_components": 42,
        "by_ecosystem": {"Debian": 40, "PyPI": 2},
        "vulnerable_components": 3,
        "severity_histogram": {"critical": 1, "high": 2},
    }
    summary = build_summary([], image="img", scan_stats=stats)
    assert summary["total_components"] == 42
    assert summary["vulnerable_components"] == 3
    assert summary["components_by_ecosystem"] == {"Debian": 40, "PyPI": 2}


def test_build_summary_partial_scan_stats_does_not_crash():
    # A future-extended or partial scan_stats block must not raise; missing
    # keys simply drop from the summary.
    summary = build_summary(
        [], image="img", scan_stats={"total_components": 5}
    )
    assert summary["total_components"] == 5
    assert "vulnerable_components" not in summary
    assert "components_by_ecosystem" not in summary


# ---- top_cves preview -----------------------------------------------------


def test_top_cves_only_cve_findings_no_creds_or_misconfig():
    findings = [
        _mk("creds", "critical", title="AWS key"),
        _mk("misconfig", "critical", title="Docker API exposed"),
        _mk("cve", "high", cve_id="CVE-2024-1"),
    ]
    summary = build_summary(findings, image="img")
    assert [c["cve_id"] for c in summary["top_cves"]] == ["CVE-2024-1"]


def test_top_cves_ordered_by_severity_then_epss_desc():
    findings = [
        _mk("cve", "low", cve_id="CVE-low"),
        _mk("cve", "high", cve_id="CVE-high-lo", epss_score=0.10),
        _mk("cve", "high", cve_id="CVE-high-hi", epss_score=0.95),
        _mk("cve", "critical", cve_id="CVE-crit"),
    ]
    summary = build_summary(findings, image="img")
    assert [c["cve_id"] for c in summary["top_cves"]] == [
        "CVE-crit", "CVE-high-hi", "CVE-high-lo", "CVE-low",
    ]


def test_top_cves_capped_at_top_n():
    findings = [
        _mk("cve", "high", cve_id=f"CVE-{i:04d}", epss_score=0.5)
        for i in range(50)
    ]
    summary = build_summary(findings, image="img", top_n=5)
    assert len(summary["top_cves"]) == 5


def test_top_cves_default_n_is_ten():
    findings = [
        _mk("cve", "high", cve_id=f"CVE-{i:04d}") for i in range(25)
    ]
    summary = build_summary(findings, image="img")
    assert len(summary["top_cves"]) == DEFAULT_TOP_CVES == 10


def test_top_cves_top_n_zero_omits_list():
    findings = [_mk("cve", "high", cve_id="CVE-1")]
    summary = build_summary(findings, image="img", top_n=0)
    assert "top_cves" not in summary


def test_top_cves_entry_carries_compact_dashboard_fields():
    finding = _mk(
        "cve", "high",
        cve_id="CVE-2024-9999",
        package="openssl",
        installed_version="3.0.7-1",
        ecosystem="Debian",
        epss_score=0.42,
        cvss_score=9.8,
        # Below-list noise that should NOT leak into the preview:
        layer_command="RUN apt-get install openssl",
        fix_urls=["https://x"],
    )
    summary = build_summary([finding], image="img")
    entry = summary["top_cves"][0]
    assert entry == {
        "severity": "high",
        "cve_id": "CVE-2024-9999",
        "package": "openssl",
        "installed_version": "3.0.7-1",
        "ecosystem": "Debian",
        "epss_score": 0.42,
        "cvss_score": 9.8,
    }
    # Per-finding "detail" blob and layer attribution must NOT leak in.
    assert "layer_command" not in entry
    assert "fix_urls" not in entry
    assert "layer_sha" not in entry


def test_top_cves_omits_missing_optional_fields():
    # A finding with no package/version/ecosystem/EPSS/CVSS must produce an
    # entry without those keys (rather than empty strings a dashboard would
    # mistake for a value).
    finding = _mk("cve", "medium", cve_id="CVE-X")
    summary = build_summary([finding], image="img")
    assert summary["top_cves"][0] == {
        "severity": "medium",
        "cve_id": "CVE-X",
    }


def test_top_cves_finding_without_epss_sorts_after_one_with_epss_same_severity():
    # No-EPSS treated as EPSS=0.0, so the with-EPSS finding sorts first.
    findings = [
        _mk("cve", "high", cve_id="CVE-no-epss"),
        _mk("cve", "high", cve_id="CVE-with-epss", epss_score=0.30),
    ]
    summary = build_summary(findings, image="img")
    assert [c["cve_id"] for c in summary["top_cves"]] == [
        "CVE-with-epss", "CVE-no-epss",
    ]


# ---- render_summary_json: serialization is valid JSON ----------------------


def test_render_summary_json_round_trips_through_json_load():
    summary = build_summary(
        [_mk("cve", "high", cve_id="CVE-1", ecosystem="PyPI")],
        image="img",
    )
    out = render_summary_json(summary)
    assert json.loads(out) == summary


def test_render_summary_json_is_indented_for_ci_log_readability():
    summary = build_summary([], image="img")
    out = render_summary_json(summary)
    # Indented (newlines + leading whitespace), not a single-line blob.
    assert "\n" in out
    assert '  "tool"' in out


# ---- CLI: parser surface --------------------------------------------------


def test_help_lists_output_json_summary_flag(capsys):
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["--help"])
    out = capsys.readouterr().out
    assert "--output-json-summary" in out


def test_parser_output_json_summary_defaults_off():
    parser = build_parser()
    args = parser.parse_args(["--image", "x"])
    assert args.output_json_summary is False


def test_parser_output_json_summary_sets_when_passed():
    parser = build_parser()
    args = parser.parse_args(["--image", "x", "--output-json-summary"])
    assert args.output_json_summary is True


# ---- CLI: --compare conflict -----------------------------------------------


def test_cli_output_json_summary_with_compare_errors_clean(capsys, tmp_path):
    # Mutually exclusive output modes; surface the conflict with exit 2.
    baseline = tmp_path / "baseline.json"
    baseline.write_text(
        json.dumps({"tool": "casket", "image": "x", "findings": []}),
        encoding="utf-8",
    )
    rc = main([
        "--image", fixture_path("alpine-image.tar"),
        "--mode", "tarball",
        "--checks", "cves",
        "--offline",
        "--output-json-summary",
        "--compare", str(baseline),
    ])
    assert rc == 2
    err = capsys.readouterr().err
    assert "mutually exclusive" in err


# ---- CLI: end-to-end against a real fixture --------------------------------


def test_cli_output_json_summary_emits_compact_object(capsys, _isolate_osv_cache):
    rc = main([
        "--image", fixture_path("alpine-image.tar"),
        "--mode", "tarball",
        "--checks", "cves",
        "--offline",
        "--output-json-summary",
    ])
    # busybox CVE present -> gate trips like the full report does.
    assert rc == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["tool"] == "casket"
    assert payload["image"] == fixture_path("alpine-image.tar")
    assert payload["finding_count"] >= 1
    # by_severity sums to finding_count (no double-counting, nothing dropped).
    assert sum(payload["by_severity"].values()) == payload["finding_count"]
    # No full findings list — that's the whole point.
    assert "findings" not in payload
    # by_ecosystem covers the CVE finding's Alpine ecosystem.
    assert "Alpine" in payload["by_ecosystem"]
    # top_cves preview is present and bounded.
    assert isinstance(payload["top_cves"], list)
    assert len(payload["top_cves"]) <= DEFAULT_TOP_CVES


def test_cli_output_json_summary_with_stats_includes_inventory(
    capsys, _isolate_osv_cache
):
    rc = main([
        "--image", fixture_path("alpine-image.tar"),
        "--mode", "tarball",
        "--checks", "cves",
        "--offline",
        "--stats",
        "--output-json-summary",
    ])
    assert rc == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["total_components"] == 2
    assert payload["vulnerable_components"] == 1
    assert payload["components_by_ecosystem"] == {"Alpine": 2}


def test_cli_output_json_summary_honors_min_severity(capsys, _isolate_osv_cache):
    # --min-severity critical drops the high-or-below busybox CVE; the summary
    # must reflect the filtered set, and the --fail-on default ('any') must
    # therefore NOT trip the gate.
    rc = main([
        "--image", fixture_path("alpine-image.tar"),
        "--mode", "tarball",
        "--checks", "cves",
        "--offline",
        "--min-severity", "critical",
        "--output-json-summary",
    ])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["finding_count"] == 0
    assert payload["by_severity"] == {}
    assert payload["top_cves"] == []


def test_cli_output_json_summary_respects_fail_on_none(capsys, _isolate_osv_cache):
    # --fail-on none should clean-exit even with a real finding; the summary
    # mode must use the same gate as the full report.
    rc = main([
        "--image", fixture_path("alpine-image.tar"),
        "--mode", "tarball",
        "--checks", "cves",
        "--offline",
        "--fail-on", "none",
        "--output-json-summary",
    ])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    # The finding still appears in the summary; only the gate suppresses exit.
    assert payload["finding_count"] >= 1


def test_cli_without_flag_emits_full_findings_report(capsys, _isolate_osv_cache):
    # Default output (no --output-json-summary) must be the unchanged full
    # findings report — byte-shape compatibility for existing pipelines.
    main([
        "--image", fixture_path("alpine-image.tar"),
        "--mode", "tarball",
        "--checks", "cves",
        "--format", "json",
        "--offline",
    ])
    payload = json.loads(capsys.readouterr().out)
    # The full report carries a `findings` array and no by_severity histogram.
    assert "findings" in payload
    assert "by_severity" not in payload
    assert "top_cves" not in payload
