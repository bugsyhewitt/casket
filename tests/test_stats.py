"""Tests for the --stats component-count inventory summary (POST_V01).

Covers the network-free package inventory surfacing, the component_stats
aggregation, the optional scan_stats block in all three output formats, the
--stats CLI flag, and that the default (flag absent) output is unchanged.

The alpine-image fixture carries two packages (clean musl + vulnerable
busybox), so it proves the stat counts the *full inventory* (2), not just the
finding count (1) — the whole point of the feature.
"""

from __future__ import annotations

import json

import pytest

from casket.checks import cves
from casket.cli import build_parser, main
from casket.findings import Finding, render, report_dict
from casket.oci import load_tarball
from casket.osv import OSVClient
from casket.scanner import component_stats
from tests.conftest import fixture_path


# ---- package_inventory: network-free full inventory -----------------------

def test_package_inventory_returns_every_package():
    img = load_tarball(fixture_path("alpine-image.tar"))
    pkgs = cves.package_inventory(img)
    names = {p.name for p in pkgs}
    # Both the clean and the vulnerable package are inventoried.
    assert names == {"musl", "busybox"}
    assert all(p.ecosystem == "Alpine" for p in pkgs)


def test_package_inventory_empty_for_image_without_package_db():
    # leaky-image has secrets but no package manager DB.
    img = load_tarball(fixture_path("leaky-image.tar"))
    assert cves.package_inventory(img) == []


# ---- component_stats: counts + per-ecosystem + vulnerable -----------------

def test_component_stats_counts_full_inventory_not_just_findings(_isolate_osv_cache):
    img = load_tarball(fixture_path("alpine-image.tar"))
    client = OSVClient(cache_path=_isolate_osv_cache, offline=True)
    findings = cves.run(img, osv_client=client)

    stats = component_stats(img, findings)
    # Two packages inventoried, but only busybox is vulnerable.
    assert stats["total_components"] == 2
    assert stats["by_ecosystem"] == {"Alpine": 2}
    assert stats["vulnerable_components"] == 1


def test_component_stats_zero_inventory():
    img = load_tarball(fixture_path("leaky-image.tar"))
    stats = component_stats(img, [])
    assert stats["total_components"] == 0
    assert stats["by_ecosystem"] == {}
    assert stats["vulnerable_components"] == 0


def test_component_stats_dedupes_vulnerable_packages_by_identity():
    # Two CVE findings against the SAME package@version count as one vulnerable
    # component (a single package with two CVEs must not inflate the count).
    findings = [
        Finding(
            category="cve", title="t1", severity="high",
            layer_sha="sha256:x", path_in_layer="p",
            detail={"package": "requests", "ecosystem": "PyPI",
                    "installed_version": "2.19.0", "cve_id": "CVE-1"},
        ),
        Finding(
            category="cve", title="t2", severity="high",
            layer_sha="sha256:x", path_in_layer="p",
            detail={"package": "requests", "ecosystem": "PyPI",
                    "installed_version": "2.19.0", "cve_id": "CVE-2"},
        ),
    ]

    class _NoPkgImage:
        layers: list = []

    stats = component_stats(_NoPkgImage(), findings)
    assert stats["vulnerable_components"] == 1


def test_component_stats_by_ecosystem_sorted_by_count_desc():
    class _Pkg:
        def __init__(self, eco):
            self.ecosystem = eco

    class _Layer:
        def __init__(self, pkgs):
            self._pkgs = pkgs

    # Build a fake image with 3 Debian, 1 PyPI; expect Debian first.
    img = type("Img", (), {})()
    img.layers = []  # component_stats uses package_inventory, so patch that.

    # Patch package_inventory for this aggregation-shape test.
    original = cves.package_inventory
    cves.package_inventory = lambda image: [
        _Pkg("Debian"), _Pkg("Debian"), _Pkg("Debian"), _Pkg("PyPI")
    ]
    try:
        stats = component_stats(img, [])
    finally:
        cves.package_inventory = original

    assert stats["total_components"] == 4
    assert list(stats["by_ecosystem"].items()) == [("Debian", 3), ("PyPI", 1)]


# ---- severity_histogram: per-severity finding counts ----------------------

def _mk(category, severity):
    return Finding(
        category=category, title="t", severity=severity,
        layer_sha="sha256:x", path_in_layer="p", detail={},
    )


class _NoPkgImage:
    layers: list = []


def test_severity_histogram_counts_all_categories():
    # The histogram spans creds/cve/misconfig, not just CVE findings.
    findings = [
        _mk("cve", "critical"),
        _mk("creds", "high"),
        _mk("misconfig", "high"),
        _mk("misconfig", "low"),
    ]
    stats = component_stats(_NoPkgImage(), findings)
    assert stats["severity_histogram"] == {"critical": 1, "high": 2, "low": 1}


def test_severity_histogram_ordered_most_severe_first():
    findings = [_mk("cve", "info"), _mk("cve", "critical"), _mk("cve", "medium")]
    stats = component_stats(_NoPkgImage(), findings)
    assert list(stats["severity_histogram"].items()) == [
        ("critical", 1), ("medium", 1), ("info", 1)
    ]


def test_severity_histogram_omits_empty_levels_and_is_empty_when_no_findings():
    stats = component_stats(_NoPkgImage(), [])
    assert stats["severity_histogram"] == {}


def test_severity_histogram_buckets_unknown_severity_last():
    findings = [_mk("misconfig", "weird"), _mk("cve", "high")]
    stats = component_stats(_NoPkgImage(), findings)
    assert list(stats["severity_histogram"].items()) == [
        ("high", 1), ("unknown", 1)
    ]


# ---- report_dict / render: optional scan_stats block ----------------------

def test_report_dict_omits_scan_stats_by_default():
    report = report_dict([], image="img")
    assert "scan_stats" not in report


def test_report_dict_includes_scan_stats_when_supplied():
    stats = {"total_components": 5, "by_ecosystem": {"PyPI": 5},
             "vulnerable_components": 1}
    report = report_dict([], image="img", scan_stats=stats)
    assert report["scan_stats"] == stats


def test_render_json_carries_scan_stats():
    stats = {"total_components": 2, "by_ecosystem": {"Alpine": 2},
             "vulnerable_components": 1}
    out = json.loads(render([], "json", image="img", scan_stats=stats))
    assert out["scan_stats"] == stats


def test_render_json_unchanged_without_stats():
    out = json.loads(render([], "json", image="img"))
    assert "scan_stats" not in out


def test_render_h1md_has_components_section():
    stats = {"total_components": 2, "by_ecosystem": {"Alpine": 2},
             "vulnerable_components": 1}
    out = render([], "h1md", image="img", scan_stats=stats)
    assert "## Components" in out
    assert "total components:** `2`" in out
    assert "vulnerable components:** `1`" in out
    assert "Alpine:** `2`" in out


def test_render_h1md_no_components_section_without_stats():
    out = render([], "h1md", image="img")
    assert "## Components" not in out


def test_render_h1md_shows_severity_histogram():
    stats = {"total_components": 2, "by_ecosystem": {"Alpine": 2},
             "vulnerable_components": 1,
             "severity_histogram": {"critical": 1, "high": 2}}
    out = render([], "h1md", image="img", scan_stats=stats)
    assert "by severity:** critical `1`, high `2`" in out


def test_render_h1md_no_severity_line_when_histogram_empty():
    stats = {"total_components": 0, "by_ecosystem": {},
             "vulnerable_components": 0, "severity_histogram": {}}
    out = render([], "h1md", image="img", scan_stats=stats)
    assert "## Components" in out
    assert "by severity" not in out


def test_render_sarif_carries_scan_stats_as_run_property():
    stats = {"total_components": 2, "by_ecosystem": {"Alpine": 2},
             "vulnerable_components": 1}
    doc = json.loads(render([], "sarif", image="img", scan_stats=stats))
    run = doc["runs"][0]
    assert run["properties"]["scan_stats"] == stats


def test_render_sarif_no_properties_without_stats():
    doc = json.loads(render([], "sarif", image="img"))
    assert "properties" not in doc["runs"][0]


# ---- CLI --stats flag end to end ------------------------------------------

def test_help_lists_stats_flag(capsys):
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["--help"])
    out = capsys.readouterr().out
    assert "--stats" in out


def test_cli_stats_adds_scan_stats_block(capsys, _isolate_osv_cache):
    rc = main([
        "--image", fixture_path("alpine-image.tar"),
        "--mode", "tarball",
        "--checks", "cves",
        "--format", "json",
        "--offline",
        "--stats",
    ])
    assert rc == 1  # busybox vuln present
    payload = json.loads(capsys.readouterr().out)
    assert "scan_stats" in payload
    assert payload["scan_stats"]["total_components"] == 2
    assert payload["scan_stats"]["vulnerable_components"] == 1
    assert payload["scan_stats"]["by_ecosystem"] == {"Alpine": 2}
    # The busybox CVE is the only finding; histogram reflects it (over all checks).
    histogram = payload["scan_stats"]["severity_histogram"]
    assert sum(histogram.values()) == payload["finding_count"]


def test_cli_without_stats_has_no_block(capsys, _isolate_osv_cache):
    main([
        "--image", fixture_path("alpine-image.tar"),
        "--mode", "tarball",
        "--checks", "cves",
        "--format", "json",
        "--offline",
    ])
    payload = json.loads(capsys.readouterr().out)
    assert "scan_stats" not in payload


def test_cli_stats_compare_mode_ignores_block(
    capsys, tmp_path, _isolate_osv_cache
):
    # Generate a real baseline from casket itself (so its fingerprints match),
    # then re-run with --stats --compare. No new findings -> exit 0, and the
    # scan_stats key on the current report must not break the diff.
    rc = main([
        "--image", fixture_path("alpine-image.tar"),
        "--mode", "tarball",
        "--checks", "cves",
        "--format", "json",
        "--offline",
    ])
    assert rc == 1
    base_path = tmp_path / "baseline.json"
    base_path.write_text(capsys.readouterr().out, encoding="utf-8")

    rc = main([
        "--image", fixture_path("alpine-image.tar"),
        "--mode", "tarball",
        "--checks", "cves",
        "--format", "json",
        "--offline",
        "--stats",
        "--compare", str(base_path),
    ])
    # No new findings vs baseline -> exit 0; the diff ran cleanly despite stats.
    assert rc == 0
    diff = json.loads(capsys.readouterr().out)
    assert diff["summary"]["added"] == 0
    # The diff document is finding-centric; it does not carry scan_stats.
    assert "scan_stats" not in diff
