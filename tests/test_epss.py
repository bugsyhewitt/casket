"""Tests for EPSS (Exploit Prediction Scoring System) enrichment & filtering.

casket enriches every CVE finding with its EPSS score — the FIRST.org model's
probability that the vuln will be exploited in the wild over the next 30 days —
and exposes a ``--min-epss`` report filter that keeps only findings at or above
a probability threshold. CVSS says how *bad* a vuln is; EPSS says how *likely*
it is to be exploited, which is the sharper triage signal on a busy image.

The EPSS client mirrors the OSV client's cache-first, offline-safe contract:
cache hits never touch the network, a batched GET resolves all misses in one
request, and an offline/failed lookup degrades to "no score" (the field is
simply omitted) rather than crashing. The ``epss_score`` / ``epss_percentile``
fields flow through json / h1md / sarif output for free, and are omitted
entirely for CVEs with no published score, so existing tests stay unaffected.
"""

from __future__ import annotations

import json

import httpx
import pytest

from casket.checks import cves
from casket import findings as findings_mod
from casket.cli import _epss_threshold, build_parser, main
from casket.epss import EPSSClient, _coerce_score
from casket.findings import Finding
from casket.oci import load_tarball
from casket.osv import OSVClient
from casket.scanner import enrich_with_epss, filter_by_epss, run_checks
from tests.conftest import fixture_path


# --- EPSSClient: cache-first, offline-safe -------------------------------


def test_cache_hit_never_hits_network(_isolate_epss_cache, monkeypatch):
    client = EPSSClient(cache_path=_isolate_epss_cache)
    client.seed("CVE-2018-18074", {"score": 0.42, "percentile": 0.9})

    def _boom(*a, **k):
        raise AssertionError("network must not be touched on a cache hit")

    monkeypatch.setattr(httpx, "get", _boom)
    scores = client.scores_for(["CVE-2018-18074"])
    assert scores == {"CVE-2018-18074": {"score": 0.42, "percentile": 0.9}}


def test_cache_persisted_to_disk(_isolate_epss_cache):
    client = EPSSClient(cache_path=_isolate_epss_cache)
    client.seed("CVE-2021-0001", {"score": 0.1})
    on_disk = json.loads(_isolate_epss_cache.read_text())
    assert "CVE-2021-0001" in on_disk

    fresh = EPSSClient(cache_path=_isolate_epss_cache, offline=True)
    assert fresh.scores_for(["CVE-2021-0001"]) == {"CVE-2021-0001": {"score": 0.1}}


def test_batched_get_for_all_misses(_isolate_epss_cache, monkeypatch):
    calls = {"n": 0}

    class _Resp:
        def raise_for_status(self):
            pass

        def json(self):
            return {
                "data": [
                    {"cve": "CVE-A", "epss": "0.5", "percentile": "0.97"},
                    {"cve": "CVE-B", "epss": "0.01", "percentile": "0.30"},
                ]
            }

    def _get(url, params=None, timeout=None):
        calls["n"] += 1
        assert url.endswith("/epss")
        # Both misses ride in ONE comma-separated cve= query.
        assert params["cve"] == "CVE-A,CVE-B"
        return _Resp()

    monkeypatch.setattr(httpx, "get", _get)
    client = EPSSClient(cache_path=_isolate_epss_cache)
    scores = client.scores_for(["CVE-A", "CVE-B"])
    assert calls["n"] == 1
    assert scores["CVE-A"] == {"score": 0.5, "percentile": 0.97}
    assert scores["CVE-B"] == {"score": 0.01, "percentile": 0.3}


def test_miss_then_served_from_cache(_isolate_epss_cache, monkeypatch):
    calls = {"n": 0}

    class _Resp:
        def raise_for_status(self):
            pass

        def json(self):
            return {"data": [{"cve": "CVE-X", "epss": "0.2", "percentile": "0.5"}]}

    def _get(url, params=None, timeout=None):
        calls["n"] += 1
        return _Resp()

    monkeypatch.setattr(httpx, "get", _get)
    client = EPSSClient(cache_path=_isolate_epss_cache)
    first = client.scores_for(["CVE-X"])
    assert first["CVE-X"]["score"] == 0.2
    assert calls["n"] == 1

    second = client.scores_for(["CVE-X"])
    assert second == first
    assert calls["n"] == 1  # cache hit, no extra call


def test_unscored_cve_is_cached_as_none_and_not_requeried(
    _isolate_epss_cache, monkeypatch
):
    calls = {"n": 0}

    class _Resp:
        def raise_for_status(self):
            pass

        def json(self):
            # The model has no row for this CVE (reserved / too fresh).
            return {"data": []}

    def _get(url, params=None, timeout=None):
        calls["n"] += 1
        return _Resp()

    monkeypatch.setattr(httpx, "get", _get)
    client = EPSSClient(cache_path=_isolate_epss_cache)
    assert client.scores_for(["CVE-UNSCORED"]) == {}
    assert calls["n"] == 1

    # The "no score" is cached as None, so the next run doesn't re-query.
    def _boom(*a, **k):
        raise AssertionError("a cached 'no score' must not re-query")

    monkeypatch.setattr(httpx, "get", _boom)
    assert client.scores_for(["CVE-UNSCORED"]) == {}


def test_offline_miss_returns_empty(_isolate_epss_cache, monkeypatch):
    def _boom(*a, **k):
        raise AssertionError("offline must not hit network")

    monkeypatch.setattr(httpx, "get", _boom)
    client = EPSSClient(cache_path=_isolate_epss_cache, offline=True)
    assert client.scores_for(["CVE-NOPE"]) == {}


def test_network_failure_degrades_to_empty_and_not_cached(
    _isolate_epss_cache, monkeypatch
):
    def _get(*a, **k):
        raise httpx.ConnectError("no route")

    monkeypatch.setattr(httpx, "get", _get)
    client = EPSSClient(cache_path=_isolate_epss_cache)
    assert client.scores_for(["CVE-FAIL"]) == {}
    # The failed lookup is NOT cached, so a later online run retries. The cache
    # file may not even exist yet (nothing was persisted) — either way, the
    # failed id must be absent.
    raw = _isolate_epss_cache.read_text() if _isolate_epss_cache.exists() else "{}"
    assert "CVE-FAIL" not in json.loads(raw or "{}")


def test_scores_for_dedupes_and_skips_blanks(_isolate_epss_cache, monkeypatch):
    seen = {}

    class _Resp:
        def raise_for_status(self):
            pass

        def json(self):
            return {"data": [{"cve": "CVE-D", "epss": "0.3"}]}

    def _get(url, params=None, timeout=None):
        seen["cve"] = params["cve"]
        return _Resp()

    monkeypatch.setattr(httpx, "get", _get)
    client = EPSSClient(cache_path=_isolate_epss_cache)
    client.scores_for(["CVE-D", "CVE-D", "", None])  # type: ignore[list-item]
    # The duplicate is queried once; blanks/None are dropped.
    assert seen["cve"] == "CVE-D"


def test_no_ids_no_network(_isolate_epss_cache, monkeypatch):
    def _boom(*a, **k):
        raise AssertionError("no ids must not hit network")

    monkeypatch.setattr(httpx, "get", _boom)
    client = EPSSClient(cache_path=_isolate_epss_cache)
    assert client.scores_for([]) == {}


# --- _coerce_score (pure helper) -----------------------------------------


def test_coerce_score_parses_string_fields():
    assert _coerce_score({"epss": "0.125", "percentile": "0.88"}) == {
        "score": 0.125,
        "percentile": 0.88,
    }


def test_coerce_score_score_only():
    assert _coerce_score({"epss": "0.5"}) == {"score": 0.5}


def test_coerce_score_bad_percentile_dropped_not_fatal():
    assert _coerce_score({"epss": "0.5", "percentile": "x"}) == {"score": 0.5}


def test_coerce_score_missing_or_bad_epss_is_none():
    assert _coerce_score({}) is None
    assert _coerce_score({"epss": "not-a-number"}) is None
    assert _coerce_score("nope") is None


# --- enrich_with_epss (scanner post-processing) --------------------------


def _cve_finding(cve_id, sev="high"):
    return Finding(
        category="cve",
        title=f"pkg 1.0: {cve_id}",
        severity=sev,
        layer_sha="sha256:deadbeef",
        path_in_layer="x",
        detail={"cve_id": cve_id, "package": "pkg", "installed_version": "1.0"},
    )


def test_enrich_attaches_score_and_percentile(_isolate_epss_cache):
    client = EPSSClient(cache_path=_isolate_epss_cache, offline=True)
    client.seed("CVE-2018-18074", {"score": 0.7, "percentile": 0.99})
    findings = [_cve_finding("CVE-2018-18074")]
    enrich_with_epss(findings, client)
    assert findings[0].detail["epss_score"] == 0.7
    assert findings[0].detail["epss_percentile"] == 0.99


def test_enrich_omits_keys_for_unscored_cve(_isolate_epss_cache):
    client = EPSSClient(cache_path=_isolate_epss_cache, offline=True)
    findings = [_cve_finding("CVE-NO-SCORE")]
    enrich_with_epss(findings, client)
    assert "epss_score" not in findings[0].detail
    assert "epss_percentile" not in findings[0].detail


def test_enrich_skips_non_cve_findings(_isolate_epss_cache):
    client = EPSSClient(cache_path=_isolate_epss_cache, offline=True)
    creds = Finding(
        category="creds", title="key", severity="critical",
        layer_sha="sha256:a", path_in_layer="x", detail={"rule": "aws"},
    )
    enrich_with_epss([creds], client)
    assert "epss_score" not in creds.detail


def test_enrich_ignores_ghsa_only_ids(_isolate_epss_cache, monkeypatch):
    # A finding whose headline id is a GHSA (no CVE alias) is not EPSS-keyable;
    # we must not even attempt a lookup for it.
    client = EPSSClient(cache_path=_isolate_epss_cache)

    def _boom(*a, **k):
        raise AssertionError("a non-CVE id must not trigger a lookup")

    monkeypatch.setattr(httpx, "get", _boom)
    f = _cve_finding("GHSA-x84v-xcm2-53pg")
    enrich_with_epss([f], client)
    assert "epss_score" not in f.detail


# --- filter_by_epss ------------------------------------------------------


def test_filter_none_is_noop():
    fs = [_cve_finding("CVE-1")]
    assert filter_by_epss(fs, None) == fs


def test_filter_keeps_at_or_above_threshold():
    low = _cve_finding("CVE-LOW")
    low.detail["epss_score"] = 0.1
    high = _cve_finding("CVE-HIGH")
    high.detail["epss_score"] = 0.6
    kept = filter_by_epss([low, high], 0.5)
    assert kept == [high]


def test_filter_boundary_is_inclusive():
    f = _cve_finding("CVE-EQ")
    f.detail["epss_score"] = 0.5
    assert filter_by_epss([f], 0.5) == [f]


def test_filter_drops_cve_without_score():
    f = _cve_finding("CVE-NOSCORE")  # no epss_score in detail
    assert filter_by_epss([f], 0.1) == []


def test_filter_always_keeps_non_cve_findings():
    creds = Finding(
        category="creds", title="key", severity="critical",
        layer_sha="sha256:a", path_in_layer="x", detail={"rule": "aws"},
    )
    misc = Finding(
        category="misconfig", title="root", severity="high",
        layer_sha="sha256:b", path_in_layer="<image config>",
        detail={"rule": "running_as_root"},
    )
    # Even a very high threshold never prunes creds/misconfig.
    assert filter_by_epss([creds, misc], 0.99) == [creds, misc]


# --- _epss_threshold (CLI argparse type) ---------------------------------


def test_threshold_accepts_valid_probability():
    assert _epss_threshold("0.0") == 0.0
    assert _epss_threshold("0.5") == 0.5
    assert _epss_threshold("1.0") == 1.0


def test_threshold_rejects_out_of_range():
    import argparse

    with pytest.raises(argparse.ArgumentTypeError):
        _epss_threshold("1.5")
    with pytest.raises(argparse.ArgumentTypeError):
        _epss_threshold("-0.1")


def test_threshold_rejects_non_number():
    import argparse

    with pytest.raises(argparse.ArgumentTypeError):
        _epss_threshold("high")


def test_parser_rejects_bad_min_epss(capsys):
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["--image", "x.tar", "--min-epss", "2.0"])


# --- output-format surfacing ---------------------------------------------


def _seed_osv(client):
    client.seed(
        "PyPI", "requests", "2.19.0",
        [{"id": "GHSA-x", "aliases": ["CVE-2018-18074"], "summary": "leak",
          "database_specific": {"severity": "MEDIUM"}}],
    )


def test_epss_score_flows_to_all_output_formats(
    _isolate_osv_cache, _isolate_epss_cache
):
    img = load_tarball(fixture_path("old-package.tar"))
    osv = OSVClient(cache_path=_isolate_osv_cache, offline=True)
    _seed_osv(osv)
    epss = EPSSClient(cache_path=_isolate_epss_cache, offline=True)
    epss.seed("CVE-2018-18074", {"score": 0.66, "percentile": 0.98})

    findings = run_checks(img, ["cves"], osv_client=osv, epss_client=epss)
    assert findings and findings[0].detail["epss_score"] == 0.66

    doc = json.loads(findings_mod.render(findings, "json", image="i:l"))
    assert doc["findings"][0]["epss_score"] == 0.66
    assert doc["findings"][0]["epss_percentile"] == 0.98

    sarif = json.loads(findings_mod.render(findings, "sarif", image="i:l"))
    assert sarif["runs"][0]["results"][0]["properties"]["epss_score"] == 0.66

    md = findings_mod.render(findings, "h1md", image="i:l")
    assert "epss_score" in md and "0.66" in md


# --- end-to-end through the CLI ------------------------------------------


def test_cli_enriches_cve_with_epss(capsys, _isolate_osv_cache, _isolate_epss_cache):
    OSVClient(cache_path=_isolate_osv_cache).seed(
        "PyPI", "requests", "2.19.0",
        [{"id": "GHSA-x", "aliases": ["CVE-2018-18074"], "summary": "leak",
          "database_specific": {"severity": "MEDIUM"}}],
    )
    EPSSClient(cache_path=_isolate_epss_cache).seed(
        "CVE-2018-18074", {"score": 0.33, "percentile": 0.91}
    )
    rc = main([
        "--image", fixture_path("old-package.tar"),
        "--mode", "tarball", "--checks", "cves",
        "--format", "json", "--offline",
    ])
    assert rc == 1
    payload = json.loads(capsys.readouterr().out)
    cve = next(f for f in payload["findings"] if f["category"] == "cve")
    assert cve["epss_score"] == 0.33
    assert cve["epss_percentile"] == 0.91


def test_cli_min_epss_prunes_below_threshold(
    capsys, _isolate_osv_cache, _isolate_epss_cache
):
    OSVClient(cache_path=_isolate_osv_cache).seed(
        "PyPI", "requests", "2.19.0",
        [{"id": "GHSA-x", "aliases": ["CVE-2018-18074"], "summary": "leak",
          "database_specific": {"severity": "MEDIUM"}}],
    )
    # The single CVE scores 0.05 — below a 0.5 floor, so it is pruned and the
    # report is empty -> clean exit 0.
    EPSSClient(cache_path=_isolate_epss_cache).seed(
        "CVE-2018-18074", {"score": 0.05, "percentile": 0.4}
    )
    rc = main([
        "--image", fixture_path("old-package.tar"),
        "--mode", "tarball", "--checks", "cves",
        "--format", "json", "--offline", "--min-epss", "0.5",
    ])
    payload = json.loads(capsys.readouterr().out)
    assert payload["finding_count"] == 0
    assert rc == 0


def test_cli_min_epss_keeps_above_threshold(
    capsys, _isolate_osv_cache, _isolate_epss_cache
):
    OSVClient(cache_path=_isolate_osv_cache).seed(
        "PyPI", "requests", "2.19.0",
        [{"id": "GHSA-x", "aliases": ["CVE-2018-18074"], "summary": "leak",
          "database_specific": {"severity": "MEDIUM"}}],
    )
    EPSSClient(cache_path=_isolate_epss_cache).seed(
        "CVE-2018-18074", {"score": 0.8, "percentile": 0.99}
    )
    rc = main([
        "--image", fixture_path("old-package.tar"),
        "--mode", "tarball", "--checks", "cves",
        "--format", "json", "--offline", "--min-epss", "0.5",
    ])
    assert rc == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["finding_count"] == 1
    assert payload["findings"][0]["epss_score"] == 0.8


def test_help_lists_min_epss(capsys):
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["--help"])
    assert "--min-epss" in capsys.readouterr().out
