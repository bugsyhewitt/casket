"""OSV client caching tests (criterion 9: cache to avoid API hammering)."""

from __future__ import annotations

import json

import httpx
import pytest

from casket.osv import OSVClient


def test_cache_hit_never_hits_network(_isolate_osv_cache, monkeypatch):
    client = OSVClient(cache_path=_isolate_osv_cache)
    client.seed("PyPI", "requests", "2.19.0", [{"id": "CVE-2018-18074"}])

    def _boom(*a, **k):
        raise AssertionError("network must not be touched on a cache hit")

    monkeypatch.setattr(httpx, "post", _boom)
    vulns = client.query("PyPI", "requests", "2.19.0")
    assert vulns == [{"id": "CVE-2018-18074"}]


def test_cache_persisted_to_disk(_isolate_osv_cache):
    client = OSVClient(cache_path=_isolate_osv_cache)
    client.seed("PyPI", "flask", "0.12.0", [{"id": "CVE-2018-1000656"}])
    on_disk = json.loads(_isolate_osv_cache.read_text())
    assert "PyPI|flask|0.12.0" in on_disk

    # A fresh client loads the persisted cache without network.
    fresh = OSVClient(cache_path=_isolate_osv_cache, offline=True)
    assert fresh.query("PyPI", "flask", "0.12.0") == [{"id": "CVE-2018-1000656"}]


def test_miss_queries_then_caches(_isolate_osv_cache, monkeypatch):
    calls = {"n": 0}

    class _Resp:
        def raise_for_status(self):
            pass

        def json(self):
            return {"vulns": [{"id": "OSV-TEST-1"}]}

    def _post(url, json=None, timeout=None):
        calls["n"] += 1
        return _Resp()

    monkeypatch.setattr(httpx, "post", _post)
    client = OSVClient(cache_path=_isolate_osv_cache)
    first = client.query("PyPI", "django", "1.0")
    assert first == [{"id": "OSV-TEST-1"}]
    assert calls["n"] == 1

    # Second query for the same tuple is served from cache: no extra call.
    second = client.query("PyPI", "django", "1.0")
    assert second == first
    assert calls["n"] == 1


def test_offline_miss_returns_empty(_isolate_osv_cache, monkeypatch):
    def _boom(*a, **k):
        raise AssertionError("offline must not hit network")

    monkeypatch.setattr(httpx, "post", _boom)
    client = OSVClient(cache_path=_isolate_osv_cache, offline=True)
    assert client.query("PyPI", "nope", "9.9.9") == []


def test_network_failure_degrades_to_empty(_isolate_osv_cache, monkeypatch):
    def _post(*a, **k):
        raise httpx.ConnectError("no route")

    monkeypatch.setattr(httpx, "post", _post)
    client = OSVClient(cache_path=_isolate_osv_cache)
    assert client.query("PyPI", "x", "1") == []


def test_query_ecosystems_prefers_first_non_empty(_isolate_osv_cache):
    client = OSVClient(cache_path=_isolate_osv_cache, offline=True)
    # Only the release-qualified ecosystem has a vuln; bare does not.
    client.seed("Alpine:v3.18", "busybox", "1.36.0-r0", [{"id": "OSV-REL"}])
    vulns = client.query_ecosystems(
        ["Alpine:v3.18", "Alpine"], "busybox", "1.36.0-r0"
    )
    assert vulns == [{"id": "OSV-REL"}]


def test_query_ecosystems_falls_back_to_bare(_isolate_osv_cache):
    client = OSVClient(cache_path=_isolate_osv_cache, offline=True)
    # Only the bare ecosystem resolves (seed-DB style); the release-qualified
    # candidate misses, so we fall through to "Alpine".
    client.seed("Alpine", "busybox", "1.36.0-r0", [{"id": "OSV-BARE"}])
    vulns = client.query_ecosystems(
        ["Alpine:v3.20", "Alpine"], "busybox", "1.36.0-r0"
    )
    assert vulns == [{"id": "OSV-BARE"}]


def test_query_ecosystems_skips_none_and_dedupes(_isolate_osv_cache, monkeypatch):
    calls = []

    def _boom(url, json=None, timeout=None):
        calls.append(json)
        raise AssertionError("offline must not hit network")

    monkeypatch.setattr(httpx, "post", _boom)
    client = OSVClient(cache_path=_isolate_osv_cache, offline=True)
    # None candidate is skipped; the duplicate "Alpine" is queried once. No
    # match anywhere -> empty list, and (offline) no network attempt.
    assert client.query_ecosystems([None, "Alpine", "Alpine"], "x", "1") == []
    assert calls == []
