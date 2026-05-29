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


# --- query_batch (Rotation 17, POST_V01 candidate: bulk CVE batching) -------


def test_query_batch_serves_cache_and_seed_without_network(
    _isolate_osv_cache, monkeypatch
):
    def _boom(*a, **k):
        raise AssertionError("fully cached/seeded batch must not hit network")

    monkeypatch.setattr(httpx, "post", _boom)
    monkeypatch.setattr(httpx, "get", _boom)
    client = OSVClient(cache_path=_isolate_osv_cache)
    client.seed("PyPI", "requests", "2.19.0", [{"id": "CVE-2018-18074"}])
    client.seed("PyPI", "flask", "0.12.0", [{"id": "CVE-2018-1000656"}])

    # Both tuples resolve from cache — no network attempt at all (the mocked
    # post/get would explode), proving query_batch is cache-first.
    results = client.query_batch(
        [
            (["PyPI"], "requests", "2.19.0"),
            (["PyPI"], "flask", "0.12.0"),
        ]
    )
    assert results[0] == [{"id": "CVE-2018-18074"}]
    assert results[1] == [{"id": "CVE-2018-1000656"}]


def test_query_batch_single_request_for_all_misses(_isolate_osv_cache, monkeypatch):
    post_calls = {"n": 0}
    get_calls = []

    class _BatchResp:
        def raise_for_status(self):
            pass

        def json(self):
            # Aligned to the order of queries sent: django vuln, pillow none.
            return {
                "results": [
                    {"vulns": [{"id": "OSV-DJANGO-1", "modified": "x"}]},
                    {"vulns": []},
                ]
            }

    def _post(url, json=None, timeout=None):
        post_calls["n"] += 1
        assert url.endswith("/v1/querybatch")
        assert len(json["queries"]) == 2
        return _BatchResp()

    class _VulnResp:
        def __init__(self, vid):
            self._vid = vid

        def raise_for_status(self):
            pass

        def json(self):
            return {"id": self._vid, "summary": "hydrated", "severity": []}

    def _get(url, timeout=None):
        get_calls.append(url)
        vid = url.rsplit("/", 1)[-1]
        return _VulnResp(vid)

    monkeypatch.setattr(httpx, "post", _post)
    monkeypatch.setattr(httpx, "get", _get)

    client = OSVClient(cache_path=_isolate_osv_cache)
    results = client.query_batch(
        [
            (["PyPI"], "django", "1.0"),
            (["PyPI"], "pillow", "5.0"),
        ]
    )
    # Exactly one batched POST for both misses.
    assert post_calls["n"] == 1
    # Only the one vulnerable package was hydrated.
    assert get_calls == ["https://api.osv.dev/v1/vulns/OSV-DJANGO-1"]
    assert results[0] == [{"id": "OSV-DJANGO-1", "summary": "hydrated", "severity": []}]
    assert results[1] == []


def test_query_batch_caches_results_per_tuple(_isolate_osv_cache, monkeypatch):
    class _BatchResp:
        def raise_for_status(self):
            pass

        def json(self):
            return {"results": [{"vulns": [{"id": "OSV-A"}]}]}

    class _VulnResp:
        def raise_for_status(self):
            pass

        def json(self):
            return {"id": "OSV-A", "summary": "full"}

    monkeypatch.setattr(httpx, "post", lambda *a, **k: _BatchResp())
    monkeypatch.setattr(httpx, "get", lambda *a, **k: _VulnResp())

    client = OSVClient(cache_path=_isolate_osv_cache)
    client.query_batch([(["PyPI"], "lodash", "4.0")])

    # The full record is persisted under the per-tuple key, so a later plain
    # query() is served from cache with no further network.
    def _boom(*a, **k):
        raise AssertionError("cached tuple must not re-query")

    monkeypatch.setattr(httpx, "post", _boom)
    monkeypatch.setattr(httpx, "get", _boom)
    assert client.query("PyPI", "lodash", "4.0") == [{"id": "OSV-A", "summary": "full"}]


def test_query_batch_offline_misses_return_empty(_isolate_osv_cache, monkeypatch):
    def _boom(*a, **k):
        raise AssertionError("offline batch must not hit network")

    monkeypatch.setattr(httpx, "post", _boom)
    monkeypatch.setattr(httpx, "get", _boom)
    client = OSVClient(cache_path=_isolate_osv_cache, offline=True)
    client.seed("PyPI", "seeded", "1.0", [{"id": "SEED-1"}])

    results = client.query_batch(
        [
            (["PyPI"], "seeded", "1.0"),  # seed hit
            (["PyPI"], "unknown", "9.9"),  # offline miss
        ]
    )
    assert results[0] == [{"id": "SEED-1"}]
    assert results[1] == []


def test_query_batch_network_failure_degrades_to_empty(_isolate_osv_cache, monkeypatch):
    def _post(*a, **k):
        raise httpx.ConnectError("no route")

    monkeypatch.setattr(httpx, "post", _post)
    client = OSVClient(cache_path=_isolate_osv_cache)
    client.seed("PyPI", "ok", "1.0", [{"id": "S"}])

    results = client.query_batch(
        [
            (["PyPI"], "ok", "1.0"),  # cache/seed hit survives the failed batch
            (["PyPI"], "miss", "1.0"),
        ]
    )
    assert results[0] == [{"id": "S"}]
    assert results[1] == []  # batch failed -> uncached empty (retryable later)
    # The failed tuple was NOT cached, so a later run can retry.
    assert "PyPI|miss|1.0" not in json.loads(_isolate_osv_cache.read_text() or "{}")


def test_query_batch_prefers_release_qualified_candidate(_isolate_osv_cache):
    client = OSVClient(cache_path=_isolate_osv_cache, offline=True)
    # Release-qualified ecosystem is seeded; bare is not. The first candidate
    # wins, mirroring query_ecosystems.
    client.seed("Alpine:v3.18", "busybox", "1.36.0-r0", [{"id": "REL"}])
    results = client.query_batch(
        [(["Alpine:v3.18", "Alpine"], "busybox", "1.36.0-r0")]
    )
    assert results[0] == [{"id": "REL"}]


def test_query_batch_falls_back_to_bare_candidate(_isolate_osv_cache):
    client = OSVClient(cache_path=_isolate_osv_cache, offline=True)
    # Only the bare ecosystem resolves (seed-DB style); the release-qualified
    # candidate misses, so the bare candidate is served.
    client.seed("Debian", "openssl", "3.0.0", [{"id": "BARE"}])
    results = client.query_batch(
        [(["Debian:12", "Debian"], "openssl", "3.0.0")]
    )
    assert results[0] == [{"id": "BARE"}]


def test_query_batch_dedupes_identical_misses_into_one_query(
    _isolate_osv_cache, monkeypatch
):
    seen_queries = {}

    class _BatchResp:
        def __init__(self, n):
            self._n = n

        def raise_for_status(self):
            pass

        def json(self):
            return {"results": [{"vulns": []} for _ in range(self._n)]}

    def _post(url, json=None, timeout=None):
        seen_queries["count"] = len(json["queries"])
        return _BatchResp(len(json["queries"]))

    monkeypatch.setattr(httpx, "post", _post)
    client = OSVClient(cache_path=_isolate_osv_cache)
    # Two jobs for the SAME (ecosystem, package, version) -> one batched query.
    results = client.query_batch(
        [
            (["PyPI"], "same", "1.0"),
            (["PyPI"], "same", "1.0"),
        ]
    )
    assert seen_queries["count"] == 1
    assert results == [[], []]


def test_query_batch_keeps_stub_when_hydration_fails(_isolate_osv_cache, monkeypatch):
    class _BatchResp:
        def raise_for_status(self):
            pass

        def json(self):
            return {"results": [{"vulns": [{"id": "OSV-STUB", "modified": "t"}]}]}

    monkeypatch.setattr(httpx, "post", lambda *a, **k: _BatchResp())

    def _get_fail(*a, **k):
        raise httpx.ConnectError("vulns endpoint down")

    monkeypatch.setattr(httpx, "get", _get_fail)
    client = OSVClient(cache_path=_isolate_osv_cache)
    results = client.query_batch([(["PyPI"], "p", "1.0")])
    # Hydration failed, but the finding is preserved via the stub (severity may
    # default downstream — never a lost finding).
    assert results[0] == [{"id": "OSV-STUB", "modified": "t"}]


def test_query_batch_empty_jobs_returns_empty(_isolate_osv_cache, monkeypatch):
    def _boom(*a, **k):
        raise AssertionError("no jobs must not hit network")

    monkeypatch.setattr(httpx, "post", _boom)
    client = OSVClient(cache_path=_isolate_osv_cache)
    assert client.query_batch([]) == []
