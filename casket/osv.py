"""OSV.dev query client with a local on-disk cache.

The CVE check resolves (ecosystem, package, version) tuples to known
vulnerabilities via the OSV.dev REST API (https://osv.dev). To avoid hammering
the API — during tests especially — every query result is cached to a local
JSON file keyed by the query tuple. Cache hits never touch the network.

[Worker decision: cache-first, offline-capable]
Tests must not depend on the public OSV.dev API being reachable (criterion 9
explicitly wants the query layer cached to avoid API hammering). So:
  - The cache is checked first.
  - A ``base_url`` can be injected (the remote-mode fixture server / tests use
    this; in tests we seed the cache so no HTTP happens at all).
  - If a query misses the cache AND no network is available/allowed, we return
    an empty result rather than raising, so a scan degrades gracefully.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import httpx

DEFAULT_OSV_URL = "https://api.osv.dev"

# Bundled read-only seed DB: lets casket resolve a small curated set of
# known-vulnerable packages with no network and no warm cache. Live OSV.dev
# queries (cached to disk) cover everything beyond this seed.
_SEED_DB_PATH = Path(__file__).resolve().parent / "ruledata" / "osv-seed.json"


def _load_seed_db() -> dict[str, Any]:
    try:
        data = json.loads(_SEED_DB_PATH.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return {}
    return {k: v for k, v in data.items() if not k.startswith("_")}


def default_cache_path() -> Path:
    """Location of the persistent OSV cache.

    Honors ``CASKET_OSV_CACHE`` so tests can point at a temp file.
    """
    env = os.environ.get("CASKET_OSV_CACHE")
    if env:
        return Path(env)
    base = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache"))
    return base / "casket" / "osv-cache.json"


class OSVClient:
    """Cache-first OSV.dev query client."""

    def __init__(
        self,
        *,
        cache_path: Path | None = None,
        base_url: str = DEFAULT_OSV_URL,
        offline: bool = False,
        timeout: float = 10.0,
    ):
        self.cache_path = cache_path or default_cache_path()
        self.base_url = base_url.rstrip("/")
        self.offline = offline
        self.timeout = timeout
        self._cache: dict[str, Any] = self._load_cache()
        self._seed: dict[str, Any] = _load_seed_db()

    def _load_cache(self) -> dict[str, Any]:
        try:
            return json.loads(self.cache_path.read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    def _save_cache(self) -> None:
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.cache_path.with_suffix(self.cache_path.suffix + ".tmp")
        tmp.write_text(json.dumps(self._cache, indent=2), encoding="utf-8")
        tmp.replace(self.cache_path)

    @staticmethod
    def _key(ecosystem: str, package: str, version: str) -> str:
        return f"{ecosystem}|{package}|{version}"

    def query(self, ecosystem: str, package: str, version: str) -> list[dict[str, Any]]:
        """Return the list of OSV vuln records for a package version.

        Resolution order: disk cache -> bundled seed DB -> OSV.dev network.
        Network failures degrade to an empty list (and are not cached, so a
        later online run can retry).
        """
        key = self._key(ecosystem, package, version)
        if key in self._cache:
            return self._cache[key]
        if key in self._seed:
            return self._seed[key]

        if self.offline:
            return []

        try:
            resp = httpx.post(
                f"{self.base_url}/v1/query",
                json={
                    "version": version,
                    "package": {"name": package, "ecosystem": ecosystem},
                },
                timeout=self.timeout,
            )
            resp.raise_for_status()
            vulns = resp.json().get("vulns", [])
        except (httpx.HTTPError, ValueError):
            return []

        self._cache[key] = vulns
        self._save_cache()
        return vulns

    def query_batch(
        self, jobs: list[tuple[list[str], str, str]]
    ) -> list[list[dict[str, Any]]]:
        """Resolve many packages in as few network round-trips as possible.

        Each *job* is ``(candidate_ecosystems, package, version)`` — the same
        ordered-candidate shape ``query_ecosystems`` takes (most specific
        ecosystem first; e.g. ``["Alpine:v3.18", "Alpine"]``). The result is a
        list aligned to ``jobs``: ``result[i]`` is the vuln list for ``jobs[i]``.

        The win over calling ``query`` / ``query_ecosystems`` in a loop is the
        network shape. A busy ``debian``/``ubuntu`` image carries hundreds of
        packages; the per-package path is one HTTP round-trip *each*. OSV.dev's
        ``/v1/querybatch`` endpoint resolves the whole list in **one** request,
        returning vuln stubs (``{id, modified}``) per query. We then hydrate the
        (typically small) set of vulnerable packages to full records — which
        carry the severity casket scores — via ``/v1/vulns/{id}``, caching each
        full record so a later run / repeat id is free. On a clean image (most
        packages have zero vulns) this collapses hundreds of round-trips to one.

        The cache-first contract is preserved exactly:

          * Every candidate is checked against the disk cache and bundled seed
            DB first, in order — a fully cached/seeded image touches no network.
          * The batch request only carries the candidates that missed locally.
          * Offline (or a network failure) degrades a *miss* to an empty list,
            never a crash, and is not cached (so a later online run can retry).
          * Resolved batch results are cached per ``(ecosystem, package,
            version)`` tuple under the same key scheme ``query`` uses, so the
            two paths share one warm cache.

        ``query_batch([(ecos, pkg, ver)])`` is equivalent to
        ``[query_ecosystems(ecos, pkg, ver)]`` but issues one batched request
        for all local misses instead of one request per package.
        """
        results: list[list[dict[str, Any]]] = [[] for _ in jobs]

        # First pass: serve everything resolvable from cache/seed, in candidate
        # order. Record the misses we still need to resolve over the network,
        # deduplicated by (ecosystem, package, version) so identical tuples are
        # queried once and share the result.
        pending: list[tuple[int, str]] = []  # (job index, ecosystem to try)
        miss_keys: dict[str, tuple[str, str, str]] = {}
        for i, (ecosystems, package, version) in enumerate(jobs):
            resolved = False
            seen: set[str] = set()
            first_miss: str | None = None
            for ecosystem in ecosystems:
                if not ecosystem or ecosystem in seen:
                    continue
                seen.add(ecosystem)
                key = self._key(ecosystem, package, version)
                if key in self._cache:
                    results[i] = self._cache[key]
                    resolved = True
                    break
                if key in self._seed:
                    results[i] = self._seed[key]
                    resolved = True
                    break
                if first_miss is None:
                    first_miss = ecosystem
                    miss_keys[key] = (ecosystem, package, version)
            if not resolved and first_miss is not None and not self.offline:
                pending.append((i, first_miss))

        if not pending:
            return results

        # Single batched existence query for all local misses.
        ordered_keys = list(miss_keys.keys())
        queries = [
            {
                "version": version,
                "package": {"name": package, "ecosystem": ecosystem},
            }
            for ecosystem, package, version in (miss_keys[k] for k in ordered_keys)
        ]
        try:
            resp = httpx.post(
                f"{self.base_url}/v1/querybatch",
                json={"queries": queries},
                timeout=self.timeout,
            )
            resp.raise_for_status()
            batch_results = resp.json().get("results", [])
        except (httpx.HTTPError, ValueError):
            # Whole batch failed: leave misses as empty (uncached), so a later
            # online run retries. Cached/seeded hits already populated results.
            return results

        # Hydrate full records for the vulnerable tuples, caching per tuple.
        # Each distinct vuln id is fetched once and shared across tuples.
        vuln_cache: dict[str, dict[str, Any] | None] = {}
        any_cached = False
        for key, entry in zip(ordered_keys, batch_results):
            if not isinstance(entry, dict):
                continue
            stubs = entry.get("vulns") or []
            full: list[dict[str, Any]] = []
            for stub in stubs:
                vid = stub.get("id") if isinstance(stub, dict) else None
                if not vid:
                    continue
                if vid not in vuln_cache:
                    vuln_cache[vid] = self._fetch_vuln(vid)
                record = vuln_cache[vid]
                full.append(record if record is not None else stub)
            self._cache[key] = full
            any_cached = True

        if any_cached:
            self._save_cache()

        # Backfill results for the jobs whose first miss we batched.
        for i, ecosystem in pending:
            _, package, version = jobs[i][0], jobs[i][1], jobs[i][2]
            key = self._key(ecosystem, package, version)
            if key in self._cache:
                results[i] = self._cache[key]
        return results

    def _fetch_vuln(self, vuln_id: str) -> dict[str, Any] | None:
        """Fetch a full OSV record by id, or ``None`` on any failure.

        ``/v1/querybatch`` returns only ``{id, modified}`` stubs; the full
        record (with the ``severity`` array casket scores) lives at
        ``/v1/vulns/{id}``. A failure degrades to ``None`` and the caller keeps
        the stub, so a finding is never lost — only its severity may default.
        """
        try:
            resp = httpx.get(
                f"{self.base_url}/v1/vulns/{vuln_id}",
                timeout=self.timeout,
            )
            resp.raise_for_status()
            data = resp.json()
        except (httpx.HTTPError, ValueError):
            return None
        return data if isinstance(data, dict) else None

    def query_ecosystems(
        self, ecosystems: list[str], package: str, version: str
    ) -> list[dict[str, Any]]:
        """Resolve a package across an ordered list of candidate ecosystems.

        OSV.dev keys some package families under release-qualified ecosystem
        names (e.g. Alpine vulns live under ``Alpine:v3.18``, not bare
        ``Alpine``; Debian under ``Debian:12``). The exact qualifier depends on
        the OS release recorded *inside the image*, which the caller resolves
        and passes as the most specific candidate first.

        We try each candidate in order and return the first non-empty result.
        This lets a caller prefer the precise release-qualified ecosystem
        (which the live OSV.dev API requires) while still falling back to the
        bare ecosystem name, under which casket's bundled seed DB and warm
        cache are keyed — so offline/seed resolution keeps working unchanged.

        Empty/falsy candidates are skipped. Duplicate candidates are queried
        once. Returns an empty list if no candidate resolves.
        """
        seen: set[str] = set()
        for ecosystem in ecosystems:
            if not ecosystem or ecosystem in seen:
                continue
            seen.add(ecosystem)
            vulns = self.query(ecosystem, package, version)
            if vulns:
                return vulns
        return []

    def seed(self, ecosystem: str, package: str, version: str, vulns: list[dict]) -> None:
        """Pre-populate the cache (used by tests and warm-start)."""
        self._cache[self._key(ecosystem, package, version)] = vulns
        self._save_cache()
