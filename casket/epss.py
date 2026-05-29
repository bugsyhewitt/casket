"""EPSS (Exploit Prediction Scoring System) client with an on-disk cache.

CVSS answers "how *bad* is this vuln if exploited?" — it says nothing about how
*likely* exploitation is. EPSS fills that gap: the FIRST.org EPSS model assigns
every published CVE a probability (0.0–1.0) that it will be exploited in the
wild over the next 30 days, plus a percentile rank against all scored CVEs.
On a busy base image carrying hundreds of OS-package CVEs, that probability is
the single most useful triage signal — it lets an operator prioritise the
handful of vulns attackers are actually exploiting over the long tail of
high-CVSS-but-never-exploited ones.

casket enriches each CVE finding with its EPSS score (``epss_score`` /
``epss_percentile``) and exposes a ``--min-epss`` report filter that keeps only
findings at or above a probability threshold.

[Worker decision: mirror the OSV client's cache-first, offline-safe contract]
This client deliberately mirrors ``casket.osv.OSVClient``:

  - Results are cached to a local JSON file keyed by CVE id; cache hits never
    touch the network (tests seed the cache so no HTTP happens at all).
  - A ``base_url`` can be injected so tests run against a fake without network.
  - ``offline`` (and any network failure) degrades a *miss* to "no score"
    rather than raising — a finding is never lost, only its EPSS fields are
    omitted. Misses are not cached, so a later online run can retry.
  - The FIRST EPSS API takes a comma-separated ``cve=`` list, so all of an
    image's CVEs resolve in **one** batched GET request (cache-first: only the
    ids that miss locally are queried).

The endpoint is a public, read-only ``GET https://api.first.org/data/v1/epss``;
no auth, no rate-limit concerns for the small per-image id set casket sends.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import httpx

DEFAULT_EPSS_URL = "https://api.first.org/data/v1"


def default_cache_path() -> Path:
    """Location of the persistent EPSS cache.

    Honors ``CASKET_EPSS_CACHE`` so tests can point at a temp file; otherwise
    sits beside the OSV cache under ``~/.cache/casket/``.
    """
    env = os.environ.get("CASKET_EPSS_CACHE")
    if env:
        return Path(env)
    base = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache"))
    return base / "casket" / "epss-cache.json"


def _coerce_score(raw: Any) -> dict[str, float] | None:
    """Coerce a raw EPSS API row into ``{"score", "percentile"}`` floats.

    The FIRST API returns each field as a *string* (e.g. ``"0.00123"``). A row
    missing or with an unparseable ``epss`` is treated as "no score" (``None``)
    rather than raising — a single bad row never aborts enrichment.
    """
    if not isinstance(raw, dict):
        return None
    try:
        score = float(raw["epss"])
    except (KeyError, TypeError, ValueError):
        return None
    out: dict[str, float] = {"score": score}
    percentile = raw.get("percentile")
    if percentile is not None:
        try:
            out["percentile"] = float(percentile)
        except (TypeError, ValueError):
            pass
    return out


class EPSSClient:
    """Cache-first FIRST.org EPSS query client."""

    def __init__(
        self,
        *,
        cache_path: Path | None = None,
        base_url: str = DEFAULT_EPSS_URL,
        offline: bool = False,
        timeout: float = 10.0,
    ):
        self.cache_path = cache_path or default_cache_path()
        self.base_url = base_url.rstrip("/")
        self.offline = offline
        self.timeout = timeout
        self._cache: dict[str, Any] = self._load_cache()

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

    def scores_for(self, cve_ids: list[str]) -> dict[str, dict[str, float]]:
        """Resolve EPSS scores for a list of CVE ids, cache-first.

        Returns a mapping ``cve_id -> {"score": float, "percentile": float}``
        for every id that has a published EPSS score. Ids with no score (the
        EPSS model only covers published CVEs; reserved/rejected/very-fresh ids
        are absent) are simply not present in the result, never an error.

        Resolution order: disk cache first, then a single batched network GET
        for all cache misses. The cache distinguishes "known to have no score"
        (cached as ``None``) from "never looked up" so a CVE the model doesn't
        cover isn't re-queried every run. Offline (or any network failure)
        degrades misses to "no score" and does *not* cache them, so a later
        online run can retry.
        """
        result: dict[str, dict[str, float]] = {}
        misses: list[str] = []
        seen: set[str] = set()
        for cve in cve_ids:
            if not isinstance(cve, str) or not cve or cve in seen:
                continue
            seen.add(cve)
            if cve in self._cache:
                cached = self._cache[cve]
                if cached is not None:
                    result[cve] = cached
                # else: cached miss (None) — known to have no score, skip.
                continue
            misses.append(cve)

        if not misses or self.offline:
            return result

        try:
            resp = httpx.get(
                f"{self.base_url}/epss",
                params={"cve": ",".join(misses)},
                timeout=self.timeout,
            )
            resp.raise_for_status()
            rows = resp.json().get("data", [])
        except (httpx.HTTPError, ValueError):
            # Whole batch failed: leave misses unscored (uncached) so a later
            # online run retries. Cached hits already populated result.
            return result

        if not isinstance(rows, list):
            return result

        # Map the returned rows back to their CVE ids, coercing string fields.
        fetched: dict[str, dict[str, float] | None] = {}
        for row in rows:
            if not isinstance(row, dict):
                continue
            cve = row.get("cve")
            if not isinstance(cve, str) or not cve:
                continue
            fetched[cve] = _coerce_score(row)

        # Cache every miss we asked about — a present score as its dict, an
        # absent/unscorable one as None (a cached "no score") so it isn't
        # re-queried on the next run.
        for cve in misses:
            score = fetched.get(cve)
            self._cache[cve] = score
            if score is not None:
                result[cve] = score
        self._save_cache()
        return result

    def seed(self, cve_id: str, score: dict[str, float] | None) -> None:
        """Pre-populate the cache (used by tests and warm-start).

        Pass ``None`` to seed a "known to have no EPSS score" entry.
        """
        self._cache[cve_id] = score
        self._save_cache()
