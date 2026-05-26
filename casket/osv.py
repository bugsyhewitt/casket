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

    def seed(self, ecosystem: str, package: str, version: str, vulns: list[dict]) -> None:
        """Pre-populate the cache (used by tests and warm-start)."""
        self._cache[self._key(ecosystem, package, version)] = vulns
        self._save_cache()
