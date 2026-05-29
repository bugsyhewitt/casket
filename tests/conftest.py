"""Shared test fixtures for casket.

Regenerates the OCI tarball fixtures once per session and points the OSV cache
at a temp file so no test ever hits the public OSV.dev API.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from tests.build_fixtures import build_all

FIXTURE_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="session", autouse=True)
def _ensure_fixtures():
    build_all()


@pytest.fixture(autouse=True)
def _isolate_osv_cache(tmp_path, monkeypatch):
    """Per-test OSV cache file so tests never touch the real cache or network."""
    cache = tmp_path / "osv-cache.json"
    monkeypatch.setenv("CASKET_OSV_CACHE", str(cache))
    yield cache


@pytest.fixture(autouse=True)
def _isolate_epss_cache(tmp_path, monkeypatch):
    """Per-test EPSS cache file so tests never touch the real cache or network."""
    cache = tmp_path / "epss-cache.json"
    monkeypatch.setenv("CASKET_EPSS_CACHE", str(cache))
    yield cache


def fixture_path(name: str) -> str:
    return str(FIXTURE_DIR / name)
