"""Scan orchestration: load an image by mode, run the selected checks."""

from __future__ import annotations

from typing import Any

from casket import checks as checks_mod
from casket.findings import Finding
from casket.oci import Image, load_tarball


def load_image(image_ref: str, mode: str) -> Image:
    """Load an image for the given mode.

    Imports for podman/remote are deferred so tarball-only runs don't require
    httpx-driven code paths to import cleanly and so import errors surface only
    when the relevant mode is actually used.
    """
    if mode == "tarball":
        return load_tarball(image_ref)
    if mode == "podman":
        from casket.podman_mode import load_podman

        return load_podman(image_ref)
    if mode == "remote":
        from casket.remote_mode import load_remote

        return load_remote(image_ref)
    raise ValueError(f"unknown mode: {mode!r}")


def run_checks(
    image: Image,
    selected: list[str],
    *,
    osv_client: Any = None,
) -> list[Finding]:
    """Run the named checks against a loaded image and collect findings."""
    findings: list[Finding] = []
    for name in selected:
        fn = checks_mod.REGISTRY[name]
        findings.extend(fn(image, osv_client=osv_client))
    return findings


def resolve_checks(checks_arg: str) -> list[str]:
    """Translate the --checks value into a concrete check list."""
    if checks_arg == "all":
        return list(checks_mod.ALL_CHECKS)
    if checks_arg == "cves":
        return ["cves"]
    return [checks_arg]
