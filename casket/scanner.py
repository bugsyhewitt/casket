"""Scan orchestration: load an image by mode, run the selected checks."""

from __future__ import annotations

from typing import Any

from casket import checks as checks_mod
from casket.findings import Finding
from casket.oci import Image, load_tarball


def load_image(
    image_ref: str,
    mode: str,
    *,
    token: str | None = None,
    registry_user: str | None = None,
    registry_password: str | None = None,
) -> Image:
    """Load an image for the given mode.

    Imports for podman/remote are deferred so tarball-only runs don't require
    httpx-driven code paths to import cleanly and so import errors surface only
    when the relevant mode is actually used.

    ``token``/``registry_user``/``registry_password`` are only meaningful for
    ``remote`` mode and are ignored otherwise.
    """
    if mode == "tarball":
        return load_tarball(image_ref)
    if mode == "podman":
        from casket.podman_mode import load_podman

        return load_podman(image_ref)
    if mode == "remote":
        from casket.remote_mode import load_remote

        return load_remote(
            image_ref,
            token=token,
            user=registry_user,
            password=registry_password,
        )
    raise ValueError(f"unknown mode: {mode!r}")


def run_checks(
    image: Image,
    selected: list[str],
    *,
    osv_client: Any = None,
) -> list[Finding]:
    """Run the named checks against a loaded image and collect findings.

    After collection, each finding is annotated with the Dockerfile command
    that introduced its layer (``detail["layer_command"]``) when the image
    config carries the relevant ``history`` entry. This makes findings
    actionable: an operator sees *which build instruction* (e.g.
    ``RUN apt-get install -y openssl``) produced the issue, not just an opaque
    layer digest. Findings whose ``layer_sha`` is the synthetic config digest
    (misconfig checks) or whose layer has no resolvable command are left
    unannotated.
    """
    findings: list[Finding] = []
    for name in selected:
        fn = checks_mod.REGISTRY[name]
        findings.extend(fn(image, osv_client=osv_client))

    command_map = image.layer_command_map()
    if command_map:
        for finding in findings:
            command = command_map.get(finding.layer_sha)
            if command is not None:
                finding.detail["layer_command"] = command

    return findings


def resolve_checks(checks_arg: str) -> list[str]:
    """Translate the --checks value into a concrete check list."""
    if checks_arg == "all":
        return list(checks_mod.ALL_CHECKS)
    if checks_arg == "cves":
        return ["cves"]
    return [checks_arg]
