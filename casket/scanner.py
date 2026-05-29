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


# Severity ordering for the CI gate (lower rank == more severe). Mirrors the
# ordering in findings.py; kept here to avoid a render-layer import in the
# gate path.
_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# Accepted --fail-on values, in declaration order (for the CLI choices list).
FAIL_ON_CHOICES = ["any", "critical", "high", "medium", "low", "info", "none"]

# Accepted --min-severity values, in declaration order (for the CLI choices
# list). ``all`` (the default) reports every finding — casket's original
# behaviour; a severity name suppresses anything *below* it from the report.
MIN_SEVERITY_CHOICES = ["all", "critical", "high", "medium", "low", "info"]


def filter_by_severity(
    findings: list[Finding], min_severity: str = "all"
) -> list[Finding]:
    """Drop findings below ``min_severity`` from the report.

    Unlike ``exit_code`` (which gates only the *build*), this prunes what gets
    *rendered*, so an operator can cut noise on a busy image — e.g.
    ``--min-severity high`` shows only high and critical findings.

      - ``"all"`` (default): return every finding unchanged (original behaviour).
      - a severity (``critical``/``high``/``medium``/``low``/``info``): keep only
        findings *at that severity or more severe*. ``--min-severity medium``
        keeps critical/high/medium and drops low/info.

    Findings whose severity is unrecognised rank below ``info`` and are dropped
    by any concrete threshold (kept only under ``all``), matching the
    fail-safe-quiet posture of the severity gate.
    """
    if min_severity == "all":
        return list(findings)
    threshold = _SEVERITY_RANK.get(min_severity)
    if threshold is None:  # unknown value: don't silently hide everything
        return list(findings)
    return [
        f
        for f in findings
        if _SEVERITY_RANK.get(f.severity, 99) <= threshold
    ]


def exit_code(findings: list[Finding], fail_on: str = "any") -> int:
    """Compute the process exit code for a scan, gated by severity threshold.

    The CI gate decides *whether findings should fail the build*, independent
    of what gets reported — every finding is always rendered. ``fail_on``:

      - ``"any"``  (default): exit 1 if there is *any* finding. This preserves
        casket's original binary behaviour.
      - a severity (``critical``/``high``/``medium``/``low``/``info``): exit 1
        only if at least one finding is *at that severity or more severe*. e.g.
        ``--fail-on high`` ignores medium/low/info findings for gating but still
        fails on high and critical.
      - ``"none"``: never exit 1 on findings — report-only mode. Useful for
        publishing results (SARIF upload, dashboards) without breaking the build.

    Returns 0 (clean / below threshold) or 1 (gate tripped). Load errors are
    surfaced as exit 2 by the caller, never here.
    """
    if not findings:
        return 0
    if fail_on == "none":
        return 0
    if fail_on == "any":
        return 1
    threshold = _SEVERITY_RANK.get(fail_on)
    if threshold is None:  # unknown value: fail safe (treat as "any")
        return 1
    for finding in findings:
        rank = _SEVERITY_RANK.get(finding.severity, 99)
        if rank <= threshold:
            return 1
    return 0
