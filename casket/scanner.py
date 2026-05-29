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
    epss_client: Any = None,
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

    When an ``epss_client`` is supplied, CVE findings are additionally enriched
    with their EPSS (Exploit Prediction Scoring System) score — the probability
    that the vuln will be exploited in the wild — via a single batched lookup.
    This is a prioritisation signal CVSS severity alone can't give: it surfaces
    *which* of an image's many CVEs are actually being exploited. See
    ``enrich_with_epss``.
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

    if epss_client is not None:
        enrich_with_epss(findings, epss_client)

    return findings


def enrich_with_epss(findings: list[Finding], epss_client: Any) -> None:
    """Annotate CVE findings in place with their EPSS score / percentile.

    EPSS scores are keyed by CVE id, so only ``cve`` findings carrying a
    ``CVE-…`` identifier are enrichable (the EPSS model covers published CVEs,
    not GHSA / distro ids). We collect every such id, resolve them in **one**
    batched, cache-first lookup, then attach ``epss_score`` and (when present)
    ``epss_percentile`` to each matching finding's ``detail``. A finding whose
    CVE has no published EPSS score, or that carries no CVE id, is left
    untouched — the keys are omitted entirely rather than set to a sentinel, so
    clean/seed findings and the existing output stay byte-compatible.

    The ``epss_score`` flows through every output format for free (json
    flatten, h1md bullet, SARIF result property), exactly like the other CVE
    enrichment fields.
    """
    cve_ids: list[str] = []
    for finding in findings:
        if finding.category != "cve":
            continue
        cve = finding.detail.get("cve_id")
        if isinstance(cve, str) and cve.startswith("CVE-"):
            cve_ids.append(cve)

    if not cve_ids:
        return

    scores = epss_client.scores_for(cve_ids)
    if not scores:
        return

    for finding in findings:
        if finding.category != "cve":
            continue
        cve = finding.detail.get("cve_id")
        if not isinstance(cve, str):
            continue
        score = scores.get(cve)
        if score is None:
            continue
        finding.detail["epss_score"] = score["score"]
        if "percentile" in score:
            finding.detail["epss_percentile"] = score["percentile"]


def component_stats(image: Image, findings: list[Finding]) -> dict[str, Any]:
    """Summarize the image's package inventory as component-count statistics.

    This realizes the "SBOM component count stats" idea **without** crossing the
    "no SBOM generation" v0.1 guardrail: it does not emit a CycloneDX/SPDX
    document — it reports *counts* of the partial package inventory the CVE check
    already extracts (``casket.checks.cves.package_inventory``, network-free).

    The returned block:

      - ``total_components``: total installed packages extracted across all
        layers (an image with no resolvable package DBs reports ``0``).
      - ``by_ecosystem``: ``{ecosystem: count}`` (e.g. ``{"Debian": 412,
        "PyPI": 7}``), sorted by descending count then name for stable output.
      - ``vulnerable_components``: the number of *distinct* packages
        (name@version per ecosystem) that have at least one CVE finding — i.e.
        how much of the inventory is actually affected, which a raw
        ``finding_count`` (one per vuln, so a single package can inflate it)
        does not tell you.

    ``findings`` is the already-filtered finding set so the vulnerable count
    reflects what the operator sees (a CVE triaged away by --vex/--min-severity
    is no longer counted as a vulnerable component). Only ``cve`` findings carry
    package identity, so creds/misconfig findings are ignored here.
    """
    from casket.checks.cves import package_inventory

    packages = package_inventory(image)
    by_ecosystem: dict[str, int] = {}
    for pkg in packages:
        by_ecosystem[pkg.ecosystem] = by_ecosystem.get(pkg.ecosystem, 0) + 1

    vulnerable: set[tuple[str, str, str]] = set()
    for f in findings:
        if f.category != "cve":
            continue
        detail = f.detail
        eco = detail.get("ecosystem")
        name = detail.get("package")
        version = detail.get("installed_version")
        if isinstance(eco, str) and isinstance(name, str) and isinstance(version, str):
            vulnerable.add((eco, name, version))

    ordered = dict(
        sorted(by_ecosystem.items(), key=lambda kv: (-kv[1], kv[0]))
    )
    return {
        "total_components": len(packages),
        "by_ecosystem": ordered,
        "vulnerable_components": len(vulnerable),
    }


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


def filter_by_epss(
    findings: list[Finding], min_epss: float | None = None
) -> list[Finding]:
    """Drop CVE findings whose EPSS score is below ``min_epss`` from the report.

    EPSS is the probability (0.0–1.0) that a CVE will be exploited in the wild
    over the next 30 days. ``--min-epss 0.5`` keeps only the CVEs the EPSS model
    rates at least 50% likely to be exploited — a far sharper triage knob than
    CVSS severity on a busy image, where most high-CVSS OS-package CVEs are never
    actually exploited.

      - ``None`` (the default / flag absent): return every finding unchanged.
      - a float in ``[0.0, 1.0]``: keep every **non-CVE** finding (creds /
        misconfig have no EPSS score and are never about exploitation
        probability), and keep a CVE finding only if its ``epss_score`` is
        present *and* at or above the threshold.

    The "drop CVEs without a score" posture is deliberate and matches what the
    flag asks for: an explicit ``--min-epss`` is a request to see only CVEs that
    clear an exploitation-likelihood bar, so a CVE with no published EPSS score
    (or one that couldn't be fetched — e.g. ``--offline`` with a cold cache)
    does not clear it. creds/misconfig findings are a different question
    entirely and always survive an EPSS filter.
    """
    if min_epss is None:
        return list(findings)
    kept: list[Finding] = []
    for f in findings:
        if f.category != "cve":
            kept.append(f)
            continue
        score = f.detail.get("epss_score")
        if isinstance(score, (int, float)) and score >= min_epss:
            kept.append(f)
    return kept


def _vex_identifiers(finding: Finding) -> list[str]:
    """Every identifier a VEX statement could reference this CVE finding by.

    A VEX document names a vulnerability by *some* id — the operator may have
    written ``CVE-2018-18074`` while the OSV record's headline id is a GHSA, or
    vice-versa. To match robustly we check the finding against its headline CVE
    (``cve_id``), the raw OSV id (``osv_id``), **and** every cross-reference
    alias (``aliases``). Any one of them appearing in the suppression set
    suppresses the finding.
    """
    detail = finding.detail
    ids: list[str] = []
    for key in ("cve_id", "osv_id"):
        value = detail.get(key)
        if isinstance(value, str) and value:
            ids.append(value)
    aliases = detail.get("aliases")
    if isinstance(aliases, list):
        ids.extend(a for a in aliases if isinstance(a, str) and a)
    return ids


def filter_by_vex(
    findings: list[Finding], suppressed: set[str] | None = None
) -> list[Finding]:
    """Drop CVE findings the operator's VEX document marked not-affected/fixed.

    ``suppressed`` is the set of vulnerability identifiers produced by
    ``casket.vex.parse_vex`` — vulns whose VEX status is ``not_affected`` or
    ``fixed`` (i.e. "do not report this against this image"). A ``cve`` finding
    is dropped iff *any* of its identifiers (headline CVE id, OSV id, or any
    alias — see ``_vex_identifiers``) is in that set.

      - ``None`` / empty set (no ``--vex`` flag, or a VEX file with no
        suppressing statements): return every finding unchanged (no-op).
      - otherwise: keep every **non-CVE** finding (VEX is a CVE-triage format;
        creds/misconfig are out of its scope and always survive), and keep a
        CVE finding only when none of its identifiers is suppressed.

    Like the other report filters this shapes the *reported* set before the
    exit-code gate / ``--compare`` diff runs, so what fails the build matches
    what the operator sees — a vuln triaged away in VEX neither shows up nor
    secretly trips the gate.
    """
    if not suppressed:
        return list(findings)
    kept: list[Finding] = []
    for f in findings:
        if f.category != "cve":
            kept.append(f)
            continue
        if any(ident in suppressed for ident in _vex_identifiers(f)):
            continue
        kept.append(f)
    return kept


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
