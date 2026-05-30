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
      - ``severity_histogram``: ``{severity: count}`` over **every** reported
        finding — creds, cve, and misconfig alike — keyed by the five canonical
        severity levels and ordered most-severe-first (``critical`` → ``info``).
        Severities with no findings are omitted so the block stays compact, and
        an unrecognised severity is bucketed under ``"unknown"`` (last) rather
        than dropped. Where ``finding_count`` answers "how many issues?" this
        answers "what's the severity distribution?" — the canonical triage
        question, and the natural complement to the component counts. It counts
        the *filtered* findings, so it always matches what the operator sees.

    ``findings`` is the already-filtered finding set so the vulnerable count and
    the severity histogram reflect what the operator sees (a CVE triaged away by
    --vex/--min-severity is no longer counted). Only ``cve`` findings carry
    package identity, so creds/misconfig findings are ignored for the package
    counts — but they *are* counted in the severity histogram.
    """
    from casket.checks.cves import package_inventory

    packages = package_inventory(image)
    by_ecosystem: dict[str, int] = {}
    for pkg in packages:
        by_ecosystem[pkg.ecosystem] = by_ecosystem.get(pkg.ecosystem, 0) + 1

    vulnerable: set[tuple[str, str, str]] = set()
    severity_counts: dict[str, int] = {}
    for f in findings:
        sev = f.severity if f.severity in _SEVERITY_RANK else "unknown"
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
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
    # Severity histogram ordered most-severe-first; recognised levels follow the
    # canonical rank, an "unknown" bucket (if any) sorts last. Empty levels are
    # omitted entirely so the block stays compact.
    severity_histogram = dict(
        sorted(
            severity_counts.items(),
            key=lambda kv: _SEVERITY_RANK.get(kv[0], 99),
        )
    )
    return {
        "total_components": len(packages),
        "by_ecosystem": ordered,
        "vulnerable_components": len(vulnerable),
        "severity_histogram": severity_histogram,
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

# Accepted --suppress-severity values (for the CLI choices list). Each is an
# *exact* severity band to mute — unlike --min-severity's floor, naming a level
# here drops that level alone, so an operator can carve out an arbitrary band
# (e.g. mute medium+low while keeping critical/high AND info).
SUPPRESS_SEVERITY_CHOICES = ["critical", "high", "medium", "low", "info"]


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


def filter_by_cvss_floor(
    findings: list[Finding], min_cvss: float | None = None
) -> list[Finding]:
    """Drop CVE findings whose numeric CVSS base score is below ``min_cvss``.

    The qualitative severity band (``critical``/``high``/…) maps a *range* of
    CVSS scores to one bucket, so ``--min-severity high`` keeps every CVE scored
    7.0-10.0 — a 7.0 and a 9.8 are both ``high`` even though the 9.8 is
    materially more urgent. ``--cvss-floor`` is the *numeric* knob: it keeps
    only CVE findings whose ``cvss_score`` is at or above the threshold, so an
    operator can carve any cutoff inside a band (e.g. only score >= 7.5).

      - ``None`` (the default / flag absent): return every finding unchanged.
      - a float in ``[0.0, 10.0]``: keep every **non-CVE** finding (creds /
        misconfig carry no CVSS score and are a different class of problem),
        and keep a CVE finding only if its ``cvss_score`` is present *and* at
        or above the threshold.

    The "drop CVEs without a score" posture matches ``--min-epss``: an explicit
    ``--cvss-floor`` is a request to see only CVEs that clear a numeric bar,
    so a CVE whose OSV record carries no scorable CVSS vector (severity then
    came from the record's ``database_specific`` string or the conservative
    default — see ``CVE severity`` in the README) does not clear it.
    creds/misconfig findings always survive an explicit floor.
    """
    if min_cvss is None:
        return list(findings)
    kept: list[Finding] = []
    for f in findings:
        if f.category != "cve":
            kept.append(f)
            continue
        score = f.detail.get("cvss_score")
        if isinstance(score, (int, float)) and score >= min_cvss:
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


def filter_by_ecosystem(
    findings: list[Finding], suppressed: set[str] | None = None
) -> list[Finding]:
    """Drop CVE findings whose OSV ecosystem the operator chose to suppress.

    ``suppressed`` is a set of ecosystem names to hide (case-insensitively) —
    e.g. ``{"debian"}`` to drop every Debian OS-package CVE and focus on
    application dependencies (PyPI/npm/…), or ``{"alpine", "debian", "red hat"}``
    to mute all OS-package noise at once. Ecosystem only exists on ``cve``
    findings (creds/misconfig carry no package identity), so this never touches
    them — they always survive.

      - ``None`` / empty set (no ``--suppress-ecosystem`` flag): return every
        finding unchanged (no-op, casket's original behaviour).
      - otherwise: keep every **non-CVE** finding, and keep a CVE finding only
        when its ``detail["ecosystem"]`` (lower-cased) is *not* in the suppress
        set. A CVE finding that carries no ecosystem is kept (it can't be matched
        against the suppress list, so it is never silently hidden).

    Matching is case-insensitive so an operator needn't remember OSV's exact
    capitalisation (``Debian``/``debian``, ``Red Hat``/``red hat`` all match).

    Like ``--min-severity`` / ``--min-epss`` / ``--vex`` this shapes the
    *reported* set before the exit-code gate / ``--compare`` diff runs, so what
    fails the build matches what the operator sees — a CVE suppressed by
    ecosystem neither shows up nor secretly trips the gate.
    """
    if not suppressed:
        return list(findings)
    lowered = {e.lower() for e in suppressed}
    kept: list[Finding] = []
    for f in findings:
        if f.category != "cve":
            kept.append(f)
            continue
        eco = f.detail.get("ecosystem")
        if isinstance(eco, str) and eco.lower() in lowered:
            continue
        kept.append(f)
    return kept


# Map OSV ecosystem names to the canonical purl type
# (https://github.com/package-url/purl-spec/blob/master/PURL-TYPES.rst).
# Unknown ecosystems fall back to a lowercased, alphanumeric-stripped form so
# a future ecosystem still produces a stable, matchable purl rather than no purl.
_ECOSYSTEM_TO_PURL_TYPE = {
    "pypi": "pypi",
    "debian": "deb",
    "alpine": "apk",
    "red hat": "rpm",
}


def _purl_for_finding(finding: Finding) -> str | None:
    """Synthesize a Package URL for a CVE finding, or None if not derivable.

    Builds ``pkg:<type>/<name>@<version>`` from the finding's ecosystem,
    package, and installed_version. Returns ``None`` for non-CVE findings or
    when any field is missing — these can't be purl-matched so the caller
    treats them as "no purl" and the filter's posture (drop on explicit
    request, matching --min-epss / --cvss-floor) decides what to do.
    """
    if finding.category != "cve":
        return None
    detail = finding.detail
    eco = detail.get("ecosystem")
    name = detail.get("package")
    version = detail.get("installed_version")
    if not (isinstance(eco, str) and isinstance(name, str)
            and isinstance(version, str) and eco and name and version):
        return None
    eco_key = eco.lower()
    purl_type = _ECOSYSTEM_TO_PURL_TYPE.get(eco_key)
    if purl_type is None:
        # Defensive fallback: a future ecosystem still gets a stable purl
        # (lowercased, alphanumeric-only) rather than vanishing under any filter.
        purl_type = "".join(c for c in eco_key if c.isalnum()) or "unknown"
    return f"pkg:{purl_type}/{name}@{version}"


def filter_by_purl(
    findings: list[Finding], patterns: list[str] | None = None
) -> list[Finding]:
    """Keep only CVE findings whose purl matches at least one ``patterns`` glob.

    ``--suppress-ecosystem`` mutes a whole OSV ecosystem; ``--purl-filter`` is
    the *selection* knob at the package level — keep only the CVEs whose
    installed component matches a Package URL glob. The motivating case the
    ecosystem-level knob cannot express: "only show CVEs against my application
    dependencies under ``pkg:pypi/myapp-*``" or "only show CVEs against
    openssl regardless of distro" (``pkg:*/openssl@*``). Patterns use
    ``fnmatch`` glob semantics (``*``, ``?``, ``[seq]``); matching is
    case-insensitive so an operator needn't remember the canonical lowercased
    purl type spelling.

      - ``None`` / empty list (no ``--purl-filter`` flag): return every finding
        unchanged (no-op, casket's original behaviour).
      - otherwise: keep every **non-CVE** finding (creds / misconfig carry no
        package identity and are a different class of problem — purl is a
        package addressing scheme), and keep a CVE finding only when its
        synthesized purl matches at least one pattern. Multiple patterns OR.

    Synthesis follows the purl spec's canonical types:
    ``PyPI -> pkg:pypi/...``, ``Debian -> pkg:deb/...``, ``Alpine -> pkg:apk/...``,
    ``Red Hat -> pkg:rpm/...``. A CVE finding missing ecosystem / package /
    installed_version produces no purl and so cannot match any pattern — it is
    pruned by an explicit filter (matching ``--cvss-floor`` / ``--min-epss``
    posture: an explicit selection bar requires the data to evaluate it).

    Like the other report filters this shapes the *reported* set before the
    exit-code gate / ``--compare`` diff runs, so what fails the build matches
    what the operator sees.
    """
    if not patterns:
        return list(findings)
    import fnmatch

    lowered_patterns = [p.lower() for p in patterns]
    kept: list[Finding] = []
    for f in findings:
        if f.category != "cve":
            kept.append(f)
            continue
        purl = _purl_for_finding(f)
        if purl is None:
            continue
        purl_lower = purl.lower()
        if any(fnmatch.fnmatchcase(purl_lower, p) for p in lowered_patterns):
            kept.append(f)
    return kept


def filter_by_severity_band(
    findings: list[Finding], suppressed: set[str] | None = None
) -> list[Finding]:
    """Drop findings whose severity is in an operator-named set of bands.

    Where ``--min-severity`` is a *floor* (keep everything at-or-above one
    threshold), this is a *band* mute (drop exactly the named levels), so the two
    knobs together can carve out any arbitrary severity range. The motivating
    case ``--min-severity`` cannot express: keep the genuine risk (critical/high)
    **and** the audit-trail noise floor (info) while muting the busy middle —
    ``--suppress-severity medium --suppress-severity low`` does exactly that,
    something no single floor can (dropping low with ``--min-severity`` would
    also drop info, and there is no upper bound to mute high while keeping
    critical+info). Naming several levels mutes several bands at once.

    ``suppressed`` is a set of severity names to hide. It applies to **every**
    finding category (creds / cve / misconfig all carry a severity), unlike the
    CVE-only ecosystem/EPSS/VEX filters — a severity band is a cross-category
    notion.

      - ``None`` / empty set (no ``--suppress-severity`` flag): return every
        finding unchanged (no-op, casket's original behaviour).
      - otherwise: keep a finding only when its ``severity`` is *not* in the
        suppress set. A finding whose severity is unrecognised is never in the
        (validated) suppress set, so it always survives — an unknown severity is
        never silently hidden by this filter.

    Like ``--min-severity`` / ``--min-epss`` / ``--vex`` / ``--suppress-ecosystem``
    this shapes the *reported* set before the exit-code gate / ``--compare`` diff
    runs, so what fails the build matches what the operator sees — a band muted
    here neither shows up nor secretly trips the gate.
    """
    if not suppressed:
        return list(findings)
    return [f for f in findings if f.severity not in suppressed]


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
