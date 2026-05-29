"""Machine-readable scan summary for CI dashboards and metric aggregation.

The full ``--format json`` report is per-finding: one object per credential /
CVE / misconfiguration, with the full ``detail`` flattened on each. That is the
right canonical artefact for triage, ``--compare`` diffing, and SARIF / h1md
rendering — but it is the *wrong* shape for the question "how is this image
doing today?" on a CI dashboard or a per-build metrics pipeline. A dashboard
wants one compact JSON document with counts, histograms, and a small top-N
preview, not the entire finding list.

``--output-json-summary`` emits exactly that: a single, flat JSON object
keyed by stable, name-only fields, deliberately omitting the full ``findings``
array so a CI pipe-step like::

    casket --image img.tar --output-json-summary | jq '.by_severity.critical'

is the canonical use. The summary is computed from the **same filtered finding
set** the full report uses, so a CVE triaged away by ``--min-severity`` /
``--min-epss`` / ``--vex`` / ``--suppress-ecosystem`` / ``--suppress-severity``
is invisible to the summary too — what the dashboard sees matches what the
operator sees in the full report. The ``--fail-on`` exit-code gate runs on the
same set, so the build outcome stays consistent across the two output modes.

This is **not** a replacement for the full ``--format json`` report: it carries
no per-finding detail (no layer attribution, no CVSS vector, no fix URLs), and
``--compare`` cannot consume it (compare diffs the full findings list). It is a
sibling output mode for the dashboard / metric-aggregation use case.

Zero new dependencies: stdlib ``json`` only, like the rest of casket. Network-
free: it consumes the in-memory finding set the rest of the scan already
produced, plus the network-free ``package_inventory``.
"""

from __future__ import annotations

import json
from typing import Any

from casket import __version__
from casket.findings import Finding


# Severity ordering used to bucket the histogram and to rank "top" CVEs.
# Mirrors the canonical rank used across scanner.py / findings.py — kept here
# so the summary module never imports a render-layer constant from findings.
_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# How many CVEs to surface in the ``top_cves`` preview. Small enough to keep
# the summary scannable in a CI log, large enough to cover the worst few
# findings on a typical busy image. The full list lives in the canonical
# --format json report; this is a dashboard preview, not a triage worksheet.
DEFAULT_TOP_CVES = 10


def build_summary(
    findings: list[Finding],
    *,
    image: str,
    scan_stats: dict[str, Any] | None = None,
    top_n: int = DEFAULT_TOP_CVES,
) -> dict[str, Any]:
    """Build the compact dashboard / metric-aggregation summary object.

    ``findings`` MUST be the already-filtered set (--min-severity, --min-epss,
    --vex, --suppress-ecosystem, --suppress-severity all applied) — the
    summary intentionally reports what the operator would see in the full
    report, never the pre-filter universe.

    ``scan_stats`` (when supplied) carries the component-count inventory
    block from ``casket.scanner.component_stats`` — total/vulnerable
    components and the per-ecosystem breakdown. The summary surfaces those
    counts as first-class keys (``total_components`` / ``vulnerable_components``
    / ``by_ecosystem``) so a dashboard consumer needn't reach into a nested
    object. When omitted, those keys are omitted too rather than reported as
    ``0`` / ``{}`` so absence (the operator didn't ask for inventory) stays
    distinguishable from "no packages found".

    ``top_n`` is the size of the ``top_cves`` preview (default 10). Pass 0 to
    omit the list entirely (a dashboard that only consumes the counts).
    """
    by_severity = _severity_histogram(findings)
    by_category = _category_histogram(findings)
    by_ecosystem_cve = _cve_ecosystem_histogram(findings)
    top_cves = _top_cves(findings, top_n) if top_n > 0 else []

    summary: dict[str, Any] = {
        "tool": "casket",
        "version": __version__,
        "image": image,
        "finding_count": len(findings),
        "by_severity": by_severity,
        "by_category": by_category,
        "by_ecosystem": by_ecosystem_cve,
    }
    if scan_stats is not None:
        # Surface the inventory counts as first-class keys. Use defensive
        # ``.get`` so a partial / future-extended scan_stats block never
        # raises here — missing keys are simply omitted from the summary.
        total = scan_stats.get("total_components")
        if total is not None:
            summary["total_components"] = total
        vulnerable = scan_stats.get("vulnerable_components")
        if vulnerable is not None:
            summary["vulnerable_components"] = vulnerable
        eco_inventory = scan_stats.get("by_ecosystem")
        if eco_inventory:
            summary["components_by_ecosystem"] = eco_inventory
    if top_n > 0:
        summary["top_cves"] = top_cves
    return summary


def render_summary_json(summary: dict[str, Any]) -> str:
    """Serialize the summary as a stable, indented JSON string.

    Indented (two-space) for human readability in CI logs; ``sort_keys=False``
    so the declared key order (``tool`` / ``version`` / ``image`` / counts /
    histograms / top_cves) stays stable across runs.
    """
    return json.dumps(summary, indent=2, sort_keys=False)


# ---- Histograms -----------------------------------------------------------


def _severity_histogram(findings: list[Finding]) -> dict[str, int]:
    """``{severity: count}`` over every finding, ordered most-severe-first.

    Recognised levels follow the canonical rank; an unrecognised severity is
    bucketed under ``"unknown"`` (sorted last) rather than dropped, mirroring
    ``scanner.component_stats``'s severity_histogram. Empty levels are omitted
    so the block stays compact.
    """
    counts: dict[str, int] = {}
    for f in findings:
        sev = f.severity if f.severity in _SEVERITY_RANK else "unknown"
        counts[sev] = counts.get(sev, 0) + 1
    return dict(
        sorted(counts.items(), key=lambda kv: _SEVERITY_RANK.get(kv[0], 99))
    )


def _category_histogram(findings: list[Finding]) -> dict[str, int]:
    """``{category: count}`` over every finding, ordered by descending count.

    Categories are the three check kinds (``creds`` / ``cve`` / ``misconfig``).
    Ordered by descending count then name for stable output so the noisiest
    category shows up first.
    """
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.category] = counts.get(f.category, 0) + 1
    return dict(sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])))


def _cve_ecosystem_histogram(findings: list[Finding]) -> dict[str, int]:
    """``{ecosystem: count}`` over CVE findings only (creds/misconfig carry none).

    Sorted by descending count then name. A CVE finding missing an
    ``ecosystem`` is bucketed under ``"unknown"`` (last, by name) rather than
    silently dropped, so a malformed entry never disappears from the count.
    """
    counts: dict[str, int] = {}
    for f in findings:
        if f.category != "cve":
            continue
        eco = f.detail.get("ecosystem")
        key = eco if isinstance(eco, str) and eco else "unknown"
        counts[key] = counts.get(key, 0) + 1
    return dict(sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])))


# ---- Top-N CVE preview ----------------------------------------------------


def _top_cve_sort_key(f: Finding) -> tuple[int, float, str]:
    """Sort key for the top-N CVE preview: severity asc (worse first),
    then EPSS desc (more likely-exploited first), then CVE id for stability.

    EPSS is converted to a *negative* float so a higher EPSS sorts earlier
    under Python's natural ascending sort. A finding without an EPSS score
    sorts after any finding *with* one at the same severity (it ranks at
    EPSS=0.0 — the conservative "no signal" position).
    """
    rank = _SEVERITY_RANK.get(f.severity, 99)
    raw = f.detail.get("epss_score")
    epss = float(raw) if isinstance(raw, (int, float)) else 0.0
    cve = f.detail.get("cve_id")
    cve_id = cve if isinstance(cve, str) else f.title
    return (rank, -epss, cve_id)


def _top_cves(findings: list[Finding], top_n: int) -> list[dict[str, Any]]:
    """Return the top-N CVE findings as a compact list of dicts.

    "Top" = worst by severity, then most likely to be exploited (EPSS desc),
    then CVE id (alphabetical, for stability). Only CVE-category findings are
    eligible — a dashboard preview for known-vulnerable packages, not for
    creds or misconfigs (those are surfaced via the ``by_category`` count).

    Each entry is a small, flat object with only the fields a dashboard /
    metric system needs (no per-finding ``detail`` blob, no layer attribution,
    no CVSS vector — those live in the full ``--format json`` report). Keys
    are omitted when the source detail is absent so a clean / seed-only run
    doesn't ship empty-string fields a dashboard would mistake for a value.
    """
    cves = [f for f in findings if f.category == "cve"]
    cves.sort(key=_top_cve_sort_key)
    preview: list[dict[str, Any]] = []
    for f in cves[:top_n]:
        entry: dict[str, Any] = {
            "severity": f.severity,
        }
        for src, dst in (
            ("cve_id", "cve_id"),
            ("package", "package"),
            ("installed_version", "installed_version"),
            ("ecosystem", "ecosystem"),
            ("epss_score", "epss_score"),
            ("cvss_score", "cvss_score"),
        ):
            value = f.detail.get(src)
            if value not in (None, ""):
                entry[dst] = value
        preview.append(entry)
    return preview
