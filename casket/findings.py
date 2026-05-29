"""Finding data model and serialization for casket.

A Finding is the atomic unit of casket output. Every check (creds, cves,
misconfig) emits zero or more Findings. Findings carry layer attribution so an
operator can tell *which* image layer introduced an issue.

Output formats:
  - json:  machine-readable list of findings (the canonical format)
  - h1md:  a HackerOne-style markdown report for human submission
  - sarif: SARIF 2.1.0 for GitHub Advanced Security / CI code-scanning ingest

[Worker decision: layer attribution model]
Every finding carries `layer_sha` (the digest of the layer that introduced it)
and, where applicable, `path_in_layer` (the file inside that layer). Misconfig
findings derived from image *config* rather than a layer filesystem use the
config's own descriptor digest as the layer_sha and a synthetic path of
"<image config>" so the JSON shape stays uniform across all categories.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from typing import Any

from casket import __version__

# Severity ordering used for sorting / h1md grouping.
_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# SARIF 2.1.0 schema URL and severity → result.level mapping.
_SARIF_SCHEMA = (
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/"
    "sarif-schema-2.1.0.json"
)
_SARIF_INFO_URI = "https://github.com/bugsyhewitt/casket"
_SEVERITY_TO_SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}

# GitHub code-scanning sorts and gates findings by the CVSS-like float in
# ``properties.security-severity`` (a *string*, per GitHub's ingest contract).
# Values follow POST_V01 Item 2: critical=9.5, high=7.5, medium=5.0, low=2.0,
# info=0.0. The float lands on both the rule's defaultConfiguration-adjacent
# ``properties`` (where GitHub reads it) and each result's properties.
_SEVERITY_TO_SECURITY_SEVERITY = {
    "critical": "9.5",
    "high": "7.5",
    "medium": "5.0",
    "low": "2.0",
    "info": "0.0",
}


@dataclass
class Finding:
    """A single scan finding with layer attribution."""

    category: str  # "creds" | "cve" | "misconfig"
    title: str
    severity: str  # critical | high | medium | low | info
    layer_sha: str
    path_in_layer: str
    detail: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        base = asdict(self)
        # Flatten the detail dict to top level so consumers can find e.g.
        # "cve_id", "package", "rule" directly on the finding object as the
        # v0.1 criteria require, while keeping a nested copy for completeness.
        for key, value in self.detail.items():
            base[key] = value
        return base


def _severity_key(finding: Finding) -> tuple[int, str]:
    return (_SEVERITY_RANK.get(finding.severity, 99), finding.category)


def render(findings: list[Finding], fmt: str, *, image: str) -> str:
    """Render findings in the requested format."""
    ordered = sorted(findings, key=_severity_key)
    if fmt == "json":
        return _render_json(ordered, image=image)
    if fmt == "h1md":
        return _render_h1md(ordered, image=image)
    if fmt == "sarif":
        return _render_sarif(ordered, image=image)
    raise ValueError(f"unknown format: {fmt!r}")


def report_dict(findings: list[Finding], *, image: str) -> dict[str, Any]:
    """Build the canonical casket JSON report object (sorted by severity).

    This is the in-memory form of the ``--format json`` output; ``_render_json``
    serializes it, and ``--compare`` consumes it directly without a serialize /
    re-parse round-trip.
    """
    ordered = sorted(findings, key=_severity_key)
    return {
        "tool": "casket",
        "image": image,
        "finding_count": len(ordered),
        "findings": [f.to_dict() for f in ordered],
    }


def _render_json(findings: list[Finding], *, image: str) -> str:
    return json.dumps(report_dict(findings, image=image), indent=2, sort_keys=False)


def _render_h1md(findings: list[Finding], *, image: str) -> str:
    lines: list[str] = []
    lines.append(f"# casket scan report: `{image}`")
    lines.append("")
    lines.append(f"**Findings:** {len(findings)}")
    lines.append("")
    if not findings:
        lines.append("_No findings._")
        return "\n".join(lines) + "\n"

    for f in findings:
        lines.append(f"## [{f.severity.upper()}] {f.title}")
        lines.append("")
        lines.append(f"- **category:** `{f.category}`")
        lines.append(f"- **layer:** `{f.layer_sha}`")
        lines.append(f"- **path:** `{f.path_in_layer}`")
        for key, value in f.detail.items():
            lines.append(f"- **{key}:** `{value}`")
        lines.append("")
    return "\n".join(lines) + "\n"


def _sarif_rule_id(finding: Finding) -> str:
    """Stable rule identifier for a finding.

    creds / misconfig findings carry a ``rule`` slug in ``detail``; cve findings
    carry a ``cve_id``. We namespace by category so ids stay unambiguous across
    check types and never collide (e.g. a rule slug equal to a CVE alias).
    """
    detail = finding.detail
    slug = detail.get("rule") or detail.get("cve_id") or finding.category
    return f"{finding.category}/{slug}"


def _sarif_level(severity: str) -> str:
    return _SEVERITY_TO_SARIF_LEVEL.get(severity, "warning")


def _security_severity(severity: str) -> str:
    """CVSS-like float (as a string) GitHub code-scanning sorts/gates on."""
    return _SEVERITY_TO_SECURITY_SEVERITY.get(severity, "5.0")


def _sarif_message(finding: Finding) -> str:
    """Human-readable result message, enriched with the salient detail fields."""
    parts = [finding.title]
    detail = finding.detail
    if finding.category == "cve":
        summary = detail.get("summary")
        if summary:
            parts.append(str(summary))
    extras = []
    for key in ("package", "installed_version", "ecosystem", "port", "env_var", "user"):
        if key in detail and detail[key] not in (None, ""):
            extras.append(f"{key}={detail[key]}")
    if extras:
        parts.append("(" + ", ".join(extras) + ")")
    return " ".join(parts)


def _render_sarif(findings: list[Finding], *, image: str) -> str:
    """Render findings as a SARIF 2.1.0 document.

    One ``rule`` per distinct finding type (deduped by rule id), one ``result``
    per finding. Locations use ``artifactLocation.uri`` pointing at the layer
    path inside the image so GitHub code-scanning attributes the issue to a
    concrete artifact; the image ref and layer digest ride along as properties.
    """
    rules: list[dict[str, Any]] = []
    rule_index: dict[str, int] = {}
    results: list[dict[str, Any]] = []

    for f in findings:
        rule_id = _sarif_rule_id(f)
        if rule_id not in rule_index:
            rule_index[rule_id] = len(rules)
            rules.append(
                {
                    "id": rule_id,
                    "name": f.category,
                    "shortDescription": {"text": f.title},
                    "defaultConfiguration": {"level": _sarif_level(f.severity)},
                    "properties": {
                        "category": f.category,
                        "severity": f.severity,
                        # GitHub code-scanning reads the CVSS-like float here on
                        # the reportingDescriptor to sort/gate by severity.
                        "security-severity": _security_severity(f.severity),
                    },
                }
            )

        # SARIF requires a non-empty artifact URI. Synthetic config "paths"
        # (e.g. "<image config>") are not real files, so flag them as logical.
        uri = f.path_in_layer or "<unknown>"
        results.append(
            {
                "ruleId": rule_id,
                "ruleIndex": rule_index[rule_id],
                "level": _sarif_level(f.severity),
                "message": {"text": _sarif_message(f)},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": uri}
                        }
                    }
                ],
                "properties": {
                    "category": f.category,
                    "severity": f.severity,
                    "security-severity": _security_severity(f.severity),
                    "image": image,
                    "layer_sha": f.layer_sha,
                    **{k: v for k, v in f.detail.items()},
                },
            }
        )

    doc = {
        "$schema": _SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "casket",
                        "version": __version__,
                        "informationUri": _SARIF_INFO_URI,
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(doc, indent=2, sort_keys=False)
