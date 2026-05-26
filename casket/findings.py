"""Finding data model and serialization for casket.

A Finding is the atomic unit of casket output. Every check (creds, cves,
misconfig) emits zero or more Findings. Findings carry layer attribution so an
operator can tell *which* image layer introduced an issue.

Output formats:
  - json: machine-readable list of findings (the canonical format)
  - h1md: a HackerOne-style markdown report for human submission

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


# Severity ordering used for sorting / h1md grouping.
_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


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
    raise ValueError(f"unknown format: {fmt!r}")


def _render_json(findings: list[Finding], *, image: str) -> str:
    payload = {
        "tool": "casket",
        "image": image,
        "finding_count": len(findings),
        "findings": [f.to_dict() for f in findings],
    }
    return json.dumps(payload, indent=2, sort_keys=False)


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
