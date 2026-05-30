"""Diff two casket scan reports — what's new, gone, or changed.

[Worker decision: --compare diff mode — Rotation 18, POST_V01 Item 16]
A container image is rebuilt constantly. The operator question that drives CI is
rarely "what findings does this image have?" (the absolute set is often a large,
slow-moving wall of OS-package CVEs) but "did *this* build introduce anything
new versus the last known-good scan?". casket already emits a canonical JSON
report; this module compares two of them and classifies every finding as
``added`` (a regression — present now, absent in the baseline), ``removed``
(fixed/gone), ``changed`` (the same finding, but its severity moved — e.g. a
CVE re-scored from medium to critical), or ``unchanged``.

The hard part of a diff is *identity*: which finding in the current scan is "the
same" finding as one in the baseline? We deliberately fingerprint on the
finding's **semantic identity**, not on volatile build artifacts:

  - ``layer_sha`` is excluded — a rebuild produces fresh layer digests for
    byte-identical content, so keying on it would report every finding as
    added+removed on every rebuild (useless).
  - ``summary`` / ``layer_command`` are excluded — descriptive, not identifying;
    an OSV summary edit must not masquerade as a new finding.
  - ``severity`` is excluded from *identity* but compared *separately*: a finding
    whose identity matches but whose severity moved is ``changed``, surfacing
    re-scored CVEs (exactly what the Rotation 9–16 severity-accuracy arc makes
    worth watching) without losing the finding to an added/removed pair.

Per category the identity key is the minimal set that pins the issue:

  - ``cve``:      category + cve_id + osv_id + package + ecosystem +
                  installed_version  (the same CVE on the same package version)
  - ``creds``:    category + rule + path_in_layer  (the same secret rule firing
                  on the same file path)
  - ``misconfig``: category + rule + the salient detail value (port / user / …)
  - fallback:     category + rule-or-title + path_in_layer

This module is pure data-in / data-out (stdlib ``json`` only, no network, no I/O
beyond what the caller hands it), so it is trivially testable and composes with
every existing output path.
"""

from __future__ import annotations

import json
from typing import Any

# Detail keys that identify *which issue* a finding is, per category. Order is
# significant only for readability of the fingerprint; the tuple is hashed whole.
_IDENTITY_DETAIL_KEYS: dict[str, tuple[str, ...]] = {
    "cve": ("cve_id", "osv_id", "package", "ecosystem", "installed_version"),
    "creds": ("rule",),
    "misconfig": ("rule", "port", "user", "env_var"),
}

# Detail keys that never contribute to identity (descriptive / volatile).
_VOLATILE_DETAIL_KEYS = frozenset({"summary", "layer_command", "severity"})


def finding_fingerprint(finding: dict[str, Any]) -> str:
    """A stable identity string for a finding across two scans.

    Built from the finding's category and its category-specific identifying
    detail keys (plus ``path_in_layer`` where the path *is* the identity, as for
    creds and the generic fallback). Excludes ``layer_sha``, ``severity``, and
    the volatile descriptive keys, so a rebuild of byte-identical content yields
    the same fingerprint and a severity re-score does not look like a new
    finding.
    """
    category = str(finding.get("category", ""))
    parts: list[str] = [category]

    if category == "cve":
        for key in _IDENTITY_DETAIL_KEYS["cve"]:
            parts.append(f"{key}={finding.get(key, '')}")
    elif category == "creds":
        parts.append(f"rule={finding.get('rule', '')}")
        parts.append(f"path={finding.get('path_in_layer', '')}")
    elif category == "misconfig":
        # The rule plus whichever salient value pins this particular instance
        # (an exposed *port*, a running *user*, an *env_var*); empty if absent.
        parts.append(f"rule={finding.get('rule', '')}")
        for key in ("port", "user", "env_var"):
            if key in finding and finding[key] not in (None, ""):
                parts.append(f"{key}={finding[key]}")
    else:
        # Generic fallback: a rule-or-title plus path.
        parts.append(f"id={finding.get('rule') or finding.get('title', '')}")
        parts.append(f"path={finding.get('path_in_layer', '')}")

    return "|".join(parts)


def _index(findings: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Index findings by fingerprint. Later duplicates keep the first seen.

    Two findings with an identical fingerprint are, by construction, the same
    issue; we keep the first so the diff is deterministic.
    """
    out: dict[str, dict[str, Any]] = {}
    for f in findings:
        fp = finding_fingerprint(f)
        out.setdefault(fp, f)
    return out


def diff_reports(
    baseline: dict[str, Any], current: dict[str, Any]
) -> dict[str, Any]:
    """Compare two canonical casket JSON reports.

    ``baseline`` and ``current`` are the parsed objects casket's json renderer
    emits (``{"tool", "image", "finding_count", "findings": [...]}``). Returns a
    diff document:

        {
          "tool": "casket",
          "diff": true,
          "baseline_image": "<from baseline.image>",
          "current_image":  "<from current.image>",
          "summary": {"added": N, "removed": N, "changed": N, "unchanged": N},
          "added":     [ <current finding>, ... ],   # regressions
          "removed":   [ <baseline finding>, ... ],  # fixed / gone
          "changed":   [ {"from_severity", "to_severity", "finding"}, ... ],
          "unchanged": [ <current finding>, ... ],
        }

    A *changed* entry carries the current finding plus the severity it moved
    from/to — the common case being a CVE re-scored by an OSV update or a casket
    severity-calculator improvement.
    """
    base_findings = baseline.get("findings", []) or []
    cur_findings = current.get("findings", []) or []

    base_idx = _index(base_findings)
    cur_idx = _index(cur_findings)

    added: list[dict[str, Any]] = []
    removed: list[dict[str, Any]] = []
    changed: list[dict[str, Any]] = []
    unchanged: list[dict[str, Any]] = []

    for fp, cur in cur_idx.items():
        base = base_idx.get(fp)
        if base is None:
            added.append(cur)
            continue
        base_sev = base.get("severity")
        cur_sev = cur.get("severity")
        if base_sev != cur_sev:
            changed.append(
                {
                    "from_severity": base_sev,
                    "to_severity": cur_sev,
                    "finding": cur,
                }
            )
        else:
            unchanged.append(cur)

    for fp, base in base_idx.items():
        if fp not in cur_idx:
            removed.append(base)

    return {
        "tool": "casket",
        "diff": True,
        "baseline_image": baseline.get("image"),
        "current_image": current.get("image"),
        "summary": {
            "added": len(added),
            "removed": len(removed),
            "changed": len(changed),
            "unchanged": len(unchanged),
        },
        "added": added,
        "removed": removed,
        "changed": changed,
        "unchanged": unchanged,
    }


def render_diff_json(diff: dict[str, Any]) -> str:
    """Serialize a diff document as indented JSON (the canonical diff format)."""
    return json.dumps(diff, indent=2, sort_keys=False)


# Severity rank for ordering h1md diff sections; mirrors the rank used by the
# findings renderer so the worst regressions sort first. Unknown / missing
# severities sink to the bottom.
_DIFF_SEVERITY_RANK: dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}


def _diff_severity_key(finding: dict[str, Any]) -> int:
    return _DIFF_SEVERITY_RANK.get(str(finding.get("severity", "")), 99)


def _finding_one_liner(finding: dict[str, Any]) -> str:
    """A compact, scannable one-line description of a finding for the diff.

    The full per-finding detail already lives in the JSON diff (and in a fresh
    ``--format h1md`` scan); the diff h1md is a triage summary — operators want
    "what changed?" at a glance, not a re-render of every detail field.
    """
    severity = str(finding.get("severity", "?")).upper()
    category = finding.get("category", "")
    if category == "cve":
        cve_id = finding.get("cve_id") or finding.get("osv_id") or "?"
        package = finding.get("package") or "?"
        version = finding.get("installed_version") or "?"
        ecosystem = finding.get("ecosystem")
        eco_suffix = f" [{ecosystem}]" if ecosystem else ""
        return f"- **[{severity}]** `{cve_id}` — `{package}@{version}`{eco_suffix}"
    if category == "creds":
        rule = finding.get("rule") or finding.get("title") or "?"
        path = finding.get("path_in_layer") or "?"
        return f"- **[{severity}]** `{rule}` — `{path}`"
    if category == "misconfig":
        rule = finding.get("rule") or finding.get("title") or "?"
        bits = []
        for key in ("port", "user", "env_var"):
            value = finding.get(key)
            if value not in (None, ""):
                bits.append(f"{key}=`{value}`")
        detail = (" " + ", ".join(bits)) if bits else ""
        return f"- **[{severity}]** `{rule}`{detail}"
    # Fallback: surface whatever identifying fields we have without crashing.
    title = finding.get("title") or finding.get("rule") or "?"
    path = finding.get("path_in_layer") or ""
    suffix = f" — `{path}`" if path else ""
    return f"- **[{severity}]** {title}{suffix}"


def render_diff_h1md(diff: dict[str, Any]) -> str:
    """Render a diff document as human-readable Markdown (h1md).

    Mirrors the structure of the JSON diff (added / removed / changed /
    unchanged) but as a Markdown summary sized for a PR comment, Slack snippet,
    or build-log artifact. The JSON diff stays the authoritative machine form
    (still consumable by other tools); this is the operator-facing view.

    Sections sort worst-severity-first within each bucket so the most dangerous
    regressions sit at the top. ``unchanged`` collapses to a count line — the
    operator looking at a diff cares about deltas, not the stable wall.
    """
    summary = diff.get("summary") or {}
    added = list(diff.get("added") or [])
    removed = list(diff.get("removed") or [])
    changed = list(diff.get("changed") or [])
    unchanged_count = int(summary.get("unchanged", len(diff.get("unchanged") or [])))

    added.sort(key=_diff_severity_key)
    removed.sort(key=_diff_severity_key)
    # `changed` entries wrap a finding under a "finding" key; sort by that.
    changed.sort(key=lambda c: _diff_severity_key(c.get("finding") or {}))

    lines: list[str] = []
    lines.append("# casket scan diff")
    lines.append("")
    baseline_image = diff.get("baseline_image") or "?"
    current_image = diff.get("current_image") or "?"
    lines.append(f"- **baseline:** `{baseline_image}`")
    lines.append(f"- **current:** `{current_image}`")
    lines.append("")
    lines.append(
        "**Summary:** "
        f"added `{len(added)}`, "
        f"removed `{len(removed)}`, "
        f"changed `{len(changed)}`, "
        f"unchanged `{unchanged_count}`"
    )
    lines.append("")

    # Added: NEW findings since the baseline — the regression signal.
    lines.append(f"## Added ({len(added)})")
    lines.append("")
    if added:
        lines.append(
            "_New findings introduced by this build (regressions)._"
        )
        lines.append("")
        for f in added:
            lines.append(_finding_one_liner(f))
        lines.append("")
    else:
        lines.append("_No new findings._")
        lines.append("")

    # Removed: findings that disappeared between baseline and current — wins.
    lines.append(f"## Removed ({len(removed)})")
    lines.append("")
    if removed:
        lines.append("_Findings present in the baseline that are gone now._")
        lines.append("")
        for f in removed:
            lines.append(_finding_one_liner(f))
        lines.append("")
    else:
        lines.append("_None._")
        lines.append("")

    # Changed: same finding, severity moved (the OSV/CVSS re-score signal).
    lines.append(f"## Changed ({len(changed)})")
    lines.append("")
    if changed:
        lines.append("_Same finding, severity moved (re-scored)._")
        lines.append("")
        for entry in changed:
            finding = entry.get("finding") or {}
            from_sev = str(entry.get("from_severity", "?")).upper()
            to_sev = str(entry.get("to_severity", "?")).upper()
            base_line = _finding_one_liner(finding)
            # Replace the leading severity tag with a from->to arrow so the
            # operator sees the movement, not just the current band.
            # _finding_one_liner always starts with "- **[SEV]** ", so splice.
            prefix, _, rest = base_line.partition("** ")
            lines.append(f"- **[{from_sev} -> {to_sev}]** {rest}")
        lines.append("")
    else:
        lines.append("_None._")
        lines.append("")

    # Unchanged collapses to a count: the diff exists to surface deltas.
    lines.append(f"## Unchanged ({unchanged_count})")
    lines.append("")
    lines.append(
        f"_{unchanged_count} finding(s) carry over from the baseline unchanged._"
    )
    lines.append("")

    return "\n".join(lines) + "\n"


def load_baseline_report(path: str) -> dict[str, Any]:
    """Load and minimally validate a baseline casket JSON report from disk.

    Raises ``ValueError`` with a clear message if the file isn't a JSON object
    carrying a ``findings`` list — so the CLI can surface a clean error rather
    than a traceback or a silently-empty diff.
    """
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, dict) or not isinstance(data.get("findings"), list):
        raise ValueError(
            f"{path!r} is not a casket JSON report "
            "(expected an object with a 'findings' array)"
        )
    return data


def regression_count(diff: dict[str, Any]) -> int:
    """Number of *new* findings (the CI-actionable regression signal).

    A build that adds findings versus its baseline is the thing a gate should
    catch. ``changed`` (re-scored) findings are intentionally *not* counted as
    regressions here — they were already present; only their severity moved —
    so the diff gate stays a clean "did this build introduce something new?".
    """
    return len(diff.get("added", []) or [])
