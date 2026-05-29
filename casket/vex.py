"""VEX (Vulnerability Exploitability eXchange) suppression for casket.

A scanner that only ever *adds* findings is unusable on a real image: a busy
base layer carries dozens of OS-package CVEs that a vendor has already
triaged as *not exploitable in this image* (the vulnerable code path is never
reached, the affected component isn't shipped, a backported patch fixed it
without bumping the version string). Every mature scanner ships a way to
record that triage and suppress the noise — Trivy/Grype consume VEX, GitHub
consumes dismissals. casket consumes an **OpenVEX** document.

This module parses an OpenVEX-style JSON document into the set of
vulnerability identifiers an operator has declared *not affected* (or already
*fixed* out-of-band), so the report can drop those CVE findings instead of
crying wolf on every scan. The filter itself lives in ``scanner.py`` next to
the other report filters (``filter_by_severity`` / ``filter_by_epss``); this
module owns only the *parsing* of the VEX document into a suppression set.

The OpenVEX shape we read (https://github.com/openvex/spec), tolerantly:

    {
      "@context": "https://openvex.dev/ns/v0.2.0",
      "statements": [
        {
          "vulnerability": {"name": "CVE-2018-18074"},
          "status": "not_affected"
        },
        {"vulnerability": "CVE-2021-0001", "status": "fixed"}
      ]
    }

Suppressing statuses are ``not_affected`` and ``fixed`` — both mean "do not
report this against this image". ``affected`` / ``under_investigation``
statements are *not* suppressing (the operator is telling us to keep showing
them) and are ignored here. A ``vulnerability`` may be either an object with a
``name`` (the spec form) or a bare string (a common shorthand); either way we
take the identifier verbatim. Unknown statuses, missing fields, and non-string
identifiers are skipped defensively rather than raising — a hand-maintained
VEX file should never crash a scan.
"""

from __future__ import annotations

import json
from typing import Any

# OpenVEX statuses that mean "do not report this vulnerability against this
# image". ``affected`` and ``under_investigation`` are deliberately excluded:
# the operator is asserting the finding is real / still being triaged, so we
# keep surfacing it.
SUPPRESSING_STATUSES = frozenset({"not_affected", "fixed"})


class VEXError(ValueError):
    """A VEX document could not be parsed (malformed JSON or wrong shape)."""


def _vuln_id(vulnerability: Any) -> str | None:
    """Extract the vulnerability identifier from a statement's ``vulnerability``.

    The spec form is an object ``{"name": "CVE-..."}``; a bare string is also
    accepted as a common shorthand. Anything else yields ``None`` (the
    statement is skipped).
    """
    if isinstance(vulnerability, str):
        ident = vulnerability.strip()
        return ident or None
    if isinstance(vulnerability, dict):
        name = vulnerability.get("name")
        if isinstance(name, str):
            ident = name.strip()
            return ident or None
    return None


def parse_vex(text: str) -> set[str]:
    """Parse an OpenVEX JSON document into a set of suppressed vuln identifiers.

    Returns the set of vulnerability ids (CVE / GHSA / OSV / distro ids) whose
    most-recent statement carries a suppressing status (``not_affected`` /
    ``fixed``). Only the identifier string is kept — matching against a finding
    (by ``cve_id`` / ``osv_id`` / any alias) is the filter's job, not ours.

    Raises ``VEXError`` if the text is not valid JSON or is not an object with
    a list of ``statements``. Individual malformed statements are skipped (not
    fatal) — a single bad row shouldn't void an otherwise-usable VEX file.
    """
    try:
        doc = json.loads(text)
    except (ValueError, TypeError) as exc:
        raise VEXError(f"VEX document is not valid JSON: {exc}") from exc

    if not isinstance(doc, dict):
        raise VEXError("VEX document must be a JSON object")

    statements = doc.get("statements")
    if not isinstance(statements, list):
        raise VEXError("VEX document must carry a 'statements' array")

    suppressed: set[str] = set()
    for stmt in statements:
        if not isinstance(stmt, dict):
            continue
        status = stmt.get("status")
        if status not in SUPPRESSING_STATUSES:
            continue
        ident = _vuln_id(stmt.get("vulnerability"))
        if ident is not None:
            suppressed.add(ident)
    return suppressed


def load_vex(path: str) -> set[str]:
    """Read a VEX document from ``path`` and return its suppressed-id set.

    ``FileNotFoundError`` propagates (the CLI maps it to a clean exit 2);
    malformed content raises ``VEXError`` (also surfaced as exit 2). An empty
    suppression set (a syntactically-valid VEX file with no suppressing
    statements) is returned as-is — a no-op filter, not an error.
    """
    with open(path, encoding="utf-8") as fh:
        return parse_vex(fh.read())
