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

**Time-bounded expiry.** A triage assertion is a point-in-time judgement: a
CVE marked ``not_affected`` today may become relevant after a new layer, a new
dependency, or a freshly-disclosed exploit chain. A suppression that lives
forever silently is a stale-triage hazard — the operator stops seeing the CVE
and forgets it was ever waived. OpenVEX statements therefore carry a
``timestamp`` (and the document carries one the statements inherit). casket
reads those timestamps so the caller can enforce a maximum age: with
``--vex-max-age DAYS`` a suppressing statement older than the window is treated
as **expired** and its vuln re-surfaces in the report, forcing re-triage.
Parsing the timestamps is this module's job; applying the window is
``effective_suppression_set``.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

# OpenVEX statuses that mean "do not report this vulnerability against this
# image". ``affected`` and ``under_investigation`` are deliberately excluded:
# the operator is asserting the finding is real / still being triaged, so we
# keep surfacing it.
SUPPRESSING_STATUSES = frozenset({"not_affected", "fixed"})


class VEXError(ValueError):
    """A VEX document could not be parsed (malformed JSON or wrong shape)."""


@dataclass(frozen=True)
class VEXStatement:
    """One suppressing VEX statement: the vuln id and when it was asserted.

    ``timestamp`` is the statement's own ``timestamp`` if present, else the
    document-level ``timestamp`` it inherits (OpenVEX inheritance), else
    ``None`` when neither is present or either is unparseable. ``None`` means
    "undated": under the no-expiry path it suppresses unconditionally; under an
    age window it cannot be proven fresh and so is treated as expired (see
    ``effective_suppression_set``).
    """

    vuln_id: str
    timestamp: datetime | None


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


def _parse_timestamp(value: Any) -> datetime | None:
    """Parse an OpenVEX ISO-8601 ``timestamp`` into an aware UTC ``datetime``.

    OpenVEX timestamps are RFC 3339 / ISO-8601. We accept a trailing ``Z`` (the
    common spelling ``datetime.fromisoformat`` couldn't read before 3.11) and
    normalise everything to UTC so the age comparison is timezone-correct. A
    naive timestamp (no offset) is assumed UTC. Anything unparseable — or a
    non-string — yields ``None`` (the statement is then "undated"), never an
    exception: a hand-edited timestamp typo must not crash a scan.
    """
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text:
        return None
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def parse_vex_statements(text: str) -> list[VEXStatement]:
    """Parse an OpenVEX JSON document into a list of suppressing statements.

    Each returned ``VEXStatement`` pairs a suppressed vulnerability id (from a
    ``not_affected`` / ``fixed`` statement) with the timestamp at which the
    assertion was made — the statement's own ``timestamp`` if present, else the
    document-level ``timestamp`` it inherits (OpenVEX inheritance), else
    ``None``. This is the richer parse that powers time-bounded expiry;
    ``parse_vex`` is the no-expiry set wrapper over it.

    Raises ``VEXError`` if the text is not valid JSON or is not an object with
    a list of ``statements``. Individual malformed statements are skipped (not
    fatal) — a single bad row shouldn't void an otherwise-usable VEX file. A
    malformed timestamp is *not* fatal either: the statement is kept with a
    ``None`` timestamp (undated) rather than dropped.
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

    doc_ts = _parse_timestamp(doc.get("timestamp"))

    out: list[VEXStatement] = []
    for stmt in statements:
        if not isinstance(stmt, dict):
            continue
        status = stmt.get("status")
        if status not in SUPPRESSING_STATUSES:
            continue
        ident = _vuln_id(stmt.get("vulnerability"))
        if ident is None:
            continue
        ts = _parse_timestamp(stmt.get("timestamp"))
        if ts is None:
            ts = doc_ts
        out.append(VEXStatement(vuln_id=ident, timestamp=ts))
    return out


def parse_vex(text: str) -> set[str]:
    """Parse an OpenVEX JSON document into a set of suppressed vuln identifiers.

    Returns the set of vulnerability ids (CVE / GHSA / OSV / distro ids) whose
    statement carries a suppressing status (``not_affected`` / ``fixed``),
    *ignoring* timestamps — the no-expiry view. Only the identifier string is
    kept; matching against a finding (by ``cve_id`` / ``osv_id`` / any alias) is
    the filter's job, not ours. For time-bounded expiry use
    ``parse_vex_statements`` + ``effective_suppression_set``.

    Raises ``VEXError`` if the text is not valid JSON or is not an object with
    a list of ``statements``.
    """
    return {s.vuln_id for s in parse_vex_statements(text)}


def effective_suppression_set(
    statements: list[VEXStatement],
    max_age_days: int | None,
    *,
    now: datetime | None = None,
) -> set[str]:
    """Resolve suppressing statements to the live suppression set under a window.

    ``max_age_days`` is the operator's re-triage window:

      - ``None`` (no ``--vex-max-age``): expiry is off — every suppressing id is
        returned, exactly like ``parse_vex``. Timestamps are irrelevant.
      - a positive int: a statement suppresses only while it is *no older than*
        the window. A statement whose timestamp is more than ``max_age_days``
        before ``now`` has **expired** and its id is dropped (the vuln
        re-surfaces). A statement at *exactly* the window edge is still live
        (expiry is strictly older-than). An **undated** statement (no parseable
        timestamp anywhere) cannot be proven fresh, so under a window it is
        treated as expired and dropped — an unbounded, undated waiver must not
        silently outlive the chosen review window.

    ``now`` defaults to the current UTC time; it is injectable for testing.
    """
    if max_age_days is None:
        return {s.vuln_id for s in statements}

    current = now or datetime.now(timezone.utc)
    cutoff = current - timedelta(days=max_age_days)
    live: set[str] = set()
    for s in statements:
        if s.timestamp is None:
            continue  # undated -> cannot prove fresh -> expired under a window
        if s.timestamp >= cutoff:
            live.add(s.vuln_id)
    return live


def load_vex_statements(path: str) -> list[VEXStatement]:
    """Read a VEX document from ``path`` and return its suppressing statements.

    ``FileNotFoundError`` propagates (the CLI maps it to a clean exit 2);
    malformed content raises ``VEXError`` (also surfaced as exit 2).
    """
    with open(path, encoding="utf-8") as fh:
        return parse_vex_statements(fh.read())


def load_vex(path: str) -> set[str]:
    """Read a VEX document from ``path`` and return its suppressed-id set.

    The no-expiry view (timestamps ignored). ``FileNotFoundError`` propagates;
    malformed content raises ``VEXError``. An empty suppression set (a
    syntactically-valid VEX file with no suppressing statements) is returned
    as-is — a no-op filter, not an error.
    """
    return {s.vuln_id for s in load_vex_statements(path)}
