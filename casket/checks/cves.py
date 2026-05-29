"""CVE check: extract installed packages from layers, query OSV.dev.

[Worker decision: package extraction scope for v0.1]
We extract packages from four common, easy-to-parse, daemonless sources:

  - PyPI:   ``*.dist-info/METADATA`` and ``*.egg-info/PKG-INFO`` (Name/Version)
  - Debian: ``var/lib/dpkg/status`` (Package/Version stanzas)
  - Alpine: ``lib/apk/db/installed`` (APKINDEX P:/V: stanzas)
  - RPM:    ``var/lib/rpm/rpmdb.sqlite`` (RHEL 9+/Fedora/Amazon Linux 2023)

This covers the bundled ``old-package`` fixture and the most common real images
without pulling in a heavyweight SBOM library — staying within the v0.1
"no SBOM generation" guardrail. Each discovered package version is resolved
against OSV.dev (cache-first via ``casket.osv``).

[Worker decision: RPM extraction scope — Rotation 6, POST_V01 Item 4]
Only the modern SQLite rpmdb (``var/lib/rpm/rpmdb.sqlite``, RHEL 9+, Fedora,
Amazon Linux 2023) is supported. The legacy Berkeley DB rpmdb
(``var/lib/rpm/Packages`` on RHEL 7/8 / CentOS 7) has no stdlib parser and
would require the ``rpm`` C bindings or a hand-rolled BDB decoder — out of
scope for this single focused change. A legacy ``Packages`` file present
without a ``rpmdb.sqlite`` is silently skipped (no finding, no error, never a
crash). The SQLite path stores each installed package as a binary RPM *header*
blob in a ``Packages(hnum, blob)`` table; we parse that header format directly
with stdlib ``struct`` to pull NAME/VERSION/RELEASE/EPOCH/ARCH — no native
dependency. OSV ecosystem name: ``"Red Hat"`` (per osv.dev's ecosystem list);
we tag RPM packages with the bare ecosystem so the cache-first / seed DB path
resolves them deterministically offline, mirroring the Alpine decision above.

[Worker decision: Alpine release-qualified ecosystem — Rotation 10, POST_V01 Item 8]
OSV.dev keys Alpine vulns under release-qualified ecosystems like
``Alpine:v3.18``, not a bare ``Alpine``. The Rotation 2 implementation tagged
Alpine packages with the bare ecosystem ``"Alpine"``, which the bundled seed
DB / disk cache resolve fine — but a *live* OSV.dev query for bare ``Alpine``
returns nothing, so casket's flagship Alpine CVE coverage was effectively
seed-only against the real API. This rotation closes that gap: we read
``etc/alpine-release`` (a one-line plaintext version, e.g. ``3.18.4``) from the
image, derive the release-qualified ecosystem ``Alpine:vMAJOR.MINOR``
(``Alpine:v3.18``), and query that *first*, falling back to bare ``Alpine``.
The release-qualified name is what the live API needs; the bare fallback keeps
the seed DB and warm cache (both keyed on bare ``Alpine``) resolving offline
exactly as before. If no ``etc/alpine-release`` is present we query bare
``Alpine`` only — identical to the previous behaviour, never a crash.

[Worker decision: Debian/Ubuntu release-qualified ecosystem — Rotation 11]
The exact gap Rotation 10 closed for Alpine also exists for Debian: OSV.dev
keys Debian vulns under release-qualified ecosystems like ``Debian:12`` (the
major release number), not a bare ``Debian``. dpkg packages were tagged with
the bare ecosystem ``"Debian"`` since v0.1, so a *live* OSV.dev query returned
nothing — Debian CVE coverage was effectively seed-only against the real API.
This rotation mirrors the Alpine fix: we read the Debian release from the image
(``etc/debian_version`` — a one-line version like ``12.4`` — falling back to the
``VERSION_ID`` field of ``etc/os-release`` for Ubuntu and minimal images),
derive the release-qualified ecosystem ``Debian:MAJOR`` (``Debian:12``), and
query that *first*, falling back to bare ``Debian``. The bare fallback keeps the
seed DB and warm cache (keyed on bare ``Debian``) resolving offline exactly as
before. If no release marker is present we query bare ``Debian`` only —
identical to the previous behaviour, never a crash. The reported
``detail["ecosystem"]`` stays the bare ``"Debian"`` for output uniformity, as
with Alpine; the qualifier is a query-time concern only.
"""

from __future__ import annotations

import os
import re
import sqlite3
import struct
import tempfile
from dataclasses import dataclass
from typing import Any

from casket.findings import Finding
from casket.oci import Image, Layer
from casket.osv import OSVClient

_DIST_INFO_RE = re.compile(r"\.(dist-info|egg-info)/(METADATA|PKG-INFO)$")
_DPKG_STATUS = "var/lib/dpkg/status"
_APK_INSTALLED = "lib/apk/db/installed"
_RPMDB_SQLITE = "var/lib/rpm/rpmdb.sqlite"
_ALPINE_RELEASE = "etc/alpine-release"
_DEBIAN_VERSION = "etc/debian_version"
_OS_RELEASE = "etc/os-release"

# An Alpine release line looks like ``3.18.4`` (or rarely ``3.18``). We keep the
# MAJOR.MINOR pair to build the OSV ecosystem qualifier ``Alpine:vMAJOR.MINOR``.
_ALPINE_RELEASE_RE = re.compile(r"^(\d+)\.(\d+)(?:\.\d+)?")

# A Debian version line looks like ``12.4`` or ``12`` (and sometimes a testing
# codename like ``bookworm/sid`` — non-numeric, which we ignore). We keep the
# MAJOR number to build the OSV ecosystem qualifier ``Debian:MAJOR``.
_DEBIAN_VERSION_RE = re.compile(r"^(\d+)(?:\.\d+)*")
# In etc/os-release, the release number lives in ``VERSION_ID="12"`` (the value
# may or may not be quoted). We pull the leading integer of that value.
_OS_RELEASE_VERSION_ID_RE = re.compile(
    r'^VERSION_ID\s*=\s*"?(\d+)', re.MULTILINE
)

# RPM header tags we care about (see lib/rpmtag.h in the rpm sources).
_RPMTAG_NAME = 1000
_RPMTAG_VERSION = 1001
_RPMTAG_RELEASE = 1002
_RPMTAG_EPOCH = 1003
_RPMTAG_ARCH = 1022

# RPM header field type codes (see lib/header.h: rpmTagType_e).
_RPM_INT32_TYPE = 4
_RPM_STRING_TYPE = 6
_RPM_I18NSTRING_TYPE = 9


@dataclass(frozen=True)
class Package:
    ecosystem: str  # OSV ecosystem name, e.g. "PyPI", "Debian"
    name: str
    version: str
    layer_sha: str
    path_in_layer: str


def _parse_pypi_metadata(text: str) -> tuple[str | None, str | None]:
    name = version = None
    for line in text.splitlines():
        if line.startswith("Name:"):
            name = line.split(":", 1)[1].strip()
        elif line.startswith("Version:"):
            version = line.split(":", 1)[1].strip()
        if name and version:
            break
    return name, version


def _parse_dpkg_status(text: str) -> list[tuple[str, str]]:
    pkgs = []
    name = version = None
    for line in text.splitlines():
        if line.startswith("Package:"):
            name = line.split(":", 1)[1].strip()
        elif line.startswith("Version:"):
            version = line.split(":", 1)[1].strip()
        elif line.strip() == "":
            if name and version:
                pkgs.append((name, version))
            name = version = None
    if name and version:
        pkgs.append((name, version))
    return pkgs


def _parse_apk_installed(text: str) -> list[tuple[str, str]]:
    """Parse an Alpine ``lib/apk/db/installed`` database.

    The file is plaintext APKINDEX format: one stanza per installed package,
    stanzas separated by blank lines, each line a single ``K:value`` field.
    We only need ``P`` (package name) and ``V`` (version)::

        P:musl
        V:1.2.3-r4
        T:the musl c library
        ...

        P:busybox
        V:1.36.0-r0
        ...
    """
    pkgs: list[tuple[str, str]] = []
    name = version = None
    for line in text.splitlines():
        if line.startswith("P:"):
            name = line[2:].strip()
        elif line.startswith("V:"):
            version = line[2:].strip()
        elif line.strip() == "":
            if name and version:
                pkgs.append((name, version))
            name = version = None
    if name and version:
        pkgs.append((name, version))
    return pkgs


def _parse_alpine_release(text: str) -> str | None:
    """Derive the OSV ecosystem qualifier from an ``etc/alpine-release`` line.

    The file holds a single version like ``3.18.4`` (sometimes ``3.18`` or with
    a trailing ``_alpha``/edge marker). We extract MAJOR.MINOR and return the
    OSV ecosystem qualifier ``Alpine:vMAJOR.MINOR`` (e.g. ``Alpine:v3.18``).
    Returns ``None`` if no recognisable version is found — the caller then
    falls back to the bare ``Alpine`` ecosystem.
    """
    for line in text.splitlines():
        m = _ALPINE_RELEASE_RE.match(line.strip())
        if m:
            return f"Alpine:v{m.group(1)}.{m.group(2)}"
    return None


def _detect_alpine_ecosystem(image: Image) -> str | None:
    """Scan an image for ``etc/alpine-release`` and return its ecosystem tag.

    ``etc/alpine-release`` and ``lib/apk/db/installed`` can live in different
    layers, so release detection is an image-level pass: the first layer that
    carries a parseable release wins. Returns the release-qualified ecosystem
    (e.g. ``Alpine:v3.18``) or ``None`` if no release marker is present.
    """
    for layer in image.layers:
        for path, _size, reader in layer.iter_files():
            if path == _ALPINE_RELEASE:
                text = reader().decode("utf-8", errors="ignore")
                qualified = _parse_alpine_release(text)
                if qualified:
                    return qualified
    return None


def _parse_debian_version(text: str) -> str | None:
    """Derive the OSV ecosystem qualifier from an ``etc/debian_version`` line.

    The file holds a single version like ``12.4`` (sometimes a bare major
    ``12``, or a testing codename like ``bookworm/sid`` which is non-numeric).
    OSV keys Debian vulns under the *major* release number, so we extract MAJOR
    and return ``Debian:MAJOR`` (e.g. ``Debian:12``). Returns ``None`` if no
    recognisable numeric version is found — the caller then derives the release
    from ``etc/os-release`` or falls back to the bare ``Debian`` ecosystem.
    """
    for line in text.splitlines():
        m = _DEBIAN_VERSION_RE.match(line.strip())
        if m:
            return f"Debian:{m.group(1)}"
    return None


def _parse_os_release_debian(text: str) -> str | None:
    """Derive ``Debian:MAJOR`` from an ``etc/os-release`` ``VERSION_ID``.

    Ubuntu, Debian-slim and other minimal images often carry ``etc/os-release``
    but no ``etc/debian_version``. The ``VERSION_ID`` field holds the numeric
    release (``VERSION_ID="12"`` on Debian 12, ``VERSION_ID="22.04"`` on Ubuntu
    22.04). OSV keys Debian-family vulns under the major number, so we return
    ``Debian:MAJOR``. Returns ``None`` if no numeric ``VERSION_ID`` is present.
    """
    m = _OS_RELEASE_VERSION_ID_RE.search(text)
    if m:
        return f"Debian:{m.group(1)}"
    return None


def _detect_debian_ecosystem(image: Image) -> str | None:
    """Scan an image for a Debian release marker and return its ecosystem tag.

    The release marker (``etc/debian_version`` or ``etc/os-release``) and the
    package db (``var/lib/dpkg/status``) can live in different layers, so
    detection is an image-level pass. ``etc/debian_version`` is preferred; we
    fall back to the ``VERSION_ID`` of ``etc/os-release`` (Ubuntu / slim images).
    The first layer that yields a parseable release wins. Returns the
    release-qualified ecosystem (e.g. ``Debian:12``) or ``None`` if no release
    marker is present.
    """
    os_release_candidate: str | None = None
    for layer in image.layers:
        for path, _size, reader in layer.iter_files():
            if path == _DEBIAN_VERSION:
                text = reader().decode("utf-8", errors="ignore")
                qualified = _parse_debian_version(text)
                if qualified:
                    return qualified
            elif path == _OS_RELEASE and os_release_candidate is None:
                text = reader().decode("utf-8", errors="ignore")
                os_release_candidate = _parse_os_release_debian(text)
    return os_release_candidate


def _parse_rpm_header(blob: bytes) -> dict[str, str]:
    """Parse a single binary RPM header blob into the fields casket needs.

    The SQLite rpmdb stores each installed package as the package's RPM
    *header* in its native binary form (the same structure rpm uses on the
    wire). The layout is::

        [ 8-byte region trailer / lead ... ] (may be absent in the db blob)
        4 bytes  index entry count   (big-endian uint32)
        4 bytes  data store length    (big-endian uint32)
        index entries: count * 16 bytes, each:
            4 bytes tag     (big-endian uint32)
            4 bytes type    (big-endian uint32)
            4 bytes offset  (big-endian int32, into the data store)
            4 bytes count   (big-endian uint32)
        data store: <data length> bytes

    Blobs taken straight from the sqlite ``Packages.blob`` column begin at the
    index-count word (no 8-byte header magic). We parse defensively: any
    malformed blob yields an empty dict rather than raising, so a single bad
    package never aborts a scan.
    """
    try:
        if len(blob) < 8:
            return {}
        # Some rpm versions prefix an 8-byte header magic
        # (\x8e\xad\xe8\x01 + 4 reserved). Skip it if present.
        offset = 0
        if blob[:4] == b"\x8e\xad\xe8\x01":
            offset = 8
        (index_count, data_len) = struct.unpack_from(">II", blob, offset)
        offset += 8
        index_size = index_count * 16
        if index_count <= 0 or index_count > 100_000:
            return {}
        if offset + index_size > len(blob):
            return {}
        store_start = offset + index_size
        store_end = store_start + data_len
        if store_end > len(blob):
            store_end = len(blob)
        store = blob[store_start:store_end]

        wanted = {
            _RPMTAG_NAME: "name",
            _RPMTAG_VERSION: "version",
            _RPMTAG_RELEASE: "release",
            _RPMTAG_EPOCH: "epoch",
            _RPMTAG_ARCH: "arch",
        }
        out: dict[str, str] = {}
        for i in range(index_count):
            entry_off = offset + i * 16
            tag, typ, data_off, count = struct.unpack_from(
                ">IIiI", blob, entry_off
            )
            field = wanted.get(tag)
            if field is None:
                continue
            if typ in (_RPM_STRING_TYPE, _RPM_I18NSTRING_TYPE):
                end = store.find(b"\x00", data_off)
                if end < 0:
                    continue
                out[field] = store[data_off:end].decode(
                    "utf-8", errors="ignore"
                )
            elif typ == _RPM_INT32_TYPE:
                if data_off + 4 <= len(store):
                    (val,) = struct.unpack_from(">I", store, data_off)
                    out[field] = str(val)
        return out
    except (struct.error, IndexError, ValueError):
        return {}


def _rpm_evr(header: dict[str, str]) -> str | None:
    """Compose an EVR (epoch:version-release) string from a parsed header.

    Returns ``None`` if version is missing. Epoch is included only when
    present and non-zero, matching how OSV/rpm reference RHEL package versions.
    """
    version = header.get("version")
    if not version:
        return None
    release = header.get("release")
    epoch = header.get("epoch")
    evr = version
    if release:
        evr = f"{version}-{release}"
    if epoch and epoch not in ("0",):
        evr = f"{epoch}:{evr}"
    return evr


def _parse_rpmdb_sqlite(db_bytes: bytes) -> list[tuple[str, str]]:
    """Extract ``(name, evr)`` pairs from a SQLite rpmdb blob.

    The sqlite3 stdlib module can only open a file path, not an in-memory
    buffer, so we spill the blob to a private tempfile, open it read-only, and
    delete it afterwards. Any error (not actually sqlite, missing Packages
    table, unreadable headers) degrades to an empty list — never a crash.
    """
    pkgs: list[tuple[str, str]] = []
    tmp_path: str | None = None
    try:
        fd, tmp_path = tempfile.mkstemp(prefix="casket-rpmdb-", suffix=".sqlite")
        with os.fdopen(fd, "wb") as fh:
            fh.write(db_bytes)
        conn = sqlite3.connect(f"file:{tmp_path}?mode=ro", uri=True)
        try:
            cur = conn.execute("SELECT blob FROM Packages")
            for (blob,) in cur:
                if blob is None:
                    continue
                header = _parse_rpm_header(bytes(blob))
                name = header.get("name")
                evr = _rpm_evr(header)
                if name and evr:
                    pkgs.append((name, evr))
        finally:
            conn.close()
    except (sqlite3.Error, OSError):
        return []
    finally:
        if tmp_path is not None:
            try:
                os.unlink(tmp_path)
            except OSError:  # pragma: no cover - best-effort cleanup
                pass
    return pkgs


def _extract_packages(layer: Layer) -> list[Package]:
    found: list[Package] = []
    for path, size, reader in layer.iter_files():
        if _DIST_INFO_RE.search(path):
            text = reader().decode("utf-8", errors="ignore")
            name, version = _parse_pypi_metadata(text)
            if name and version:
                found.append(
                    Package("PyPI", name, version, layer.digest, path)
                )
        elif path == _DPKG_STATUS:
            text = reader().decode("utf-8", errors="ignore")
            for name, version in _parse_dpkg_status(text):
                found.append(
                    Package("Debian", name, version, layer.digest, path)
                )
        elif path == _APK_INSTALLED:
            text = reader().decode("utf-8", errors="ignore")
            for name, version in _parse_apk_installed(text):
                found.append(
                    Package("Alpine", name, version, layer.digest, path)
                )
        elif path == _RPMDB_SQLITE:
            for name, version in _parse_rpmdb_sqlite(reader()):
                found.append(
                    Package("Red Hat", name, version, layer.digest, path)
                )
    return found


def run(image: Image, *, osv_client: Any = None) -> list[Finding]:
    client = osv_client or OSVClient()
    findings: list[Finding] = []

    # Resolve the release-qualified Alpine ecosystem once per image. OSV.dev
    # keys Alpine vulns under e.g. "Alpine:v3.18"; querying that (with a bare
    # "Alpine" fallback for the seed DB / warm cache) is what makes live Alpine
    # CVE lookups actually work. None when the image carries no release marker.
    alpine_ecosystem = _detect_alpine_ecosystem(image)

    # Same release-qualified resolution for Debian/Ubuntu: OSV.dev keys Debian
    # vulns under e.g. "Debian:12". We query that first (live API) with a bare
    # "Debian" fallback (seed DB / cache). None when no release marker exists.
    debian_ecosystem = _detect_debian_ecosystem(image)

    for layer in image.layers:
        for pkg in _extract_packages(layer):
            if pkg.ecosystem == "Alpine":
                # Release-qualified first (live API), bare "Alpine" fallback
                # (seed DB / cache). query_ecosystems dedupes and skips falsy.
                vulns = client.query_ecosystems(
                    [alpine_ecosystem, "Alpine"], pkg.name, pkg.version
                )
            elif pkg.ecosystem == "Debian":
                # Release-qualified first (live API), bare "Debian" fallback
                # (seed DB / cache). query_ecosystems dedupes and skips falsy.
                vulns = client.query_ecosystems(
                    [debian_ecosystem, "Debian"], pkg.name, pkg.version
                )
            else:
                vulns = client.query(pkg.ecosystem, pkg.name, pkg.version)
            for vuln in vulns:
                cve_id = vuln.get("id", "UNKNOWN")
                aliases = vuln.get("aliases", [])
                # Prefer a CVE-style alias as the headline id when present.
                cve = next((a for a in aliases if a.startswith("CVE-")), cve_id)
                findings.append(
                    Finding(
                        category="cve",
                        title=f"{pkg.name} {pkg.version}: {cve}",
                        severity=_severity_from_osv(vuln),
                        layer_sha=pkg.layer_sha,
                        path_in_layer=pkg.path_in_layer,
                        detail={
                            "cve_id": cve,
                            "osv_id": cve_id,
                            "package": pkg.name,
                            "ecosystem": pkg.ecosystem,
                            "installed_version": pkg.version,
                            "summary": vuln.get("summary", ""),
                        },
                    )
                )
    return findings


def _severity_from_osv(vuln: dict) -> str:
    """Best-effort qualitative severity from an OSV record.

    Resolution order, most-authoritative first:

    1. ``database_specific.severity`` — an explicit qualitative label
       (``CRITICAL``/``HIGH``/``MEDIUM``/``LOW``) some ecosystems (PyPI/GHSA)
       attach. When present and recognised it wins outright.
    2. The OSV-standard top-level ``severity`` array — a list of
       ``{"type": "CVSS_V3"|"CVSS_V4", "score": "<vector>"}`` entries. Most
       real OSV.dev records (Debian, Alpine, Red Hat especially) carry a CVSS
       *vector* here and **no** ``database_specific.severity`` at all. We parse
       the CVSS base score out of the vector and map it to a qualitative band
       per the standard CVSS v3.x severity ranges. Preferring the highest CVSS
       version available (V4 over V3) keeps the rating current as OSV migrates.
    3. Fallback: ``high`` — conservative when nothing is parseable, matching
       the prior behaviour so a missing/garbled record never silently downgrades.

    Returning the precise band (rather than blanket ``high``) is what makes the
    ``--fail-on`` gate and the SARIF ``security-severity`` sort meaningful for
    OS-package CVEs.
    """
    spec = vuln.get("database_specific", {})
    if isinstance(spec, dict):
        sev = str(spec.get("severity", "")).lower()
        if sev in {"critical", "high", "medium", "low"}:
            return sev

    band = _severity_from_cvss_array(vuln.get("severity"))
    if band is not None:
        return band

    return "high"


# CVSS metric type codes ranked by recency; later versions win when several are
# present on a record (OSV records frequently carry both V3 and V4 vectors).
_CVSS_TYPE_RANK = {"CVSS_V2": 0, "CVSS_V3": 1, "CVSS_V4": 2}

# Pull the ``AV:N/AC:L/...`` metric string out of a CVSS vector, regardless of
# the ``CVSS:3.1/`` or ``CVSS:4.0/`` prefix some emitters include.
_CVSS_BASE_SCORE_RE = re.compile(r"\b([A-Z]+):([A-Z]+)\b")


def _severity_from_cvss_array(severities: Any) -> str | None:
    """Map an OSV-standard ``severity`` array to a qualitative band.

    ``severities`` is the value of the record's top-level ``severity`` key: a
    list of ``{"type": ..., "score": "<CVSS vector>"}`` dicts. We compute the
    CVSS base score from the highest-version vector present and bucket it into
    the standard qualitative bands::

        0.0          -> none  (treated as ``low`` for output uniformity)
        0.1 –  3.9   -> low
        4.0 –  6.9   -> medium
        7.0 –  8.9   -> high
        9.0 – 10.0   -> critical

    Returns ``None`` when no usable CVSS vector can be scored, so the caller
    falls through to its own default.
    """
    if not isinstance(severities, list):
        return None

    best_rank = -1
    best_score: float | None = None
    for entry in severities:
        if not isinstance(entry, dict):
            continue
        typ = str(entry.get("type", ""))
        score_str = entry.get("score")
        if not isinstance(score_str, str):
            continue
        rank = _CVSS_TYPE_RANK.get(typ, -1)
        if rank < best_rank:
            continue
        value = _cvss_base_score(score_str)
        if value is None:
            continue
        # On equal rank keep the first; a strictly newer version always wins.
        if rank > best_rank or best_score is None:
            best_rank = rank
            best_score = value

    if best_score is None:
        return None
    return _cvss_band(best_score)


def _cvss_base_score(vector: str) -> float | None:
    """Compute the CVSS v3.x base score from a vector string.

    OSV stores CVSS as the vector (``CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H``),
    not the numeric score, so we recompute the base score from the metrics. We
    implement the standard CVSS v3.0/v3.1 base-score formula (the two share the
    same base equation; the only v3.1 change is to environmental/temporal
    rounding, which does not affect the base score we need here).

    Returns ``None`` if the vector is missing any required base metric — the
    caller then ignores this entry. CVSS v2 and v4 vectors are not scored here
    (different formulae); they are skipped and a lower-ranked usable vector,
    if any, is used instead.
    """
    metrics = dict(_CVSS_BASE_SCORE_RE.findall(vector))
    # Required base metrics for CVSS v3.x.
    required = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")
    if not all(k in metrics for k in required):
        return None

    av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}.get(metrics["AV"])
    ac = {"L": 0.77, "H": 0.44}.get(metrics["AC"])
    ui = {"N": 0.85, "R": 0.62}.get(metrics["UI"])
    scope_changed = metrics["S"] == "C"
    # Privileges Required is scope-dependent.
    if scope_changed:
        pr = {"N": 0.85, "L": 0.68, "H": 0.5}.get(metrics["PR"])
    else:
        pr = {"N": 0.85, "L": 0.62, "H": 0.27}.get(metrics["PR"])
    cia = {"H": 0.56, "L": 0.22, "N": 0.0}
    c = cia.get(metrics["C"])
    i = cia.get(metrics["I"])
    a = cia.get(metrics["A"])
    if None in (av, ac, pr, ui, c, i, a):
        return None

    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    exploitability = 8.22 * av * ac * pr * ui

    if impact <= 0:
        return 0.0
    if scope_changed:
        base = min(1.08 * (impact + exploitability), 10.0)
    else:
        base = min(impact + exploitability, 10.0)
    # CVSS rounds the base score *up* to one decimal place.
    return _cvss_roundup(base)


def _cvss_roundup(value: float) -> float:
    """CVSS v3.1 ``Roundup``: round up to the nearest tenth.

    Implemented on integer-tenths to avoid binary float drift (e.g. 4.0001 must
    become 4.1, while an exact 4.0 must stay 4.0).
    """
    int_input = round(value * 100_000)
    if int_input % 10_000 == 0:
        return int_input / 100_000
    return (int(int_input / 10_000) + 1) / 10.0


def _cvss_band(score: float) -> str:
    """Bucket a CVSS base score into casket's qualitative severity vocabulary."""
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    # CVSS "none" (0.0) folds into low for output uniformity (casket has no
    # "none" band); 0.1–3.9 is the standard low band.
    return "low"
