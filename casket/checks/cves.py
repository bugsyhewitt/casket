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


def _cvss_score_to_severity(score: float) -> str:
    """Map a CVSS base score to casket's qualitative severity band.

    Bands follow the CVSS v3.1 / v4.0 qualitative rating scale:
    9.0–10.0 critical, 7.0–8.9 high, 4.0–6.9 medium, 0.1–3.9 low, 0.0 info.
    """
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0.0:
        return "low"
    return "info"


# CVSS v2.0 base-score metric weights (FIRST CVSS v2.0 spec, section 3.2.1).
# Access Vector / Access Complexity / Authentication and the shared
# Confidentiality/Integrity/Availability impact scale.
_CVSS2_AV = {"L": 0.395, "A": 0.646, "N": 1.0}
_CVSS2_AC = {"H": 0.35, "M": 0.61, "L": 0.71}
_CVSS2_AU = {"M": 0.45, "S": 0.56, "N": 0.704}
_CVSS2_CIA = {"N": 0.0, "P": 0.275, "C": 0.660}


# CVSS v3.x base-score metric weights (CVSS v3.1 specification, section 7.1).
_CVSS3_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_CVSS3_AC = {"L": 0.77, "H": 0.44}
# Privileges Required is scope-dependent; the higher value applies when the
# scope is changed. We store the (unchanged, changed) pair.
_CVSS3_PR = {"N": (0.85, 0.85), "L": (0.62, 0.68), "H": (0.27, 0.5)}
_CVSS3_UI = {"N": 0.85, "R": 0.62}
_CVSS3_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


def _roundup(value: float) -> float:
    """CVSS v3.1 Appendix A roundup: round up to one decimal place."""
    int_input = round(value * 100_000)
    if int_input % 10_000 == 0:
        return int_input / 100_000.0
    return (int(int_input / 10_000) + 1) / 10.0


def _cvss3_base_score(vector: str) -> float | None:
    """Compute a CVSS v3.x base score from a vector string.

    Accepts vectors with or without the ``CVSS:3.x/`` prefix. Returns ``None``
    if a required base metric is missing or malformed — the caller then falls
    back to other severity sources rather than guessing.
    """
    metrics: dict[str, str] = {}
    for part in vector.split("/"):
        if ":" not in part:
            continue
        key, _, val = part.partition(":")
        metrics[key.strip().upper()] = val.strip().upper()

    try:
        av = _CVSS3_AV[metrics["AV"]]
        ac = _CVSS3_AC[metrics["AC"]]
        ui = _CVSS3_UI[metrics["UI"]]
        scope_changed = metrics["S"] == "C"
        pr = _CVSS3_PR[metrics["PR"]][1 if scope_changed else 0]
        conf = _CVSS3_CIA[metrics["C"]]
        integ = _CVSS3_CIA[metrics["I"]]
        avail = _CVSS3_CIA[metrics["A"]]
    except KeyError:
        return None

    iss = 1.0 - ((1.0 - conf) * (1.0 - integ) * (1.0 - avail))
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    exploitability = 8.22 * av * ac * pr * ui

    if impact <= 0:
        return 0.0
    if scope_changed:
        return _roundup(min(1.08 * (impact + exploitability), 10.0))
    return _roundup(min(impact + exploitability, 10.0))


def _cvss_vector_metrics(vector: str) -> dict[str, str]:
    """Split a ``KEY:VAL/KEY:VAL`` CVSS vector into an upper-cased metric map.

    Tolerates an optional leading version token (``CVSS:3.1`` / ``CVSS:4.0``)
    and stray whitespace. Legacy CVSS v2 vectors carry no version prefix.
    """
    metrics: dict[str, str] = {}
    for part in vector.split("/"):
        if ":" not in part:
            continue
        key, _, val = part.partition(":")
        metrics[key.strip().upper()] = val.strip().upper()
    return metrics


def _cvss2_base_score(vector: str) -> float | None:
    """Compute a CVSS v2.0 base score from a vector string.

    Legacy CVSS v2 vectors (e.g. ``AV:N/AC:L/Au:N/C:P/I:P/A:P``) carry no
    ``CVSS:`` version prefix and use the v2 metric set (Access Vector / Access
    Complexity / Authentication + CIA impact on the partial/complete scale).
    The closed-form base-score formula is from the FIRST CVSS v2.0 spec
    (section 3.2.1)::

        Impact         = 10.41 * (1 - (1-C)*(1-I)*(1-A))
        Exploitability = 20 * AV * AC * Au
        f(Impact)      = 0 if Impact == 0 else 1.176
        BaseScore      = round1(((0.6*Impact)+(0.4*Exploitability)-1.5) * f(Impact))

    Returns ``None`` if a required metric is missing or malformed, so the
    caller falls back to other severity sources rather than guessing.
    """
    metrics = _cvss_vector_metrics(vector)
    try:
        av = _CVSS2_AV[metrics["AV"]]
        ac = _CVSS2_AC[metrics["AC"]]
        au = _CVSS2_AU[metrics["AU"]]
        conf = _CVSS2_CIA[metrics["C"]]
        integ = _CVSS2_CIA[metrics["I"]]
        avail = _CVSS2_CIA[metrics["A"]]
    except KeyError:
        return None

    impact = 10.41 * (1.0 - (1.0 - conf) * (1.0 - integ) * (1.0 - avail))
    exploitability = 20.0 * av * ac * au
    f_impact = 0.0 if impact == 0 else 1.176
    base = ((0.6 * impact) + (0.4 * exploitability) - 1.5) * f_impact
    # CVSS v2 rounds the base score to one decimal place.
    return round(max(base, 0.0), 1)


def _severity_from_cvss_vector(vector: str) -> str | None:
    """Derive a qualitative severity from a CVSS vector string, or ``None``.

    Handles CVSS v3.x and legacy CVSS v2 vectors by computing the base score
    with a small stdlib calculator and mapping it through casket's unified
    qualitative band (``_cvss_score_to_severity``). Version is identified by the
    ``CVSS:3`` / ``CVSS:4`` prefix; a bare (prefix-less) vector that carries the
    v2-only ``Au`` metric is scored as v2, otherwise as v3. CVSS v4.0 vectors
    (``CVSS:4.0/…``) use a lookup-table scoring model we don't reproduce here
    and return ``None`` (caller falls back to ``database_specific.severity``).

    [Worker decision: unified severity band — Rotation 14, POST_V01 v2 scoring]
    CVSS v2's *native* qualitative scale has no "critical" tier (v2 tops out at
    "High" for 7.0–10.0). We deliberately map v2 base scores through the same
    v3.1 band function (≥9.0 critical) the rest of casket uses, so every finding
    — v2- or v3-sourced — speaks one severity vocabulary. The --fail-on gate and
    SARIF security-severity float both consume that single vocabulary; emitting
    a v2-only scale here would split it. The numeric score is faithful to the v2
    spec; only the qualitative label is unified.
    """
    v = vector.strip()
    upper = v.upper()
    if upper.startswith("CVSS:4"):
        # v4.0 base scoring is table-driven, not a closed-form formula; we
        # don't reproduce it. Fall through to other severity sources.
        return None
    if upper.startswith("CVSS:3"):
        score = _cvss3_base_score(v)
        if score is not None:
            return _cvss_score_to_severity(score)
        return None
    if upper.startswith("CVSS:2"):
        score = _cvss2_base_score(v)
        if score is not None:
            return _cvss_score_to_severity(score)
        return None
    # Prefix-less vector: the v2-only ``Au`` metric disambiguates it as v2,
    # otherwise treat a bare vector as v3 (the original behaviour).
    metrics = _cvss_vector_metrics(v)
    if "AU" in metrics:
        score = _cvss2_base_score(v)
        if score is not None:
            return _cvss_score_to_severity(score)
        return None
    score = _cvss3_base_score(v)
    if score is not None:
        return _cvss_score_to_severity(score)
    return None


def _severity_from_osv(vuln: dict) -> str:
    """Best-effort qualitative severity for an OSV record.

    Resolution order, most authoritative first:

    1. The standard OSV ``severity`` array — a list of
       ``{"type": "CVSS_V3"|"CVSS_V2"|..., "score": "<vector>"}`` entries. This
       is where OSV.dev actually records CVSS for the overwhelming majority of
       records; we parse CVSS v3.x *and* legacy v2 vectors and map the base
       score to a band. (The original implementation ignored this field
       entirely, so almost every live finding silently defaulted to "high";
       Rotation 13 added v3 scoring, Rotation 14 added v2 — older CVEs on the
       aged packages a container scanner finds are frequently v2-only.) CVSS
       v4.0 vectors are not yet scored and fall through to source 2.
    2. The non-standard ``database_specific.severity`` string (some ecosystems
       — notably GHSA-sourced records — set this), accepted verbatim.
    3. A conservative ``"high"`` default when neither is usable.
    """
    # 1. Standard OSV severity array (CVSS vectors).
    for entry in vuln.get("severity", []) or []:
        if not isinstance(entry, dict):
            continue
        score = entry.get("score")
        if not isinstance(score, str):
            continue
        derived = _severity_from_cvss_vector(score)
        if derived is not None:
            return derived

    # 2. Non-standard per-database qualitative severity.
    spec = vuln.get("database_specific", {})
    if isinstance(spec, dict):
        sev = str(spec.get("severity", "")).lower()
        if sev in {"critical", "high", "medium", "low", "info"}:
            return sev

    # 3. Conservative default.
    return "high"
