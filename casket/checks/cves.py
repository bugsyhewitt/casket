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
    """Best-effort severity from an OSV record's database_specific or CVSS."""
    spec = vuln.get("database_specific", {})
    sev = str(spec.get("severity", "")).lower()
    if sev in {"critical", "high", "medium", "low"}:
        return sev
    return "high"
