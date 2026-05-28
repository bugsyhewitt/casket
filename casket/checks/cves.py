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

[Worker decision: Alpine OSV ecosystem name — Rotation 2, POST_V01 Item 1]
OSV.dev keys Alpine vulns under release-qualified ecosystems like
``Alpine:v3.18``, not a bare ``Alpine``. casket cannot reliably know the
release version of an arbitrary layer without parsing ``etc/alpine-release``
(which is not guaranteed present in every layer). We therefore tag Alpine
packages with the bare ecosystem ``"Alpine"`` so the cache-first / seed DB
path resolves them deterministically offline. The OSVClient could be taught to
fan out across release-qualified ecosystems against the live API as a later
focused improvement; that is explicitly out of scope for this single change.
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

    for layer in image.layers:
        for pkg in _extract_packages(layer):
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
