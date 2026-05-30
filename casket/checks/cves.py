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

[Worker decision: OSV reference & alias enrichment — Rotation 19]
POST_V01 lists "GHSA / NVD reference enrichment" as a candidate next item, but
notes both add an external network dependency and rate-limit/auth concerns. The
OSV record casket *already fetches and caches* for severity carries that data
itself: the ``aliases`` array (the same vuln's CVE / GHSA / distro ids) and the
``references`` array (the upstream advisory, patch/fix, and exploit URLs OSV
aggregates). v0.1 discarded all of it, keeping only a single CVE alias as the
headline id and the summary. This rotation surfaces the rest into the finding
``detail`` — the full ``aliases`` list, plus ``fix_urls`` / ``advisory_urls`` /
``exploit_urls`` bucketed from the OSV ``references`` ``type`` enum. This makes a
finding *actionable* (here is the patch, here is the advisory) with **zero new
dependencies and zero new network calls** — the GHSA/NVD enrichment value
without the external-API cost, because OSV's references already aggregate those
upstream links. The new detail keys flow through all three output formats for
free (json flatten, h1md bullets, SARIF result properties). Keys are omitted
entirely when empty, so clean/seed findings and the existing tests are
unaffected.

[Worker decision: fixed-version remediation surfacing — Rotation 21]
Rotation 19 surfaced the advisory and patch *URLs* from the OSV record, but not
the single most actionable remediation field a scanner can give an operator:
*which version to upgrade to*. OSV records carry it in the ``affected`` array —
each range's ``{"fixed": "<ver>"}`` event marks the version that resolves the
vuln. This rotation extracts those into ``detail["fixed_versions"]`` (the full
de-duplicated list across the package's ranges), turning a finding from "here is
the advisory" into "...and upgrade to X to fix it". Like the Rotation 19
enrichment it costs **zero new dependencies and zero new network calls** — the
``affected`` array is already in the record casket fetches and caches for
severity. The key flows through json / h1md / sarif output for free and is
omitted entirely for still-unfixed vulns (no ``fixed`` event), so clean/seed
findings and the existing tests are unaffected. See ``_fixed_versions_from_osv``.
"""

from __future__ import annotations

import math
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


def package_inventory(image: Image) -> list[Package]:
    """Return every installed package the CVE check can extract from an image.

    This is the *partial package inventory* casket already builds while scanning
    (PyPI / Debian / Alpine / RPM records — see the module docstring), surfaced
    as a standalone, **network-free** call. ``run`` uses it to build its OSV
    jobs; ``casket.scanner.component_stats`` uses it to report per-ecosystem
    component counts without producing a full SBOM artifact (the "no SBOM
    generation" v0.1 guardrail stands — this is a count of what's already read,
    not a generated CycloneDX/SPDX document).

    Extraction reads layer files only; it never touches OSV.dev or any network.
    Packages are returned in layer order, with no de-duplication (a package
    recorded in two layers appears twice, matching what ``run`` resolves).
    """
    packages: list[Package] = []
    for layer in image.layers:
        packages.extend(_extract_packages(layer))
    return packages


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

    # Collect every package across every layer first, then resolve them all in
    # a single batched OSV query (one HTTP round-trip for all local cache misses
    # instead of one per package — a large win on busy Debian/Ubuntu images).
    # Each job carries its ordered ecosystem candidates: the release-qualified
    # name first (what the live API needs) with the bare ecosystem as a fallback
    # (under which the seed DB / warm cache are keyed). query_batch dedupes and
    # skips falsy candidates, exactly like query_ecosystems.
    packages = package_inventory(image)

    jobs: list[tuple[list[str], str, str]] = []
    for pkg in packages:
        if pkg.ecosystem == "Alpine":
            candidates = [alpine_ecosystem, "Alpine"]
        elif pkg.ecosystem == "Debian":
            candidates = [debian_ecosystem, "Debian"]
        else:
            candidates = [pkg.ecosystem]
        jobs.append((candidates, pkg.name, pkg.version))

    vuln_lists = client.query_batch(jobs)

    for pkg, vulns in zip(packages, vuln_lists):
        for vuln in vulns:
            cve_id = vuln.get("id", "UNKNOWN")
            aliases = _aliases_from_osv(vuln)
            # Prefer a CVE-style alias as the headline id when present.
            cve = next((a for a in aliases if a.startswith("CVE-")), cve_id)
            detail: dict[str, Any] = {
                "cve_id": cve,
                "osv_id": cve_id,
                "package": pkg.name,
                "ecosystem": pkg.ecosystem,
                "installed_version": pkg.version,
                "summary": vuln.get("summary", ""),
            }
            # Surface the cross-reference identifiers and remediation/advisory
            # links the OSV record already carries (no extra network call): the
            # full alias list (CVE + GHSA + other DB ids) and the most
            # actionable reference URLs (patch/fix, advisory, exploit). This is
            # what turns a finding from "package X has CVE-Y" into "...and here
            # is the patch and the advisory". See _references_from_osv.
            if aliases:
                detail["aliases"] = aliases
            # The single most actionable remediation field: which version to
            # upgrade to. Pulled from the OSV ``affected`` ranges' ``fixed``
            # events — already in the record casket fetched, no extra network
            # call. Omitted when the vuln is still unfixed (no ``fixed`` event).
            fixed = _fixed_versions_from_osv(vuln, pkg.name)
            if fixed:
                detail["fixed_versions"] = fixed
            # Surface the numeric CVSS base score and the source vector when the
            # OSV record carries a scorable CVSS entry. The qualitative
            # ``severity`` band (below) tells the operator the bucket; the score
            # tells them where within it (a 9.8 critical reads differently from a
            # 9.0 one), and the vector shows the attack shape that produced it.
            # Already computed during banding — no extra network call, no extra
            # calculator pass beyond the one band lookup. Omitted when the record
            # has no scorable CVSS vector (severity then came from
            # database_specific or the conservative default).
            cvss = _cvss_from_osv(vuln)
            if cvss is not None:
                score, version, vector = cvss
                detail["cvss_score"] = score
                detail["cvss_version"] = version
                detail["cvss_vector"] = vector
                # v4.0 Supplemental Metric Group surfacing — extra extrinsic
                # triage context (Safety, Automatable, Recovery, Value Density,
                # Response Effort, Provider Urgency) that does NOT affect the
                # base score but tells an operator *whether* a finding warrants
                # priority within its band. Omitted entirely when the source
                # vector carries no supplemental metrics (the common base-only
                # case), so default output is byte-identical. Only v4.0 carries
                # a supplemental group; v2/v3 have no such metrics.
                if version == "4.0":
                    supplemental = _cvss4_supplemental_metrics(vector)
                    if supplemental:
                        detail["cvss_supplemental"] = supplemental
            refs = _references_from_osv(vuln)
            if refs.get("fix"):
                detail["fix_urls"] = refs["fix"]
            if refs.get("advisory"):
                detail["advisory_urls"] = refs["advisory"]
            if refs.get("exploit"):
                detail["exploit_urls"] = refs["exploit"]
            findings.append(
                Finding(
                    category="cve",
                    title=f"{pkg.name} {pkg.version}: {cve}",
                    severity=_severity_from_osv(vuln),
                    layer_sha=pkg.layer_sha,
                    path_in_layer=pkg.path_in_layer,
                    detail=detail,
                )
            )
    return findings


# OSV reference ``type`` values we surface, grouped by the operator question
# they answer. The OSV schema defines a fixed enum
# (https://ossf.github.io/osv-schema/#references-field); we map the
# remediation- and triage-relevant ones into three actionable buckets and
# ignore the rest (PACKAGE/ARTICLE/INTRODUCED/etc.) to keep the report focused.
_OSV_FIX_REF_TYPES = frozenset({"FIX"})
_OSV_ADVISORY_REF_TYPES = frozenset({"ADVISORY", "REPORT"})
_OSV_EXPLOIT_REF_TYPES = frozenset({"EXPLOIT", "EVIDENCE"})


def _fixed_versions_from_osv(vuln: dict, package_name: str) -> list[str]:
    """Extract the remediation (fixed) versions from an OSV record.

    The single most actionable remediation field a scanner can surface is *which
    version to upgrade to*. OSV records carry it in the ``affected`` array: each
    affected entry pins a ``package`` (ecosystem + name) and one or more
    ``ranges``, whose ``events`` mark version transitions —
    ``{"introduced": "0"}`` opens a vulnerable range and ``{"fixed": "<ver>"}``
    closes it (the version that *resolves* the vuln). We collect every ``fixed``
    version across the ranges whose affected ``package.name`` matches the
    installed package — first-seen order, de-duplicated.

    Surfacing this costs **no extra network call**: the ``affected`` array is
    already in the OSV record casket fetches and caches for severity. It is the
    natural completion of the Rotation 19 enrichment (which surfaced the advisory
    and patch *URLs* but not the concrete version to upgrade to).

    Defensive throughout: a non-list ``affected``, malformed entries, a missing
    ``package``/``ranges``/``events``, non-string versions, the open-ended
    ``"0"`` sentinel, and ranges with no ``fixed`` event (still-unfixed vulns)
    are all skipped rather than crashing the scan. Package-name matching is
    case-insensitive and tolerates a missing affected ``package`` (some seed /
    sparse records omit it) by accepting its ranges — better to surface a fix
    than to drop it on a name mismatch.
    """
    raw = vuln.get("affected")
    if not isinstance(raw, list):
        return []
    want = package_name.strip().lower()
    out: list[str] = []
    seen: set[str] = set()
    for affected in raw:
        if not isinstance(affected, dict):
            continue
        pkg = affected.get("package")
        if isinstance(pkg, dict):
            name = pkg.get("name")
            if isinstance(name, str) and name.strip().lower() != want:
                # An affected entry that names a *different* package — skip it.
                continue
        ranges = affected.get("ranges")
        if not isinstance(ranges, list):
            continue
        for rng in ranges:
            if not isinstance(rng, dict):
                continue
            events = rng.get("events")
            if not isinstance(events, list):
                continue
            for event in events:
                if not isinstance(event, dict):
                    continue
                fixed = event.get("fixed")
                if not isinstance(fixed, str):
                    continue
                fixed = fixed.strip()
                if not fixed or fixed == "0" or fixed in seen:
                    continue
                seen.add(fixed)
                out.append(fixed)
    return out


def _aliases_from_osv(vuln: dict) -> list[str]:
    """Return the OSV record's alias ids as a clean, de-duplicated string list.

    OSV records cross-reference the same vulnerability under several identifier
    schemes (a CVE id, a GHSA id, distro-specific ids, …) in the ``aliases``
    array. We coerce defensively — a non-list ``aliases`` or non-string entries
    are dropped rather than crashing the scan — preserve first-seen order, and
    de-duplicate.
    """
    raw = vuln.get("aliases")
    if not isinstance(raw, list):
        return []
    out: list[str] = []
    seen: set[str] = set()
    for entry in raw:
        if not isinstance(entry, str):
            continue
        entry = entry.strip()
        if not entry or entry in seen:
            continue
        seen.add(entry)
        out.append(entry)
    return out


def _references_from_osv(vuln: dict) -> dict[str, list[str]]:
    """Bucket an OSV record's reference URLs into fix / advisory / exploit lists.

    The OSV ``references`` array is a list of ``{"type": <enum>, "url": <str>}``
    entries. We map the remediation- and triage-relevant ``type`` values into
    three buckets an operator acts on — ``fix`` (the patch/remediation), the
    ``advisory`` write-up, and any ``exploit`` proof — and ignore the rest.
    Each bucket preserves first-seen order and de-duplicates URLs. Malformed
    entries (non-dict, missing/blank url, non-string type) are skipped, never
    raised, so a single bad reference never aborts a scan.

    Surfacing these costs no extra network call: the URLs are already in the OSV
    record casket fetches and caches for severity. This is the zero-dependency,
    no-new-API path to the GHSA/NVD reference enrichment POST_V01 flagged —
    OSV's own ``references`` already aggregate the upstream advisory and patch
    links.
    """
    buckets: dict[str, list[str]] = {"fix": [], "advisory": [], "exploit": []}
    seen: dict[str, set[str]] = {"fix": set(), "advisory": set(), "exploit": set()}
    raw = vuln.get("references")
    if not isinstance(raw, list):
        return buckets
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        url = entry.get("url")
        if not isinstance(url, str) or not url.strip():
            continue
        url = url.strip()
        rtype = entry.get("type")
        rtype = rtype.strip().upper() if isinstance(rtype, str) else ""
        if rtype in _OSV_FIX_REF_TYPES:
            bucket = "fix"
        elif rtype in _OSV_ADVISORY_REF_TYPES:
            bucket = "advisory"
        elif rtype in _OSV_EXPLOIT_REF_TYPES:
            bucket = "exploit"
        else:
            continue
        if url in seen[bucket]:
            continue
        seen[bucket].add(url)
        buckets[bucket].append(url)
    return buckets


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


# --- CVSS v4.0 base-score calculator (Rotation 16, POST_V01 candidate) ----
#
# Unlike v2/v3, CVSS v4.0's base score is not a closed-form formula. The FIRST
# CVSS v4.0 specification (section 8.2) defines scoring as a MacroVector lookup
# plus severity-distance interpolation. This is a faithful, line-for-line port
# of the FIRST/Red Hat reference implementation
# (https://github.com/RedHatProductSecurity/cvss-v4-calculator), restricted to
# the BASE metrics OSV records. Threat / Environmental / Supplemental metrics
# default to their score-neutral values (E -> A, CR/IR/AR -> H, no modified
# metrics), which is exactly how a base-only vector scores. Zero new
# dependencies — stdlib only.
#
# The algorithm:
#   1. Reduce the vector to a 6-digit *MacroVector*, one digit per equivalence
#      class (EQ1..EQ6) — ``_cvss4_macrovector``.
#   2. Look up the MacroVector's reference score in ``_CVSS4_LOOKUP``.
#   3. Interpolate: for each EQ, measure the severity distance from the chosen
#      most-severe "max vector" corner, scale it against the score gap to the
#      next-lower MacroVector, and subtract the mean proportional distance.

# Required base metrics for a scorable v4.0 vector.
_CVSS4_BASE_METRICS = (
    "AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA",
)

# Per-metric severity-level weights used to measure severity distance. Lower
# value == more severe (the 0.1 step matches the reference exactly).
_CVSS4_AV_LV = {"N": 0.0, "A": 0.1, "L": 0.2, "P": 0.3}
_CVSS4_PR_LV = {"N": 0.0, "L": 0.1, "H": 0.2}
_CVSS4_UI_LV = {"N": 0.0, "P": 0.1, "A": 0.2}
_CVSS4_AC_LV = {"L": 0.0, "H": 0.1}
_CVSS4_AT_LV = {"N": 0.0, "P": 0.1}
_CVSS4_VC_LV = {"H": 0.0, "L": 0.1, "N": 0.2}
_CVSS4_VI_LV = {"H": 0.0, "L": 0.1, "N": 0.2}
_CVSS4_VA_LV = {"H": 0.0, "L": 0.1, "N": 0.2}
_CVSS4_SC_LV = {"H": 0.1, "L": 0.2, "N": 0.3}
_CVSS4_SI_LV = {"S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3}
_CVSS4_SA_LV = {"S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3}
_CVSS4_CR_LV = {"H": 0.0, "M": 0.1, "L": 0.2}
_CVSS4_IR_LV = {"H": 0.0, "M": 0.1, "L": 0.2}
_CVSS4_AR_LV = {"H": 0.0, "M": 0.1, "L": 0.2}
_CVSS4_LEVEL_MAPS = {
    "AV": _CVSS4_AV_LV, "PR": _CVSS4_PR_LV, "UI": _CVSS4_UI_LV,
    "AC": _CVSS4_AC_LV, "AT": _CVSS4_AT_LV,
    "VC": _CVSS4_VC_LV, "VI": _CVSS4_VI_LV, "VA": _CVSS4_VA_LV,
    "SC": _CVSS4_SC_LV, "SI": _CVSS4_SI_LV, "SA": _CVSS4_SA_LV,
    "CR": _CVSS4_CR_LV, "IR": _CVSS4_IR_LV, "AR": _CVSS4_AR_LV,
}

# The official MacroVector -> base-score lookup (FIRST/Red Hat reference
# ``cvss_lookup.js``). Keys are the 6-digit MacroVector; values the base score.
_CVSS4_LOOKUP: dict[str, float] = {
    "000000": 10.0, "000001": 9.9, "000010": 9.8, "000011": 9.5,
    "000020": 9.5, "000021": 9.2, "000100": 10.0, "000101": 9.6,
    "000110": 9.3, "000111": 8.7, "000120": 9.1, "000121": 8.1,
    "000200": 9.3, "000201": 9.0, "000210": 8.9, "000211": 8.0,
    "000220": 8.1, "000221": 6.8, "001000": 9.8, "001001": 9.5,
    "001010": 9.5, "001011": 9.2, "001020": 9.0, "001021": 8.4,
    "001100": 9.3, "001101": 9.2, "001110": 8.9, "001111": 8.1,
    "001120": 8.1, "001121": 6.5, "001200": 8.8, "001201": 8.0,
    "001210": 7.8, "001211": 7.0, "001220": 6.9, "001221": 4.8,
    "002001": 9.2, "002011": 8.2, "002021": 7.2, "002101": 7.9,
    "002111": 6.9, "002121": 5.0, "002201": 6.9, "002211": 5.5,
    "002221": 2.7, "010000": 9.9, "010001": 9.7, "010010": 9.5,
    "010011": 9.2, "010020": 9.2, "010021": 8.5, "010100": 9.5,
    "010101": 9.1, "010110": 9.0, "010111": 8.3, "010120": 8.4,
    "010121": 7.1, "010200": 9.2, "010201": 8.1, "010210": 8.2,
    "010211": 7.1, "010220": 7.2, "010221": 5.3, "011000": 9.5,
    "011001": 9.3, "011010": 9.2, "011011": 8.5, "011020": 8.5,
    "011021": 7.3, "011100": 9.2, "011101": 8.2, "011110": 8.0,
    "011111": 7.2, "011120": 7.0, "011121": 5.9, "011200": 8.4,
    "011201": 7.0, "011210": 7.1, "011211": 5.2, "011220": 5.0,
    "011221": 3.0, "012001": 8.6, "012011": 7.5, "012021": 5.2,
    "012101": 7.1, "012111": 5.2, "012121": 2.9, "012201": 6.3,
    "012211": 2.9, "012221": 1.7, "100000": 9.8, "100001": 9.5,
    "100010": 9.4, "100011": 8.7, "100020": 9.1, "100021": 8.1,
    "100100": 9.4, "100101": 8.9, "100110": 8.6, "100111": 7.4,
    "100120": 7.7, "100121": 6.4, "100200": 8.7, "100201": 7.5,
    "100210": 7.4, "100211": 6.3, "100220": 6.3, "100221": 4.9,
    "101000": 9.4, "101001": 8.9, "101010": 8.8, "101011": 7.7,
    "101020": 7.6, "101021": 6.7, "101100": 8.6, "101101": 7.6,
    "101110": 7.4, "101111": 5.8, "101120": 5.9, "101121": 5.0,
    "101200": 7.2, "101201": 5.7, "101210": 5.7, "101211": 5.2,
    "101220": 5.2, "101221": 2.5, "102001": 8.3, "102011": 7.0,
    "102021": 5.4, "102101": 6.5, "102111": 5.8, "102121": 2.6,
    "102201": 5.3, "102211": 2.1, "102221": 1.3, "110000": 9.5,
    "110001": 9.0, "110010": 8.8, "110011": 7.6, "110020": 7.6,
    "110021": 7.0, "110100": 9.0, "110101": 7.7, "110110": 7.5,
    "110111": 6.2, "110120": 6.1, "110121": 5.3, "110200": 7.7,
    "110201": 6.6, "110210": 6.8, "110211": 5.9, "110220": 5.2,
    "110221": 3.0, "111000": 8.9, "111001": 7.8, "111010": 7.6,
    "111011": 6.7, "111020": 6.2, "111021": 5.8, "111100": 7.4,
    "111101": 5.9, "111110": 5.7, "111111": 5.7, "111120": 4.7,
    "111121": 2.3, "111200": 6.1, "111201": 5.2, "111210": 5.7,
    "111211": 2.9, "111220": 2.4, "111221": 1.6, "112001": 7.1,
    "112011": 5.9, "112021": 3.0, "112101": 5.8, "112111": 2.6,
    "112121": 1.5, "112201": 2.3, "112211": 1.3, "112221": 0.6,
    "200000": 9.3, "200001": 8.7, "200010": 8.6, "200011": 7.2,
    "200020": 7.5, "200021": 5.8, "200100": 8.6, "200101": 7.4,
    "200110": 7.4, "200111": 6.1, "200120": 5.6, "200121": 3.4,
    "200200": 7.0, "200201": 5.4, "200210": 5.2, "200211": 4.0,
    "200220": 4.0, "200221": 2.2, "201000": 8.5, "201001": 7.5,
    "201010": 7.4, "201011": 5.5, "201020": 6.2, "201021": 5.1,
    "201100": 7.2, "201101": 5.7, "201110": 5.5, "201111": 4.1,
    "201120": 4.6, "201121": 1.9, "201200": 5.3, "201201": 3.6,
    "201210": 3.4, "201211": 1.9, "201220": 1.9, "201221": 0.8,
    "202001": 6.4, "202011": 5.1, "202021": 2.0, "202101": 4.7,
    "202111": 2.1, "202121": 1.1, "202201": 2.4, "202211": 0.9,
    "202221": 0.4, "210000": 8.8, "210001": 7.5, "210010": 7.3,
    "210011": 5.3, "210020": 6.0, "210021": 5.0, "210100": 7.3,
    "210101": 5.5, "210110": 5.9, "210111": 4.0, "210120": 4.1,
    "210121": 2.0, "210200": 5.4, "210201": 4.3, "210210": 4.5,
    "210211": 2.2, "210220": 2.0, "210221": 1.1, "211000": 7.5,
    "211001": 5.5, "211010": 5.8, "211011": 4.5, "211020": 4.0,
    "211021": 2.1, "211100": 6.1, "211101": 5.1, "211110": 4.8,
    "211111": 1.8, "211120": 2.0, "211121": 0.9, "211200": 4.6,
    "211201": 1.8, "211210": 1.7, "211211": 0.7, "211220": 0.8,
    "211221": 0.2, "212001": 5.3, "212011": 2.4, "212021": 1.4,
    "212101": 2.4, "212111": 1.2, "212121": 0.5, "212201": 1.0,
    "212211": 0.3, "212221": 0.1,
}

# Max severity-distance depth per EQ MacroVector level (reference
# ``max_severity.js``). EQ3/EQ6 share a joint table keyed [eq3][eq6].
_CVSS4_MAX_SEVERITY: dict[str, dict[int, int]] = {
    "eq1": {0: 1, 1: 4, 2: 5},
    "eq2": {0: 1, 1: 2},
    "eq4": {0: 6, 1: 5, 2: 4},
    "eq5": {0: 1, 1: 1, 2: 1},
}
_CVSS4_MAX_SEVERITY_EQ3EQ6: dict[int, dict[int, int]] = {
    0: {0: 7, 1: 6},
    1: {0: 8, 1: 8},
    2: {1: 10},
}

# Most-severe "max vector" corners per EQ level (reference ``max_composed.js``).
# EQ3 is keyed [eq3_level][eq6_level] because EQ3/EQ6 are jointly composed.
_CVSS4_MAX_COMPOSED_EQ1 = {
    0: ["AV:N/PR:N/UI:N/"],
    1: ["AV:A/PR:N/UI:N/", "AV:N/PR:L/UI:N/", "AV:N/PR:N/UI:P/"],
    2: ["AV:P/PR:N/UI:N/", "AV:A/PR:L/UI:P/"],
}
_CVSS4_MAX_COMPOSED_EQ2 = {
    0: ["AC:L/AT:N/"],
    1: ["AC:H/AT:N/", "AC:L/AT:P/"],
}
_CVSS4_MAX_COMPOSED_EQ3 = {
    0: {
        0: ["VC:H/VI:H/VA:H/CR:H/IR:H/AR:H/"],
        1: ["VC:H/VI:H/VA:L/CR:M/IR:M/AR:H/", "VC:H/VI:H/VA:H/CR:M/IR:M/AR:M/"],
    },
    1: {
        0: ["VC:L/VI:H/VA:H/CR:H/IR:H/AR:H/", "VC:H/VI:L/VA:H/CR:H/IR:H/AR:H/"],
        1: [
            "VC:L/VI:H/VA:L/CR:H/IR:M/AR:H/",
            "VC:L/VI:H/VA:H/CR:H/IR:M/AR:M/",
            "VC:H/VI:L/VA:H/CR:M/IR:H/AR:M/",
            "VC:H/VI:L/VA:L/CR:M/IR:H/AR:H/",
            "VC:L/VI:L/VA:H/CR:H/IR:H/AR:M/",
        ],
    },
    2: {
        1: ["VC:L/VI:L/VA:L/CR:H/IR:H/AR:H/"],
    },
}
_CVSS4_MAX_COMPOSED_EQ4 = {
    0: ["SC:H/SI:S/SA:S/"],
    1: ["SC:H/SI:H/SA:H/"],
    2: ["SC:L/SI:L/SA:L/"],
}
_CVSS4_MAX_COMPOSED_EQ5 = {
    0: ["E:A/"],
    1: ["E:P/"],
    2: ["E:U/"],
}


def _cvss4_m(metrics: dict[str, str], metric: str) -> str:
    """Resolve an effective v4 metric value, applying the spec's defaults.

    Mirrors the reference ``m()``: ``E=X`` defaults to ``A``, ``CR/IR/AR=X``
    default to ``H``, and a modified environmental metric ``M<metric>`` (when
    not ``X``) overrides the base value. Base-only vectors carry none of these,
    so this collapses to the plain base value for the metrics OSV records.
    """
    selected = metrics.get(metric, "X")
    if metric == "E" and selected in ("X", ""):
        return "A"
    if metric in ("CR", "IR", "AR") and selected in ("X", ""):
        return "H"
    modified = metrics.get("M" + metric)
    if modified is not None and modified != "X":
        return modified
    return selected if selected not in ("",) else "X"


def _cvss4_macrovector(metrics: dict[str, str]) -> str | None:
    """Compute the 6-digit MacroVector (reference ``macroVector``), or ``None``.

    Faithful to the FIRST spec's EQ partition rules. Returns ``None`` if a
    required base metric carries an unrecognised value (any EQ left unresolved).
    """

    def mv(metric: str) -> str:
        return _cvss4_m(metrics, metric)

    av, pr, ui = mv("AV"), mv("PR"), mv("UI")
    ac, at = mv("AC"), mv("AT")
    vc, vi, va = mv("VC"), mv("VI"), mv("VA")
    sc, si, sa = mv("SC"), mv("SI"), mv("SA")

    # EQ1
    if av == "N" and pr == "N" and ui == "N":
        eq1 = "0"
    elif (av == "N" or pr == "N" or ui == "N") and av != "P":
        eq1 = "1"
    elif av == "P" or not (av == "N" or pr == "N" or ui == "N"):
        eq1 = "2"
    else:
        return None

    # EQ2
    if ac == "L" and at == "N":
        eq2 = "0"
    else:
        eq2 = "1"

    # EQ3
    if vc == "H" and vi == "H":
        eq3 = "0"
    elif vc == "H" or vi == "H" or va == "H":
        eq3 = "1"
    elif not (vc == "H" or vi == "H" or va == "H"):
        eq3 = "2"
    else:
        return None

    # EQ4 (MSI/MSA Safety only via modified metrics; base vectors have none)
    if mv("MSI") == "S" or mv("MSA") == "S":
        eq4 = "0"
    elif sc == "H" or si == "H" or sa == "H":
        eq4 = "1"
    else:
        eq4 = "2"

    # EQ5 (Exploit Maturity; base-only defaults to A -> 0)
    e = mv("E")
    if e == "A":
        eq5 = "0"
    elif e == "P":
        eq5 = "1"
    elif e == "U":
        eq5 = "2"
    else:
        return None

    # EQ6 (security requirements; base-only CR/IR/AR default to H)
    cr, ir, ar = mv("CR"), mv("IR"), mv("AR")
    if (
        (cr == "H" and vc == "H")
        or (ir == "H" and vi == "H")
        or (ar == "H" and va == "H")
    ):
        eq6 = "0"
    else:
        eq6 = "1"

    # Validate the base metric values are recognised (defends None scoring).
    for key, val in (
        ("AV", av), ("PR", pr), ("UI", ui), ("AC", ac), ("AT", at),
        ("VC", vc), ("VI", vi), ("VA", va), ("SC", sc), ("SI", si), ("SA", sa),
    ):
        if val not in _CVSS4_LEVEL_MAPS[key]:
            return None

    return eq1 + eq2 + eq3 + eq4 + eq5 + eq6


def _cvss4_extract(metric: str, max_vector: str) -> str:
    """Pull a metric value out of a composed max-vector string.

    Mirrors the reference ``extractValueMetric``: find ``<metric>:`` and read
    up to the next ``/``.
    """
    idx = max_vector.find(metric + ":")
    if idx < 0:
        return ""
    start = idx + len(metric) + 1
    end = max_vector.find("/", start)
    if end < 0:
        return max_vector[start:]
    return max_vector[start:end]


def _cvss4_base_score(vector: str) -> float | None:
    """Compute a CVSS v4.0 base score from a vector string.

    Faithful port of the FIRST/Red Hat reference ``cvss_score``, scoped to the
    base metrics. Returns ``None`` if a required base metric is missing or the
    vector reduces to no valid MacroVector — the caller then falls back to other
    severity sources rather than guessing.
    """
    metrics = _cvss_vector_metrics(vector)
    metrics.pop("CVSS", None)
    for required in _CVSS4_BASE_METRICS:
        if required not in metrics:
            return None

    # Shortcut: no impact on any system -> 0.0 (reference exception).
    if all(
        _cvss4_m(metrics, k) == "N"
        for k in ("VC", "VI", "VA", "SC", "SI", "SA")
    ):
        return 0.0

    macrovector = _cvss4_macrovector(metrics)
    if macrovector is None:
        return None
    value = _CVSS4_LOOKUP.get(macrovector)
    if value is None:
        return None

    eq1, eq2, eq3, eq4, eq5, eq6 = (int(d) for d in macrovector)

    # Next-lower MacroVectors per EQ (None when they don't exist).
    def lower(idx: int, delta: int = 1) -> float | None:
        digits = list(macrovector)
        digits[idx] = str(int(digits[idx]) + delta)
        return _CVSS4_LOOKUP.get("".join(digits))

    score_eq1_lower = lower(0)
    score_eq2_lower = lower(1)
    score_eq4_lower = lower(3)
    score_eq5_lower = lower(4)

    # EQ3/EQ6 are jointly related (reference logic).
    if eq3 == 1 and eq6 == 1:
        score_eq3eq6_lower = lower(2)
    elif eq3 == 0 and eq6 == 1:
        score_eq3eq6_lower = lower(2)
    elif eq3 == 1 and eq6 == 0:
        score_eq3eq6_lower = lower(5)
    elif eq3 == 0 and eq6 == 0:
        left = lower(5)
        right = lower(2)
        if left is None:
            score_eq3eq6_lower = right
        elif right is None:
            score_eq3eq6_lower = left
        else:
            score_eq3eq6_lower = max(left, right)
    else:  # 21 -> 32 does not exist
        digits = list(macrovector)
        digits[2] = str(eq3 + 1)
        digits[5] = str(eq6 + 1)
        score_eq3eq6_lower = _CVSS4_LOOKUP.get("".join(digits))

    # Compose the candidate max-vectors (cartesian product of per-EQ corners).
    eq1_maxes = _CVSS4_MAX_COMPOSED_EQ1[eq1]
    eq2_maxes = _CVSS4_MAX_COMPOSED_EQ2[eq2]
    eq3_eq6_maxes = _CVSS4_MAX_COMPOSED_EQ3[eq3].get(eq6, [])
    eq4_maxes = _CVSS4_MAX_COMPOSED_EQ4[eq4]
    eq5_maxes = _CVSS4_MAX_COMPOSED_EQ5[eq5]

    chosen: str | None = None
    distances: dict[str, float] = {}
    for m1 in eq1_maxes:
        for m2 in eq2_maxes:
            for m36 in eq3_eq6_maxes:
                for m4 in eq4_maxes:
                    for m5 in eq5_maxes:
                        max_vector = m1 + m2 + m36 + m4 + m5
                        d: dict[str, float] = {}
                        ok = True
                        for met in (
                            "AV", "PR", "UI", "AC", "AT", "VC", "VI", "VA",
                            "SC", "SI", "SA", "CR", "IR", "AR",
                        ):
                            lv = _CVSS4_LEVEL_MAPS[met]
                            actual = lv.get(_cvss4_m(metrics, met))
                            ref = lv.get(_cvss4_extract(met, max_vector))
                            if actual is None or ref is None:
                                ok = False
                                break
                            diff = actual - ref
                            # A tiny negative epsilon from float subtraction must
                            # not reject a corner; the reference compares raw.
                            if diff < -1e-9:
                                ok = False
                                break
                            d[met] = diff
                        if ok:
                            chosen = max_vector
                            distances = d
                            break
                    if chosen is not None:
                        break
                if chosen is not None:
                    break
            if chosen is not None:
                break
        if chosen is not None:
            break

    if chosen is None:
        # No corner dominates the vector; cannot interpolate. Fall back.
        return None

    sd = distances
    cur_eq1 = sd["AV"] + sd["PR"] + sd["UI"]
    cur_eq2 = sd["AC"] + sd["AT"]
    cur_eq3eq6 = sd["VC"] + sd["VI"] + sd["VA"] + sd["CR"] + sd["IR"] + sd["AR"]
    cur_eq4 = sd["SC"] + sd["SI"] + sd["SA"]

    step = 0.1
    max_eq1 = _CVSS4_MAX_SEVERITY["eq1"][eq1] * step
    max_eq2 = _CVSS4_MAX_SEVERITY["eq2"][eq2] * step
    max_eq3eq6 = _CVSS4_MAX_SEVERITY_EQ3EQ6[eq3][eq6] * step
    max_eq4 = _CVSS4_MAX_SEVERITY["eq4"][eq4] * step

    n_existing = 0
    norm_eq1 = norm_eq2 = norm_eq3eq6 = norm_eq4 = norm_eq5 = 0.0

    if score_eq1_lower is not None:
        n_existing += 1
        norm_eq1 = (value - score_eq1_lower) * (cur_eq1 / max_eq1)
    if score_eq2_lower is not None:
        n_existing += 1
        norm_eq2 = (value - score_eq2_lower) * (cur_eq2 / max_eq2)
    if score_eq3eq6_lower is not None:
        n_existing += 1
        norm_eq3eq6 = (value - score_eq3eq6_lower) * (cur_eq3eq6 / max_eq3eq6)
    if score_eq4_lower is not None:
        n_existing += 1
        norm_eq4 = (value - score_eq4_lower) * (cur_eq4 / max_eq4)
    if score_eq5_lower is not None:
        n_existing += 1
        norm_eq5 = 0.0  # eq5 percentage is always 0

    if n_existing == 0:
        mean_distance = 0.0
    else:
        mean_distance = (
            norm_eq1 + norm_eq2 + norm_eq3eq6 + norm_eq4 + norm_eq5
        ) / n_existing

    value -= mean_distance
    if value < 0:
        value = 0.0
    if value > 10:
        value = 10.0
    # Match the reference's ``Math.round(value * 10) / 10`` (round half *up*),
    # which differs from Python's banker's rounding on .x5 boundaries.
    return math.floor(value * 10 + 0.5) / 10.0


def _cvss_score_and_version(vector: str) -> tuple[float, str] | None:
    """Compute the numeric base score and CVSS version label for a vector.

    Returns ``(base_score, version)`` where ``version`` is ``"2.0"``, ``"3.x"``,
    or ``"4.0"``, or ``None`` if the vector is unrecognised / unscorable. This is
    the single place casket turns a vector into a number: ``_severity_from_cvss_vector``
    bands the score for the qualitative label, and ``_cvss_from_osv`` surfaces the
    raw number and the version for operator triage. Version is identified by the
    ``CVSS:2`` / ``CVSS:3`` / ``CVSS:4`` prefix; a bare (prefix-less) vector that
    carries the v2-only ``Au`` metric is scored as v2, otherwise as v3 (the
    original prefix-less behaviour).
    """
    v = vector.strip()
    upper = v.upper()
    if upper.startswith("CVSS:4"):
        score = _cvss4_base_score(v)
        return (score, "4.0") if score is not None else None
    if upper.startswith("CVSS:3"):
        score = _cvss3_base_score(v)
        return (score, "3.x") if score is not None else None
    if upper.startswith("CVSS:2"):
        score = _cvss2_base_score(v)
        return (score, "2.0") if score is not None else None
    # Prefix-less vector: the v2-only ``Au`` metric disambiguates it as v2,
    # otherwise treat a bare vector as v3 (the original behaviour).
    metrics = _cvss_vector_metrics(v)
    if "AU" in metrics:
        score = _cvss2_base_score(v)
        return (score, "2.0") if score is not None else None
    score = _cvss3_base_score(v)
    return (score, "3.x") if score is not None else None


def _severity_from_cvss_vector(vector: str) -> str | None:
    """Derive a qualitative severity from a CVSS vector string, or ``None``.

    Handles CVSS v3.x, v4.0, and legacy CVSS v2 vectors by computing the base
    score with a small stdlib calculator and mapping it through casket's unified
    qualitative band (``_cvss_score_to_severity``). Version is identified by the
    ``CVSS:3`` / ``CVSS:4`` prefix; a bare (prefix-less) vector that carries the
    v2-only ``Au`` metric is scored as v2, otherwise as v3.

    [Worker decision: unified severity band — Rotation 14, POST_V01 v2 scoring]
    CVSS v2's *native* qualitative scale has no "critical" tier (v2 tops out at
    "High" for 7.0–10.0). We deliberately map v2 base scores through the same
    v3.1 band function (≥9.0 critical) the rest of casket uses, so every finding
    — v2- or v3-sourced — speaks one severity vocabulary. The --fail-on gate and
    SARIF security-severity float both consume that single vocabulary; emitting
    a v2-only scale here would split it. The numeric score is faithful to the v2
    spec; only the qualitative label is unified.

    [Worker decision: CVSS v4.0 scoring — Rotation 16, POST_V01 candidate]
    v4.0's base score is not closed-form: it's a MacroVector lookup plus
    severity-distance interpolation (FIRST spec section 8.2). We implement that
    faithfully (``_cvss4_base_score``), scoped to the BASE metrics OSV records;
    Threat/Environmental/Supplemental metrics default to their score-neutral
    values, which is how a base-only vector scores. This closes the last
    unscored CVSS family — v4 vectors previously fell through to the "high"
    default, degrading severity accuracy that the --fail-on gate, SARIF
    security-severity sort, and --min-severity filter all consume.
    """
    result = _cvss_score_and_version(vector)
    if result is None:
        return None
    score, _version = result
    return _cvss_score_to_severity(score)


# CVSS v4.0 Supplemental Metric Group (FIRST CVSS v4.0 spec section 2.4).
# These metrics convey *additional extrinsic context* about a vulnerability
# (operator-facing triage signal — Safety, recovery effort, provider urgency)
# but **do not affect the base score**, so casket parses-and-ignores them when
# computing the band. Surfacing them as decoded labels in finding ``detail``
# gives an operator triage context the band alone can't carry: a base score of
# 7.5 with ``safety: present`` (a physical-harm risk) is qualitatively
# different from a 7.5 with ``safety: negligible``, and ``provider_urgency:
# red`` is a vendor's own "patch now" signal that the base score doesn't
# encode. Keys are omitted individually when the source metric is absent or
# ``X`` (Not Defined), and the whole block is omitted when no supplemental
# metric is present — so a base-only vector adds nothing to the report and the
# output stays byte-identical to the pre-surfacing default. Only applies to
# v4.0 vectors; v2/v3 have no supplemental metric group.
#
# Decoded labels follow the FIRST spec's documented prose terms verbatim
# (lower-cased) so operators can grep them against the spec without an
# additional lookup table.
_CVSS4_SUPPLEMENTAL_DECODE: dict[str, dict[str, str]] = {
    # Safety (S): impact on human Safety per IEC 61508. Spec values:
    #   X = Not Defined, N = Negligible, P = Present.
    "S": {"N": "negligible", "P": "present"},
    # Automatable (AU): can the attack be automated across many targets?
    #   X = Not Defined, N = No, Y = Yes.
    "AU": {"N": "no", "Y": "yes"},
    # Recovery (R): system recoverability after exploit.
    #   X = Not Defined, A = Automatic, U = User, I = Irrecoverable.
    "R": {"A": "automatic", "U": "user", "I": "irrecoverable"},
    # Value Density (V): how dense is the resource controlled by the target?
    #   X = Not Defined, D = Diffuse, C = Concentrated.
    "V": {"D": "diffuse", "C": "concentrated"},
    # Vulnerability Response Effort (RE): effort to deploy the fix.
    #   X = Not Defined, L = Low, M = Moderate, H = High.
    "RE": {"L": "low", "M": "moderate", "H": "high"},
    # Provider Urgency (U): vendor-asserted patch urgency (TLP-coloured).
    #   X = Not Defined, Clear/Green/Amber/Red.
    "U": {
        "CLEAR": "clear", "GREEN": "green",
        "AMBER": "amber", "RED": "red",
    },
}

# Stable output-key order for the supplemental block (matches FIRST's spec
# section ordering: Safety, Automatable, Recovery, Value Density, Response
# Effort, Provider Urgency). Stable ordering keeps the JSON/SARIF surface
# diffable run-to-run.
_CVSS4_SUPPLEMENTAL_ORDER: tuple[tuple[str, str], ...] = (
    ("S", "safety"),
    ("AU", "automatable"),
    ("R", "recovery"),
    ("V", "value_density"),
    ("RE", "response_effort"),
    ("U", "provider_urgency"),
)


def _cvss4_supplemental_metrics(vector: str) -> dict[str, str]:
    """Extract decoded CVSS v4.0 Supplemental Metric Group values from a vector.

    Returns a ``{snake_case_label: decoded_value}`` dict in stable spec order.
    A metric absent from the vector, set to ``X`` (Not Defined), or carrying an
    unrecognised value is omitted — only operator-actionable values surface.
    The result is empty (``{}``) when the vector carries no supplemental
    metrics at all, which is the common case for base-only OSV records. Only
    meaningful for v4.0 vectors; callers should gate on the version label.

    The supplemental metric group does NOT affect the base score (FIRST CVSS
    v4.0 spec section 2.4), so this is a pure surfacing helper — no scoring
    side effects.
    """
    metrics = _cvss_vector_metrics(vector)
    out: dict[str, str] = {}
    for raw_key, label in _CVSS4_SUPPLEMENTAL_ORDER:
        raw = metrics.get(raw_key)
        if not raw or raw == "X":
            continue
        decoded = _CVSS4_SUPPLEMENTAL_DECODE[raw_key].get(raw)
        if decoded is None:
            continue
        out[label] = decoded
    return out


def _cvss_from_osv(vuln: dict) -> tuple[float, str, str] | None:
    """Extract the numeric CVSS base score, version, and source vector.

    Walks the standard OSV ``severity`` array in order and returns
    ``(base_score, version, vector)`` for the first entry casket can score
    (CVSS v4.0/v3.x/v2), or ``None`` when no scorable CVSS vector is present
    (the record's severity then came from ``database_specific`` or the
    conservative default, and there is no numeric score to surface).

    This is the triage companion to ``_severity_from_osv``: the band tells an
    operator *which* bucket a finding is in, the numeric score tells them where
    *within* the bucket it sits (a 9.8 critical vs. a 9.0 one), and the vector
    shows *why*. The score is already computed during banding — surfacing it
    discards nothing and adds no work beyond the same single calculator call.
    """
    for entry in vuln.get("severity", []) or []:
        if not isinstance(entry, dict):
            continue
        vector = entry.get("score")
        if not isinstance(vector, str):
            continue
        result = _cvss_score_and_version(vector)
        if result is not None:
            score, version = result
            return (score, version, vector.strip())
    return None


def _severity_from_osv(vuln: dict) -> str:
    """Best-effort qualitative severity for an OSV record.

    Resolution order, most authoritative first:

    1. The standard OSV ``severity`` array — a list of
       ``{"type": "CVSS_V4"|"CVSS_V3"|"CVSS_V2"|..., "score": "<vector>"}``
       entries. This is where OSV.dev actually records CVSS for the overwhelming
       majority of records; we parse CVSS v4.0, v3.x *and* legacy v2 vectors and
       map the base score to a band. (The original implementation ignored this
       field entirely, so almost every live finding silently defaulted to
       "high"; Rotation 13 added v3 scoring, Rotation 14 added v2 — older CVEs on
       the aged packages a container scanner finds are frequently v2-only — and
       Rotation 16 added v4.0, closing the last unscored CVSS family. A CVSS
       record carrying a malformed vector still falls through to source 2.)
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
