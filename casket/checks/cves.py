"""CVE check: extract installed packages from layers, query OSV.dev.

[Worker decision: package extraction scope for v0.1]
We extract packages from three common, easy-to-parse, daemonless sources:

  - PyPI:   ``*.dist-info/METADATA`` and ``*.egg-info/PKG-INFO`` (Name/Version)
  - Debian: ``var/lib/dpkg/status`` (Package/Version stanzas)
  - Alpine: ``lib/apk/db/installed`` (APKINDEX P:/V: stanzas)

This covers the bundled ``old-package`` fixture and the most common real images
without pulling in a heavyweight SBOM library — staying within the v0.1
"no SBOM generation" guardrail. Each discovered package version is resolved
against OSV.dev (cache-first via ``casket.osv``).

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

import re
from dataclasses import dataclass
from typing import Any

from casket.findings import Finding
from casket.oci import Image, Layer
from casket.osv import OSVClient

_DIST_INFO_RE = re.compile(r"\.(dist-info|egg-info)/(METADATA|PKG-INFO)$")
_DPKG_STATUS = "var/lib/dpkg/status"
_APK_INSTALLED = "lib/apk/db/installed"


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
