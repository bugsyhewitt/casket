"""Credential-leak check: scan layer file contents for secret patterns."""

from __future__ import annotations

import re
from typing import Any

from casket.findings import Finding
from casket.oci import Image
from casket.rules import load_ruleset

# Skip files that are unlikely to hold readable secrets / are too big to bother
# decoding as text. Keeps the scan fast and avoids false positives on binaries.
_MAX_BYTES = 1_000_000
_BINARY_PREFIXES = (b"\x7fELF", b"\x89PNG", b"\xff\xd8\xff", b"PK\x03\x04")


def _looks_binary(blob: bytes) -> bool:
    if blob.startswith(_BINARY_PREFIXES):
        return True
    return b"\x00" in blob[:4096]


def run(image: Image, *, osv_client: Any = None) -> list[Finding]:
    rules = load_ruleset("creds")
    compiled = [(r, re.compile(r["regex"])) for r in rules]
    findings: list[Finding] = []

    for layer in image.layers:
        for path, size, reader in layer.iter_files():
            if size > _MAX_BYTES:
                continue
            blob = reader()
            if _looks_binary(blob):
                continue
            try:
                text = blob.decode("utf-8", errors="ignore")
            except Exception:  # pragma: no cover - decode w/ errors never raises
                continue
            for rule, pattern in compiled:
                if pattern.search(text):
                    findings.append(
                        Finding(
                            category="creds",
                            title=rule["title"],
                            severity=rule.get("severity", "high"),
                            layer_sha=layer.digest,
                            path_in_layer=path,
                            detail={"rule": rule["id"]},
                        )
                    )
    return findings
