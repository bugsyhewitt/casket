"""Credential-leak check: scan layer file contents for secret patterns."""

from __future__ import annotations

import math
import re
from collections import Counter
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


def _shannon_entropy(s: str, charset: str) -> float:
    """Return Shannon entropy (bits/char) of characters in *s* that are in *charset*."""
    if not s:
        return 0.0
    chars = [c for c in s if c in charset]
    if not chars:
        return 0.0
    total = len(chars)
    return -sum((c / total) * math.log2(c / total) for c in Counter(chars).values())


# Regex to find runs of base64-alphabet characters of sufficient length.
# We compile once at module level; the minimum length is the most permissive
# threshold (20) — we apply the per-rule min_length check afterwards.
_BASE64_RUN_RE = re.compile(r"[A-Za-z0-9+/=]{20,}")


def _scan_entropy(text: str, rule: dict[str, Any], path: str) -> list[str]:
    """Return a list of redacted match descriptions that exceed the entropy threshold.

    Each element is a string like ``'AbCdEfGh... (entropy=5.23)'``.
    """
    charset: str = rule.get("charset", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
    min_length: int = rule.get("min_length", 20)
    threshold: float = rule.get("entropy_threshold", 4.5)

    # Lower threshold for log files.
    is_log_path = "log" in path.lower() or path.lower().endswith(".log")
    if is_log_path:
        threshold = rule.get("entropy_threshold_log", 4.0)

    hits: list[str] = []
    for m in _BASE64_RUN_RE.finditer(text):
        token = m.group(0)
        if len(token) < min_length:
            continue
        entropy = _shannon_entropy(token, charset)
        if entropy > threshold:
            # Emit first 8 chars only — enough for triage, not enough to leak.
            redacted = token[:8] + "..."
            hits.append(f"{redacted} (entropy={entropy:.2f})")
    return hits


def run(image: Image, *, osv_client: Any = None) -> list[Finding]:
    rules = load_ruleset("creds")
    # Partition rules by kind: regex (default) vs entropy.
    regex_rules: list[tuple[dict[str, Any], re.Pattern[str]]] = []
    entropy_rules: list[dict[str, Any]] = []
    for r in rules:
        if r.get("kind") == "entropy":
            entropy_rules.append(r)
        else:
            regex_rules.append((r, re.compile(r["regex"])))

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

            # Phase 1: regex pattern matching (existing behaviour).
            for rule, pattern in regex_rules:
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

            # Phase 2: entropy analysis for tokens that don't match known formats.
            for rule in entropy_rules:
                hits = _scan_entropy(text, rule, path)
                if hits:
                    # Emit one finding per file (not per token) with a detail
                    # listing the first hit's redacted prefix + entropy score.
                    findings.append(
                        Finding(
                            category="creds",
                            title=rule["title"],
                            severity=rule.get("severity", "medium"),
                            layer_sha=layer.digest,
                            path_in_layer=path,
                            detail={
                                "rule": rule["id"],
                                "finding_id": rule.get("finding_id", "CASKET-CREDS-ENTROPY-001"),
                                "detail": hits[0],
                                "match_count": len(hits),
                            },
                        )
                    )
    return findings
