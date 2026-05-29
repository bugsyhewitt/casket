"""Misconfiguration check: inspect image config for risky settings.

Operates on the image config (the Dockerfile-equivalent settings baked into the
image), not layer file contents. Findings use the config descriptor digest as
their ``layer_sha`` so the JSON shape stays uniform with the other checks.
"""

from __future__ import annotations

import re
from typing import Any

from casket.findings import Finding
from casket.oci import Image
from casket.rules import load_ruleset

# Values of config.User that mean "root".
_ROOT_USERS = {"", "root", "0", "0:0", "root:root"}


def _port_number(port: str) -> str:
    """Extract the bare port number from an ExposedPorts key.

    ExposedPorts keys look like ``"22/tcp"``, ``"5432/udp"``, or sometimes a
    bare ``"22"``. We key the sensitive-port map on the number alone so a port
    matches regardless of its protocol suffix.
    """
    return str(port).split("/", 1)[0].strip()


def run(image: Image, *, osv_client: Any = None) -> list[Finding]:
    rules = load_ruleset("misconfig")
    cfg = image.config.get("config", {}) or {}
    layer_sha = image.config_descriptor_digest
    findings: list[Finding] = []

    # Build the sensitive-port lookup once so the exposed_port handler can skip
    # any port the sensitive_port rule already reports (no duplicate findings).
    sensitive_rule = next((r for r in rules if r.get("kind") == "sensitive_port"), None)
    sensitive_ports: dict[str, dict[str, Any]] = (
        (sensitive_rule.get("ports") or {}) if sensitive_rule else {}
    )

    for rule in rules:
        kind = rule.get("kind")
        if kind == "running_as_root":
            user = str(cfg.get("User", "")).strip()
            if user in _ROOT_USERS:
                findings.append(
                    Finding(
                        category="misconfig",
                        title=rule["title"],
                        severity=rule.get("severity", "high"),
                        layer_sha=layer_sha,
                        path_in_layer="<image config>",
                        detail={
                            "rule": rule["rule"],
                            "user": user or "(unset → root)",
                        },
                    )
                )
        elif kind == "sensitive_port":
            for port in (cfg.get("ExposedPorts") or {}):
                info = sensitive_ports.get(_port_number(port))
                if info is None:
                    continue
                findings.append(
                    Finding(
                        category="misconfig",
                        title=rule["title"],
                        # Per-port severity from the rule's ports map; fall back
                        # to high (sensitive ports are high-risk by definition).
                        severity=str(info.get("severity", "high")),
                        layer_sha=layer_sha,
                        path_in_layer="<image config>",
                        detail={
                            "rule": rule["rule"],
                            "port": port,
                            "service": info.get("service", "unknown"),
                        },
                    )
                )
        elif kind == "exposed_port":
            for port in (cfg.get("ExposedPorts") or {}):
                # A sensitive port is reported by the sensitive_port rule above;
                # don't also emit a generic low-severity finding for it.
                if _port_number(port) in sensitive_ports:
                    continue
                findings.append(
                    Finding(
                        category="misconfig",
                        title=rule["title"],
                        severity=rule.get("severity", "low"),
                        layer_sha=layer_sha,
                        path_in_layer="<image config>",
                        detail={"rule": rule["rule"], "port": port},
                    )
                )
        elif kind == "suspicious_env":
            name_re = re.compile(rule["env_name_regex"])
            for entry in (cfg.get("Env") or []):
                name = entry.split("=", 1)[0]
                if name_re.search(name):
                    findings.append(
                        Finding(
                            category="misconfig",
                            title=rule["title"],
                            severity=rule.get("severity", "medium"),
                            layer_sha=layer_sha,
                            path_in_layer="<image config>",
                            detail={"rule": rule["rule"], "env_var": name},
                        )
                    )
    return findings
