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


def run(image: Image, *, osv_client: Any = None) -> list[Finding]:
    rules = load_ruleset("misconfig")
    cfg = image.config.get("config", {}) or {}
    layer_sha = image.config_descriptor_digest
    findings: list[Finding] = []

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
        elif kind == "exposed_port":
            for port in (cfg.get("ExposedPorts") or {}):
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
