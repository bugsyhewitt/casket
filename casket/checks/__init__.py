"""casket scan checks: creds, cves, misconfig."""

from __future__ import annotations

from casket.checks import creds, cves, misconfig

# Map check name -> callable(image, *, osv_client=None) -> list[Finding]
REGISTRY = {
    "creds": creds.run,
    "cves": cves.run,
    "misconfig": misconfig.run,
}

ALL_CHECKS = ["creds", "cves", "misconfig"]
