"""Tests for OSV fixed-version remediation surfacing (Rotation 21).

casket surfaces the *remediation version* — which version to upgrade to —
that the OSV record already carries in its ``affected`` ranges (the ``fixed``
event of each vulnerable range), into the CVE finding ``detail`` as
``fixed_versions``. This is the single most actionable remediation field a
scanner can give an operator, and it costs no extra network call: the
``affected`` array is already in the record casket fetches and caches for
severity.

The key flows through json / h1md / sarif output for free, and is omitted
entirely for still-unfixed vulns (no ``fixed`` event), so clean/seed findings
and the existing tests are unaffected.
"""

from __future__ import annotations

import json

from casket.checks import cves
from casket import findings as findings_mod
from casket.oci import load_tarball
from casket.osv import OSVClient
from tests.conftest import fixture_path


# --- _fixed_versions_from_osv (pure helper) -----------------------------


def test_fixed_extracts_single_version():
    vuln = {
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "requests"},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "0"}, {"fixed": "2.20.0"}],
                    }
                ],
            }
        ]
    }
    assert cves._fixed_versions_from_osv(vuln, "requests") == ["2.20.0"]


def test_fixed_collects_multiple_across_ranges_deduped_in_order():
    vuln = {
        "affected": [
            {
                "package": {"name": "openssl"},
                "ranges": [
                    {"events": [{"introduced": "0"}, {"fixed": "3.0.7"}]},
                    {"events": [{"introduced": "3.1.0"}, {"fixed": "3.1.4"}]},
                    {"events": [{"introduced": "3.0.0"}, {"fixed": "3.0.7"}]},
                ],
            }
        ]
    }
    # Two distinct fixes, first-seen order, the duplicate 3.0.7 collapsed.
    assert cves._fixed_versions_from_osv(vuln, "openssl") == ["3.0.7", "3.1.4"]


def test_fixed_ignores_open_ended_zero_and_introduced_only():
    vuln = {
        "affected": [
            {
                "package": {"name": "foo"},
                "ranges": [
                    # An unfixed range: only an introduced event.
                    {"events": [{"introduced": "0"}]},
                    # A bizarre but valid "fixed": "0" — the open sentinel, skip.
                    {"events": [{"introduced": "1.0"}, {"fixed": "0"}]},
                ],
            }
        ]
    }
    assert cves._fixed_versions_from_osv(vuln, "foo") == []


def test_fixed_filters_by_package_name_case_insensitive():
    vuln = {
        "affected": [
            {
                "package": {"name": "OpenSSL"},
                "ranges": [{"events": [{"fixed": "3.0.7"}]}],
            },
            {
                # A different package's affected entry must not leak in.
                "package": {"name": "libcrypto-other"},
                "ranges": [{"events": [{"fixed": "9.9.9"}]}],
            },
        ]
    }
    assert cves._fixed_versions_from_osv(vuln, "openssl") == ["3.0.7"]


def test_fixed_accepts_affected_entry_with_no_package():
    # Sparse / seed records sometimes omit the affected ``package`` — better to
    # surface the fix than to drop it on a missing-name mismatch.
    vuln = {
        "affected": [
            {"ranges": [{"events": [{"introduced": "0"}, {"fixed": "1.2.3"}]}]}
        ]
    }
    assert cves._fixed_versions_from_osv(vuln, "anything") == ["1.2.3"]


def test_fixed_tolerates_malformed_structures():
    vuln = {
        "affected": [
            "not-a-dict",
            {"package": {"name": "foo"}},  # no ranges
            {"package": {"name": "foo"}, "ranges": "x"},  # ranges not a list
            {"package": {"name": "foo"}, "ranges": ["bad", {"events": "x"}]},
            {
                "package": {"name": "foo"},
                "ranges": [
                    {"events": ["bad", {"fixed": 7}, {"fixed": ""}, {"fixed": "  "}]}
                ],
            },
            {
                "package": {"name": "foo"},
                "ranges": [{"events": [{"fixed": "5.0.0"}]}],
            },
        ]
    }
    assert cves._fixed_versions_from_osv(vuln, "foo") == ["5.0.0"]


def test_fixed_missing_or_malformed_affected_returns_empty():
    assert cves._fixed_versions_from_osv({}, "foo") == []
    assert cves._fixed_versions_from_osv({"affected": None}, "foo") == []
    assert cves._fixed_versions_from_osv({"affected": "x"}, "foo") == []


# --- end-to-end through cves.run() --------------------------------------


def _seed_with_fix(client, *, fixed="2.20.0"):
    client.seed(
        "PyPI",
        "requests",
        "2.19.0",
        [
            {
                "id": "GHSA-x84v-xcm2-53pg",
                "aliases": ["CVE-2018-18074", "GHSA-x84v-xcm2-53pg"],
                "summary": "requests sends auth on redirect",
                "database_specific": {"severity": "MEDIUM"},
                "affected": [
                    {
                        "package": {"ecosystem": "PyPI", "name": "requests"},
                        "ranges": [
                            {
                                "type": "ECOSYSTEM",
                                "events": [
                                    {"introduced": "0"},
                                    {"fixed": fixed},
                                ],
                            }
                        ],
                    }
                ],
            }
        ],
    )


def test_run_surfaces_fixed_versions(_isolate_osv_cache):
    img = load_tarball(fixture_path("old-package.tar"))
    client = OSVClient(cache_path=_isolate_osv_cache, offline=True)
    _seed_with_fix(client)

    findings = cves.run(img, osv_client=client)
    assert findings
    assert findings[0].detail["fixed_versions"] == ["2.20.0"]


def test_run_omits_fixed_versions_when_unfixed(_isolate_osv_cache):
    """A vuln with no ``fixed`` event must not gain an empty key."""
    img = load_tarball(fixture_path("old-package.tar"))
    client = OSVClient(cache_path=_isolate_osv_cache, offline=True)
    client.seed(
        "PyPI",
        "requests",
        "2.19.0",
        [
            {
                "id": "OSV-UNFIXED",
                "summary": "still unfixed",
                "database_specific": {"severity": "low"},
                "affected": [
                    {
                        "package": {"ecosystem": "PyPI", "name": "requests"},
                        "ranges": [{"events": [{"introduced": "0"}]}],
                    }
                ],
            }
        ],
    )
    findings = cves.run(img, osv_client=client)
    assert findings
    assert "fixed_versions" not in findings[0].detail


def test_run_omits_fixed_versions_when_no_affected(_isolate_osv_cache):
    """Existing seed records with no ``affected`` array stay byte-compatible."""
    img = load_tarball(fixture_path("old-package.tar"))
    client = OSVClient(cache_path=_isolate_osv_cache, offline=True)
    client.seed(
        "PyPI",
        "requests",
        "2.19.0",
        [{"id": "OSV-NO-AFFECTED", "summary": "x", "database_specific": {"severity": "low"}}],
    )
    findings = cves.run(img, osv_client=client)
    assert findings
    assert "fixed_versions" not in findings[0].detail


# --- output-format surfacing --------------------------------------------


def test_fixed_versions_flow_to_json_output(_isolate_osv_cache):
    img = load_tarball(fixture_path("old-package.tar"))
    client = OSVClient(cache_path=_isolate_osv_cache, offline=True)
    _seed_with_fix(client)
    findings = cves.run(img, osv_client=client)

    doc = json.loads(findings_mod.render(findings, "json", image="img:latest"))
    assert doc["findings"][0]["fixed_versions"] == ["2.20.0"]


def test_fixed_versions_flow_to_sarif_properties(_isolate_osv_cache):
    img = load_tarball(fixture_path("old-package.tar"))
    client = OSVClient(cache_path=_isolate_osv_cache, offline=True)
    _seed_with_fix(client)
    findings = cves.run(img, osv_client=client)

    doc = json.loads(findings_mod.render(findings, "sarif", image="img:latest"))
    props = doc["runs"][0]["results"][0]["properties"]
    assert props["fixed_versions"] == ["2.20.0"]


def test_fixed_versions_flow_to_h1md_output(_isolate_osv_cache):
    img = load_tarball(fixture_path("old-package.tar"))
    client = OSVClient(cache_path=_isolate_osv_cache, offline=True)
    _seed_with_fix(client)
    findings = cves.run(img, osv_client=client)

    md = findings_mod.render(findings, "h1md", image="img:latest")
    assert "fixed_versions" in md
    assert "2.20.0" in md
