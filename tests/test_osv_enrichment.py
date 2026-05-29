"""Tests for OSV reference & alias enrichment (Rotation 19).

casket surfaces the cross-reference identifiers and remediation/advisory/exploit
URLs the OSV record already carries — no extra network call — into the CVE
finding ``detail``:

  - ``aliases``        : the full de-duplicated id list (CVE + GHSA + distro ids)
  - ``fix_urls``       : OSV ``references`` of type FIX (the patch)
  - ``advisory_urls``  : OSV ``references`` of type ADVISORY / REPORT
  - ``exploit_urls``   : OSV ``references`` of type EXPLOIT / EVIDENCE

These flow through json / h1md / sarif output for free, and the keys are omitted
when empty so clean/seed findings are unaffected.
"""

from __future__ import annotations

import json

from casket.checks import cves
from casket import findings as findings_mod
from casket.oci import load_tarball
from casket.osv import OSVClient
from tests.conftest import fixture_path


# --- _aliases_from_osv (pure helper) ------------------------------------


def test_aliases_extracts_string_list():
    vuln = {"aliases": ["CVE-2018-18074", "GHSA-x84v-xcm2-53pg"]}
    assert cves._aliases_from_osv(vuln) == [
        "CVE-2018-18074",
        "GHSA-x84v-xcm2-53pg",
    ]


def test_aliases_dedupes_preserving_order():
    vuln = {"aliases": ["CVE-1", "GHSA-2", "CVE-1", "GHSA-2", "CVE-3"]}
    assert cves._aliases_from_osv(vuln) == ["CVE-1", "GHSA-2", "CVE-3"]


def test_aliases_drops_non_strings_and_blanks():
    vuln = {"aliases": ["CVE-1", 42, None, "", "   ", "GHSA-2"]}
    assert cves._aliases_from_osv(vuln) == ["CVE-1", "GHSA-2"]


def test_aliases_missing_or_malformed_returns_empty():
    assert cves._aliases_from_osv({}) == []
    assert cves._aliases_from_osv({"aliases": None}) == []
    assert cves._aliases_from_osv({"aliases": "CVE-1"}) == []  # not a list


# --- _references_from_osv (pure helper) ---------------------------------


def test_references_buckets_by_type():
    vuln = {
        "references": [
            {"type": "FIX", "url": "https://github.com/p/p/commit/abc"},
            {"type": "ADVISORY", "url": "https://github.com/advisories/GHSA-x"},
            {"type": "REPORT", "url": "https://bugs.example/123"},
            {"type": "EXPLOIT", "url": "https://exploit.example/poc"},
            {"type": "EVIDENCE", "url": "https://evidence.example/e"},
        ]
    }
    refs = cves._references_from_osv(vuln)
    assert refs["fix"] == ["https://github.com/p/p/commit/abc"]
    assert refs["advisory"] == [
        "https://github.com/advisories/GHSA-x",
        "https://bugs.example/123",
    ]
    assert refs["exploit"] == [
        "https://exploit.example/poc",
        "https://evidence.example/e",
    ]


def test_references_ignores_irrelevant_types():
    vuln = {
        "references": [
            {"type": "PACKAGE", "url": "https://pypi.org/project/requests"},
            {"type": "ARTICLE", "url": "https://blog.example/post"},
            {"type": "WEB", "url": "https://example.com/"},
        ]
    }
    refs = cves._references_from_osv(vuln)
    assert refs == {"fix": [], "advisory": [], "exploit": []}


def test_references_type_is_case_insensitive():
    vuln = {"references": [{"type": "fix", "url": "https://patch"}]}
    assert cves._references_from_osv(vuln)["fix"] == ["https://patch"]


def test_references_dedupes_urls_within_bucket():
    vuln = {
        "references": [
            {"type": "FIX", "url": "https://patch"},
            {"type": "FIX", "url": "https://patch"},
            {"type": "FIX", "url": "https://patch2"},
        ]
    }
    assert cves._references_from_osv(vuln)["fix"] == [
        "https://patch",
        "https://patch2",
    ]


def test_references_tolerates_malformed_entries():
    vuln = {
        "references": [
            "not-a-dict",
            {"type": "FIX"},  # no url
            {"type": "FIX", "url": ""},  # blank url
            {"type": "FIX", "url": "   "},  # whitespace url
            {"url": "https://no-type"},  # missing type -> ignored
            {"type": 7, "url": "https://bad-type"},  # non-string type -> ignored
            {"type": "FIX", "url": "https://good"},
        ]
    }
    assert cves._references_from_osv(vuln)["fix"] == ["https://good"]


def test_references_missing_or_malformed_returns_empty_buckets():
    empty = {"fix": [], "advisory": [], "exploit": []}
    assert cves._references_from_osv({}) == empty
    assert cves._references_from_osv({"references": None}) == empty
    assert cves._references_from_osv({"references": "x"}) == empty


# --- end-to-end through cves.run() --------------------------------------


def _seed_enriched(client):
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
                "references": [
                    {"type": "FIX", "url": "https://github.com/psf/requests/commit/c45d"},
                    {"type": "ADVISORY", "url": "https://github.com/advisories/GHSA-x84v"},
                    {"type": "EXPLOIT", "url": "https://exploit.example/requests-poc"},
                    {"type": "WEB", "url": "https://requests.readthedocs.io/"},
                ],
            }
        ],
    )


def test_run_surfaces_aliases_and_reference_urls(_isolate_osv_cache):
    img = load_tarball(fixture_path("old-package.tar"))
    client = OSVClient(cache_path=_isolate_osv_cache, offline=True)
    _seed_enriched(client)

    findings = cves.run(img, osv_client=client)
    assert findings
    detail = findings[0].detail

    # Headline id still prefers the CVE alias.
    assert detail["cve_id"] == "CVE-2018-18074"
    assert detail["osv_id"] == "GHSA-x84v-xcm2-53pg"
    # Full alias list surfaced and de-duplicated, CVE first.
    assert detail["aliases"] == ["CVE-2018-18074", "GHSA-x84v-xcm2-53pg"]
    # Reference buckets surfaced; the irrelevant WEB ref is dropped.
    assert detail["fix_urls"] == ["https://github.com/psf/requests/commit/c45d"]
    assert detail["advisory_urls"] == ["https://github.com/advisories/GHSA-x84v"]
    assert detail["exploit_urls"] == ["https://exploit.example/requests-poc"]


def test_run_omits_enrichment_keys_when_absent(_isolate_osv_cache):
    """A record with no aliases / references must not gain empty enrichment keys.

    This keeps clean/seed findings (and the existing tests) byte-compatible.
    """
    img = load_tarball(fixture_path("old-package.tar"))
    client = OSVClient(cache_path=_isolate_osv_cache, offline=True)
    client.seed(
        "PyPI",
        "requests",
        "2.19.0",
        [{"id": "OSV-NO-REFS", "summary": "x", "database_specific": {"severity": "low"}}],
    )
    findings = cves.run(img, osv_client=client)
    assert findings
    detail = findings[0].detail
    for key in ("aliases", "fix_urls", "advisory_urls", "exploit_urls"):
        assert key not in detail
    # Headline id falls back to the OSV id when no CVE alias exists.
    assert detail["cve_id"] == "OSV-NO-REFS"


def test_run_partial_references_only_surfaces_present_buckets(_isolate_osv_cache):
    img = load_tarball(fixture_path("old-package.tar"))
    client = OSVClient(cache_path=_isolate_osv_cache, offline=True)
    client.seed(
        "PyPI",
        "requests",
        "2.19.0",
        [
            {
                "id": "CVE-2018-18074",
                "aliases": ["CVE-2018-18074"],
                "summary": "x",
                "references": [
                    {"type": "ADVISORY", "url": "https://advisory.only"},
                ],
            }
        ],
    )
    findings = cves.run(img, osv_client=client)
    detail = findings[0].detail
    assert detail["advisory_urls"] == ["https://advisory.only"]
    assert "fix_urls" not in detail
    assert "exploit_urls" not in detail


# --- output-format surfacing --------------------------------------------


def test_enrichment_flows_to_json_output(_isolate_osv_cache):
    img = load_tarball(fixture_path("old-package.tar"))
    client = OSVClient(cache_path=_isolate_osv_cache, offline=True)
    _seed_enriched(client)
    findings = cves.run(img, osv_client=client)

    doc = json.loads(findings_mod.render(findings, "json", image="img:latest"))
    f = doc["findings"][0]
    # Detail keys are flattened to the top level of each finding in json.
    assert f["fix_urls"] == ["https://github.com/psf/requests/commit/c45d"]
    assert f["advisory_urls"] == ["https://github.com/advisories/GHSA-x84v"]
    assert "CVE-2018-18074" in f["aliases"]


def test_enrichment_flows_to_sarif_properties(_isolate_osv_cache):
    img = load_tarball(fixture_path("old-package.tar"))
    client = OSVClient(cache_path=_isolate_osv_cache, offline=True)
    _seed_enriched(client)
    findings = cves.run(img, osv_client=client)

    doc = json.loads(findings_mod.render(findings, "sarif", image="img:latest"))
    props = doc["runs"][0]["results"][0]["properties"]
    assert props["fix_urls"] == ["https://github.com/psf/requests/commit/c45d"]
    assert props["advisory_urls"] == ["https://github.com/advisories/GHSA-x84v"]
    assert props["exploit_urls"] == ["https://exploit.example/requests-poc"]


def test_enrichment_flows_to_h1md_output(_isolate_osv_cache):
    img = load_tarball(fixture_path("old-package.tar"))
    client = OSVClient(cache_path=_isolate_osv_cache, offline=True)
    _seed_enriched(client)
    findings = cves.run(img, osv_client=client)

    md = findings_mod.render(findings, "h1md", image="img:latest")
    assert "fix_urls" in md
    assert "https://github.com/psf/requests/commit/c45d" in md
    assert "advisory_urls" in md
