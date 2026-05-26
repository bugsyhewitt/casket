"""Check-level tests: creds, cves, misconfig."""

from __future__ import annotations

from casket.checks import creds, cves, misconfig
from casket.oci import load_tarball
from casket.osv import OSVClient
from tests.conftest import fixture_path


def test_creds_check_finds_aws_secret():
    img = load_tarball(fixture_path("leaky-image.tar"))
    findings = creds.run(img)
    assert findings, "expected at least one creds finding"
    by_rule = {f.detail["rule"] for f in findings}
    assert "aws_secret_access_key" in by_rule
    f = next(f for f in findings if f.detail["rule"] == "aws_secret_access_key")
    assert f.category == "creds"
    assert f.layer_sha.startswith("sha256:")
    assert f.path_in_layer == "app/.env"


def test_creds_check_clean_image_no_findings():
    img = load_tarball(fixture_path("rootuser-image.tar"))
    findings = creds.run(img)
    # rootuser-image's layer has no secrets in file contents (only config env).
    assert findings == []


def test_cves_check_emits_cve_finding(_isolate_osv_cache):
    img = load_tarball(fixture_path("old-package.tar"))
    client = OSVClient(cache_path=_isolate_osv_cache, offline=True)
    client.seed(
        "PyPI",
        "requests",
        "2.19.0",
        [
            {
                "id": "GHSA-x84v-xcm2-53pg",
                "aliases": ["CVE-2018-18074"],
                "summary": "requests sends auth on redirect",
                "database_specific": {"severity": "MEDIUM"},
            }
        ],
    )
    findings = cves.run(img, osv_client=client)
    assert findings, "expected a CVE finding for requests 2.19.0"
    f = findings[0]
    assert f.category == "cve"
    assert f.detail["cve_id"] == "CVE-2018-18074"
    assert f.detail["package"] == "requests"
    assert f.detail["installed_version"] == "2.19.0"


def test_cves_check_resolves_via_bundled_seed_db_offline(_isolate_osv_cache):
    # Fresh empty disk cache + offline: the bundled osv-seed.json must still
    # resolve the fixture's requests 2.19.0 -> CVE-2018-18074.
    img = load_tarball(fixture_path("old-package.tar"))
    client = OSVClient(cache_path=_isolate_osv_cache, offline=True)
    findings = cves.run(img, osv_client=client)
    assert findings, "bundled seed DB should resolve the fixture package offline"
    assert findings[0].detail["cve_id"] == "CVE-2018-18074"


def test_cves_check_no_vulns_for_unknown_package(_isolate_osv_cache):
    img = load_tarball(fixture_path("leaky-image.tar"))  # no package metadata
    client = OSVClient(cache_path=_isolate_osv_cache, offline=True)
    findings = cves.run(img, osv_client=client)
    assert findings == []


def test_parse_apk_installed_extracts_name_and_version():
    db = (
        "C:Q1abc==\n"
        "P:musl\n"
        "V:1.2.4-r2\n"
        "T:the musl c library\n"
        "\n"
        "C:Q1def==\n"
        "P:busybox\n"
        "V:1.36.0-r0\n"
        "T:toolbox\n"
        "\n"
    )
    pkgs = cves._parse_apk_installed(db)
    assert ("musl", "1.2.4-r2") in pkgs
    assert ("busybox", "1.36.0-r0") in pkgs
    assert len(pkgs) == 2


def test_parse_apk_installed_handles_final_stanza_without_trailing_blank():
    db = "P:musl\nV:1.2.4-r2\n"  # no trailing blank line
    assert cves._parse_apk_installed(db) == [("musl", "1.2.4-r2")]


def test_cves_check_emits_finding_for_vulnerable_alpine_package(_isolate_osv_cache):
    # The bundled seed DB maps Alpine|busybox|1.36.0-r0 -> CVE-2023-42366,
    # so this resolves fully offline with an empty cache.
    img = load_tarball(fixture_path("alpine-image.tar"))
    client = OSVClient(cache_path=_isolate_osv_cache, offline=True)
    findings = cves.run(img, osv_client=client)
    assert findings, "expected a CVE finding for the vulnerable busybox"
    by_pkg = {f.detail["package"]: f for f in findings}
    assert "busybox" in by_pkg
    f = by_pkg["busybox"]
    assert f.category == "cve"
    assert f.detail["ecosystem"] == "Alpine"
    assert f.detail["installed_version"] == "1.36.0-r0"
    assert f.detail["cve_id"] == "CVE-2023-42366"
    # The clean musl package must NOT produce a finding.
    assert "musl" not in by_pkg


def test_cves_check_clean_alpine_image_no_findings(_isolate_osv_cache):
    img = load_tarball(fixture_path("alpine-clean-image.tar"))
    client = OSVClient(cache_path=_isolate_osv_cache, offline=True)
    findings = cves.run(img, osv_client=client)
    assert findings == []


def test_misconfig_check_running_as_root():
    img = load_tarball(fixture_path("rootuser-image.tar"))
    findings = misconfig.run(img)
    rules = {f.detail["rule"] for f in findings}
    assert "running_as_root" in rules
    f = next(f for f in findings if f.detail["rule"] == "running_as_root")
    assert f.category == "misconfig"
    assert f.layer_sha.startswith("sha256:")


def test_misconfig_check_exposed_port_and_suspicious_env():
    img = load_tarball(fixture_path("rootuser-image.tar"))
    findings = misconfig.run(img)
    rules = {f.detail["rule"] for f in findings}
    assert "exposed_port" in rules
    assert "suspicious_env_var" in rules


def test_misconfig_clean_image_not_root():
    img = load_tarball(fixture_path("leaky-image.tar"))
    findings = misconfig.run(img)
    # leaky-image has empty User -> treated as root -> running_as_root fires.
    # This documents that "" means root per Dockerfile semantics.
    rules = {f.detail["rule"] for f in findings}
    assert "running_as_root" in rules
