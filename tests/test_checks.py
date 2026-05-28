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


def test_parse_alpine_release_extracts_major_minor():
    assert cves._parse_alpine_release("3.18.4\n") == "Alpine:v3.18"
    assert cves._parse_alpine_release("3.20.0") == "Alpine:v3.20"
    # MAJOR.MINOR with no patch is accepted.
    assert cves._parse_alpine_release("3.19") == "Alpine:v3.19"
    # Trailing edge/markers after the numeric prefix are ignored.
    assert cves._parse_alpine_release("3.18.0_alpha20231114") == "Alpine:v3.18"


def test_parse_alpine_release_none_on_garbage():
    assert cves._parse_alpine_release("") is None
    assert cves._parse_alpine_release("edge\n") is None
    assert cves._parse_alpine_release("not a version") is None


def test_detect_alpine_ecosystem_scans_cross_layer():
    # etc/alpine-release lives in a separate layer from the apk db; detection
    # is image-level and must find it.
    img = load_tarball(fixture_path("alpine-release-image.tar"))
    assert cves._detect_alpine_ecosystem(img) == "Alpine:v3.18"


def test_detect_alpine_ecosystem_none_without_release_marker():
    # alpine-image carries an apk db but no etc/alpine-release.
    img = load_tarball(fixture_path("alpine-image.tar"))
    assert cves._detect_alpine_ecosystem(img) is None


def test_cves_resolves_alpine_via_release_qualified_ecosystem(_isolate_osv_cache):
    # The vuln is seeded ONLY under the release-qualified ecosystem
    # "Alpine:v3.18" — NOT bare "Alpine". This proves casket queries the
    # release-qualified name (what the live OSV.dev API requires) rather than
    # relying on the bare-ecosystem seed/cache path.
    img = load_tarball(fixture_path("alpine-release-image.tar"))
    client = OSVClient(cache_path=_isolate_osv_cache, offline=True)
    client.seed(
        "Alpine:v3.18",
        "busybox",
        "1.36.0-r0",
        [
            {
                "id": "CVE-2023-42366",
                "aliases": ["CVE-2023-42366"],
                "summary": "busybox awk heap overflow",
                "database_specific": {"severity": "MEDIUM"},
            }
        ],
    )
    findings = cves.run(img, osv_client=client)
    assert findings, "expected a CVE finding resolved via Alpine:v3.18"
    f = findings[0]
    assert f.detail["package"] == "busybox"
    assert f.detail["cve_id"] == "CVE-2023-42366"
    # The reported ecosystem stays the stable bare tag for output uniformity.
    assert f.detail["ecosystem"] == "Alpine"


def test_cves_alpine_bare_fallback_still_resolves_seed_db(_isolate_osv_cache):
    # alpine-image has no etc/alpine-release, so the release-qualified candidate
    # is None and casket falls back to bare "Alpine" — the bundled seed DB path.
    # This is the pre-existing behaviour, preserved unchanged.
    img = load_tarball(fixture_path("alpine-image.tar"))
    client = OSVClient(cache_path=_isolate_osv_cache, offline=True)
    findings = cves.run(img, osv_client=client)
    by_pkg = {f.detail["package"] for f in findings}
    assert "busybox" in by_pkg


# ---------------------------------------------------------------------------
# Debian release-qualified ecosystem tests (Rotation 11)
# ---------------------------------------------------------------------------

def test_parse_debian_version_extracts_major():
    assert cves._parse_debian_version("12.4\n") == "Debian:12"
    assert cves._parse_debian_version("11") == "Debian:11"
    # A bare major with a trailing minor/patch keeps the major only.
    assert cves._parse_debian_version("10.13") == "Debian:10"


def test_parse_debian_version_none_on_codename():
    # Testing/unstable releases carry a non-numeric codename, not a version.
    assert cves._parse_debian_version("bookworm/sid\n") is None
    assert cves._parse_debian_version("") is None


def test_parse_os_release_extracts_version_id():
    text = (
        'PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\n'
        'VERSION_ID="12"\n'
        "ID=debian\n"
    )
    assert cves._parse_os_release_debian(text) == "Debian:12"
    # Ubuntu's VERSION_ID is a dotted version; the major is taken.
    ubuntu = 'NAME="Ubuntu"\nVERSION_ID="22.04"\nID=ubuntu\n'
    assert cves._parse_os_release_debian(ubuntu) == "Debian:22"


def test_parse_os_release_none_without_version_id():
    assert cves._parse_os_release_debian("ID=debian\nNAME=Debian\n") is None


def test_detect_debian_ecosystem_scans_cross_layer():
    # etc/debian_version lives in a separate layer from the dpkg db; detection
    # is image-level and must find it.
    img = load_tarball(fixture_path("debian-release-image.tar"))
    assert cves._detect_debian_ecosystem(img) == "Debian:12"


def test_detect_debian_ecosystem_falls_back_to_os_release():
    # No etc/debian_version present; detection must use os-release VERSION_ID.
    img = load_tarball(fixture_path("debian-osrelease-image.tar"))
    assert cves._detect_debian_ecosystem(img) == "Debian:12"


def test_detect_debian_ecosystem_none_without_marker():
    # old-package fixture carries no Debian release marker at all.
    img = load_tarball(fixture_path("old-package.tar"))
    assert cves._detect_debian_ecosystem(img) is None


def test_cves_resolves_debian_via_release_qualified_ecosystem(_isolate_osv_cache):
    # The vuln is seeded ONLY under the release-qualified ecosystem "Debian:12"
    # — NOT bare "Debian". This proves casket queries the release-qualified name
    # (what the live OSV.dev API requires) rather than the bare-ecosystem path.
    img = load_tarball(fixture_path("debian-release-image.tar"))
    client = OSVClient(cache_path=_isolate_osv_cache, offline=True)
    client.seed(
        "Debian:12",
        "openssl",
        "3.0.11-1~deb12u1",
        [
            {
                "id": "CVE-2023-5678",
                "aliases": ["CVE-2023-5678"],
                "summary": "openssl X9.42 DH slow key check",
                "database_specific": {"severity": "MEDIUM"},
            }
        ],
    )
    findings = cves.run(img, osv_client=client)
    assert findings, "expected a CVE finding resolved via Debian:12"
    f = findings[0]
    assert f.detail["package"] == "openssl"
    assert f.detail["cve_id"] == "CVE-2023-5678"
    # The reported ecosystem stays the stable bare tag for output uniformity.
    assert f.detail["ecosystem"] == "Debian"


def test_cves_resolves_debian_via_os_release_fallback(_isolate_osv_cache):
    # Release marker only in os-release; resolution still uses "Debian:12".
    img = load_tarball(fixture_path("debian-osrelease-image.tar"))
    client = OSVClient(cache_path=_isolate_osv_cache, offline=True)
    client.seed(
        "Debian:12",
        "openssl",
        "3.0.11-1~deb12u1",
        [{"id": "CVE-2023-5678", "aliases": ["CVE-2023-5678"], "summary": "x"}],
    )
    findings = cves.run(img, osv_client=client)
    assert findings, "expected a CVE finding via os-release-derived Debian:12"
    assert findings[0].detail["cve_id"] == "CVE-2023-5678"


def test_cves_debian_bare_fallback_still_resolves_seed_db(_isolate_osv_cache):
    # The bundled seed DB keys the vuln under bare "Debian". With an image that
    # has a release marker, the release-qualified candidate is tried first and
    # misses (not in seed), then the bare "Debian" fallback hits the seed DB —
    # proving the fallback chain works end-to-end offline.
    img = load_tarball(fixture_path("debian-release-image.tar"))
    client = OSVClient(cache_path=_isolate_osv_cache, offline=True)
    findings = cves.run(img, osv_client=client)
    by_pkg = {f.detail["package"] for f in findings}
    assert "openssl" in by_pkg


# ---------------------------------------------------------------------------
# RPM package extraction tests (POST_V01 Item 4)
# ---------------------------------------------------------------------------

def test_parse_rpm_header_extracts_name_version_release_epoch():
    from tests.build_fixtures import _rpm_header_blob

    blob = _rpm_header_blob(
        name="openssl", version="3.0.7", release="6.el9", epoch=1, arch="x86_64"
    )
    header = cves._parse_rpm_header(blob)
    assert header["name"] == "openssl"
    assert header["version"] == "3.0.7"
    assert header["release"] == "6.el9"
    assert header["epoch"] == "1"
    assert header["arch"] == "x86_64"


def test_parse_rpm_header_malformed_blob_returns_empty():
    assert cves._parse_rpm_header(b"") == {}
    assert cves._parse_rpm_header(b"\x00\x01\x02") == {}
    assert cves._parse_rpm_header(b"garbage that is not an rpm header at all") == {}


def test_rpm_evr_includes_epoch_only_when_nonzero():
    assert cves._rpm_evr({"version": "1.2", "release": "3.el9"}) == "1.2-3.el9"
    assert cves._rpm_evr({"version": "1.2", "release": "3.el9", "epoch": "0"}) == "1.2-3.el9"
    assert cves._rpm_evr({"version": "1.2", "release": "3.el9", "epoch": "1"}) == "1:1.2-3.el9"
    assert cves._rpm_evr({"version": "1.2"}) == "1.2"
    assert cves._rpm_evr({"release": "3.el9"}) is None


def test_parse_rpmdb_sqlite_extracts_packages():
    from tests.build_fixtures import _rpmdb_sqlite_bytes

    db = _rpmdb_sqlite_bytes(
        [
            {"name": "openssl", "version": "3.0.7", "release": "6.el9", "epoch": 1},
            {"name": "bash", "version": "5.1.8", "release": "6.el9"},
        ]
    )
    pkgs = cves._parse_rpmdb_sqlite(db)
    assert ("openssl", "1:3.0.7-6.el9") in pkgs
    assert ("bash", "5.1.8-6.el9") in pkgs
    assert len(pkgs) == 2


def test_parse_rpmdb_sqlite_non_sqlite_returns_empty():
    # A Berkeley DB / random blob is not a sqlite db -> empty, never a crash.
    assert cves._parse_rpmdb_sqlite(b"\x00\x05\x16\x53 not sqlite\n") == []


def test_cves_check_emits_finding_for_vulnerable_rpm_package(_isolate_osv_cache):
    # The bundled seed DB maps Red Hat|openssl|1:3.0.7-6.el9 -> CVE-2023-0464,
    # so this resolves fully offline with an empty cache.
    img = load_tarball(fixture_path("rpm-image.tar"))
    client = OSVClient(cache_path=_isolate_osv_cache, offline=True)
    findings = cves.run(img, osv_client=client)
    assert findings, "expected a CVE finding for the vulnerable openssl"
    by_pkg = {f.detail["package"]: f for f in findings}
    assert "openssl" in by_pkg
    f = by_pkg["openssl"]
    assert f.category == "cve"
    assert f.detail["ecosystem"] == "Red Hat"
    assert f.detail["installed_version"] == "1:3.0.7-6.el9"
    assert f.detail["cve_id"] == "CVE-2023-0464"
    assert f.path_in_layer == "var/lib/rpm/rpmdb.sqlite"
    # The clean bash package must NOT produce a finding.
    assert "bash" not in by_pkg


def test_cves_check_clean_rpm_image_no_findings(_isolate_osv_cache):
    img = load_tarball(fixture_path("rpm-clean-image.tar"))
    client = OSVClient(cache_path=_isolate_osv_cache, offline=True)
    findings = cves.run(img, osv_client=client)
    assert findings == []


def test_cves_check_legacy_rpm_bdb_skipped_silently(_isolate_osv_cache):
    # RHEL 7/8 ship a Berkeley DB `Packages` file with no rpmdb.sqlite.
    # casket must skip it: no findings, no exception.
    img = load_tarball(fixture_path("rpm-legacy-image.tar"))
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


# ---------------------------------------------------------------------------
# Entropy-based credential detection tests
# ---------------------------------------------------------------------------

def test_creds_entropy_detects_high_entropy_string():
    """A high-entropy base64-like token fires the high_entropy_string rule."""
    img = load_tarball(fixture_path("entropy-image.tar"))
    findings = creds.run(img)
    by_rule = {f.detail["rule"] for f in findings}
    assert "high_entropy_string" in by_rule, (
        f"expected high_entropy_string finding; got rules: {by_rule}"
    )


def test_creds_entropy_finding_has_correct_fields():
    """Entropy finding carries required fields: severity, finding_id, detail, match_count."""
    img = load_tarball(fixture_path("entropy-image.tar"))
    findings = creds.run(img)
    ef = next((f for f in findings if f.detail.get("rule") == "high_entropy_string"), None)
    assert ef is not None, "no high_entropy_string finding"
    assert ef.severity == "medium"
    assert ef.category == "creds"
    assert ef.detail.get("finding_id") == "CASKET-CREDS-ENTROPY-001"
    # detail should show first 8 chars + "..." + entropy score
    assert "..." in ef.detail.get("detail", "")
    assert "entropy=" in ef.detail.get("detail", "")
    assert isinstance(ef.detail.get("match_count"), int)
    assert ef.detail["match_count"] >= 1


def test_creds_entropy_redacts_token_to_8_chars():
    """The finding detail exposes only the first 8 characters of the matched token."""
    img = load_tarball(fixture_path("entropy-image.tar"))
    findings = creds.run(img)
    ef = next((f for f in findings if f.detail.get("rule") == "high_entropy_string"), None)
    assert ef is not None
    detail_str = ef.detail.get("detail", "")
    # Format: "AbCdEfGh... (entropy=N.NN)"
    prefix = detail_str.split("...")[0]
    assert len(prefix) == 8, f"expected 8-char prefix, got {len(prefix)!r}: {detail_str!r}"


def test_creds_entropy_low_entropy_string_not_flagged():
    """A repeated-character string (low entropy) must NOT produce an entropy finding."""
    img = load_tarball(fixture_path("entropy-image.tar"))
    findings = creds.run(img)
    # The readme.txt file contains only 'A' repeated — entropy 0, should not fire.
    entropy_findings = [f for f in findings if f.detail.get("rule") == "high_entropy_string"]
    for ef in entropy_findings:
        assert ef.path_in_layer != "app/readme.txt", (
            "low-entropy repeated string should not produce an entropy finding"
        )


def test_creds_entropy_log_path_uses_lower_threshold():
    """Tokens in log paths fire at the lower 4.0 entropy threshold."""
    img = load_tarball(fixture_path("entropy-logfile-image.tar"))
    findings = creds.run(img)
    by_rule = {f.detail["rule"] for f in findings}
    assert "high_entropy_string" in by_rule, (
        "log-path token with entropy ~4.46 should fire at log threshold 4.0"
    )
    ef = next(f for f in findings if f.detail.get("rule") == "high_entropy_string")
    assert "log" in ef.path_in_layer


def test_creds_entropy_existing_regex_rules_still_fire():
    """Adding entropy detection must not break existing regex-based creds rules."""
    img = load_tarball(fixture_path("leaky-image.tar"))
    findings = creds.run(img)
    by_rule = {f.detail["rule"] for f in findings}
    assert "aws_secret_access_key" in by_rule, "existing aws regex rule must still fire"


def test_creds_entropy_clean_image_no_entropy_findings():
    """A clean image with no secrets must not produce any entropy findings."""
    img = load_tarball(fixture_path("alpine-clean-image.tar"))
    findings = creds.run(img)
    entropy_findings = [f for f in findings if f.detail.get("rule") == "high_entropy_string"]
    assert entropy_findings == [], (
        f"clean image should not produce entropy findings; got: {entropy_findings}"
    )


# --- OSV CVSS-vector severity parsing -------------------------------------
# OSV.dev records CVSS in the standard top-level ``severity`` array as
# ``{"type": "CVSS_V3", "score": "<vector>"}``. casket parses the v3.x vector
# to a base score and maps it to a qualitative band. The previous code only
# read the non-standard ``database_specific.severity`` and so defaulted almost
# every live finding to "high" — degrading --fail-on and SARIF security-severity.


def test_cvss3_base_score_matches_spec_reference_vectors():
    """The stdlib CVSS v3.1 calculator matches published reference base scores."""
    assert cves._cvss3_base_score(
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    ) == 9.8
    assert cves._cvss3_base_score(
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
    ) == 10.0
    assert cves._cvss3_base_score(
        "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
    ) == 7.8
    assert cves._cvss3_base_score(
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
    ) == 5.3


def test_cvss3_base_score_accepts_vector_without_prefix():
    """A bare vector (no ``CVSS:3.1/`` prefix) still scores via the v3 formula."""
    assert cves._cvss3_base_score(
        "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    ) == 9.8


def test_cvss3_base_score_returns_none_on_missing_metric():
    """A vector missing a required base metric yields None (caller falls back)."""
    assert cves._cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N") is None
    assert cves._cvss3_base_score("garbage") is None


def test_cvss_score_to_severity_band_boundaries():
    """Score-to-band mapping follows the CVSS v3.1 qualitative scale exactly."""
    assert cves._cvss_score_to_severity(10.0) == "critical"
    assert cves._cvss_score_to_severity(9.0) == "critical"
    assert cves._cvss_score_to_severity(8.9) == "high"
    assert cves._cvss_score_to_severity(7.0) == "high"
    assert cves._cvss_score_to_severity(6.9) == "medium"
    assert cves._cvss_score_to_severity(4.0) == "medium"
    assert cves._cvss_score_to_severity(3.9) == "low"
    assert cves._cvss_score_to_severity(0.1) == "low"
    assert cves._cvss_score_to_severity(0.0) == "info"


def test_severity_from_osv_reads_standard_cvss_array():
    """A standard OSV ``severity`` CVSS_V3 array drives the qualitative severity."""
    vuln = {
        "id": "GHSA-xxxx",
        "severity": [
            {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
        ],
    }
    assert cves._severity_from_osv(vuln) == "critical"


def test_severity_from_osv_cvss_array_beats_database_specific():
    """The standard CVSS array is authoritative over database_specific.severity."""
    vuln = {
        "severity": [
            {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"}
        ],
        "database_specific": {"severity": "CRITICAL"},
    }
    # 5.3 -> medium from the vector, NOT critical from database_specific.
    assert cves._severity_from_osv(vuln) == "medium"


def test_severity_from_osv_falls_back_to_database_specific_for_non_v3_vector():
    """A non-v3 (e.g. CVSS v2) vector is unscored; fall back to database_specific."""
    vuln = {
        "severity": [{"type": "CVSS_V2", "score": "AV:N/AC:L/Au:N/C:P/I:P/A:P"}],
        "database_specific": {"severity": "low"},
    }
    assert cves._severity_from_osv(vuln) == "low"


def test_severity_from_osv_defaults_to_high_when_no_signal():
    """No CVSS array and no database_specific severity -> conservative 'high'."""
    assert cves._severity_from_osv({"id": "X"}) == "high"


def test_severity_from_osv_tolerates_malformed_severity_entries():
    """Malformed entries in the severity array never crash; we fall through."""
    vuln = {
        "severity": [
            "not-a-dict",
            {"type": "CVSS_V3"},  # no score key
            {"type": "CVSS_V3", "score": 9.8},  # score not a string
        ],
        "database_specific": {"severity": "medium"},
    }
    assert cves._severity_from_osv(vuln) == "medium"


def test_cves_finding_severity_derives_from_cvss_array(_isolate_osv_cache):
    """End-to-end: a CVE finding's severity comes from the OSV CVSS_V3 vector."""
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
                "severity": [
                    {
                        "type": "CVSS_V3",
                        "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    }
                ],
            }
        ],
    )
    findings = cves.run(img, osv_client=client)
    assert findings
    assert findings[0].severity == "critical", (
        "finding severity must derive from the 9.8 CVSS vector, not default 'high'"
    )
