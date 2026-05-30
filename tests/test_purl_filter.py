"""Tests for --purl-filter report filtering.

``--purl-filter`` keeps only CVE findings whose synthesized Package URL matches
at least one glob pattern. Where ``--suppress-ecosystem`` is the *mute* knob at
the ecosystem level, ``--purl-filter`` is the *selection* knob at the package
level — focus a scan on a specific package set (e.g. only pkg:pypi/* app
dependencies, or pkg:*/openssl@* across distros).

``filter_by_purl()`` is the pure decision function; the CLI e2e tests confirm
it's wired into the rendered output and that the exit-code gate applies to the
*filtered* (reported) set.
"""

from __future__ import annotations

import json

import pytest

from casket.cli import build_parser, main
from casket.findings import Finding
from casket.scanner import _purl_for_finding, filter_by_purl
from tests.conftest import fixture_path


def _cve(
    *,
    package: str = "requests",
    version: str = "2.19.0",
    ecosystem: str = "PyPI",
    cve_id: str = "CVE-2018-18074",
) -> Finding:
    detail: dict[str, object] = {
        "cve_id": cve_id,
        "package": package,
        "installed_version": version,
        "ecosystem": ecosystem,
    }
    return Finding(
        category="cve",
        title=f"{package} {version}: {cve_id}",
        severity="high",
        layer_sha="sha256:deadbeef",
        path_in_layer="usr/lib/x",
        detail=detail,
    )


def _misconfig() -> Finding:
    return Finding(
        category="misconfig",
        title="running as root",
        severity="high",
        layer_sha="sha256:cafef00d",
        path_in_layer="<image config>",
        detail={"rule": "running_as_root"},
    )


def _creds() -> Finding:
    return Finding(
        category="creds",
        title="AWS key",
        severity="critical",
        layer_sha="sha256:beefcafe",
        path_in_layer="app/.env",
        detail={"rule": "aws_secret_access_key"},
    )


def _ids(findings: list[Finding]) -> list[str]:
    return [f.detail.get("cve_id") or f.detail.get("rule") for f in findings]


# ---- _purl_for_finding helper --------------------------------------------

def test_purl_pypi_canonical_type():
    assert _purl_for_finding(_cve(ecosystem="PyPI", package="requests",
                                  version="2.19.0")) == "pkg:pypi/requests@2.19.0"


def test_purl_debian_canonical_type():
    assert _purl_for_finding(_cve(ecosystem="Debian", package="openssl",
                                  version="3.0.7-1")) == "pkg:deb/openssl@3.0.7-1"


def test_purl_alpine_canonical_type():
    assert _purl_for_finding(_cve(ecosystem="Alpine", package="busybox",
                                  version="1.36.0-r0")) == "pkg:apk/busybox@1.36.0-r0"


def test_purl_redhat_canonical_type():
    # "Red Hat" (with the space) maps to the canonical pkg:rpm/... type
    assert _purl_for_finding(_cve(ecosystem="Red Hat", package="openssl",
                                  version="1:3.0.7-6.el9")) == \
        "pkg:rpm/openssl@1:3.0.7-6.el9"


def test_purl_ecosystem_case_insensitive():
    # OSV's casing isn't always what the operator types — accept both
    assert _purl_for_finding(_cve(ecosystem="pypi")) == "pkg:pypi/requests@2.19.0"
    assert _purl_for_finding(_cve(ecosystem="PYPI")) == "pkg:pypi/requests@2.19.0"


def test_purl_unknown_ecosystem_falls_back_to_alphanumeric_type():
    # Defensive: a future ecosystem should still produce a stable, matchable
    # purl rather than vanishing under an explicit filter.
    f = _cve(ecosystem="Some New Ecosystem!", package="x", version="1")
    assert _purl_for_finding(f) == "pkg:somenewecosystem/x@1"


def test_purl_none_for_non_cve():
    assert _purl_for_finding(_misconfig()) is None
    assert _purl_for_finding(_creds()) is None


def test_purl_none_when_required_fields_missing():
    f = _cve()
    f.detail.pop("ecosystem")
    assert _purl_for_finding(f) is None
    f = _cve()
    f.detail.pop("package")
    assert _purl_for_finding(f) is None
    f = _cve()
    f.detail.pop("installed_version")
    assert _purl_for_finding(f) is None


def test_purl_none_when_field_is_empty_string():
    # An empty string is no more matchable than a missing key.
    f = _cve()
    f.detail["installed_version"] = ""
    assert _purl_for_finding(f) is None


# ---- pure filter_by_purl ---------------------------------------------------

def test_none_returns_everything_unchanged():
    findings = [_cve(), _cve(package="urllib3"), _misconfig()]
    assert filter_by_purl(findings, None) == findings


def test_empty_list_returns_everything_unchanged():
    # An empty pattern list is a no-op (the flag was supplied no values) — the
    # alternative would silently drop every CVE, a footgun.
    findings = [_cve(), _misconfig()]
    assert filter_by_purl(findings, []) == findings


def test_default_arg_reports_everything():
    findings = [_cve(), _misconfig()]
    assert filter_by_purl(findings) == findings


def test_filter_keeps_matching_pypi_purls():
    findings = [
        _cve(ecosystem="PyPI", package="requests", version="2.19.0",
             cve_id="CVE-A"),
        _cve(ecosystem="Debian", package="openssl", version="3.0.0",
             cve_id="CVE-B"),
        _cve(ecosystem="Alpine", package="busybox", version="1.0",
             cve_id="CVE-C"),
    ]
    out = filter_by_purl(findings, ["pkg:pypi/*"])
    assert _ids(out) == ["CVE-A"]


def test_filter_keeps_specific_package_across_ecosystems():
    # The motivating cross-distro case: "show me openssl CVEs everywhere"
    findings = [
        _cve(ecosystem="Debian", package="openssl", version="3.0.0",
             cve_id="CVE-A"),
        _cve(ecosystem="Red Hat", package="openssl", version="1:3.0.7-6.el9",
             cve_id="CVE-B"),
        _cve(ecosystem="PyPI", package="requests", version="2.19.0",
             cve_id="CVE-C"),
    ]
    out = filter_by_purl(findings, ["pkg:*/openssl@*"])
    assert sorted(_ids(out)) == ["CVE-A", "CVE-B"]


def test_filter_supports_multiple_patterns_or():
    findings = [
        _cve(ecosystem="PyPI", package="requests", version="2.19.0",
             cve_id="CVE-A"),
        _cve(ecosystem="Debian", package="openssl", version="3.0.0",
             cve_id="CVE-B"),
        _cve(ecosystem="Alpine", package="busybox", version="1.0",
             cve_id="CVE-C"),
    ]
    out = filter_by_purl(findings, ["pkg:pypi/*", "pkg:deb/*"])
    assert sorted(_ids(out)) == ["CVE-A", "CVE-B"]


def test_filter_version_glob():
    findings = [
        _cve(package="requests", version="2.19.0", cve_id="CVE-A"),
        _cve(package="requests", version="2.20.0", cve_id="CVE-B"),
        _cve(package="requests", version="3.0.0", cve_id="CVE-C"),
    ]
    out = filter_by_purl(findings, ["pkg:pypi/requests@2.*"])
    assert sorted(_ids(out)) == ["CVE-A", "CVE-B"]


def test_filter_case_insensitive_pattern():
    # purl types are lowercase by spec but the operator may type uppercase
    findings = [_cve(ecosystem="PyPI", package="Requests", version="1.0")]
    out = filter_by_purl(findings, ["PKG:PYPI/*"])
    assert len(out) == 1


def test_non_cve_findings_always_survive():
    findings = [_misconfig(), _creds(), _cve()]
    out = filter_by_purl(findings, ["pkg:pypi/nope@*"])
    # only the matching CVE is filtered; creds/misconfig pass through
    assert out == [findings[0], findings[1]]


def test_cve_without_purl_is_pruned_by_explicit_filter():
    # matches --cvss-floor / --min-epss posture: an explicit selection bar
    # requires the data to evaluate it
    f = _cve()
    f.detail.pop("ecosystem")
    out = filter_by_purl([f, _cve()], ["pkg:pypi/*"])
    assert len(out) == 1  # the one with a derivable purl survives


def test_no_pattern_matches_drops_every_cve():
    findings = [_cve(), _cve(package="urllib3")]
    out = filter_by_purl(findings, ["pkg:nonexistent/*"])
    assert out == []


def test_returns_a_new_list_not_the_input():
    findings = [_cve()]
    out = filter_by_purl(findings, None)
    assert out is not findings


def test_empty_input_is_empty():
    assert filter_by_purl([], ["pkg:pypi/*"]) == []


# ---- argparse wiring ------------------------------------------------------

def test_parser_default_purl_filter_is_none():
    parser = build_parser()
    args = parser.parse_args(["--image", "x.tar"])
    assert args.purl_filter is None


def test_parser_accepts_single_purl_filter():
    parser = build_parser()
    args = parser.parse_args(["--image", "x.tar", "--purl-filter", "pkg:pypi/*"])
    assert args.purl_filter == ["pkg:pypi/*"]


def test_parser_purl_filter_is_repeatable():
    parser = build_parser()
    args = parser.parse_args([
        "--image", "x.tar",
        "--purl-filter", "pkg:pypi/*",
        "--purl-filter", "pkg:deb/openssl@*",
    ])
    assert args.purl_filter == ["pkg:pypi/*", "pkg:deb/openssl@*"]


def test_help_lists_purl_filter(capsys):
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["--help"])
    assert "--purl-filter" in capsys.readouterr().out


# ---- CLI e2e: filtering against a real fixture ----------------------------
#
# old-package.tar ships requests 2.19.0 (PyPI). The seeded OSV cache emits a
# CVE finding; --purl-filter against a matching glob keeps it (gate trips);
# a non-matching glob prunes it (gate clean).


def _seed_requests_cve(_isolate_osv_cache):
    """Seed the OSV cache with a stable advisory for requests 2.19.0."""
    from casket.osv import OSVClient

    seed = OSVClient(cache_path=_isolate_osv_cache)
    seed.seed(
        "PyPI",
        "requests",
        "2.19.0",
        [
            {
                "id": "GHSA-x84v-xcm2-53pg",
                "aliases": ["CVE-2018-18074"],
                "summary": "auth leak",
                "severity": [
                    {
                        "type": "CVSS_V3",
                        "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                    }
                ],
            }
        ],
    )


def test_e2e_purl_filter_matching_keeps_the_cve(capsys, _isolate_osv_cache):
    _seed_requests_cve(_isolate_osv_cache)
    rc = main(
        [
            "--image", fixture_path("old-package.tar"),
            "--mode", "tarball",
            "--checks", "cves",
            "--format", "json",
            "--offline",
            "--purl-filter", "pkg:pypi/requests@*",
        ]
    )
    payload = json.loads(capsys.readouterr().out)
    cves = [f for f in payload["findings"] if f["category"] == "cve"]
    assert cves and cves[0]["package"] == "requests"
    assert rc == 1  # the matching CVE survives -> gate trips


def test_e2e_purl_filter_non_matching_prunes_and_gate_passes(
    capsys, _isolate_osv_cache
):
    _seed_requests_cve(_isolate_osv_cache)
    rc = main(
        [
            "--image", fixture_path("old-package.tar"),
            "--mode", "tarball",
            "--checks", "cves",
            "--format", "json",
            "--offline",
            "--purl-filter", "pkg:deb/*",  # no Debian packages in the fixture
        ]
    )
    payload = json.loads(capsys.readouterr().out)
    assert not [f for f in payload["findings"] if f["category"] == "cve"]
    # finding_count reflects the filtered report
    assert payload["finding_count"] == len(payload["findings"])
    assert rc == 0  # nothing left to fail on


def test_e2e_purl_filter_multiple_patterns_or(capsys, _isolate_osv_cache):
    _seed_requests_cve(_isolate_osv_cache)
    rc = main(
        [
            "--image", fixture_path("old-package.tar"),
            "--mode", "tarball",
            "--checks", "cves",
            "--format", "json",
            "--offline",
            # One miss, one hit — the OR keeps the finding.
            "--purl-filter", "pkg:deb/*",
            "--purl-filter", "pkg:pypi/requests@*",
        ]
    )
    payload = json.loads(capsys.readouterr().out)
    cves = [f for f in payload["findings"] if f["category"] == "cve"]
    assert cves and cves[0]["package"] == "requests"
    assert rc == 1
