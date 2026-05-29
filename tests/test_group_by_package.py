"""Tests for the --group-by-package h1md presentation feature.

A single vulnerable package routinely produces 10+ CVE findings; left
ungrouped, an h1md report becomes a long flat list dominated by repeated
package/version headers. ``--group-by-package`` collapses every CVE finding
that shares an (ecosystem, package, version) into a single section in h1md
output, so the operator triages one package at a time. The flag is a pure
presentation change:

  - Only h1md is affected. json/sarif are byte-for-byte unchanged so machine
    consumers stay stable. The exit-code gate and --compare diff also stay
    unchanged (they run on the same finding list either way).
  - Non-CVE findings (creds, misconfig) render exactly as before, under the
    grouped CVE section. They carry no ``package`` field and are not a
    triage-by-package workflow.
  - A CVE finding missing a ``package`` field (defensive) renders ungrouped
    in its own per-finding section, just like before the flag was added.
"""

from __future__ import annotations

from casket.findings import Finding, render


def _cve(cve_id: str, package: str, version: str, severity: str = "high") -> Finding:
    """Build a synthetic CVE Finding suitable for the renderer."""
    return Finding(
        category="cve",
        title=f"{cve_id} in {package} {version}",
        severity=severity,
        layer_sha="sha256:layer",
        path_in_layer="var/lib/dpkg/status",
        detail={
            "cve_id": cve_id,
            "package": package,
            "installed_version": version,
            "ecosystem": "Debian:12",
        },
    )


# ---- h1md grouping ---------------------------------------------------------


def test_group_by_package_collapses_cves_for_one_package():
    """Three CVEs against one package collapse into a single h1md section."""
    findings = [
        _cve("CVE-2024-0001", "openssl", "3.0.0"),
        _cve("CVE-2024-0002", "openssl", "3.0.0"),
        _cve("CVE-2024-0003", "openssl", "3.0.0"),
    ]
    out = render(findings, "h1md", image="img", group_by_package=True)
    # One package section, not three per-CVE sections.
    assert out.count("## Package: `openssl") == 1
    # All three CVE ids appear inside that section as bullets.
    assert "CVE-2024-0001" in out
    assert "CVE-2024-0002" in out
    assert "CVE-2024-0003" in out
    # The per-finding "## [SEVERITY]" header used in the ungrouped layout
    # must not appear once we group.
    assert "## [HIGH]" not in out


def test_group_by_package_separates_distinct_packages():
    """Distinct packages get distinct sections (no cross-package merge)."""
    findings = [
        _cve("CVE-2024-0001", "openssl", "3.0.0"),
        _cve("CVE-2024-0010", "curl", "7.88.1"),
    ]
    out = render(findings, "h1md", image="img", group_by_package=True)
    assert "## Package: `openssl@3.0.0`" in out
    assert "## Package: `curl@7.88.1`" in out


def test_group_by_package_separates_same_package_different_versions():
    """Two installed versions of the same package stay in separate sections.

    Multi-stage builds and overlay images can ship two copies of one package
    at different versions; an operator triaging by ``(package, version)``
    needs them surfaced separately.
    """
    findings = [
        _cve("CVE-2024-0001", "openssl", "3.0.0"),
        _cve("CVE-2024-0001", "openssl", "1.1.1k"),
    ]
    out = render(findings, "h1md", image="img", group_by_package=True)
    assert "## Package: `openssl@3.0.0`" in out
    assert "## Package: `openssl@1.1.1k`" in out


def test_group_by_package_shows_worst_severity_in_section_header():
    """A package section header surfaces the worst severity among its CVEs.

    With the section header collapsing N per-CVE severities into one, the
    operator needs the highest band visible at a glance so triage order
    isn't lost.
    """
    findings = [
        _cve("CVE-2024-0001", "openssl", "3.0.0", severity="low"),
        _cve("CVE-2024-0002", "openssl", "3.0.0", severity="critical"),
        _cve("CVE-2024-0003", "openssl", "3.0.0", severity="medium"),
    ]
    out = render(findings, "h1md", image="img", group_by_package=True)
    assert "## Package: `openssl@3.0.0` [CRITICAL]" in out


def test_group_by_package_lists_per_cve_severity_in_bullets():
    """Each CVE bullet still labels its own severity for triage clarity."""
    findings = [
        _cve("CVE-2024-0001", "openssl", "3.0.0", severity="low"),
        _cve("CVE-2024-0002", "openssl", "3.0.0", severity="critical"),
    ]
    out = render(findings, "h1md", image="img", group_by_package=True)
    # CVE bullets carry the per-finding severity band.
    assert "CVE-2024-0002" in out
    # Sanity: both severity tokens show up somewhere inside the section.
    assert "critical" in out.lower()
    assert "low" in out.lower()


def test_group_by_package_renders_non_cve_findings_ungrouped():
    """Creds / misconfig findings stay in their own ungrouped sections.

    Grouping by package is a CVE-triage workflow; creds and misconfig
    findings carry no ``package`` field and would render as a degenerate
    "no package" group that adds noise. They render under their own
    per-finding headers as before.
    """
    cve = _cve("CVE-2024-0001", "openssl", "3.0.0")
    cred = Finding(
        category="creds",
        title="AWS access key id leaked",
        severity="high",
        layer_sha="sha256:layer",
        path_in_layer="app/.env",
        detail={"rule": "aws-access-key-id"},
    )
    misconfig = Finding(
        category="misconfig",
        title="container runs as root",
        severity="medium",
        layer_sha="sha256:cfg",
        path_in_layer="<image config>",
        detail={"rule": "runs-as-root"},
    )
    out = render([cve, cred, misconfig], "h1md", image="img", group_by_package=True)
    # CVE collapsed under a package section.
    assert "## Package: `openssl@3.0.0`" in out
    # Non-CVE findings keep their per-finding ungrouped headers.
    assert "## [HIGH] AWS access key id leaked" in out
    assert "## [MEDIUM] container runs as root" in out


def test_group_by_package_falls_back_for_cve_without_package_field():
    """A CVE finding missing ``package`` renders ungrouped (defensive)."""
    odd = Finding(
        category="cve",
        title="CVE-2024-9999 in mystery",
        severity="high",
        layer_sha="sha256:layer",
        path_in_layer="?",
        detail={"cve_id": "CVE-2024-9999"},  # no "package" field
    )
    out = render([odd], "h1md", image="img", group_by_package=True)
    assert "## Package:" not in out
    assert "## [HIGH] CVE-2024-9999 in mystery" in out


# ---- presentation-only contract: json / sarif unchanged --------------------


def test_group_by_package_does_not_change_json_output():
    """json output is byte-for-byte identical with or without the flag."""
    findings = [
        _cve("CVE-2024-0001", "openssl", "3.0.0"),
        _cve("CVE-2024-0002", "openssl", "3.0.0"),
    ]
    plain = render(findings, "json", image="img")
    grouped = render(findings, "json", image="img", group_by_package=True)
    assert plain == grouped


def test_group_by_package_does_not_change_sarif_output():
    """sarif output is byte-for-byte identical with or without the flag."""
    findings = [
        _cve("CVE-2024-0001", "openssl", "3.0.0"),
    ]
    plain = render(findings, "sarif", image="img")
    grouped = render(findings, "sarif", image="img", group_by_package=True)
    assert plain == grouped


# ---- default behaviour unchanged ------------------------------------------


def test_h1md_ungrouped_default_unchanged():
    """Without the flag, h1md keeps the per-finding section layout."""
    findings = [
        _cve("CVE-2024-0001", "openssl", "3.0.0"),
        _cve("CVE-2024-0002", "openssl", "3.0.0"),
    ]
    out = render(findings, "h1md", image="img")
    # Per-finding headers, no Package section.
    assert out.count("## [HIGH]") == 2
    assert "## Package:" not in out


def test_group_by_package_empty_findings_is_no_findings_message():
    """No findings + flag set still produces the standard no-findings body."""
    out = render([], "h1md", image="img", group_by_package=True)
    assert "_No findings._" in out
    assert "## Package:" not in out


# ---- CLI flag wiring -------------------------------------------------------


def test_cli_help_lists_group_by_package_flag(capsys):
    """The flag is discoverable through --help."""
    from casket.cli import build_parser

    parser = build_parser()
    help_text = parser.format_help()
    assert "--group-by-package" in help_text


def test_cli_parses_group_by_package_flag():
    """The flag parses to ``args.group_by_package == True``."""
    from casket.cli import build_parser

    parser = build_parser()
    args = parser.parse_args(["--image", "x", "--group-by-package"])
    assert args.group_by_package is True


def test_cli_group_by_package_default_false():
    """Default is ``False`` so existing invocations are unchanged."""
    from casket.cli import build_parser

    parser = build_parser()
    args = parser.parse_args(["--image", "x"])
    assert args.group_by_package is False
