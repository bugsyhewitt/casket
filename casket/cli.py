"""casket command-line interface.

casket — a daemonless, podman-native container image scanner.
No Docker, no daemon, no root.

Usage examples:
  casket --image image.tar --mode tarball --checks all --format json
  casket --image localhost/myapp:latest --mode podman --checks creds
  casket --image http://registry.local:5000/library/app:1.0 --mode remote
"""

from __future__ import annotations

import argparse
import os
import sys

from casket import __version__
from casket.compare import (
    diff_reports,
    load_baseline_report,
    regression_count,
    render_diff_h1md,
    render_diff_json,
)
from casket.findings import render, report_dict
from casket.summary import build_summary, render_summary_json
from casket.scanner import (
    FAIL_ON_CHOICES,
    MIN_SEVERITY_CHOICES,
    SUPPRESS_SEVERITY_CHOICES,
    component_stats,
    exit_code,
    filter_by_ecosystem,
    filter_by_epss,
    filter_by_severity,
    filter_by_severity_band,
    filter_by_vex,
    load_image,
    resolve_checks,
    run_checks,
)

_EPILOG = """\
casket stays daemonless on purpose: it never talks to a Docker daemon, never
needs root. podman mode requires the `podman` CLI (optional system dependency).
remote mode requires network access to the target registry.

ETHICAL USE: only scan images you own or are explicitly authorized to assess.
"""


def _epss_threshold(value: str) -> float:
    """argparse type for --min-epss: a probability in the closed range [0, 1].

    EPSS scores are probabilities, so a threshold outside ``[0.0, 1.0]`` is a
    user error (and a value > 1.0 would silently suppress *every* CVE). We raise
    a clean argparse error rather than accept it.
    """
    try:
        f = float(value)
    except (TypeError, ValueError):
        raise argparse.ArgumentTypeError(
            f"invalid EPSS threshold {value!r}: expected a number in [0.0, 1.0]"
        )
    if not (0.0 <= f <= 1.0):
        raise argparse.ArgumentTypeError(
            f"EPSS threshold {f} out of range: expected a probability in [0.0, 1.0]"
        )
    return f


def _vex_max_age(value: str) -> int:
    """argparse type for --vex-max-age: a strictly-positive whole number of days.

    The flag expresses a re-triage window, so a zero or negative window is
    meaningless (and ``0`` would expire *every* suppression, including
    timestamped-today ones — a silent footgun). Non-integers and non-positive
    values are rejected with a clean argparse error.
    """
    try:
        days = int(value)
    except (TypeError, ValueError):
        raise argparse.ArgumentTypeError(
            f"invalid --vex-max-age {value!r}: expected a positive integer "
            "number of days"
        )
    if days <= 0:
        raise argparse.ArgumentTypeError(
            f"--vex-max-age must be a positive number of days, got {days}"
        )
    return days


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="casket",
        description=(
            "A daemonless, podman-native container image scanner. "
            "Scans OCI image tarballs, podman image references, or remote "
            "registry URLs for leaked credentials, known-vulnerable packages, "
            "and misconfigurations — with per-layer attribution."
        ),
        epilog=_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--image",
        required=True,
        metavar="REF",
        help="image to scan: tarball path, podman image reference, or registry URL",
    )
    parser.add_argument(
        "--mode",
        choices=["tarball", "podman", "remote"],
        default="tarball",
        help="how to load the image (default: tarball)",
    )
    parser.add_argument(
        "--checks",
        choices=["creds", "cves", "misconfig", "all"],
        default="all",
        help="which checks to run (default: all)",
    )
    parser.add_argument(
        "--format",
        choices=["json", "h1md", "sarif"],
        default="json",
        help="output format (default: json)",
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="never hit the network for CVE lookups (cache-only)",
    )
    parser.add_argument(
        "--fail-on",
        choices=FAIL_ON_CHOICES,
        default="any",
        metavar="THRESHOLD",
        help=(
            "CI gate: exit 1 only when a finding is at this severity or higher "
            "(critical, high, medium, low, info). 'any' (default) fails on any "
            "finding; 'none' never fails on findings (report-only). All "
            "findings are reported regardless of threshold."
        ),
    )
    parser.add_argument(
        "--min-severity",
        choices=MIN_SEVERITY_CHOICES,
        default="all",
        metavar="THRESHOLD",
        help=(
            "report only findings at this severity or higher "
            "(critical, high, medium, low, info). 'all' (default) reports every "
            "finding. Cuts noise on busy images; the exit-code gate (--fail-on) "
            "applies to the findings that remain after filtering."
        ),
    )
    parser.add_argument(
        "--min-epss",
        type=_epss_threshold,
        default=None,
        metavar="PROBABILITY",
        help=(
            "report only CVE findings whose EPSS score (exploitation "
            "probability, 0.0-1.0) is at this threshold or higher. Enriches "
            "every CVE finding with its EPSS score from FIRST.org (cached, "
            "read-only) and prunes the rest. creds/misconfig findings are "
            "unaffected. Omitting the flag reports every finding (default)."
        ),
    )
    parser.add_argument(
        "--vex",
        metavar="VEX.json",
        help=(
            "suppress CVE findings an OpenVEX document marks not_affected or "
            "fixed. Takes a VEX JSON file (https://openvex.dev); every CVE "
            "finding whose id (CVE, OSV, or any alias) is named by a "
            "suppressing statement is dropped from the report. creds/misconfig "
            "findings are unaffected. Like --min-severity/--min-epss it shapes "
            "the reported set before the gate/diff, so a triaged-away CVE "
            "neither shows up nor trips the exit-code gate. Omitting the flag "
            "reports every finding (default)."
        ),
    )
    parser.add_argument(
        "--vex-max-age",
        type=_vex_max_age,
        default=None,
        metavar="DAYS",
        help=(
            "expire VEX suppressions older than DAYS days, forcing re-triage. "
            "A --vex statement whose OpenVEX timestamp is older than this "
            "window (or that carries no timestamp at all) is treated as "
            "expired, so the CVE it waived re-surfaces in the report and the "
            "exit-code gate. Requires --vex; without it this flag is inert. "
            "Omitting it keeps every suppression forever (default)."
        ),
    )
    parser.add_argument(
        "--suppress-ecosystem",
        action="append",
        default=None,
        metavar="ECOSYSTEM",
        help=(
            "suppress CVE findings from this OSV ecosystem (case-insensitive); "
            "repeatable. e.g. --suppress-ecosystem Debian hides every Debian "
            "OS-package CVE so you can focus on application dependencies "
            "(PyPI/npm/…); pass it again (--suppress-ecosystem Debian "
            "--suppress-ecosystem Alpine) to mute several at once. Only CVE "
            "findings carry an ecosystem, so creds/misconfig findings are "
            "unaffected. Like --min-severity/--min-epss/--vex it shapes the "
            "reported set before the gate/diff, so a suppressed CVE neither "
            "shows up nor trips the exit-code gate. Omitting the flag reports "
            "every finding (default)."
        ),
    )
    parser.add_argument(
        "--suppress-severity",
        action="append",
        default=None,
        choices=SUPPRESS_SEVERITY_CHOICES,
        metavar="SEVERITY",
        help=(
            "suppress findings at exactly this severity band (critical, high, "
            "medium, low, info); repeatable. Where --min-severity is a floor "
            "(keep everything at-or-above one level), this mutes the named "
            "level(s) alone, so the two together can carve out any range — e.g. "
            "--suppress-severity medium --suppress-severity low keeps "
            "critical/high AND info while dropping the busy middle (something a "
            "single --min-severity floor can't express). Applies to every "
            "finding category. Like the other report filters it shapes the "
            "reported set before the gate/diff, so a muted band neither shows up "
            "nor trips the exit-code gate. Omitting the flag reports every "
            "finding (default)."
        ),
    )
    parser.add_argument(
        "--stats",
        action="store_true",
        help=(
            "add a component-count inventory summary to the report: total "
            "installed packages, a per-ecosystem breakdown (Debian/PyPI/Alpine/"
            "RPM), how many distinct packages are vulnerable, and a severity "
            "histogram (finding counts per severity, over all checks). This is a "
            "count of the partial package inventory casket already extracts — "
            "it does NOT generate an SBOM (CycloneDX/SPDX) and adds no network "
            "calls. Shows up as a 'scan_stats' object in json/sarif and a "
            "'Components' section in h1md. Omitting the flag leaves output "
            "unchanged (default)."
        ),
    )
    parser.add_argument(
        "--group-by-package",
        action="store_true",
        help=(
            "h1md only: collapse CVE findings that share an (package, "
            "installed_version) into a single section, surfacing the package's "
            "worst severity in the section header and listing each CVE as a "
            "bullet. A single vulnerable package routinely produces 10+ CVEs; "
            "grouping turns a long flat list into one section per package so "
            "the operator triages by component. Pure presentation: json/sarif "
            "are byte-for-byte unchanged so machine consumers stay stable, and "
            "--fail-on / --compare run on the same finding set either way. "
            "creds/misconfig findings (no package field) render under their "
            "per-finding headers as before. Omitting the flag keeps the "
            "ungrouped per-finding layout (default)."
        ),
    )
    parser.add_argument(
        "--output-json-summary",
        action="store_true",
        help=(
            "emit a compact, machine-readable JSON summary instead of the full "
            "findings report — sized for CI dashboards and per-build metrics "
            "pipelines. The summary carries finding counts (total, by severity, "
            "by category, by CVE ecosystem), the component-count inventory when "
            "--stats is set, and a top-10 CVE preview (worst severity first, "
            "then by EPSS) — but NOT the full per-finding detail, so it is not a "
            "replacement for --format json and cannot be consumed by --compare. "
            "Honours every report filter (--min-severity, --min-epss, --vex, "
            "--suppress-ecosystem, --suppress-severity) and the --fail-on exit "
            "code, so the summary reflects what the full report would show. "
            "Mutually exclusive with --compare."
        ),
    )
    parser.add_argument(
        "--compare",
        metavar="BASELINE.json",
        help=(
            "diff mode: compare this scan against a previous casket JSON report "
            "(produced with --format json). Emits a diff of added/removed/"
            "changed/unchanged findings and exits 1 only when this build "
            "introduces NEW findings versus the baseline. --min-severity is "
            "applied to the current scan before diffing; --fail-on is ignored "
            "in compare mode (the diff gates on new findings instead)."
        ),
    )
    parser.add_argument(
        "--diff-format",
        choices=["json", "h1md"],
        default="json",
        help=(
            "compare mode only: pick the diff output format. 'json' (default) "
            "emits the canonical machine-readable diff document (what "
            "downstream tools / future --compare consumers parse); 'h1md' emits "
            "a human-readable Markdown summary of added/removed/changed/"
            "unchanged findings, sized for a PR comment, Slack snippet, or "
            "build-log artifact. The diff content and the exit-code gate (new "
            "findings -> exit 1) are identical across formats; only the "
            "serialization changes. Ignored without --compare."
        ),
    )
    parser.add_argument(
        "--token",
        metavar="TOKEN",
        help="remote mode: static bearer token (sent as Authorization: Bearer)",
    )
    parser.add_argument(
        "--registry-user",
        metavar="USER",
        help=(
            "remote mode: username for registry bearer-token negotiation "
            "(or set CASKET_REGISTRY_USER)"
        ),
    )
    parser.add_argument(
        "--registry-password",
        metavar="PASS",
        help=(
            "remote mode: password/token for registry bearer-token negotiation "
            "(or set CASKET_REGISTRY_PASSWORD; env var preferred for CI safety)"
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"casket {__version__}",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    # --output-json-summary and --compare are different output modes (summary
    # emits a compact dashboard object; compare emits a finding-diff document)
    # and consume the report differently. Combining them is meaningless —
    # surface the conflict cleanly rather than silently letting one win.
    if args.output_json_summary and args.compare:
        print(
            "casket: --output-json-summary and --compare are mutually exclusive",
            file=sys.stderr,
        )
        return 2

    osv_client = None
    epss_client = None
    selected = resolve_checks(args.checks)
    if "cves" in selected:
        from casket.osv import OSVClient

        osv_client = OSVClient(offline=args.offline)

        # EPSS enrichment annotates every CVE finding with its exploitation
        # probability and powers the --min-epss filter. It honours --offline
        # (cache-only) exactly like the OSV lookup, and degrades a miss to "no
        # score" so an offline/cold-cache run never fails — those findings just
        # carry no EPSS field (and are pruned by an explicit --min-epss).
        from casket.epss import EPSSClient

        epss_client = EPSSClient(offline=args.offline)

    # Credentials: CLI flag wins, otherwise fall back to env vars (CI-safe).
    registry_user = args.registry_user or os.environ.get("CASKET_REGISTRY_USER")
    registry_password = args.registry_password or os.environ.get(
        "CASKET_REGISTRY_PASSWORD"
    )

    try:
        image = load_image(
            args.image,
            args.mode,
            token=args.token,
            registry_user=registry_user,
            registry_password=registry_password,
        )
    except FileNotFoundError:
        print(f"casket: image not found: {args.image}", file=sys.stderr)
        return 2
    except Exception as exc:  # surface load errors cleanly, no traceback
        print(f"casket: failed to load image: {exc}", file=sys.stderr)
        return 2

    # Parse the VEX document up front (before the scan) so a malformed file
    # fails fast with a clean exit 2 rather than after a full image scan.
    vex_suppressed: set[str] | None = None
    if args.vex:
        from casket.vex import (
            VEXError,
            effective_suppression_set,
            load_vex_statements,
        )

        try:
            vex_statements = load_vex_statements(args.vex)
        except FileNotFoundError:
            print(f"casket: VEX file not found: {args.vex}", file=sys.stderr)
            return 2
        except (VEXError, OSError) as exc:
            print(f"casket: failed to read VEX file: {exc}", file=sys.stderr)
            return 2
        # --vex-max-age (when set) expires suppressions older than the window so
        # stale triage doesn't silently hide a CVE forever. Absent, every
        # suppression stays live regardless of its timestamp (original
        # behaviour). A suppression with no parseable timestamp is treated as
        # expired under a window — it can't be proven inside the review horizon.
        vex_suppressed = effective_suppression_set(
            vex_statements, args.vex_max_age
        )

    findings = run_checks(
        image, selected, osv_client=osv_client, epss_client=epss_client
    )
    # --min-severity prunes the report (default "all" keeps everything). The
    # exit-code gate then runs on the *reported* set so the build outcome stays
    # consistent with what the operator actually sees: a suppressed low finding
    # neither shows up nor secretly fails the build. --fail-on still gates the
    # exit code among the findings that survive filtering. In --compare mode the
    # same filtered set is what we diff, so the baseline and current scans are
    # compared at the operator's chosen severity floor.
    findings = filter_by_severity(findings, args.min_severity)
    # --min-epss prunes CVE findings by exploitation probability (EPSS). Like
    # --min-severity it shapes the *reported* set before the gate / diff runs,
    # so what fails the build matches what the operator sees. Absent (the
    # default), it is a no-op. creds/misconfig findings are never pruned by it.
    findings = filter_by_epss(findings, args.min_epss)
    # --vex prunes CVE findings the operator's OpenVEX document triaged as
    # not_affected / fixed. Like the severity / EPSS filters it shapes the
    # *reported* set before the gate / diff, so a triaged-away CVE neither
    # shows up nor secretly trips the gate. Absent (the default), it is a
    # no-op; creds/misconfig findings are never pruned by it.
    findings = filter_by_vex(findings, vex_suppressed)
    # --suppress-ecosystem prunes CVE findings from operator-named OSV
    # ecosystems (e.g. hide all Debian OS-package CVEs to focus on app deps).
    # Like the severity / EPSS / VEX filters it shapes the *reported* set before
    # the gate / diff, so what fails the build matches what the operator sees.
    # Absent (the default) it is a no-op; creds/misconfig findings (which carry
    # no ecosystem) are never pruned by it.
    ecosystem_suppressed = (
        set(args.suppress_ecosystem) if args.suppress_ecosystem else None
    )
    findings = filter_by_ecosystem(findings, ecosystem_suppressed)
    # --suppress-severity mutes operator-named severity bands *exactly* (unlike
    # --min-severity's floor), so an arbitrary range can be carved out — e.g.
    # keep critical/high + info, drop medium/low. Applies to every category. Like
    # the other report filters it shapes the *reported* set before the gate /
    # diff, so what fails the build matches what the operator sees. Absent (the
    # default) it is a no-op.
    severity_suppressed = (
        set(args.suppress_severity) if args.suppress_severity else None
    )
    findings = filter_by_severity_band(findings, severity_suppressed)

    # --stats attaches a component-count inventory summary (total packages,
    # per-ecosystem breakdown, vulnerable-package count) to the report. Computed
    # from the *filtered* findings so the vulnerable count reflects what the
    # operator sees. Network-free (reuses the inventory the CVE check extracts);
    # None when the flag is absent, leaving the report shape unchanged.
    scan_stats = component_stats(image, findings) if args.stats else None

    if args.output_json_summary:
        # Dashboard / metric-aggregation output mode. Emits a compact summary
        # object instead of the full findings report, using the same filtered
        # set so the dashboard sees what the full report would. --fail-on
        # still gates the exit code on the same set (build outcome stays
        # consistent across output modes); --format is ignored here (the
        # summary is JSON-only by design — a dashboard reads JSON).
        summary = build_summary(findings, image=args.image, scan_stats=scan_stats)
        print(render_summary_json(summary))
        return exit_code(findings, args.fail_on)

    if args.compare:
        # Diff mode: compare this scan against a previous casket JSON report and
        # gate on *new* findings (regressions), not the absolute finding set.
        try:
            baseline = load_baseline_report(args.compare)
        except FileNotFoundError:
            print(
                f"casket: baseline report not found: {args.compare}",
                file=sys.stderr,
            )
            return 2
        except (ValueError, OSError) as exc:
            print(f"casket: failed to read baseline: {exc}", file=sys.stderr)
            return 2
        current = report_dict(findings, image=args.image, scan_stats=scan_stats)
        diff = diff_reports(baseline, current)
        # --diff-format picks the diff serialization. JSON is the canonical
        # machine form (the historical default, what downstream tools consume);
        # h1md is the operator-facing Markdown summary for PR comments / Slack.
        # The diff content and the exit-code gate are identical across formats.
        if args.diff_format == "h1md":
            print(render_diff_h1md(diff))
        else:
            print(render_diff_json(diff))
        # Exit 1 iff this build introduced new findings versus the baseline.
        return 1 if regression_count(diff) > 0 else 0

    output = render(
        findings,
        args.format,
        image=args.image,
        scan_stats=scan_stats,
        group_by_package=args.group_by_package,
    )
    print(output)
    return exit_code(findings, args.fail_on)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
