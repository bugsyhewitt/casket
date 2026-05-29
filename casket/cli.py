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
from casket.findings import render
from casket.scanner import (
    FAIL_ON_CHOICES,
    MIN_SEVERITY_CHOICES,
    exit_code,
    filter_by_severity,
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

    osv_client = None
    selected = resolve_checks(args.checks)
    if "cves" in selected:
        from casket.osv import OSVClient

        osv_client = OSVClient(offline=args.offline)

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

    findings = run_checks(image, selected, osv_client=osv_client)
    # --min-severity prunes the report (default "all" keeps everything). The
    # exit-code gate then runs on the *reported* set so the build outcome stays
    # consistent with what the operator actually sees: a suppressed low finding
    # neither shows up nor secretly fails the build. --fail-on still gates the
    # exit code among the findings that survive filtering.
    findings = filter_by_severity(findings, args.min_severity)
    output = render(findings, args.format, image=args.image)
    print(output)
    return exit_code(findings, args.fail_on)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
