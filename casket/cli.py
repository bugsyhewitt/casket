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
import sys

from casket import __version__
from casket.findings import render
from casket.scanner import load_image, resolve_checks, run_checks

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
        choices=["json", "h1md"],
        default="json",
        help="output format (default: json)",
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="never hit the network for CVE lookups (cache-only)",
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

    try:
        image = load_image(args.image, args.mode)
    except FileNotFoundError:
        print(f"casket: image not found: {args.image}", file=sys.stderr)
        return 2
    except Exception as exc:  # surface load errors cleanly, no traceback
        print(f"casket: failed to load image: {exc}", file=sys.stderr)
        return 2

    findings = run_checks(image, selected, osv_client=osv_client)
    output = render(findings, args.format, image=args.image)
    print(output)
    # Exit 1 if any findings (useful in CI gates); 0 if clean.
    return 1 if findings else 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
