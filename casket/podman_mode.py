"""Podman mode: load an image by reference via the podman CLI (daemonless).

We shell out to ``podman save --format oci-archive`` to materialize a local OCI
tarball, then parse it with ``casket.oci`` — the same code path as tarball mode.
This mirrors miasma's nmap shell-out pattern: we wrap a trusted system binary
rather than reimplementing a registry/storage client.

Podman is an OPTIONAL system dependency. If the ``podman`` binary is absent,
``load_podman`` raises ``PodmanUnavailable`` with a clear message. Tests mock
``subprocess.run`` so they never require podman to be installed.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path

from casket.oci import Image, load_tarball


class PodmanUnavailable(Exception):
    """Raised when the podman CLI is required but not installed/usable."""


def podman_available() -> bool:
    return shutil.which("podman") is not None


def load_podman(reference: str, *, podman_bin: str = "podman") -> Image:
    """Materialize ``reference`` to an OCI tarball via podman and parse it."""
    if shutil.which(podman_bin) is None:
        raise PodmanUnavailable(
            "podman CLI not found on PATH. Install podman to use --mode podman "
            "(see README, 'System dependencies'). casket stays daemonless: it "
            "never talks to a Docker daemon."
        )

    with tempfile.TemporaryDirectory(prefix="casket-podman-") as tmp:
        out = Path(tmp) / "image.tar"
        proc = subprocess.run(
            [podman_bin, "save", "--format", "oci-archive", "-o", str(out), reference],
            capture_output=True,
            text=True,
        )
        if proc.returncode != 0:
            raise PodmanUnavailable(
                f"`podman save` failed for {reference!r}: "
                f"{proc.stderr.strip() or proc.stdout.strip()}"
            )
        if not out.exists():
            raise PodmanUnavailable(
                f"`podman save` reported success but produced no archive for {reference!r}"
            )
        return load_tarball(str(out))
