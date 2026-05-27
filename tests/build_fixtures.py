"""Build deterministic OCI image-layout tarballs for tests.

Run as a script to (re)generate the bundled fixtures under tests/fixtures/:

    python -m tests.build_fixtures

We hand-roll valid OCI image layouts using only stdlib so the fixtures need no
container runtime to exist. Each fixture is a real, parseable OCI tarball.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import tarfile
from pathlib import Path

FIXTURE_DIR = Path(__file__).parent / "fixtures"


def _layer_tar(files: dict[str, bytes]) -> bytes:
    """Build a gzip-less tar holding the given path->content files."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for name, content in files.items():
            info = tarfile.TarInfo(name=name)
            info.size = len(content)
            info.mode = 0o644
            tf.addfile(info, io.BytesIO(content))
    return buf.getvalue()


def _digest(blob: bytes) -> str:
    return "sha256:" + hashlib.sha256(blob).hexdigest()


def build_oci_image(
    out_path: Path,
    *,
    layers: list[dict[str, bytes]],
    config_overrides: dict | None = None,
) -> str:
    """Write a valid OCI image-layout tarball. Returns the top layer digest."""
    blobs: dict[str, bytes] = {}  # digest -> bytes

    layer_descs = []
    diff_ids = []
    history = []
    for files in layers:
        tar_bytes = _layer_tar(files)
        d = _digest(tar_bytes)
        blobs[d] = tar_bytes
        layer_descs.append(
            {
                "mediaType": "application/vnd.oci.image.layer.v1.tar",
                "digest": d,
                "size": len(tar_bytes),
            }
        )
        diff_ids.append(d)
        history.append({"created_by": f"ADD layer {d[:19]}"})

    config_obj = {
        "architecture": "amd64",
        "os": "linux",
        "config": {
            "User": "",
            "Env": ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],
            "ExposedPorts": {},
        },
        "rootfs": {"type": "layers", "diff_ids": diff_ids},
        "history": history,
    }
    if config_overrides:
        # shallow-merge into config_obj["config"]
        for k, v in config_overrides.items():
            if k == "config":
                config_obj["config"].update(v)
            else:
                config_obj[k] = v

    config_bytes = json.dumps(config_obj, sort_keys=True).encode()
    config_digest = _digest(config_bytes)
    blobs[config_digest] = config_bytes

    manifest_obj = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "digest": config_digest,
            "size": len(config_bytes),
        },
        "layers": layer_descs,
    }
    manifest_bytes = json.dumps(manifest_obj, sort_keys=True).encode()
    manifest_digest = _digest(manifest_bytes)
    blobs[manifest_digest] = manifest_bytes

    index_obj = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": [
            {
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": manifest_digest,
                "size": len(manifest_bytes),
            }
        ],
    }
    index_bytes = json.dumps(index_obj, sort_keys=True).encode()
    oci_layout_bytes = json.dumps({"imageLayoutVersion": "1.0.0"}).encode()

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(out_path, mode="w") as tf:
        def add(name: str, content: bytes):
            info = tarfile.TarInfo(name=name)
            info.size = len(content)
            info.mode = 0o644
            tf.addfile(info, io.BytesIO(content))

        add("oci-layout", oci_layout_bytes)
        add("index.json", index_bytes)
        for digest, blob in blobs.items():
            alg, _, hexd = digest.partition(":")
            add(f"blobs/{alg}/{hexd}", blob)

    return layer_descs[-1]["digest"]


def build_all() -> dict[str, str]:
    """Generate every bundled fixture. Returns name -> top layer digest."""
    digests = {}

    # leaky-image: a layer with a planted AWS secret access key.
    digests["leaky-image"] = build_oci_image(
        FIXTURE_DIR / "leaky-image.tar",
        layers=[
            {
                "app/main.py": b"print('hello world')\n",
                "app/.env": (
                    b"DB_HOST=localhost\n"
                    b"AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
                    b"AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
                ),
            },
        ],
    )

    # old-package: a layer with a deliberately old package manifest the CVE
    # check can resolve against OSV. We plant a python "requests" 2.19.0 entry
    # in a dpkg-style and a PyPI-style record. The OSV fixture/cache maps it.
    digests["old-package"] = build_oci_image(
        FIXTURE_DIR / "old-package.tar",
        layers=[
            {
                "usr/lib/python3/dist-packages/requests-2.19.0.dist-info/METADATA": (
                    b"Metadata-Version: 2.1\n"
                    b"Name: requests\n"
                    b"Version: 2.19.0\n"
                ),
            },
        ],
    )

    # alpine-image: an Alpine layer carrying a real-format apk installed DB.
    # It declares a known-vulnerable busybox 1.36.0-r0 (seeded -> CVE-2023-42366)
    # alongside a clean musl entry, so tests can assert findings fire only for
    # the vulnerable package and not the clean one.
    digests["alpine-image"] = build_oci_image(
        FIXTURE_DIR / "alpine-image.tar",
        layers=[
            {
                "lib/apk/db/installed": (
                    b"C:Q1eXXX==\n"
                    b"P:musl\n"
                    b"V:1.2.4-r2\n"
                    b"A:x86_64\n"
                    b"T:the musl c library (libc) implementation\n"
                    b"U:https://musl.libc.org/\n"
                    b"L:MIT\n"
                    b"\n"
                    b"C:Q1bYYY==\n"
                    b"P:busybox\n"
                    b"V:1.36.0-r0\n"
                    b"A:x86_64\n"
                    b"T:Size optimized toolbox of many common UNIX utilities\n"
                    b"U:https://busybox.net/\n"
                    b"L:GPL-2.0-only\n"
                    b"\n"
                ),
            },
        ],
    )

    # alpine-clean-image: an Alpine layer whose packages have no seeded vulns.
    digests["alpine-clean-image"] = build_oci_image(
        FIXTURE_DIR / "alpine-clean-image.tar",
        layers=[
            {
                "lib/apk/db/installed": (
                    b"C:Q1zZZZ==\n"
                    b"P:musl\n"
                    b"V:1.2.5-r0\n"
                    b"A:x86_64\n"
                    b"T:the musl c library (libc) implementation\n"
                    b"\n"
                ),
            },
        ],
    )

    # entropy-image: a layer with a high-entropy base64-alphabet string that
    # does NOT match any regex pattern, plus a low-entropy control string.
    # The high-entropy token is 32 chars of near-random base64 chars (entropy ~5.x).
    digests["entropy-image"] = build_oci_image(
        FIXTURE_DIR / "entropy-image.tar",
        layers=[
            {
                # High-entropy token that looks like a raw secret (no known prefix).
                # "sVq3+Zk8mN2pRjLwT9dXoC5eAhYf1Gu7" — 34 chars, high entropy.
                "app/config.yml": (
                    b"database:\n"
                    b"  host: localhost\n"
                    b"  secret_token: sVq3+Zk8mN2pRjLwT9dXoC5eAhYf1Gu7\n"
                ),
                # Low-entropy string — should NOT produce an entropy finding.
                "app/readme.txt": (
                    b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
                ),
            },
        ],
    )

    # entropy-logfile-image: a layer whose path contains "log" — the lower
    # threshold (4.0) should apply.
    digests["entropy-logfile-image"] = build_oci_image(
        FIXTURE_DIR / "entropy-logfile-image.tar",
        layers=[
            {
                # This token has entropy ~4.2 — above the log threshold (4.0)
                # but below the normal threshold (4.5), so it fires only for logs.
                "var/log/app.log": (
                    b"2024-01-01 startup token=aBcDeFgHiJkLmNoPqRsTuV\n"
                ),
            },
        ],
    )

    # rootuser-image: config declares USER root -> misconfig.
    digests["rootuser-image"] = build_oci_image(
        FIXTURE_DIR / "rootuser-image.tar",
        layers=[{"app/run.sh": b"#!/bin/sh\necho run\n"}],
        config_overrides={
            "config": {
                "User": "root",
                "ExposedPorts": {"22/tcp": {}},
                "Env": [
                    "PATH=/usr/bin",
                    "API_TOKEN=supersecrettoken1234567890",
                ],
            }
        },
    )

    return digests


if __name__ == "__main__":
    d = build_all()
    for name, digest in d.items():
        print(f"{name}: top layer {digest}")
    print(f"fixtures written to {FIXTURE_DIR}")
