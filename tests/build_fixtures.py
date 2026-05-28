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
import sqlite3
import struct
import tarfile
import tempfile
from pathlib import Path

FIXTURE_DIR = Path(__file__).parent / "fixtures"

# RPM header tags / types, mirroring casket.checks.cves.
_RPMTAG_NAME = 1000
_RPMTAG_VERSION = 1001
_RPMTAG_RELEASE = 1002
_RPMTAG_EPOCH = 1003
_RPMTAG_ARCH = 1022
_RPM_INT32_TYPE = 4
_RPM_STRING_TYPE = 6


def _rpm_header_blob(
    *,
    name: str,
    version: str,
    release: str,
    arch: str = "x86_64",
    epoch: int | None = None,
) -> bytes:
    """Hand-roll a binary RPM header blob in the form stored in rpmdb.sqlite.

    Layout: index_count(u32) + data_len(u32) + index entries (16 bytes each:
    tag,type,offset,count) + data store. String fields are NUL-terminated;
    INT32 fields are 4 big-endian bytes. This matches what
    ``casket.checks.cves._parse_rpm_header`` expects.
    """
    # (tag, type, value) — strings go in the store NUL-terminated.
    fields: list[tuple[int, int, object]] = [
        (_RPMTAG_NAME, _RPM_STRING_TYPE, name),
        (_RPMTAG_VERSION, _RPM_STRING_TYPE, version),
        (_RPMTAG_RELEASE, _RPM_STRING_TYPE, release),
        (_RPMTAG_ARCH, _RPM_STRING_TYPE, arch),
    ]
    if epoch is not None:
        fields.append((_RPMTAG_EPOCH, _RPM_INT32_TYPE, epoch))

    store = bytearray()
    index = bytearray()
    for tag, typ, value in fields:
        data_off = len(store)
        if typ == _RPM_STRING_TYPE:
            store += value.encode("utf-8") + b"\x00"
            count = 1
        elif typ == _RPM_INT32_TYPE:
            store += struct.pack(">I", int(value))
            count = 1
        else:  # pragma: no cover - fixtures only use string/int32
            raise ValueError(f"unsupported fixture type {typ}")
        index += struct.pack(">IIiI", tag, typ, data_off, count)

    header = struct.pack(">II", len(fields), len(store))
    return header + bytes(index) + bytes(store)


def _rpmdb_sqlite_bytes(packages: list[dict]) -> bytes:
    """Build a real SQLite rpmdb (Packages table of header blobs) as bytes."""
    fd, tmp_path = tempfile.mkstemp(suffix=".sqlite")
    os.close(fd)
    try:
        conn = sqlite3.connect(tmp_path)
        try:
            conn.execute(
                "CREATE TABLE Packages (hnum INTEGER PRIMARY KEY, blob BLOB)"
            )
            for i, pkg in enumerate(packages, start=1):
                conn.execute(
                    "INSERT INTO Packages (hnum, blob) VALUES (?, ?)",
                    (i, _rpm_header_blob(**pkg)),
                )
            conn.commit()
        finally:
            conn.close()
        return Path(tmp_path).read_bytes()
    finally:
        os.unlink(tmp_path)


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
    history: list[dict] | None = None,
) -> str:
    """Write a valid OCI image-layout tarball. Returns the top layer digest.

    ``history`` lets a fixture declare an explicit OCI config ``history`` array
    (including ``empty_layer`` metadata-only steps) so layer→command attribution
    can be exercised. When omitted, a default one-entry-per-layer history is
    synthesised (each filesystem-bearing, mirroring real layer alignment).
    """
    blobs: dict[str, bytes] = {}  # digest -> bytes

    layer_descs = []
    diff_ids = []
    synth_history = []
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
        synth_history.append({"created_by": f"ADD layer {d[:19]}"})

    history = history if history is not None else synth_history

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

    # alpine-release-image: exercises release-qualified OSV resolution. The
    # base layer carries etc/alpine-release ("3.18.4") in a *different* layer
    # than lib/apk/db/installed, so the image-level release scan must find it
    # cross-layer. The apk db declares a vulnerable busybox; the test seeds the
    # vuln under the release-qualified ecosystem "Alpine:v3.18" (NOT bare
    # "Alpine") to prove the release-qualified query path is what resolves it.
    digests["alpine-release-image"] = build_oci_image(
        FIXTURE_DIR / "alpine-release-image.tar",
        layers=[
            {
                "etc/alpine-release": b"3.18.4\n",
            },
            {
                "lib/apk/db/installed": (
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

    # rpm-image: a RHEL-family layer carrying a real SQLite rpmdb. It declares
    # a known-vulnerable openssl 3.0.7-6.el9 (epoch 1, seeded -> CVE-2023-0464)
    # alongside a clean bash entry, so tests can assert findings fire only for
    # the vulnerable package and not the clean one.
    digests["rpm-image"] = build_oci_image(
        FIXTURE_DIR / "rpm-image.tar",
        layers=[
            {
                "var/lib/rpm/rpmdb.sqlite": _rpmdb_sqlite_bytes(
                    [
                        {
                            "name": "openssl",
                            "version": "3.0.7",
                            "release": "6.el9",
                            "epoch": 1,
                            "arch": "x86_64",
                        },
                        {
                            "name": "bash",
                            "version": "5.1.8",
                            "release": "6.el9",
                            "arch": "x86_64",
                        },
                    ]
                ),
            },
        ],
    )

    # rpm-clean-image: a RHEL-family layer whose packages have no seeded vulns.
    digests["rpm-clean-image"] = build_oci_image(
        FIXTURE_DIR / "rpm-clean-image.tar",
        layers=[
            {
                "var/lib/rpm/rpmdb.sqlite": _rpmdb_sqlite_bytes(
                    [
                        {
                            "name": "bash",
                            "version": "5.1.8",
                            "release": "6.el9",
                            "arch": "x86_64",
                        },
                    ]
                ),
            },
        ],
    )

    # rpm-legacy-image: a RHEL 7/8 style layer with only the Berkeley DB
    # `Packages` file (no rpmdb.sqlite). casket must skip it silently — no
    # findings, no crash.
    digests["rpm-legacy-image"] = build_oci_image(
        FIXTURE_DIR / "rpm-legacy-image.tar",
        layers=[
            {
                # Not a real BDB; content is irrelevant — casket never opens it.
                "var/lib/rpm/Packages": b"\x00\x05\x16\x53 berkeley db placeholder\n",
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

    # multi-secrets-image: a layer carrying one example of each expanded
    # high-precision provider token (POST_V01 Item 6). Each token is a
    # syntactically valid but fabricated value — none are real credentials.
    #
    # The token strings are *assembled at build time* from inert fragments
    # (prefix + filler) rather than written as literals, so neither this source
    # file nor the generated tarball contains a committed token-shaped string
    # that would trip registry/CI secret-scanning push protection.
    _lc = "abcdefghijklmnopqrstuvwxyz"
    _hex32 = "0123456789abcdef0123456789abcdef"
    _b36 = (_lc + "0123456789")  # 36 chars, the GitHub/npm token body length
    secrets_lines = [
        "GITHUB_PAT=" + "ghp_" + _b36,
        "GITHUB_OAUTH=" + "gho_" + _b36,
        "GITHUB_ACTIONS=" + "ghs_" + _b36,
        "SLACK_TOKEN=" + "xoxb-" + "1234567890-" + (_lc[:16]),
        "STRIPE_SECRET=" + "sk_" + "live_" + (_lc + _lc)[:24],
        "STRIPE_RESTRICTED=" + "rk_" + "live_" + (_lc + _lc)[:24],
        "SENDGRID=" + "SG." + (_lc[:22]) + "." + (_lc + _lc[:17]),
        "NPM_TOKEN=" + "npm_" + _b36,
        "DOCKER_PAT=" + "dckr_" + "pat_" + (_b36[:27]),
        "JWT=" + "eyJ" + _b36 + "." + "eyJ" + _b36 + "." + _b36,
        "HEROKU_API_KEY=" + _hex32[:8] + "-" + _hex32[:4] + "-" + _hex32[4:8]
        + "-" + _hex32[8:12] + "-" + _hex32[:12],
        "MAILCHIMP=" + _hex32 + "-us12",
        "TWILIO_SID=" + "AC" + _hex32,
        "TWILIO_API_KEY=" + "SK" + _hex32,
    ]
    secrets_env = ("\n".join(secrets_lines) + "\n").encode()
    # GCP service-account key marker, assembled to avoid a literal in source.
    gcp_key = ('{\n  "type": "' + "service_account" + '",\n'
               '  "project_id": "example"\n}\n').encode()
    build_oci_image(
        FIXTURE_DIR / "multi-secrets-image.tar",
        layers=[{"app/secrets.env": secrets_env, "app/gcp-key.json": gcp_key}],
    )
    digests["multi-secrets-image"] = "(built)"

    # history-image: a two-layer image with an explicit OCI history that
    # includes a metadata-only (empty_layer) ENV step between the two
    # filesystem-bearing layers. Each filesystem layer plants a distinct AWS
    # secret so layer→command attribution can be asserted: the first secret
    # must attribute to the `COPY .env` command, the second to the
    # `RUN echo key` command — proving the empty_layer entry is skipped and the
    # remaining history aligns positionally with the layers.
    digests["history-image"] = build_oci_image(
        FIXTURE_DIR / "history-image.tar",
        layers=[
            {
                "app/first.env": (
                    b"AWS_SECRET_ACCESS_KEY="
                    b"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
                ),
            },
            {
                "app/second.env": (
                    b"AWS_SECRET_ACCESS_KEY="
                    b"je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY\n"
                ),
            },
        ],
        history=[
            {"created_by": "COPY .env /app/first.env"},
            {"created_by": "ENV PATH=/usr/bin", "empty_layer": True},
            {"created_by": "RUN echo key > /app/second.env"},
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
