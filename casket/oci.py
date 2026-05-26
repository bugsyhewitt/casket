"""OCI image parsing using only the Python standard library.

casket parses container images directly from their on-disk / on-tar
representation per the OCI Image Layout Specification. No Docker, no daemon,
no external binary. We read:

  - ``index.json``        — the top-level entry point (OCI image layout)
  - ``blobs/<alg>/<hex>`` — content-addressable blobs (manifests, configs, layers)

[Worker decision: support two on-tar layouts]
Container tooling produces two slightly different tarball shapes:

  1. OCI image layout (``podman save --format oci-archive``, ``skopeo copy
     oci-archive:``): has ``oci-layout`` + ``index.json`` + ``blobs/``.
  2. Docker "v1.2" save format (``docker save`` / ``podman save`` default):
     has ``manifest.json`` listing ``Config`` and ``Layers`` by path.

The v0.1 criteria reference parsing ``manifest.json`` and ``config.json``
directly, which matches the Docker save format, while the niche statement says
"OCI image tarballs". We support BOTH so any tarball a user feeds us parses.
Layers are exposed uniformly as ``Layer`` objects regardless of source format.
"""

from __future__ import annotations

import hashlib
import io
import json
import tarfile
from dataclasses import dataclass, field
from typing import Any


class OCIParseError(Exception):
    """Raised when an image tarball cannot be parsed as OCI or docker-save."""


@dataclass
class Layer:
    """A single image layer.

    ``digest`` is the canonical layer identifier used for attribution. For OCI
    layouts it is the blob digest (``sha256:...``). For docker-save tarballs
    we compute the sha256 of the layer tar so we still have a stable id.
    """

    digest: str
    media_type: str
    _tar_bytes: bytes = field(repr=False)

    def iter_files(self):
        """Yield ``(path, size, reader)`` for each regular file in the layer.

        ``reader`` is a zero-arg callable returning the file's bytes. We defer
        reading content so checks can skip large/binary files cheaply.
        """
        raw = io.BytesIO(self._tar_bytes)
        try:
            tf = tarfile.open(fileobj=raw, mode="r:*")
        except tarfile.TarError as exc:  # pragma: no cover - defensive
            raise OCIParseError(f"layer {self.digest} is not a tar: {exc}") from exc
        with tf:
            for member in tf.getmembers():
                if not member.isfile():
                    continue
                name = member.name.lstrip("./")

                def _reader(m=member, t=tf):
                    fh = t.extractfile(m)
                    return fh.read() if fh is not None else b""

                yield name, member.size, _reader


@dataclass
class Image:
    """A parsed container image."""

    config: dict[str, Any]
    layers: list[Layer]
    source: str  # path or reference the image was loaded from

    @property
    def history(self) -> list[dict[str, Any]]:
        return self.config.get("history", [])

    @property
    def config_descriptor_digest(self) -> str:
        """A stable digest for the image config, used as a synthetic layer_sha
        for findings derived from config (e.g. misconfig USER root)."""
        blob = json.dumps(self.config, sort_keys=True).encode()
        return "sha256:" + hashlib.sha256(blob).hexdigest()


def load_tarball(path: str) -> Image:
    """Load an image from a tarball on disk (OCI layout or docker-save)."""
    try:
        tf = tarfile.open(path, mode="r:*")
    except FileNotFoundError:
        raise
    except tarfile.TarError as exc:
        raise OCIParseError(f"{path}: not a readable tar archive: {exc}") from exc

    with tf:
        members = {m.name.lstrip("./"): m for m in tf.getmembers()}

        def read(name: str) -> bytes:
            member = members.get(name) or members.get("./" + name)
            if member is None:
                raise OCIParseError(f"{path}: missing entry {name!r}")
            fh = tf.extractfile(member)
            if fh is None:
                raise OCIParseError(f"{path}: cannot read entry {name!r}")
            return fh.read()

        if "index.json" in members or "oci-layout" in members:
            return _load_oci_layout(path, members, read)
        if "manifest.json" in members:
            return _load_docker_save(path, members, read)
        raise OCIParseError(
            f"{path}: not an OCI image layout (no index.json) "
            "and not a docker-save archive (no manifest.json)"
        )


def _blob_path(digest: str) -> str:
    alg, _, hexd = digest.partition(":")
    return f"blobs/{alg}/{hexd}"


def _load_oci_layout(path, members, read) -> Image:
    index = json.loads(read("index.json"))
    manifests = index.get("manifests", [])
    if not manifests:
        raise OCIParseError(f"{path}: index.json has no manifests")
    # v0.1: take the first image manifest. Multi-arch selection is out of scope.
    manifest_desc = manifests[0]
    manifest = json.loads(read(_blob_path(manifest_desc["digest"])))

    config_desc = manifest["config"]
    config = json.loads(read(_blob_path(config_desc["digest"])))

    layers: list[Layer] = []
    for layer_desc in manifest.get("layers", []):
        digest = layer_desc["digest"]
        media_type = layer_desc.get("mediaType", "")
        blob = read(_blob_path(digest))
        layers.append(Layer(digest=digest, media_type=media_type, _tar_bytes=blob))
    return Image(config=config, layers=layers, source=path)


def _load_docker_save(path, members, read) -> Image:
    manifest = json.loads(read("manifest.json"))
    if not manifest:
        raise OCIParseError(f"{path}: manifest.json is empty")
    entry = manifest[0]
    config = json.loads(read(entry["Config"]))

    layers: list[Layer] = []
    for layer_path in entry.get("Layers", []):
        blob = read(layer_path)
        digest = "sha256:" + hashlib.sha256(blob).hexdigest()
        layers.append(
            Layer(
                digest=digest,
                media_type="application/vnd.oci.image.layer.v1.tar",
                _tar_bytes=blob,
            )
        )
    return Image(config=config, layers=layers, source=path)
