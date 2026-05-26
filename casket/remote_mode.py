"""Remote mode: pull an image manifest + blobs over the OCI distribution API.

Daemonless registry access. We speak the OCI distribution / Docker registry v2
HTTP API directly with httpx:

  GET /v2/<name>/manifests/<ref>   -> image manifest (or index, we take [0])
  GET /v2/<name>/blobs/<digest>    -> config / layer blobs

No auth flows beyond an optional static bearer token in v0.1 (Docker Hub token
negotiation, registry login, etc. are out of scope). This is gated on network
availability; tests exercise it against a local fixture HTTP server.

Reference format accepted (subset):
  [scheme://]host[:port]/namespace/repo[:tag]
  e.g. http://127.0.0.1:54321/library/alpine:3.10
If no scheme is given, https:// is assumed.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

import httpx

from casket.oci import Image, Layer

_MANIFEST_ACCEPT = ", ".join(
    [
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.docker.distribution.manifest.v2+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
    ]
)


class RemotePullError(Exception):
    """Raised when a remote image cannot be pulled."""


@dataclass
class RemoteRef:
    base_url: str  # e.g. http://127.0.0.1:5000
    name: str  # repository path, e.g. library/alpine
    reference: str  # tag or digest


def parse_reference(ref: str) -> RemoteRef:
    raw = ref
    if "://" in ref:
        scheme, _, rest = ref.partition("://")
    else:
        scheme, rest = "https", ref
    if "/" not in rest:
        raise RemotePullError(f"invalid remote reference {raw!r}: missing repository path")
    host, _, path = rest.partition("/")
    if ":" in path.split("/")[-1]:
        repo, _, tag = path.rpartition(":")
    else:
        repo, tag = path, "latest"
    return RemoteRef(base_url=f"{scheme}://{host}", name=repo, reference=tag)


def load_remote(ref: str, *, token: str | None = None, timeout: float = 15.0) -> Image:
    rr = parse_reference(ref)
    headers = {"Accept": _MANIFEST_ACCEPT}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    try:
        with httpx.Client(base_url=rr.base_url, timeout=timeout) as client:
            manifest = _get_manifest(client, rr, headers)
            config_digest = manifest["config"]["digest"]
            config = json.loads(_get_blob(client, rr, config_digest))

            layers: list[Layer] = []
            for desc in manifest.get("layers", []):
                blob = _get_blob(client, rr, desc["digest"])
                layers.append(
                    Layer(
                        digest=desc["digest"],
                        media_type=desc.get("mediaType", ""),
                        _tar_bytes=blob,
                    )
                )
    except httpx.HTTPError as exc:
        raise RemotePullError(f"failed to pull {ref!r}: {exc}") from exc

    return Image(config=config, layers=layers, source=ref)


def _get_manifest(client, rr, headers) -> dict:
    resp = client.get(f"/v2/{rr.name}/manifests/{rr.reference}", headers=headers)
    resp.raise_for_status()
    doc = resp.json()
    # If it's an index/manifest-list, resolve the first child manifest.
    if "manifests" in doc and "config" not in doc:
        child = doc["manifests"][0]["digest"]
        resp = client.get(f"/v2/{rr.name}/manifests/{child}", headers=headers)
        resp.raise_for_status()
        doc = resp.json()
    return doc


def _get_blob(client, rr, digest: str) -> bytes:
    resp = client.get(f"/v2/{rr.name}/blobs/{digest}")
    resp.raise_for_status()
    return resp.content
