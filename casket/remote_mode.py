"""Remote mode: pull an image manifest + blobs over the OCI distribution API.

Daemonless registry access. We speak the OCI distribution / Docker registry v2
HTTP API directly with httpx:

  GET /v2/<name>/manifests/<ref>   -> image manifest (or index, we take [0])
  GET /v2/<name>/blobs/<digest>    -> config / layer blobs

Auth supports two paths:

  1. A static bearer token passed directly (``--token``).
  2. OCI Distribution Spec bearer-token negotiation: when the registry replies
     ``401 WWW-Authenticate: Bearer realm=...,service=...,scope=...`` we fetch a
     token from the realm endpoint (optionally with HTTP Basic credentials) and
     retry. This is what Docker Hub, GHCR, ECR, ACR, etc. require.

Credentials may be supplied via ``--registry-user``/``--registry-password`` or
the ``CASKET_REGISTRY_USER``/``CASKET_REGISTRY_PASSWORD`` environment variables
(env vars preferred for CI safety). Credentials are NEVER logged.

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


def parse_www_authenticate(header: str) -> dict[str, str]:
    """Parse a ``WWW-Authenticate: Bearer realm=...,service=...`` challenge.

    Returns the parameter dict (e.g. ``{"realm": ..., "service": ...,
    "scope": ...}``). Returns ``{}`` if the header is not a Bearer challenge.
    Tolerant of optional whitespace and quoted or unquoted values.
    """
    header = header.strip()
    scheme, _, rest = header.partition(" ")
    if scheme.lower() != "bearer":
        return {}
    params: dict[str, str] = {}
    # Split on commas that separate key=value pairs. Values may be quoted and
    # contain commas (e.g. scope="repository:a:pull,push"), so we parse a
    # quote-aware scan rather than a naive split.
    i = 0
    rest = rest.strip()
    n = len(rest)
    while i < n:
        eq = rest.find("=", i)
        if eq == -1:
            break
        key = rest[i:eq].strip()
        j = eq + 1
        if j < n and rest[j] == '"':
            j += 1
            start = j
            while j < n and rest[j] != '"':
                j += 1
            value = rest[start:j]
            j += 1  # skip closing quote
        else:
            start = j
            while j < n and rest[j] != ",":
                j += 1
            value = rest[start:j].strip()
        if key:
            params[key] = value
        # advance past the following comma, if any
        while j < n and rest[j] in ", ":
            j += 1
        i = j
    return params


def _negotiate_token(
    challenge: dict[str, str],
    *,
    user: str | None,
    password: str | None,
    timeout: float,
) -> str | None:
    """Fetch a bearer token from the challenge realm. Returns None on failure.

    Credentials, if provided, are sent as HTTP Basic auth to the token endpoint.
    They are never logged.
    """
    realm = challenge.get("realm")
    if not realm:
        return None
    query: dict[str, str] = {}
    if "service" in challenge:
        query["service"] = challenge["service"]
    if "scope" in challenge:
        query["scope"] = challenge["scope"]
    auth = (user, password) if (user or password) else None
    try:
        resp = httpx.get(realm, params=query, auth=auth, timeout=timeout)
        resp.raise_for_status()
        body = resp.json()
    except (httpx.HTTPError, json.JSONDecodeError, ValueError):
        return None
    # Registries return the token under "token" (Docker) or "access_token" (OCI).
    return body.get("token") or body.get("access_token")


def load_remote(
    ref: str,
    *,
    token: str | None = None,
    user: str | None = None,
    password: str | None = None,
    timeout: float = 15.0,
) -> Image:
    rr = parse_reference(ref)
    headers = {"Accept": _MANIFEST_ACCEPT}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    try:
        with httpx.Client(base_url=rr.base_url, timeout=timeout) as client:
            manifest = _get_manifest(
                client, rr, headers, user=user, password=password, timeout=timeout
            )
            config_digest = manifest["config"]["digest"]
            config = json.loads(_get_blob(client, rr, config_digest, headers))

            layers: list[Layer] = []
            for desc in manifest.get("layers", []):
                blob = _get_blob(client, rr, desc["digest"], headers)
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


def _request_with_auth(client, path, headers, *, user, password, timeout):
    """GET ``path``; on a 401 Bearer challenge, negotiate a token and retry once.

    On a successful negotiation the acquired ``Authorization`` header is written
    back into ``headers`` so subsequent blob/manifest fetches reuse the token
    (registries scope tokens per-repository, so one token covers the whole pull).
    """
    resp = client.get(path, headers=headers)
    if resp.status_code == 401 and "Authorization" not in headers:
        challenge = parse_www_authenticate(resp.headers.get("WWW-Authenticate", ""))
        if challenge:
            new_token = _negotiate_token(
                challenge, user=user, password=password, timeout=timeout
            )
            if new_token:
                headers["Authorization"] = f"Bearer {new_token}"
                resp = client.get(path, headers=headers)
    resp.raise_for_status()
    return resp


def _get_manifest(client, rr, headers, *, user, password, timeout) -> dict:
    resp = _request_with_auth(
        client,
        f"/v2/{rr.name}/manifests/{rr.reference}",
        headers,
        user=user,
        password=password,
        timeout=timeout,
    )
    doc = resp.json()
    # If it's an index/manifest-list, resolve the first child manifest.
    if "manifests" in doc and "config" not in doc:
        child = doc["manifests"][0]["digest"]
        resp = _request_with_auth(
            client,
            f"/v2/{rr.name}/manifests/{child}",
            headers,
            user=user,
            password=password,
            timeout=timeout,
        )
        doc = resp.json()
    return doc


def _get_blob(client, rr, digest: str, headers: dict) -> bytes:
    # Blobs reuse the Authorization header already negotiated for the manifest.
    resp = client.get(f"/v2/{rr.name}/blobs/{digest}", headers=headers)
    resp.raise_for_status()
    return resp.content
