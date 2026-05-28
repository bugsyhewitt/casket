"""Remote mode tests against a local fixture registry server (criterion 7).

We stand up a tiny OCI-distribution-API-speaking HTTP server on an EPHEMERAL
port (socket.bind(('', 0)) — NEVER port 8888, reserved for Alfred's voice
service) that serves a manifest + config + layer blob assembled from real data.
casket then pulls it over HTTP and scans it.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import socket
import tarfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from casket import remote_mode
from casket.remote_mode import (
    load_remote,
    parse_reference,
    parse_www_authenticate,
)


def _digest(blob: bytes) -> str:
    return "sha256:" + hashlib.sha256(blob).hexdigest()


def _build_registry_blobs():
    """Build a manifest + config + one layer (with a planted secret)."""
    # Layer tar containing a leaked token.
    layer_buf = io.BytesIO()
    with tarfile.open(fileobj=layer_buf, mode="w") as tf:
        content = b"API_TOKEN=remotesecrettoken1234567890abcdef\n"
        info = tarfile.TarInfo("app/config.env")
        info.size = len(content)
        tf.addfile(info, io.BytesIO(content))
    layer_bytes = layer_buf.getvalue()
    layer_digest = _digest(layer_bytes)

    config_obj = {
        "architecture": "amd64",
        "os": "linux",
        "config": {"User": "root"},
        "rootfs": {"type": "layers", "diff_ids": [layer_digest]},
    }
    config_bytes = json.dumps(config_obj).encode()
    config_digest = _digest(config_bytes)

    manifest_obj = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "digest": config_digest,
            "size": len(config_bytes),
        },
        "layers": [
            {
                "mediaType": "application/vnd.oci.image.layer.v1.tar",
                "digest": layer_digest,
                "size": len(layer_bytes),
            }
        ],
    }
    manifest_bytes = json.dumps(manifest_obj).encode()

    blobs = {config_digest: config_bytes, layer_digest: layer_bytes}
    return manifest_bytes, blobs


@pytest.fixture
def fixture_registry():
    manifest_bytes, blobs = _build_registry_blobs()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):  # silence test output
            pass

        def do_GET(self):
            if "/manifests/" in self.path:
                self._send(200, manifest_bytes,
                           "application/vnd.oci.image.manifest.v1+json")
                return
            if "/blobs/" in self.path:
                digest = self.path.split("/blobs/", 1)[1]
                blob = blobs.get(digest)
                if blob is None:
                    self._send(404, b"not found", "text/plain")
                    return
                self._send(200, blob, "application/octet-stream")
                return
            self._send(404, b"not found", "text/plain")

        def _send(self, code, body, ctype):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    # Ephemeral port — bind to 0 and let the OS pick. Never 8888.
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()

    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.shutdown()
        server.server_close()


def test_parse_reference_variants():
    rr = parse_reference("http://127.0.0.1:5000/library/alpine:3.10")
    assert rr.base_url == "http://127.0.0.1:5000"
    assert rr.name == "library/alpine"
    assert rr.reference == "3.10"

    rr2 = parse_reference("registry.example.com/team/app")
    assert rr2.base_url == "https://registry.example.com"
    assert rr2.name == "team/app"
    assert rr2.reference == "latest"


def test_load_remote_from_fixture_server(fixture_registry):
    ref = f"{fixture_registry}/library/leaky:1.0"
    img = load_remote(ref)
    assert img.layers
    paths = {p for layer in img.layers for p, _s, _r in layer.iter_files()}
    assert "app/config.env" in paths
    assert img.config.get("config", {}).get("User") == "root"


def test_remote_pull_error_on_bad_host():
    with pytest.raises(remote_mode.RemotePullError):
        load_remote("http://127.0.0.1:1/no/such:thing", timeout=1.0)


# --- Bearer token negotiation (POST_V01 item 5) -----------------------------


def test_parse_www_authenticate_quoted():
    hdr = (
        'Bearer realm="https://auth.docker.io/token",'
        'service="registry.docker.io",'
        'scope="repository:library/alpine:pull"'
    )
    params = parse_www_authenticate(hdr)
    assert params["realm"] == "https://auth.docker.io/token"
    assert params["service"] == "registry.docker.io"
    assert params["scope"] == "repository:library/alpine:pull"


def test_parse_www_authenticate_unquoted_and_scope_with_comma():
    hdr = 'Bearer realm=https://r/token,scope="repository:a:pull,push"'
    params = parse_www_authenticate(hdr)
    assert params["realm"] == "https://r/token"
    # comma inside the quoted scope must NOT split the value
    assert params["scope"] == "repository:a:pull,push"


def test_parse_www_authenticate_non_bearer_returns_empty():
    assert parse_www_authenticate('Basic realm="x"') == {}
    assert parse_www_authenticate("") == {}


@pytest.fixture
def auth_fixture_registry():
    """A registry that 401s without a bearer token and issues one at /token.

    Mimics the Docker Hub / GHCR challenge-response flow. The token endpoint
    requires HTTP Basic credentials (user=alice, password=s3cret) and records
    whether they were presented, so the test can assert credentials flowed.
    """
    manifest_bytes, blobs = _build_registry_blobs()
    state: dict = {"issued_token": "negotiated-token-xyz", "basic_seen": None}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            # Token endpoint: validate Basic auth, return a bearer token.
            if self.path.startswith("/token"):
                authz = self.headers.get("Authorization", "")
                if authz.startswith("Basic "):
                    decoded = base64.b64decode(authz.split(" ", 1)[1]).decode()
                    state["basic_seen"] = decoded
                body = json.dumps({"token": state["issued_token"]}).encode()
                self._send(200, body, "application/json")
                return

            # Protected endpoints: require the negotiated bearer token.
            expected = f"Bearer {state['issued_token']}"
            if self.headers.get("Authorization") != expected:
                self.send_response(401)
                realm = f"http://127.0.0.1:{self.server.server_address[1]}/token"
                self.send_header(
                    "WWW-Authenticate",
                    f'Bearer realm="{realm}",service="fixture",'
                    f'scope="repository:library/leaky:pull"',
                )
                self.send_header("Content-Length", "0")
                self.end_headers()
                return

            if "/manifests/" in self.path:
                self._send(200, manifest_bytes,
                           "application/vnd.oci.image.manifest.v1+json")
                return
            if "/blobs/" in self.path:
                digest = self.path.split("/blobs/", 1)[1]
                blob = blobs.get(digest)
                if blob is None:
                    self._send(404, b"not found", "text/plain")
                    return
                self._send(200, blob, "application/octet-stream")
                return
            self._send(404, b"not found", "text/plain")

        def _send(self, code, body, ctype):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()

    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{port}", state
    finally:
        server.shutdown()
        server.server_close()


def test_load_remote_negotiates_bearer_token(auth_fixture_registry):
    base, state = auth_fixture_registry
    ref = f"{base}/library/leaky:1.0"
    img = load_remote(ref, user="alice", password="s3cret")
    # Pull succeeded only because the 401 challenge was answered.
    paths = {p for layer in img.layers for p, _s, _r in layer.iter_files()}
    assert "app/config.env" in paths
    # Credentials were presented to the token endpoint as Basic auth.
    assert state["basic_seen"] == "alice:s3cret"


def test_load_remote_negotiation_without_creds_still_works(auth_fixture_registry):
    # Anonymous pulls (no creds) still negotiate a token from the realm.
    base, state = auth_fixture_registry
    ref = f"{base}/library/leaky:1.0"
    img = load_remote(ref)
    assert img.layers
    assert state["basic_seen"] is None


def test_load_remote_fails_when_token_unobtainable(auth_fixture_registry):
    # If the realm hands back no token, the retry still 401s -> RemotePullError.
    base, state = auth_fixture_registry
    state["issued_token"] = "unused"  # server expects this, but realm returns ""

    # Monkeypatch the negotiation to simulate a token-less realm response.
    orig = remote_mode._negotiate_token
    try:
        remote_mode._negotiate_token = lambda *a, **k: None
        with pytest.raises(remote_mode.RemotePullError):
            load_remote(f"{base}/library/leaky:1.0", timeout=3.0)
    finally:
        remote_mode._negotiate_token = orig
