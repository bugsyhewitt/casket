"""Remote mode tests against a local fixture registry server (criterion 7).

We stand up a tiny OCI-distribution-API-speaking HTTP server on an EPHEMERAL
port (socket.bind(('', 0)) — NEVER port 8888, reserved for Alfred's voice
service) that serves a manifest + config + layer blob assembled from real data.
casket then pulls it over HTTP and scans it.
"""

from __future__ import annotations

import hashlib
import io
import json
import socket
import tarfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from casket import remote_mode
from casket.remote_mode import load_remote, parse_reference


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
