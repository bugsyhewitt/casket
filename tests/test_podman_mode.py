"""Podman mode tests — mocked subprocess (criterion 6).

Podman is an optional system dependency. These tests never require podman to be
installed: we patch shutil.which and subprocess.run so `podman save` "produces"
a known fixture tarball, then assert casket parses it via the same code path as
tarball mode.
"""

from __future__ import annotations

import shutil
import subprocess

import pytest

from casket import podman_mode
from tests.conftest import fixture_path


def test_podman_unavailable_raises(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda _b: None)
    with pytest.raises(podman_mode.PodmanUnavailable):
        podman_mode.load_podman("localhost/app:latest")


def test_podman_mode_loads_image_mocked(monkeypatch):
    fixture = fixture_path("leaky-image.tar")
    monkeypatch.setattr(shutil, "which", lambda _b: "/usr/bin/podman")

    def fake_run(cmd, capture_output=True, text=True):
        # cmd == ["podman", "save", "--format", "oci-archive", "-o", out, ref]
        assert cmd[0] == "podman"
        assert "save" in cmd
        assert "--format" in cmd and "oci-archive" in cmd
        out_path = cmd[cmd.index("-o") + 1]
        # Simulate podman writing the OCI archive by copying a real fixture.
        shutil.copyfile(fixture, out_path)

        class _P:
            returncode = 0
            stdout = ""
            stderr = ""

        return _P()

    monkeypatch.setattr(subprocess, "run", fake_run)
    img = podman_mode.load_podman("localhost/leaky:latest")
    assert img.layers
    # The parsed image is exactly the leaky fixture: it has the planted .env.
    paths = {
        p for layer in img.layers for p, _s, _r in layer.iter_files()
    }
    assert "app/.env" in paths


def test_podman_save_failure_raises(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda _b: "/usr/bin/podman")

    def fake_run(cmd, capture_output=True, text=True):
        class _P:
            returncode = 125
            stdout = ""
            stderr = "Error: no such image"

        return _P()

    monkeypatch.setattr(subprocess, "run", fake_run)
    with pytest.raises(podman_mode.PodmanUnavailable) as exc:
        podman_mode.load_podman("localhost/missing:latest")
    assert "no such image" in str(exc.value)
