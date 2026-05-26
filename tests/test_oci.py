"""OCI image-layout parsing tests."""

from __future__ import annotations

import pytest

from casket.oci import OCIParseError, load_tarball
from tests.conftest import fixture_path


def test_load_oci_layout_tarball():
    img = load_tarball(fixture_path("leaky-image.tar"))
    assert img.layers, "expected at least one layer"
    assert all(layer.digest.startswith("sha256:") for layer in img.layers)
    assert img.config_descriptor_digest.startswith("sha256:")


def test_layer_iter_files_yields_planted_secret_file():
    img = load_tarball(fixture_path("leaky-image.tar"))
    paths = {
        path
        for layer in img.layers
        for path, _size, _reader in layer.iter_files()
    }
    assert "app/.env" in paths
    assert "app/main.py" in paths


def test_layer_reader_returns_file_bytes():
    img = load_tarball(fixture_path("leaky-image.tar"))
    contents = {}
    for layer in img.layers:
        for path, _size, reader in layer.iter_files():
            contents[path] = reader()
    assert b"AWS_SECRET_ACCESS_KEY" in contents["app/.env"]


def test_missing_file_raises():
    with pytest.raises(FileNotFoundError):
        load_tarball("/nonexistent/path/to/image.tar")


def test_non_oci_tar_raises(tmp_path):
    import tarfile

    bogus = tmp_path / "bogus.tar"
    with tarfile.open(bogus, "w") as tf:
        info = tarfile.TarInfo("hello.txt")
        data = b"not an image"
        info.size = len(data)
        import io

        tf.addfile(info, io.BytesIO(data))
    with pytest.raises(OCIParseError):
        load_tarball(str(bogus))
