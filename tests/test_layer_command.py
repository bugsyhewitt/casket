"""Tests for layer→command attribution (POST_V01 Item 7).

Each finding should, where the image config carries the relevant ``history``
entry, be annotated with ``detail["layer_command"]`` — the Dockerfile
instruction that introduced the layer the finding lives in. This turns an opaque
layer digest into an actionable build step (e.g. ``COPY .env /app/.env``).
"""

from __future__ import annotations

import json

from casket.findings import render
from casket.oci import load_tarball
from casket.scanner import run_checks
from tests.conftest import fixture_path


def _load_history_image():
    return load_tarball(fixture_path("history-image.tar"))


def test_layer_command_map_skips_empty_layer_entries():
    img = _load_history_image()
    cmd_map = img.layer_command_map()
    # Two filesystem layers -> two entries; the ENV empty_layer step is skipped.
    assert len(cmd_map) == 2
    digests = [layer.digest for layer in img.layers]
    assert cmd_map[digests[0]] == "COPY .env /app/first.env"
    assert cmd_map[digests[1]] == "RUN echo key > /app/second.env"


def test_layer_command_map_empty_when_no_history():
    img = _load_history_image()
    img.config["history"] = []
    assert img.layer_command_map() == {}


def test_layer_command_map_never_raises_on_short_history():
    img = _load_history_image()
    # Fewer history entries than layers: zip truncates, no error.
    img.config["history"] = [{"created_by": "ONLY ONE"}]
    cmd_map = img.layer_command_map()
    assert len(cmd_map) == 1
    assert cmd_map[img.layers[0].digest] == "ONLY ONE"


def test_findings_annotated_with_layer_command():
    img = _load_history_image()
    findings = run_checks(img, ["creds"])
    assert len(findings) >= 2
    commands = {f.detail.get("layer_command") for f in findings}
    assert "COPY .env /app/first.env" in commands
    assert "RUN echo key > /app/second.env" in commands


def test_findings_attribute_command_to_correct_layer():
    img = _load_history_image()
    findings = run_checks(img, ["creds"])
    by_path = {f.path_in_layer: f.detail.get("layer_command") for f in findings}
    assert by_path["app/first.env"] == "COPY .env /app/first.env"
    assert by_path["app/second.env"] == "RUN echo key > /app/second.env"


def test_misconfig_config_findings_have_no_layer_command():
    # Misconfig findings use the synthetic config descriptor digest as their
    # layer_sha, which is never in the layer-command map, so they stay
    # unannotated rather than mis-attributing to a real layer.
    img = load_tarball(fixture_path("rootuser-image.tar"))
    findings = run_checks(img, ["misconfig"])
    assert findings, "expected at least one misconfig finding"
    for f in findings:
        assert "layer_command" not in f.detail


def test_layer_command_surfaces_in_json_output():
    img = _load_history_image()
    findings = run_checks(img, ["creds"])
    doc = json.loads(render(findings, "json", image="history-image.tar"))
    commands = {f.get("layer_command") for f in doc["findings"]}
    assert "COPY .env /app/first.env" in commands
    assert "RUN echo key > /app/second.env" in commands


def test_layer_command_surfaces_in_h1md_output():
    img = _load_history_image()
    findings = run_checks(img, ["creds"])
    md = render(findings, "h1md", image="history-image.tar")
    assert "**layer_command:**" in md
    assert "COPY .env /app/first.env" in md


def test_layer_command_surfaces_in_sarif_properties():
    img = _load_history_image()
    findings = run_checks(img, ["creds"])
    doc = json.loads(render(findings, "sarif", image="history-image.tar"))
    results = doc["runs"][0]["results"]
    commands = {r["properties"].get("layer_command") for r in results}
    assert "COPY .env /app/first.env" in commands
    assert "RUN echo key > /app/second.env" in commands
