"""SARIF 2.1.0 output format tests (POST_V01 Item 2).

These exercise the SARIF emitter against synthetic Findings so the structural
contract is asserted without depending on real image fixtures:

  - top-level ``$schema`` and ``version`` are exactly the SARIF 2.1.0 values
  - ``runs[0].tool.driver`` identifies casket with name/version/informationUri
  - one ``rule`` per distinct finding type (deduped), one ``result`` per finding
  - severity → result.level mapping (critical/high→error, medium→warning,
    low/info→note)
  - every result references a real rule via ruleId/ruleIndex
"""

from __future__ import annotations

import json

import pytest

from casket import __version__
from casket.findings import Finding, render

_SARIF_SCHEMA = (
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/"
    "sarif-schema-2.1.0.json"
)


def _findings() -> list[Finding]:
    return [
        Finding(
            category="creds",
            title="AWS access key id",
            severity="high",
            layer_sha="sha256:aaa",
            path_in_layer="app/config.env",
            detail={"rule": "aws_access_key"},
        ),
        Finding(
            category="misconfig",
            title="Container runs as root",
            severity="medium",
            layer_sha="sha256:bbb",
            path_in_layer="<image config>",
            detail={"rule": "running_as_root", "user": "(unset → root)"},
        ),
        Finding(
            category="cve",
            title="requests 2.19.0: CVE-2018-18074",
            severity="low",
            layer_sha="sha256:ccc",
            path_in_layer="usr/lib/python3/requests",
            detail={
                "cve_id": "CVE-2018-18074",
                "package": "requests",
                "ecosystem": "PyPI",
                "installed_version": "2.19.0",
                "summary": "auth leak",
            },
        ),
        # second creds finding, SAME rule slug -> must dedupe to one rule.
        Finding(
            category="creds",
            title="AWS access key id",
            severity="critical",
            layer_sha="sha256:ddd",
            path_in_layer="app/other.env",
            detail={"rule": "aws_access_key"},
        ),
    ]


def _doc() -> dict:
    return json.loads(render(_findings(), "sarif", image="example.tar"))


def test_sarif_top_level_schema_and_version():
    doc = _doc()
    assert doc["$schema"] == _SARIF_SCHEMA
    assert doc["version"] == "2.1.0"
    assert isinstance(doc["runs"], list) and len(doc["runs"]) == 1


def test_sarif_tool_driver_identity():
    driver = _doc()["runs"][0]["tool"]["driver"]
    assert driver["name"] == "casket"
    assert driver["version"] == __version__
    assert driver["informationUri"] == "https://github.com/bugsyhewitt/casket"
    assert isinstance(driver["rules"], list)


def test_sarif_rules_are_deduped_by_id():
    driver = _doc()["runs"][0]["tool"]["driver"]
    rule_ids = [r["id"] for r in driver["rules"]]
    # 4 findings but only 3 distinct rule ids (two creds share aws_access_key).
    assert len(rule_ids) == 3
    assert len(set(rule_ids)) == len(rule_ids)
    assert "creds/aws_access_key" in rule_ids
    assert "misconfig/running_as_root" in rule_ids
    assert "cve/CVE-2018-18074" in rule_ids
    for rule in driver["rules"]:
        assert rule["shortDescription"]["text"]


def test_sarif_one_result_per_finding():
    run = _doc()["runs"][0]
    results = run["results"]
    assert len(results) == 4
    for res in results:
        assert res["ruleId"]
        assert res["message"]["text"]
        # ruleIndex must point at the matching rule entry.
        idx = res["ruleIndex"]
        assert run["tool"]["driver"]["rules"][idx]["id"] == res["ruleId"]
        loc = res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        assert loc


@pytest.mark.parametrize(
    ("severity", "expected_level"),
    [
        ("critical", "error"),
        ("high", "error"),
        ("medium", "warning"),
        ("low", "note"),
        ("info", "note"),
    ],
)
def test_sarif_severity_to_level_mapping(severity, expected_level):
    f = Finding(
        category="misconfig",
        title="t",
        severity=severity,
        layer_sha="sha256:x",
        path_in_layer="<image config>",
        detail={"rule": "r"},
    )
    res = json.loads(render([f], "sarif", image="i.tar"))["runs"][0]["results"][0]
    assert res["level"] == expected_level


def test_sarif_empty_findings_is_valid():
    doc = json.loads(render([], "sarif", image="clean.tar"))
    assert doc["$schema"] == _SARIF_SCHEMA
    assert doc["runs"][0]["results"] == []
    assert doc["runs"][0]["tool"]["driver"]["rules"] == []


def test_sarif_result_carries_provenance_properties():
    res = _doc()["runs"][0]["results"][0]
    props = res["properties"]
    assert props["image"] == "example.tar"
    assert props["layer_sha"].startswith("sha256:")
    assert props["category"] in {"creds", "misconfig", "cve"}
