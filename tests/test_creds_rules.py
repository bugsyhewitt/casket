"""Expanded credential ruleset tests (POST_V01 Item 6 + Rotation 37 extension).

Verifies the 15 high-precision provider token patterns added to creds.yaml
(Item 6) and the 5 cloud/AI provider patterns added in Rotation 37 each fire
against a fabricated example, that the ruleset stays well-formed, and that
clean images produce none of these findings (no false positives).
"""

from __future__ import annotations

import pytest

from casket.checks import creds
from casket.oci import load_tarball
from casket.rules import load_ruleset
from tests.conftest import fixture_path

# Rule ids added in POST_V01 Item 6.
EXPANDED_RULE_IDS = {
    "github_pat",
    "github_oauth",
    "github_actions_token",
    "slack_token",
    "stripe_secret_key",
    "stripe_restricted_key",
    "gcp_service_account_key",
    "sendgrid_api_key",
    "npm_token",
    "docker_hub_pat",
    "jwt_token",
    "heroku_api_key",
    "mailchimp_api_key",
    "twilio_account_sid",
    "twilio_api_key_sid",
}

# Rule ids added in Rotation 37 (cloud / AI provider patterns).
R37_RULE_IDS = {
    "azure_storage_key",
    "openai_api_key",
    "anthropic_api_key",
    "databricks_token",
    "hashicorp_vault_token",
}

ALL_NEW_RULE_IDS = EXPANDED_RULE_IDS | R37_RULE_IDS


def _fired_rules(fixture: str) -> set[str]:
    img = load_tarball(fixture_path(fixture))
    findings = creds.run(img)
    return {f.detail["rule"] for f in findings}


def test_ruleset_contains_all_expanded_rules():
    """creds.yaml must define every expanded rule id with required fields."""
    rules = load_ruleset("creds")
    by_id = {r["id"]: r for r in rules}
    for rid in ALL_NEW_RULE_IDS:
        assert rid in by_id, f"rule {rid} missing from creds.yaml"
        rule = by_id[rid]
        assert rule.get("title"), f"rule {rid} has no title"
        assert rule.get("severity") in {"critical", "high", "medium", "low", "info"}
        # All expanded rules are regex rules (no entropy kind).
        assert rule.get("kind") != "entropy"
        assert rule.get("regex"), f"rule {rid} has no regex"


@pytest.mark.parametrize("rule_id", sorted(ALL_NEW_RULE_IDS))
def test_each_expanded_rule_fires_on_multi_secrets_image(rule_id):
    """Each new pattern fires against its fabricated example in the fixture."""
    fired = _fired_rules("multi-secrets-image.tar")
    assert rule_id in fired, f"expected {rule_id} to fire; fired: {sorted(fired)}"


def test_all_expanded_rules_fire_together():
    """The fixture is constructed so every expanded rule fires in one scan."""
    fired = _fired_rules("multi-secrets-image.tar")
    missing = ALL_NEW_RULE_IDS - fired
    assert not missing, f"these expanded rules did not fire: {sorted(missing)}"


def test_expanded_rules_do_not_fire_on_clean_image():
    """A clean image must not trigger any of the expanded provider patterns."""
    fired = _fired_rules("alpine-clean-image.tar")
    assert not (ALL_NEW_RULE_IDS & fired), (
        f"expanded rules false-positived on a clean image: "
        f"{sorted(ALL_NEW_RULE_IDS & fired)}"
    )


def test_existing_regex_rules_still_fire():
    """Adding the expanded ruleset must not break the original creds rules."""
    fired = _fired_rules("leaky-image.tar")
    assert "aws_secret_access_key" in fired
    assert "aws_access_key_id" in fired


def test_severity_mapping_for_critical_provider_keys():
    """Stripe secret + GCP service-account keys are classified critical."""
    img = load_tarball(fixture_path("multi-secrets-image.tar"))
    findings = creds.run(img)
    by_rule = {f.detail["rule"]: f for f in findings}
    assert by_rule["stripe_secret_key"].severity == "critical"
    assert by_rule["gcp_service_account_key"].severity == "critical"
    # Twilio identifiers are lower-confidence -> medium.
    assert by_rule["twilio_account_sid"].severity == "medium"


# ---------------------------------------------------------------------------
# Rotation 37 — cloud / AI provider pattern tests
# ---------------------------------------------------------------------------


def test_r37_ruleset_contains_all_cloud_ai_rules():
    """creds.yaml must define every Rotation-37 rule id with required fields."""
    rules = load_ruleset("creds")
    by_id = {r["id"]: r for r in rules}
    for rid in R37_RULE_IDS:
        assert rid in by_id, f"R37 rule {rid} missing from creds.yaml"
        rule = by_id[rid]
        assert rule.get("title"), f"R37 rule {rid} has no title"
        assert rule.get("severity") in {"critical", "high", "medium", "low", "info"}
        assert rule.get("kind") != "entropy"
        assert rule.get("regex"), f"R37 rule {rid} has no regex"


def test_r37_severity_mapping():
    """Azure storage key, OpenAI, Anthropic, and Vault tokens are critical;
    Databricks PAT is high."""
    img = load_tarball(fixture_path("multi-secrets-image.tar"))
    findings = creds.run(img)
    by_rule = {f.detail["rule"]: f for f in findings}
    assert by_rule["azure_storage_key"].severity == "critical"
    assert by_rule["openai_api_key"].severity == "critical"
    assert by_rule["anthropic_api_key"].severity == "critical"
    assert by_rule["hashicorp_vault_token"].severity == "critical"
    assert by_rule["databricks_token"].severity == "high"


def test_r37_rules_do_not_fire_on_clean_image():
    """R37 cloud/AI patterns must not fire on an image with no secrets."""
    fired = _fired_rules("alpine-clean-image.tar")
    assert not (R37_RULE_IDS & fired), (
        f"R37 rules false-positived on a clean image: "
        f"{sorted(R37_RULE_IDS & fired)}"
    )
