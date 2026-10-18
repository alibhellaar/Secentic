import pytest

from app.models import Decision
from app.policy import PolicyContext, evaluate_policy

APPROVE_PAYMENTS = {"id": "payments-need-approval", "description": "Payments need a person's approval",
                    "effect": "require_approval", "when": {"actions": ["payments:*"]}}
NO_PROD_DELETES = {"id": "no-deletes-in-prod", "description": "Nothing is deleted in production",
                   "effect": "deny", "when": {"environments": ["prod"], "actions": ["crm:delete"]}}


def put_policy(client, admin, rules, comment="test"):
    return client.put("/policy", json={"rules": rules, "comment": comment}, headers=admin)


# --- Versioning ---------------------------------------------------------------------------------

def test_no_policy_is_version_zero(client, admin):
    policy = client.get("/policy", headers=admin).json()
    assert policy["version"] == 0 and policy["rules"] == [] and policy["created_at"] is None


def test_every_change_is_a_new_version(client, admin):
    first = put_policy(client, admin, [APPROVE_PAYMENTS], "payments need approval")
    assert first.status_code == 201 and first.json()["version"] == 1
    second = put_policy(client, admin, [APPROVE_PAYMENTS, NO_PROD_DELETES], "no deletes in prod")
    assert second.json()["version"] == 2
    assert client.get("/policy", headers=admin).json()["version"] == 2

    versions = client.get("/policy/versions", headers=admin).json()
    assert [(v["version"], v["rule_count"]) for v in versions] == [(2, 2), (1, 1)]
    assert client.get("/policy/versions/1", headers=admin).json()["rules"] == [APPROVE_PAYMENTS]


def test_restoring_an_old_version_creates_a_new_one(client, admin):
    put_policy(client, admin, [APPROVE_PAYMENTS])
    put_policy(client, admin, [])
    restored = client.post("/policy/versions/1/restore", headers=admin)
    assert restored.status_code == 201
    assert restored.json()["version"] == 3
    assert restored.json()["rules"] == [APPROVE_PAYMENTS]
    assert restored.json()["comment"] == "Restored version 1"


def test_unknown_or_invalid_versions(client, admin):
    assert client.get("/policy/versions/7", headers=admin).status_code == 404
    assert client.post("/policy/versions/7/restore", headers=admin).status_code == 404
    assert client.get("/policy/versions/0", headers=admin).status_code == 422
    assert client.get("/policy/versions/99999999999", headers=admin).status_code == 422


# --- Validation ---------------------------------------------------------------------------------

@pytest.mark.parametrize("rule", [
    APPROVE_PAYMENTS | {"effect": "allow"},                              # policies can only restrict
    APPROVE_PAYMENTS | {"when": {"action": ["payments:*"]}},             # misspelt condition
    APPROVE_PAYMENTS | {"when": {"actions": []}},                        # empty condition
    APPROVE_PAYMENTS | {"id": "Payments Rule"},                          # malformed id
    APPROVE_PAYMENTS | {"description": ""},                              # no explanation
    APPROVE_PAYMENTS | {"when": {"actions": ["pay*ments"]}},             # wildcard in the middle
    APPROVE_PAYMENTS | {"when": {"resources": ["crm:../admin"]}},        # traversal
    APPROVE_PAYMENTS | {"when": {"tool_trust": ["somewhat"]}},           # unknown trust state
    APPROVE_PAYMENTS | {"extra": True},                                  # unknown field
])
def test_malformed_rules_refused(client, admin, rule):
    assert put_policy(client, admin, [rule]).status_code == 422


def test_rule_ids_must_be_unique(client, admin):
    assert put_policy(client, admin, [APPROVE_PAYMENTS, APPROVE_PAYMENTS]).status_code == 422


def test_rule_count_is_limited(client, admin):
    rules = [APPROVE_PAYMENTS | {"id": f"r{i}"} for i in range(201)]
    assert put_policy(client, admin, rules).status_code == 422


def test_agents_cannot_change_policy(make_agent):
    sdk, _ = make_agent()
    assert sdk.request("PUT", "/policy", {"rules": [], "comment": "let me in"}).status_code == 401


# --- Evaluation (the engine itself) -------------------------------------------------------------

def context(**overrides):
    values = {"agent": "billing-bot", "environment": "prod", "tool": "crm", "tool_trust": "trusted",
              "action": "read", "resource": "crm:accounts/42"} | overrides
    return PolicyContext(**values)


def rule(rule_id, effect, **when):
    return {"id": rule_id, "description": f"{rule_id} explained", "effect": effect, "when": when}


def test_no_matching_rule_allows_with_an_explanation():
    result = evaluate_policy([rule("r", "deny", actions=["delete"])], 4, context())
    assert result.effect == Decision.allow
    assert result.reasons == ["No rule in policy version 4 applies"]


@pytest.mark.parametrize("when, matches", [
    ({"agents": ["BILLING-BOT"]}, True), ({"agents": ["other"]}, False), ({"agents": ["ｂｉｌｌｉｎｇ-bot"]}, True),
    ({"environments": ["PROD"]}, True), ({"environments": ["dev"]}, False),
    ({"tools": ["crm"]}, True), ({"tools": ["mail"]}, False),
    ({"tool_trust": ["trusted", "unknown"]}, True), ({"tool_trust": ["unknown"]}, False),
    ({"actions": ["*"]}, True), ({"actions": ["re*"]}, True), ({"actions": ["write"]}, False),
    ({"resources": ["crm:*"]}, True), ({"resources": ["crm:accounts/42"]}, True), ({"resources": ["hr:*"]}, False),
    ({"resources": ["CRM:Accounts/4*"]}, True),  # rules compare resources ignoring case
    ({"environments": ["prod"], "actions": ["write"]}, False),  # every stated condition must match
    ({}, True),                                                  # no conditions: applies to everything
])
def test_each_condition(when, matches):
    result = evaluate_policy([rule("r", "deny", **when)], 1, context())
    assert (result.effect == Decision.deny) == matches


def test_deny_wins_over_require_approval_and_every_match_is_explained():
    rules = [rule("ask", "require_approval", actions=["read"]), rule("stop", "deny", environments=["prod"]),
             rule("unrelated", "deny", tools=["mail"])]
    result = evaluate_policy(rules, 9, context())
    assert result.effect == Decision.deny
    assert [r["id"] for r in result.matched] == ["ask", "stop"]
    assert result.reasons == ["Policy rule 'ask' (require_approval): ask explained",
                              "Policy rule 'stop' (deny): stop explained"]


def test_require_approval_when_only_approval_rules_match():
    result = evaluate_policy([rule("ask", "require_approval", resources=["crm:*"])], 1, context())
    assert result.effect == Decision.require_approval


def test_rules_compare_names_exactly_as_the_inventory_does():
    # Rows from older versions may carry surrounding spaces; the inventory ignores them, so must rules.
    legacy = context(agent="billing-bot ", environment=" Production EU")
    rule_ = rule("r", "deny", agents=["Billing-Bot"], environments=["production eu"])
    assert evaluate_policy([rule_], 1, legacy).effect == Decision.deny


def test_rules_may_name_any_environment(client, admin):
    # Environments stored by older versions are free text; a rule (which only restricts) can name them.
    assert put_policy(client, admin, [rule("legacy-env", "deny", environments=["Production EU"])]).status_code == 201


def test_rules_are_saved_in_the_one_spelling(client, admin):
    saved = put_policy(client, admin, [rule("r", "deny", actions=["CRM:Update"], resources=["crm/accounts:Secret*"])]).json()
    assert saved["rules"][0]["when"] == {"actions": ["crm:update"], "resources": ["crm:accounts/Secret*"]}


def test_a_full_policy_of_realistic_rules_can_be_saved(client, admin):
    # 200 rules (the maximum) with 300-character descriptions: about 84 KB, over the 64 KiB that
    # every other request is limited to. PUT /policy accepts up to 1 MiB.
    rules = [{"id": f"rule-{i:03d}", "description": "d" * 300, "effect": "deny",
              "when": {"actions": ["crm:update"], "environments": ["prod"]}} for i in range(200)]
    response = put_policy(client, admin, rules)
    assert response.status_code == 201 and len(response.json()["rules"]) == 200
    assert client.get("/policy/versions", headers=admin).json()[0]["rule_count"] == 200


def test_policy_bodies_over_1_mib_are_refused(client, admin):
    body = b'{"comment": "c", "rules": []' + b" " * (1024 * 1024) + b"}"
    response = client.put("/policy", content=body, headers=admin | {"Content-Type": "application/json"})
    assert response.status_code == 413 and response.json()["detail"] == "Request body too large (limit 1048576 bytes)"


def test_other_endpoints_keep_the_64_kib_limit(client, admin):
    body = b'{"name": "bot"' + b" " * (70 * 1024) + b"}"
    assert client.post("/agents/register", content=body, headers={"Content-Type": "application/json"}).status_code == 413


def test_an_empty_policy_counts_zero_rules(client, admin):
    put_policy(client, admin, [])
    assert client.get("/policy/versions", headers=admin).json()[0]["rule_count"] == 0
