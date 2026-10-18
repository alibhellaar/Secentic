from datetime import datetime, timedelta, timezone

import httpx
import pytest

from app.gateway import FAIL_CLOSED_REASON
from app.models import PolicyVersion
from secentic_sdk import ActionNotAllowed, sign_request


def in_days(days: float) -> str:
    return (datetime.now(timezone.utc) + timedelta(days=days)).replace(microsecond=0).isoformat()


@pytest.fixture
def setup(client, admin, make_agent, trust):
    """An approved agent that may use a trusted 'crm' tool, with read access to CRM accounts
    delegated for a week, and a trusted 'mail' tool it may also use (but nothing delegated for it)."""
    sdk, agent = make_agent(name="sales-bot", environment="prod")
    for name, capabilities in (("crm", ["read", "crm:update", "crm:delete"]), ("mail", ["email.send"])):
        client.post("/tools", json={"name": name, "kind": "tool", "provider": "internal", "endpoint": f"https://{name}.example",
                                    "version": "1.0", "capabilities": capabilities, "resources": [f"{name}:*"]},
                    headers=admin).raise_for_status()
        trust(name)
        client.put(f"/agents/{agent['id']}/tools/{name}", headers=admin).raise_for_status()
    delegation = client.post(f"/agents/{agent['id']}/delegations", headers=admin, json={
        "delegator": "ali", "task": "Prepare the sales report", "actions": ["read", "crm:update", "crm:delete"],
        "resources": ["crm:accounts/*"], "expires_at": in_days(7)}).json()
    return sdk, agent, delegation


def set_policy(client, admin, *rules):
    client.put("/policy", json={"rules": list(rules), "comment": "test"}, headers=admin).raise_for_status()


# --- Allow ----------------------------------------------------------------------------------------

def test_allowed_action_is_explained_and_recorded(client, admin, setup):
    sdk, agent, delegation = setup
    decision = sdk.authorize("crm", "read", "crm:accounts/42")
    assert decision["decision"] == "allow"
    assert decision["delegation_id"] == delegation["id"] and decision["policy_version"] == 0
    assert decision["reasons"][0] == "Tool 'crm' (trusted) is assigned to the agent and provides 'read' on 'crm:accounts/42'"
    assert decision["reasons"][1].startswith(f"Allowed by delegation {delegation['id']}")
    assert decision["reasons"][2] == "No rule in policy version 0 applies"

    logged = client.get("/gateway/decisions", params={"agent_id": agent["id"]}, headers=admin).json()
    assert [d["id"] for d in logged] == [decision["id"]]


# --- Deny: each check in the pipeline -----------------------------------------------------------

@pytest.mark.parametrize("tool, action, resource, reason", [
    ("calendar", "read", "crm:accounts/1", "Agent 'sales-bot' is not allowed to use tool 'calendar'"),  # unregistered
    ("crm", "export", "crm:accounts/1", "Tool 'crm' does not provide the action 'export'"),
    ("crm", "read", "hr:salaries/2026", "Tool 'crm' does not work on 'hr:salaries/2026'"),
    ("crm", "read", "crm:invoices/7", "'read' is delegated only on crm:accounts/*, not on 'crm:invoices/7'"),
    ("mail", "email.send", "mail:outbox/attacker@evil.example", "No delegation in force grants the action 'email.send'"),
])
def test_denied_actions_say_why(setup, tool, action, resource, reason):
    sdk, _, _ = setup
    decision = sdk.authorize(tool, action, resource)
    assert decision["decision"] == "deny"
    assert decision["reasons"] == [reason]


def test_tool_not_assigned_to_the_agent(client, admin, setup):
    sdk, agent, _ = setup
    client.delete(f"/agents/{agent['id']}/tools/crm", headers=admin)
    assert sdk.authorize("crm", "read", "crm:accounts/1")["reasons"] == ["Agent 'sales-bot' is not allowed to use tool 'crm'"]


def test_agents_cannot_probe_tools_they_were_not_given(client, admin, setup):
    # An unassigned tool gets the same answer whether it exists, is blocked, or not: nothing about
    # the registry, nor an administrator's block reason, leaks to the agent.
    sdk, _, _ = setup
    client.post("/tools", json={"name": "payments", "kind": "tool", "provider": "p", "endpoint": "https://p.example",
                                "version": "1", "capabilities": ["read"], "resources": ["payments:*"]}, headers=admin)
    client.post("/tools/payments/trust", json={"trust_state": "blocked", "reason": "internal investigation 4711"}, headers=admin)
    blocked = sdk.authorize("payments", "read", "crm:accounts/1")["reasons"]
    missing = sdk.authorize("no-such-tool", "read", "crm:accounts/1")["reasons"]
    assert blocked == ["Agent 'sales-bot' is not allowed to use tool 'payments'"]
    assert missing == ["Agent 'sales-bot' is not allowed to use tool 'no-such-tool'"]


def test_non_canonical_resource_cannot_slip_past_a_policy_rule(client, admin, setup):
    # 'crm:accounts//secret' would match the delegation's 'crm:accounts/*' but not the policy's
    # 'crm:accounts/secret*'; such spellings are refused outright.
    sdk, _, _ = setup
    set_policy(client, admin, {"id": "no-secret", "description": "Secret accounts are off limits", "effect": "deny",
                               "when": {"resources": ["crm:accounts/secret*"]}})
    assert sdk.authorize("crm", "read", "crm:accounts/secret")["decision"] == "deny"
    for spelling in ("crm:accounts//secret", "crm:accounts/secret/", "crm::accounts/secret"):
        response = sdk.request("POST", "/gateway/authorize", {"tool": "crm", "action": "read", "resource": spelling})
        assert response.status_code == 422, spelling


def test_changing_case_cannot_slip_past_a_policy_rule(client, admin, setup):
    sdk, _, _ = setup
    set_policy(client, admin, {"id": "no-secret", "description": "Secret accounts are off limits", "effect": "deny",
                               "when": {"resources": ["crm:accounts/secret*"], "actions": ["READ"]}})
    for spelling in ("crm:accounts/secret", "crm:accounts/Secret", "crm:accounts/SECRET"):
        assert sdk.authorize("crm", "read", spelling)["decision"] == "deny", spelling
    # Grants stay exact: a delegation or tool scope never covers another spelling.
    assert sdk.authorize("crm", "read", "CRM:accounts/1")["reasons"] == ["Tool 'crm' does not work on 'CRM:accounts/1'"]


def test_swapping_separators_cannot_slip_past_a_policy_rule(client, admin, setup):
    # With 'crm:*' delegated, 'crm:accounts:secret' is as reachable as 'crm:accounts/secret'; a rule
    # on 'crm:accounts/secret*' must stop both.
    sdk, agent, _ = setup
    client.post(f"/agents/{agent['id']}/delegations", headers=admin, json={
        "delegator": "ali", "task": "Audit the CRM", "actions": ["read"], "resources": ["crm:*"],
        "expires_at": in_days(1)}).raise_for_status()
    set_policy(client, admin, {"id": "no-secret", "description": "Secret accounts are off limits", "effect": "deny",
                               "when": {"resources": ["crm:accounts/secret*"]}})
    for spelling in ("crm:accounts/secret", "crm:accounts:secret", "crm:accounts:Secret/x"):
        decision = sdk.authorize("crm", "read", spelling)
        assert decision["decision"] == "deny" and decision["matched_rules"] == ["no-secret"], spelling


def test_requests_are_decided_and_recorded_in_the_one_spelling(client, admin, setup):
    sdk, _, delegation = setup
    decision = sdk.authorize("crm", "READ", "crm:accounts:42")
    assert decision["decision"] == "allow" and decision["delegation_id"] == delegation["id"]
    assert (decision["action"], decision["resource"]) == ("read", "crm:accounts/42")
    logged = client.get("/gateway/decisions", headers=admin).json()[0]
    assert (logged["action"], logged["resource"]) == ("read", "crm:accounts/42")


def test_a_tool_cannot_be_used_on_another_systems_resources(client, admin, setup, trust):
    # The agent may read CRM accounts, and has a trusted web search tool that also offers 'read'.
    # Reading the CRM through the web search tool is refused: it does not work on CRM resources.
    sdk, agent, _ = setup
    client.post("/tools", json={"name": "websearch", "kind": "tool", "provider": "search-co", "endpoint": "https://search.example",
                                "version": "1", "capabilities": ["read"], "resources": ["web:*"]}, headers=admin).raise_for_status()
    trust("websearch")
    client.put(f"/agents/{agent['id']}/tools/websearch", headers=admin).raise_for_status()
    decision = sdk.authorize("websearch", "read", "crm:accounts/42")
    assert decision["decision"] == "deny"
    assert decision["reasons"] == ["Tool 'websearch' does not work on 'crm:accounts/42'"]


def test_blocked_tool_is_denied_even_if_assigned(client, admin, setup):
    sdk, _, _ = setup
    client.post("/tools/crm/trust", json={"trust_state": "blocked", "reason": "data exfiltration seen"}, headers=admin)
    decision = sdk.authorize("crm", "read", "crm:accounts/1")
    assert decision["decision"] == "deny"
    assert decision["reasons"] == ["Tool 'crm' is blocked: data exfiltration seen"]


def test_prompt_injected_agent_cannot_send_data_out(setup):
    # The agent has the mail tool, but no person delegated sending email: a manipulated agent's
    # attempt to mail customer records away is denied.
    sdk, _, _ = setup
    with pytest.raises(ActionNotAllowed) as refused:
        sdk.ensure_allowed("mail", "email.send", "mail:outbox/attacker@evil.example")
    assert refused.value.decision["decision"] == "deny"


# --- Require approval ---------------------------------------------------------------------------

@pytest.mark.parametrize("state", ["unknown", "suspicious"])
def test_untrusted_tool_needs_approval(client, admin, setup, state):
    sdk, _, _ = setup
    client.post("/tools/crm/trust", json={"trust_state": state}, headers=admin)
    decision = sdk.authorize("crm", "read", "crm:accounts/1")
    assert decision["decision"] == "require_approval"
    assert f"Tool 'crm' is {state}: a person must approve its use" in decision["reasons"]


def test_rug_pull_turns_allow_into_require_approval(client, admin, setup):
    sdk, _, _ = setup
    assert sdk.authorize("crm", "read", "crm:accounts/1")["decision"] == "allow"
    client.put("/tools/crm", json={"kind": "tool", "provider": "internal", "endpoint": "https://crm.example",
                                    "version": "1.1", "capabilities": ["read", "crm:update", "crm:delete"],
                                    "resources": ["crm:*"]}, headers=admin)
    assert sdk.authorize("crm", "read", "crm:accounts/1")["decision"] == "require_approval"


# --- Policy -------------------------------------------------------------------------------------

def test_policy_rules_apply_immediately_and_are_named(client, admin, setup):
    sdk, _, _ = setup
    set_policy(client, admin,
               {"id": "updates-need-approval", "description": "CRM updates need a person", "effect": "require_approval",
                "when": {"actions": ["crm:update"]}},
               {"id": "no-deletes-in-prod", "description": "Nothing is deleted in production", "effect": "deny",
                "when": {"environments": ["prod"], "actions": ["crm:delete"]}})

    update = sdk.authorize("crm", "crm:update", "crm:accounts/1")
    assert update["decision"] == "require_approval" and update["matched_rules"] == ["updates-need-approval"]
    assert update["policy_version"] == 1
    delete = sdk.authorize("crm", "crm:delete", "crm:accounts/1")
    assert delete["decision"] == "deny"
    assert "Policy rule 'no-deletes-in-prod' (deny): Nothing is deleted in production" in delete["reasons"]
    assert sdk.authorize("crm", "read", "crm:accounts/1")["decision"] == "allow"


def test_policy_cannot_allow_what_was_not_delegated(client, admin, setup):
    # There is no allow effect: a policy can only make decisions stricter.
    sdk, _, _ = setup
    set_policy(client, admin, {"id": "ask", "description": "ask", "effect": "require_approval", "when": {}})
    assert sdk.authorize("crm", "read", "hr:salaries/1")["decision"] == "deny"


def test_most_restrictive_of_trust_and_policy_wins(client, admin, setup):
    sdk, _, _ = setup
    client.post("/tools/crm/trust", json={"trust_state": "unknown"}, headers=admin)
    set_policy(client, admin, {"id": "stop", "description": "stop", "effect": "deny", "when": {"tools": ["crm"]}})
    assert sdk.authorize("crm", "read", "crm:accounts/1")["decision"] == "deny"


# --- Failing closed -----------------------------------------------------------------------------

def test_gateway_fails_closed_when_the_policy_is_corrupt(client, admin, setup, session_factory):
    sdk, agent, _ = setup
    with session_factory() as db:  # simulate a broken engine: a stored rule without an effect
        db.add(PolicyVersion(version=1, rules=[{"id": "broken", "when": {}}], comment="corrupt"))
        db.commit()
    response = sdk.request("POST", "/gateway/authorize", {"tool": "crm", "action": "read", "resource": "crm:accounts/1"})
    assert response.status_code == 503 and response.json()["detail"] == FAIL_CLOSED_REASON
    with pytest.raises(httpx.HTTPStatusError):
        sdk.ensure_allowed("crm", "read", "crm:accounts/1")
    assert client.get("/gateway/decisions", params={"agent_id": agent["id"]}, headers=admin).json() == []


def test_gateway_fails_closed_on_any_internal_error(setup, monkeypatch):
    sdk, _, _ = setup

    def broken(*args, **kwargs):
        raise RuntimeError("database connection lost")

    monkeypatch.setattr("app.routers.gateway.decide", broken)
    response = sdk.request("POST", "/gateway/authorize", {"tool": "crm", "action": "read", "resource": "crm:accounts/1"})
    assert response.status_code == 503


# --- Who may ask --------------------------------------------------------------------------------

def test_database_errors_during_authentication_fail_closed(client, setup, monkeypatch):
    from sqlalchemy.exc import OperationalError
    from app import identity
    from app.request_guards import DATABASE_UNAVAILABLE
    sdk, _, _ = setup

    def unreachable(*args, **kwargs):
        raise OperationalError("INSERT INTO used_nonces", {}, Exception("database is unreachable"))

    monkeypatch.setattr(identity, "_consume_nonce", unreachable)
    response = sdk.request("POST", "/gateway/authorize", {"tool": "crm", "action": "read", "resource": "crm:accounts/1"})
    assert response.status_code == 503 and response.json()["detail"] == DATABASE_UNAVAILABLE
    with pytest.raises(httpx.HTTPStatusError):
        sdk.ensure_allowed("crm", "read", "crm:accounts/1")


def test_an_inactive_agent_is_denied_on_its_status_first(client, admin, setup):
    # Check 1 comes before any tool check, so the reason names the real problem.
    _, agent, _ = setup
    client.post(f"/agents/{agent['id']}/status", json={"status": "disabled"}, headers=admin).raise_for_status()
    body = {"agent_id": agent["id"], "tool": "calendar", "action": "read", "resource": "crm:accounts/1"}
    assert client.post("/gateway/simulate", json=body, headers=admin).json()["reasons"] == ["Agent is disabled"]


def test_the_agent_is_told_what_the_decision_log_says(client, admin, setup, monkeypatch):
    # Nothing is read back after the decision is stored: a failure there must not turn a recorded
    # 'allow' into a 503 (which the agent treats as a denial).
    from sqlalchemy.exc import OperationalError
    from sqlalchemy.orm import Session
    from app.models import GatewayDecision
    real_refresh = Session.refresh

    def refresh(self, instance, *args, **kwargs):
        if isinstance(instance, GatewayDecision):
            raise OperationalError("SELECT", {}, Exception("connection lost after the commit"))
        return real_refresh(self, instance, *args, **kwargs)

    monkeypatch.setattr(Session, "refresh", refresh)
    sdk, _, _ = setup
    response = sdk.request("POST", "/gateway/authorize", {"tool": "crm", "action": "read", "resource": "crm:accounts/1"})
    assert response.status_code == 200
    logged = client.get("/gateway/decisions", headers=admin).json()
    assert [(d["id"], d["decision"]) for d in logged] == [(response.json()["id"], response.json()["decision"])]


def test_only_signed_active_agents_can_ask(client, admin, setup):
    sdk, agent, _ = setup
    body = {"tool": "crm", "action": "read", "resource": "crm:accounts/1"}
    assert client.post("/gateway/authorize", json=body).status_code == 401

    raw = httpx.Request("POST", "http://testserver/gateway/authorize", json=body)
    headers, _ = sign_request(sdk.key, "POST", "/gateway/authorize", body=raw.content)
    first = client.post("/gateway/authorize", content=raw.content, headers={**headers, "Content-Type": "application/json"})
    replay = client.post("/gateway/authorize", content=raw.content, headers={**headers, "Content-Type": "application/json"})
    assert first.status_code == 200 and replay.status_code == 401

    client.post(f"/agents/{agent['id']}/status", json={"status": "disabled"}, headers=admin)
    assert sdk.request("POST", "/gateway/authorize", body).status_code == 403


# --- Administrators: simulation and the decision log --------------------------------------------

def test_simulation_decides_without_recording(client, admin, setup):
    _, agent, _ = setup
    body = {"agent_id": agent["id"], "tool": "crm", "action": "read", "resource": "crm:accounts/1"}
    now = client.post("/gateway/simulate", json=body, headers=admin).json()
    assert now["decision"] == "allow" and now["id"] is None
    later = client.post("/gateway/simulate", json=body | {"at": in_days(8)}, headers=admin).json()
    assert later["decision"] == "deny" and "expired at" in later["reasons"][0]
    assert client.get("/gateway/decisions", headers=admin).json() == []
    assert client.post("/gateway/simulate", json=body | {"agent_id": "00000000-0000-0000-0000-000000000000"},
                       headers=admin).status_code == 404


def test_simulation_at_a_moment_uses_the_policy_then_in_force(client, admin, setup):
    _, agent, _ = setup
    body = {"agent_id": agent["id"], "tool": "crm", "action": "read", "resource": "crm:accounts/1"}
    set_policy(client, admin, {"id": "no-reads", "description": "Reads are paused", "effect": "deny",
                               "when": {"actions": ["read"]}})
    then = client.get("/policy", headers=admin).json()["created_at"]
    set_policy(client, admin)  # version 2: no rules
    past = client.post("/gateway/simulate", json=body | {"at": then}, headers=admin).json()
    assert past["decision"] == "deny" and past["policy_version"] == 1
    now = client.post("/gateway/simulate", json=body, headers=admin).json()
    assert now["decision"] == "allow" and now["policy_version"] == 2


def test_decision_log_filters(client, admin, setup):
    sdk, agent, _ = setup
    sdk.authorize("crm", "read", "crm:accounts/1")
    sdk.authorize("crm", "export", "crm:accounts/1")
    sdk.authorize("crm", "read", "crm:accounts/2")
    log = lambda **params: client.get("/gateway/decisions", params=params, headers=admin).json()  # noqa: E731
    assert len(log()) == 3
    assert [d["decision"] for d in log(decision="deny")] == ["deny"]
    assert len(log(limit=2)) == 2
    assert log()[0]["resource"] == "crm:accounts/2"  # newest first
    assert client.get("/gateway/decisions", params={"agent_id": "not-a-uuid"}, headers=admin).status_code == 422


def test_agents_cannot_read_the_log_or_simulate(setup):
    sdk, agent, _ = setup
    assert sdk.request("GET", "/gateway/decisions").status_code == 401
    assert sdk.request("POST", "/gateway/simulate", {"agent_id": agent["id"], "tool": "crm", "action": "read",
                                                    "resource": "crm:a"}).status_code == 401
