from datetime import datetime, timedelta, timezone

import pytest

from app import delegation
from app.delegation import check_authority
from app.models import Agent, AgentStatus, DelegationState, RegistrationSource


def hours_from_now(hours: float) -> str:
    return (datetime.now(timezone.utc) + timedelta(hours=hours)).isoformat()


@pytest.fixture
def delegate(client, admin):
    """POST a delegation for an agent; the defaults can be overridden per test."""
    def _delegate(agent_id, **overrides):
        body = {
            "delegator": "ali",
            "task": "Prepare the monthly sales report",
            "actions": ["read"],
            "resources": ["crm:accounts/*"],
            "expires_at": hours_from_now(24),
        } | overrides
        return client.post(f"/agents/{agent_id}/delegations", json=body, headers=admin)
    return _delegate


@pytest.fixture
def check(client, admin):
    def _check(agent_id, action, resource, at=None):
        body = {"action": action, "resource": resource} | ({"at": at} if at else {})
        response = client.post(f"/agents/{agent_id}/check-authority", json=body, headers=admin)
        assert response.status_code == 200, response.text
        return response.json()
    return _check


# --- What a delegation grants ---------------------------------------------------------------

def test_delegation_grants_exactly_what_it_lists(make_agent, delegate, check):
    _, agent = make_agent()
    created = delegate(agent["id"], actions=["read"], resources=["crm:accounts/*", "crm:reports/q3"])
    assert created.status_code == 201
    assert created.json()["state"] == "active"

    allowed = check(agent["id"], "read", "crm:accounts/42")
    assert allowed["allowed"] and allowed["delegation_id"] == created.json()["id"]
    assert "delegated by ali" in allowed["reason"]
    assert check(agent["id"], "read", "crm:reports/q3")["allowed"]

    other_resource = check(agent["id"], "read", "crm:reports/q4")
    assert not other_resource["allowed"]
    assert other_resource["reason"] == "'read' is delegated only on crm:accounts/*, crm:reports/q3, not on 'crm:reports/q4'"

    other_action = check(agent["id"], "write", "crm:accounts/42")
    assert not other_action["allowed"]
    assert other_action["reason"] == "No delegation in force grants the action 'write'"


def test_agent_without_delegations_has_no_authority(make_agent, check):
    _, agent = make_agent()
    result = check(agent["id"], "read", "crm:accounts/42")
    assert not result["allowed"]
    assert result["reason"] == "The agent has no delegated authority in force"


def test_prefix_pattern_does_not_reach_sibling_resources(make_agent, delegate, check):
    _, agent = make_agent()
    delegate(agent["id"], resources=["crm:accounts/*"])
    assert not check(agent["id"], "read", "crm:accounts-archive/1")["allowed"]
    assert not check(agent["id"], "read", "crm:accounts")["allowed"]


def test_oldest_covering_delegation_decides(make_agent, delegate, check):
    _, agent = make_agent()
    first = delegate(agent["id"]).json()
    delegate(agent["id"], task="Another task")
    assert check(agent["id"], "read", "crm:accounts/1")["delegation_id"] == first["id"]


def test_duplicate_entries_are_dropped(make_agent, delegate):
    _, agent = make_agent()
    created = delegate(agent["id"], actions=["read", "read"], resources=["crm:a", "crm:a"]).json()
    assert created["actions"] == ["read"] and created["resources"] == ["crm:a"]


# --- Least privilege: what cannot be delegated ------------------------------------------------

@pytest.mark.parametrize("resources", [["*"], ["/*"], [":*"], ["crm:acc*"], ["crm:*/notes"], ["crm:accounts/../*"],
                                       ["crm:accounts/%2e%2e/admin"], ["crm accounts"], ["crm:../admin"], ["crm:.."],
                                       ["crm:accounts//x"], ["crm::x"], ["crm:accounts/"], ["/crm/x"], ["crm:accounts//*"], []])
def test_blanket_or_malformed_resource_grants_refused(make_agent, delegate, resources):
    _, agent = make_agent()
    assert delegate(agent["id"], resources=resources).status_code == 422


@pytest.mark.parametrize("actions", [["*"], ["read*"], ["send email"], []])
def test_wildcard_or_malformed_actions_refused(make_agent, delegate, actions):
    _, agent = make_agent()
    assert delegate(agent["id"], actions=actions).status_code == 422


def test_path_traversal_cannot_escape_a_grant(client, admin, make_agent, delegate):
    _, agent = make_agent()
    delegate(agent["id"], resources=["crm:accounts/*", "crm:*"])
    for resource in ("crm:accounts/../admin", "crm:../admin", "crm:accounts//secret"):
        body = {"action": "read", "resource": resource}
        assert client.post(f"/agents/{agent['id']}/check-authority", json=body, headers=admin).status_code == 422


def test_check_authority_fails_closed_on_invalid_input(session_factory):
    # The gateway calls check_authority directly, without the API's input validation.
    with session_factory() as db:
        agent = Agent(name="bot", environment="test", fingerprint="f", status=AgentStatus.active,
                      registration_source=RegistrationSource.manual)
        db.add(agent)
        db.commit()
        for resource in ("crm:accounts/../admin", "crm:../admin"):
            result = check_authority(db, agent, "read", resource)
            assert not result.allowed and result.reason.startswith("Invalid request")

        before_year_one_in_utc = datetime(1, 1, 1, tzinfo=timezone(timedelta(hours=14)))
        result = check_authority(db, agent, "read", "crm:accounts/1", at=before_year_one_in_utc)
        assert not result.allowed and result.reason == "Invalid request: time out of range"


# --- Time window ------------------------------------------------------------------------------

@pytest.mark.parametrize("window", [
    {"expires_at": hours_from_now(-1)},                                       # already over
    {"starts_at": hours_from_now(5), "expires_at": hours_from_now(2)},        # ends before it starts
    {"expires_at": hours_from_now(31 * 24)},                                  # longer than 30 days
    {"expires_at": (datetime.now() + timedelta(hours=1)).isoformat()},       # no timezone
    {"starts_at": "0001-01-01T00:00:00+14:00"},                               # before the earliest UTC time
    {"expires_at": "9999-12-31T23:59:59-05:00"},                              # after the latest UTC time
])
def test_delegation_window_rules(make_agent, delegate, window):
    _, agent = make_agent()
    assert delegate(agent["id"], **window).status_code == 422


@pytest.mark.parametrize("at", ["0001-01-01T00:00:00+14:00", "9999-12-31T23:59:59-05:00"])
def test_out_of_range_check_time_refused(client, admin, make_agent, at):
    _, agent = make_agent()
    body = {"action": "read", "resource": "crm:accounts/1", "at": at}
    assert client.post(f"/agents/{agent['id']}/check-authority", json=body, headers=admin).status_code == 422


def test_times_are_stored_and_returned_in_utc(make_agent, delegate):
    _, agent = make_agent()
    expires_karachi = (datetime.now(timezone(timedelta(hours=5))) + timedelta(hours=6)).replace(microsecond=0)
    created = delegate(agent["id"], expires_at=expires_karachi.isoformat()).json()
    returned = datetime.fromisoformat(created["expires_at"].replace("Z", "+00:00"))  # "Z" needs Python 3.11+
    assert returned.utcoffset() == timedelta(0)
    assert returned == expires_karachi


def test_scheduled_and_expired_delegations_do_not_grant(make_agent, delegate, check):
    _, agent = make_agent()
    created = delegate(agent["id"], starts_at=hours_from_now(2), expires_at=hours_from_now(4)).json()
    assert created["state"] == "scheduled"

    early = check(agent["id"], "read", "crm:accounts/1")
    assert not early["allowed"] and "only starts at" in early["reason"]
    assert check(agent["id"], "read", "crm:accounts/1", at=hours_from_now(3))["allowed"]
    late = check(agent["id"], "read", "crm:accounts/1", at=hours_from_now(5))
    assert not late["allowed"] and "expired at" in late["reason"]


# --- Revocation and agent state ---------------------------------------------------------------

def test_revoked_delegation_stops_granting(client, admin, make_agent, delegate, check):
    _, agent = make_agent()
    created = delegate(agent["id"]).json()
    url = f"/agents/{agent['id']}/delegations/{created['id']}"

    revoked = client.post(f"{url}/revoke", json={"reason": "report delivered"}, headers=admin).json()
    assert revoked["state"] == "revoked" and revoked["revocation_reason"] == "report delivered"
    result = check(agent["id"], "read", "crm:accounts/1")
    assert not result["allowed"] and "was revoked" in result["reason"]

    assert client.post(f"{url}/revoke", headers=admin).status_code == 409
    listed = client.get(f"/agents/{agent['id']}/delegations", params={"state": "revoked"}, headers=admin).json()
    assert [d["id"] for d in listed] == [created["id"]]


def test_denial_explanations_search_only_recent_history(client, admin, make_agent, delegate, check, monkeypatch):
    # A denial must not load an ever-growing history: only the latest delegations are searched for
    # one that would have covered the request.
    monkeypatch.setattr(delegation, "EXPLANATION_HISTORY", 2)
    _, agent = make_agent()
    old = delegate(agent["id"]).json()
    client.post(f"/agents/{agent['id']}/delegations/{old['id']}/revoke", headers=admin)
    assert "was revoked" in check(agent["id"], "read", "crm:accounts/1")["reason"]
    for _ in range(2):
        delegate(agent["id"], actions=["write"], resources=["hr:*"])
    result = check(agent["id"], "read", "crm:accounts/1")
    assert not result["allowed"] and result["reason"] == "No delegation in force grants the action 'read'"


def test_pending_agent_cannot_receive_authority(client, make_agent, delegate):
    _, pending = make_agent(approve=False)
    assert delegate(pending["id"]).status_code == 409
    assert delegate("no-such-agent").status_code == 404


def test_disabled_agent_has_no_authority(client, admin, make_agent, delegate, check):
    _, agent = make_agent()
    delegate(agent["id"])
    client.post(f"/agents/{agent['id']}/status", json={"status": "disabled"}, headers=admin)
    result = check(agent["id"], "read", "crm:accounts/1")
    assert not result["allowed"] and result["reason"] == "Agent is disabled"


def test_delegation_lookup_is_scoped_to_the_agent(client, admin, make_agent, delegate):
    _, a = make_agent(name="a")
    _, b = make_agent(name="b")
    created = delegate(a["id"]).json()
    assert client.get(f"/agents/{a['id']}/delegations/{created['id']}", headers=admin).status_code == 200
    assert client.get(f"/agents/{b['id']}/delegations/{created['id']}", headers=admin).status_code == 404
    assert client.post(f"/agents/{b['id']}/delegations/{created['id']}/revoke", headers=admin).status_code == 404


# --- The agent's view ---------------------------------------------------------------------------

def test_agent_sees_only_its_own_delegations_in_force(client, make_agent, delegate):
    sdk_a, a = make_agent(name="a")
    _, b = make_agent(name="b")
    in_force = delegate(a["id"]).json()
    delegate(a["id"], starts_at=hours_from_now(2), expires_at=hours_from_now(3))   # scheduled
    delegate(b["id"])

    assert [d["id"] for d in sdk_a.delegations()] == [in_force["id"]]
    assert client.get("/identity/delegations").status_code == 401


def test_agent_cannot_grant_itself_authority(make_agent):
    sdk, agent = make_agent()
    body = {"delegator": "ali", "task": "t", "actions": ["read"], "resources": ["crm:a"], "expires_at": hours_from_now(1)}
    assert sdk.request("POST", f"/agents/{agent['id']}/delegations", body).status_code == 401


def test_delegations_survive_key_rotation(make_agent, delegate):
    sdk, agent = make_agent()
    created = delegate(agent["id"]).json()
    sdk.rotate_key()
    assert [d["id"] for d in sdk.delegations()] == [created["id"]]


def test_state_filter_in_the_database_matches_state_at(client, admin, make_agent, delegate, session_factory):
    _, agent = make_agent()
    now = datetime.now(timezone.utc)
    hours = lambda n: (now + timedelta(hours=n)).isoformat()  # noqa: E731
    delegate(agent["id"])                                                    # in force now, for a day
    delegate(agent["id"], starts_at=hours(2), expires_at=hours(5))           # scheduled now
    revoked = delegate(agent["id"]).json()
    client.post(f"/agents/{agent['id']}/delegations/{revoked['id']}/revoke", headers=admin)
    with session_factory() as db:
        everything = delegation.delegations_in_state(db, agent["id"], None, now)
        assert len(everything) == 3
        for moment in (now, now + timedelta(hours=3), now + timedelta(hours=6), now + timedelta(hours=30)):
            for state in DelegationState:
                expected = [d.id for d in everything if d.state_at(moment) == state]
                assert [d.id for d in delegation.delegations_in_state(db, agent["id"], state, moment)] == expected, (moment, state)


def test_questions_about_the_past_see_a_revocation_only_from_when_it_happened(client, admin, make_agent, delegate, check):
    _, agent = make_agent()
    created = delegate(agent["id"]).json()
    before = created["starts_at"]  # in force from here on ...
    client.post(f"/agents/{agent['id']}/delegations/{created['id']}/revoke", headers=admin).raise_for_status()
    assert check(agent["id"], "read", "crm:accounts/1", at=before)["allowed"]  # ... until it was revoked
    assert "was revoked" in check(agent["id"], "read", "crm:accounts/1")["reason"]
    listed = client.get(f"/agents/{agent['id']}/delegations", params={"state": "revoked"}, headers=admin).json()
    assert [d["id"] for d in listed] == [created["id"]]


def test_two_revocations_at_once_keep_the_first(client, admin, make_agent, delegate, session_factory):
    from fastapi import HTTPException
    from app.routers.delegation import revoke_delegation
    from app.schemas import RevokeRequest
    _, agent = make_agent()
    created = delegate(agent["id"]).json()
    with session_factory() as stale:
        active = stale.get(delegation.Delegation, created["id"])  # noqa: F841 (kept: a session holds loaded objects only weakly)
        client.post(f"/agents/{agent['id']}/delegations/{created['id']}/revoke", json={"reason": "first"}, headers=admin)
        with pytest.raises(HTTPException) as refused:
            revoke_delegation(agent["id"], created["id"], RevokeRequest(reason="second"), db=stale)
    assert refused.value.status_code == 409
    listed = client.get(f"/agents/{agent['id']}/delegations", headers=admin).json()
    assert listed[0]["revocation_reason"] == "first"


def test_delegations_cannot_be_backdated(make_agent, delegate):
    _, agent = make_agent()
    long_ago = (datetime.now(timezone.utc) - timedelta(days=25)).isoformat()
    response = delegate(agent["id"], starts_at=long_ago)
    assert response.status_code == 422 and "cannot be backdated" in response.text
    a_minute_ago = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()  # clocks differ a little
    assert delegate(agent["id"], starts_at=a_minute_ago).status_code == 201


@pytest.mark.parametrize("given, stored", [
    ("crm:accounts/42", "crm:accounts/42"), ("crm:accounts:42", "crm:accounts/42"), ("crm/accounts/42", "crm:accounts/42"),
    ("redis:user:42:profile", "redis:user/42/profile"), ("crm", "crm"), ("crm:Accounts/ABC", "crm:Accounts/ABC"),
])
def test_resources_have_one_spelling(given, stored):
    assert delegation.normalize_resource(given) == stored


@pytest.mark.parametrize("given, stored", [
    ("crm:accounts/*", "crm:accounts/*"), ("crm:accounts:*", "crm:accounts/*"), ("crm/*", "crm:*"), ("crm:*", "crm:*"),
])
def test_resource_patterns_have_one_spelling(given, stored):
    assert delegation.normalize_resource_pattern(given) == stored


def test_delegations_are_stored_and_checked_in_the_one_spelling(make_agent, delegate, check):
    _, agent = make_agent()
    created = delegate(agent["id"], actions=["READ", "read"], resources=["crm:accounts:*", "crm/accounts/*"]).json()
    assert created["actions"] == ["read"] and created["resources"] == ["crm:accounts/*"]  # also deduplicated
    for action, resource in (("read", "crm:accounts:7"), ("Read", "crm/accounts/7"), ("READ", "crm:accounts/7")):
        result = check(agent["id"], action, resource)
        assert result["allowed"], (action, resource)
    assert not check(agent["id"], "read", "crm:invoices/7")["allowed"]


def _tomorrow():
    return (datetime.now(timezone.utc) + timedelta(days=1)).replace(microsecond=0)


@pytest.mark.parametrize("spell", [
    lambda t: str(int(t.timestamp())),                         # read as a Unix time by pydantic
    lambda t: str(int(t.timestamp() * 1000)),                  # ... or as milliseconds
    lambda t: t.strftime("%Y-%m-%d %H:%M:%SZ"),                # a space instead of "T"
    lambda t: t.strftime("%Y-%m-%dT%H:%MZ"),                   # no seconds
    lambda t: t.strftime("%Y-%m-%dT%H:%M:%S,5Z"),              # a comma before the fraction
    lambda t: t.strftime("%Y-%m-%dT%H:%M:%S+0000"),            # an offset without a colon
    lambda t: t.strftime("%Y-%m-%dT%H:%M:%S"),                 # no timezone
    lambda t: t.strftime("%Y-%m-%dT%H:%M:%SZ") + "\n",         # a trailing line break
    lambda t: t.strftime("%Y-%m-%dT%H:%M:%SZ").translate(str.maketrans("0123456789", "٠١٢٣٤٥٦٧٨٩")),  # other digits
])
def test_timestamps_must_be_rfc_3339(make_agent, delegate, spell):
    _, agent = make_agent()
    response = delegate(agent["id"], expires_at=spell(_tomorrow()))
    assert response.status_code == 422 and "must be an RFC 3339 timestamp with a timezone" in response.text


@pytest.mark.parametrize("spell", [
    lambda t: t.strftime("%Y-%m-%dT%H:%M:%SZ"),
    lambda t: t.strftime("%Y-%m-%dt%H:%M:%Sz"),                # RFC 3339 allows lower case
    lambda t: t.strftime("%Y-%m-%dT%H:%M:%S.123456789+00:00"),
    lambda t: t.astimezone(timezone(timedelta(hours=-5))).isoformat(),
])
def test_rfc_3339_timestamps_are_accepted(make_agent, delegate, spell):
    _, agent = make_agent()
    assert delegate(agent["id"], expires_at=spell(_tomorrow())).status_code == 201
