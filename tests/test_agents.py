import hashlib

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine, event, inspect
from sqlalchemy.exc import OperationalError

from app import utils
from app.database import Base, create_tables
from app.models import Agent, AgentKey, AgentStatus, RegistrationSource, RetiredKey, SystemSetting
from app.routers.agents import approve_agent, reject_registration
from app.routers.common import commit_or_409
from app.utils import FINGERPRINT_FORMAT, compute_fingerprint, ensure_current_fingerprints, refresh_fingerprints


def test_register_new_agent(client):
    response = client.post("/agents/register?source=api", json={
        "name": "test-agent-1", "owner": "areeb", "environment": "test"
    })
    assert response.status_code == 200
    data = response.json()
    # A claimed owner is recorded but not trusted: the agent still waits for review.
    assert data["status"] == "pending_review"
    assert data["owner"] == "areeb"
    assert data["active_key_id"] is None
    assert data["first_seen"] == data["last_seen"]


def test_duplicate_registration_does_not_create_second_row(client, admin):
    payload = {"name": "test-agent-dedup", "owner": "bhellar", "environment": "test"}
    r1 = client.post("/agents/register?source=api", json=payload)
    r2 = client.post("/agents/register?source=api", json=payload)
    assert r1.status_code == 200
    # An unsigned repeat cannot be told apart from an impostor, so it is refused rather than merged.
    assert r2.status_code == 409
    assert len(client.get("/agents/", headers=admin).json()) == 1


def test_unowned_agent_goes_to_review_queue(client, admin):
    response = client.post("/agents/register?source=sdk", json={
        "name": "shadow-agent", "environment": "test"
    })
    assert response.json()["status"] == "pending_review"
    queue = client.get("/agents/review-queue", headers=admin).json()
    assert [a["id"] for a in queue] == [response.json()["id"]]


def test_reregistration_after_approval_reuses_record(client, admin, make_agent):
    sdk, agent = make_agent(name="billing-bot", environment="prod")
    again = sdk.register("billing-bot", environment="prod", owner="ali")
    assert again["id"] == agent["id"]
    assert again["status"] == "active"
    assert len(client.get("/agents/", headers=admin).json()) == 1


def test_reregistration_cannot_change_owner(make_agent):
    sdk, _ = make_agent(name="bot", environment="prod")
    assert sdk.register("bot", environment="prod", owner="mallory")["owner"] == "ali"


def test_unsigned_reregistration_reveals_nothing_and_does_not_refresh_last_seen(client, admin):
    agent = client.post("/agents/", json={"name": "ops", "owner": "bakhtiar", "environment": "prod"}, headers=admin).json()
    client.post(f"/agents/{agent['id']}/status", json={"status": "disabled"}, headers=admin)

    response = client.post("/agents/register", json={"name": "OPS", "environment": "PROD"})
    assert response.status_code == 409
    assert "bakhtiar" not in response.text and "disabled" not in response.text
    assert client.get(f"/agents/{agent['id']}", headers=admin).json()["last_seen"] == agent["last_seen"]


def test_blank_or_space_padded_values_rejected(client, admin):
    # Values are stored exactly as sent, so surrounding spaces are an error rather than trimmed.
    assert client.post("/agents/register", json={"name": "   "}).status_code == 422
    assert client.post("/agents/register", json={"name": "bot", "environment": " "}).status_code == 422
    padded = client.post("/agents/register", json={"name": "  bot  "})
    assert padded.status_code == 422
    assert "must not start or end with a space" in padded.json()["detail"][0]["msg"]
    agent = client.post("/agents/register", json={"name": "bot"}).json()
    assert client.post(f"/agents/{agent['id']}/approve", params={"owner": "  "}, headers=admin).status_code == 422


def test_names_containing_the_old_separator_do_not_collide():
    # With "name|environment", 'a|b' in 'c' and 'a' in 'b|c' were the same agent. (Environments can
    # no longer contain "|", but stored ones from older versions might.)
    assert compute_fingerprint("billing|prod", "eu") != compute_fingerprint("billing", "prod|eu")


@pytest.mark.parametrize("first, second", [
    ("strasse-bot", "STRASSE-bot"), ("straße-bot", "strasse-bot"), ("caf\u00e9", "cafe\u0301"),
    ("ｂｉｌｌｉｎｇ", "billing"), ("x\u0130", "xi\u0307"),
])
def test_names_are_compared_by_one_unicode_rule(client, first, second):
    # NFKC with full case folding: canonically equal, compatibility-equal or case-equal names are
    # one agent, by a defined rule rather than by whatever lower() happens to fold.
    assert client.post("/agents/register", json={"name": first}).status_code == 200
    assert client.post("/agents/register", json={"name": second}).status_code == 409


@pytest.mark.parametrize("name", ["bot\u00a0", "\u00a0bot", "bot\u3000", "bo\u2028t", "bo\u200bt", "bo\u202et",
                                  "bo\x85t", "bo\u00adt", "\ufeffbot", "bo\u2066t",
                                  # found by review: other format characters, default-ignorables, blank letters
                                  "billing\u061c-bot", "billing\u180e-bot", "billing\U000e0041-bot", "billing\u034f-bot",
                                  "bot\ufe0f", "\u3164", "\u2800", "bo\U000f0000t", "bo\ufdd0t"])
def test_invisible_or_line_breaking_characters_refused(client, name):
    # A name ending in a non-breaking space would look identical to the plain name and block it.
    assert client.post("/agents/register", json={"name": name}).status_code == 422


@pytest.mark.parametrize("environment", ["pr\u043ed", "prod env", "prod|eu", "-prod", "e" * 65, "prod\u200b", "ｐｒｏｄ"])
def test_environments_are_plain_ascii_names(client, environment):
    # Policy rules select agents by environment; a look-alike ("prоd" with a Cyrillic о) would
    # escape every rule on "prod".
    assert client.post("/agents/register", json={"name": "bot", "environment": environment}).status_code == 422


@pytest.mark.parametrize("environment", ["prod", "PROD", "eu-west-1", "staging.2", "dev_ali"])
def test_ordinary_environments_accepted(client, environment):
    assert client.post("/agents/register", json={"name": "bot", "environment": environment}).status_code == 200


def test_ordinary_unicode_and_inner_spaces_accepted(client):
    for name in ("bøt", "サポート bot", "bot\u00a0two", "café", "🚀rocket", "Ünïcödé"):
        assert client.post("/agents/register", json={"name": name}).status_code == 200, name


def test_self_registration_cannot_claim_manual_source(client):
    response = client.post("/agents/register?source=manual", json={"name": "bot"})
    assert response.status_code == 422


def test_admin_endpoints_require_token(client, admin):
    assert client.get("/agents/").status_code == 401
    assert client.get("/agents/", headers={"Authorization": "Bearer wrong"}).status_code == 401
    assert client.get("/agents/", headers=admin).status_code == 200


def test_admin_endpoints_fail_closed_without_configured_token(client, admin, monkeypatch):
    monkeypatch.delenv("SECENTIC_ADMIN_TOKEN")
    assert client.get("/agents/", headers=admin).status_code == 503


def test_admin_endpoints_refuse_a_guessable_token(client, monkeypatch):
    monkeypatch.setenv("SECENTIC_ADMIN_TOKEN", "change-me")
    assert client.get("/agents/", headers={"Authorization": "Bearer change-me"}).status_code == 503


def test_manual_onboarding_creates_active_agent(client, admin):
    response = client.post("/agents/", json={"name": "ops-bot", "owner": "bakhtiar", "environment": "prod"}, headers=admin)
    assert response.status_code == 201
    assert response.json()["status"] == "active"
    assert response.json()["registration_source"] == "manual"
    assert response.json()["first_seen"] == response.json()["last_seen"]

    duplicate = client.post("/agents/", json={"name": "ops-bot", "owner": "bakhtiar", "environment": "prod"}, headers=admin)
    assert duplicate.status_code == 409


def test_approve_only_pending_agents(client, admin):
    agent = client.post("/agents/register", json={"name": "bot"}).json()
    assert client.post(f"/agents/{agent['id']}/approve", params={"owner": "ali"}, headers=admin).status_code == 200
    assert client.post(f"/agents/{agent['id']}/approve", params={"owner": "eve"}, headers=admin).status_code == 409
    assert client.post("/agents/does-not-exist/approve", params={"owner": "ali"}, headers=admin).status_code == 404


def test_status_changes(client, admin):
    agent = client.post("/agents/register", json={"name": "bot"}).json()
    url = f"/agents/{agent['id']}/status"

    # A pending agent cannot skip approval through the status endpoint.
    assert client.post(url, json={"status": "active"}, headers=admin).status_code == 409

    client.post(f"/agents/{agent['id']}/approve", params={"owner": "ali"}, headers=admin)
    assert client.post(url, json={"status": "disabled"}, headers=admin).json()["status"] == "disabled"
    assert client.post(url, json={"status": "active"}, headers=admin).json()["status"] == "active"
    assert client.post(url, json={"status": "pending_review"}, headers=admin).status_code == 422


def test_change_owner(client, admin):
    agent = client.post("/agents/register", json={"name": "bot"}).json()
    url = f"/agents/{agent['id']}/owner"
    assert client.put(url, json={"owner": "ali"}, headers=admin).status_code == 409  # pending: use /approve

    client.post(f"/agents/{agent['id']}/approve", params={"owner": "ali"}, headers=admin)
    assert client.put(url, json={"owner": "areeb"}, headers=admin).json()["owner"] == "areeb"
    assert client.put(url, json={"owner": "  "}, headers=admin).status_code == 422


def test_reject_pending_registration_frees_the_name(client, admin, make_agent):
    _, squatter = make_agent(name="billing-bot", environment="prod", approve=False)
    assert client.delete(f"/agents/{squatter['id']}", headers=admin).status_code == 204
    assert client.get(f"/agents/{squatter['id']}", headers=admin).status_code == 404

    _, real = make_agent(name="billing-bot", environment="prod", approve=False)
    assert real["id"] != squatter["id"]


def test_only_pending_registrations_can_be_rejected(client, admin, make_agent):
    _, agent = make_agent()
    assert client.delete(f"/agents/{agent['id']}", headers=admin).status_code == 409


def test_get_agent(client, admin):
    agent = client.post("/agents/register", json={"name": "bot"}).json()
    assert client.get(f"/agents/{agent['id']}", headers=admin).json()["name"] == "bot"
    assert client.get("/agents/nope", headers=admin).status_code == 404


def _agent(fingerprint):
    return Agent(name="bot", environment="prod", fingerprint=fingerprint, status=AgentStatus.active,
                 registration_source=RegistrationSource.api)


def test_old_fingerprints_are_refreshed_at_startup(session_factory):
    with session_factory() as db:
        db.add(_agent("hash-of-name-owner-and-environment"))
        db.commit()
        refresh_fingerprints(db)
        assert db.query(Agent).one().fingerprint == compute_fingerprint("bot", "prod")


def test_startup_refresh_runs_only_when_the_format_changes(session_factory):
    with session_factory() as db:
        db.add(_agent("old-format"))
        db.commit()
        ensure_current_fingerprints(db)  # no marker yet: refreshed, marker written
        assert db.query(Agent).one().fingerprint == compute_fingerprint("bot", "prod")
        assert db.get(SystemSetting, "fingerprint_format").value == FINGERPRINT_FORMAT

        db.query(Agent).one().fingerprint = "written-later"
        db.commit()
        ensure_current_fingerprints(db)  # marker current: nothing is scanned
        assert db.query(Agent).one().fingerprint == "written-later"


def test_refreshing_fingerprints_refuses_existing_duplicates(session_factory):
    with session_factory() as db:
        db.add_all([_agent("old-1"), _agent("old-2")])
        db.commit()
        with pytest.raises(RuntimeError):
            refresh_fingerprints(db)


def test_unique_constraint_race_becomes_409(session_factory):
    with session_factory() as db:
        db.add_all([_agent("same"), _agent("same")])
        with pytest.raises(HTTPException) as exc:
            commit_or_409(db, "conflict")
        assert exc.value.status_code == 409


def _first_m1_agent(name, owner, status, claimed_owner=None):
    """A row as the first M1 version stored it: fingerprint = name|owner|environment, where the owner
    is the one claimed at registration (empty if none was claimed)."""
    claimed = owner if claimed_owner is None else claimed_owner
    fingerprint = hashlib.sha256(f"{name}|{claimed}|prod".encode()).hexdigest()
    return Agent(name=name, owner=owner, environment="prod", fingerprint=fingerprint, status=status,
                 registration_source=RegistrationSource.api)


def test_upgrade_sends_agents_the_first_version_auto_activated_back_to_review(session_factory):
    # The first M1 version activated any agent that merely claimed an owner. Such agents were never
    # reviewed, so they must not stay active after an upgrade; agents an administrator approved do.
    with session_factory() as db:
        db.add_all([
            _first_m1_agent("claimed", "mallory", AgentStatus.active),                   # auto-activated
            _first_m1_agent("approved", "ali", AgentStatus.active, claimed_owner=""),    # approved by an admin
            _first_m1_agent("switched-off", "eve", AgentStatus.disabled),                 # auto-activated, then disabled
        ])
        db.commit()
        ensure_current_fingerprints(db)
        statuses = {agent.name: agent.status for agent in db.query(Agent)}
    assert statuses == {"claimed": AgentStatus.pending_review, "approved": AgentStatus.active,
                        "switched-off": AgentStatus.disabled}


def test_reject_cannot_undo_a_concurrent_approval(client, admin, make_agent, session_factory):
    # Two administrators: one rejects a pending agent while the other approves it. The rejection
    # read the agent while it was still pending; the approval lands first and must stand.
    sdk, agent = make_agent(name="ops-bot", approve=False)
    with session_factory() as stale:
        pending = stale.get(Agent, agent["id"])  # kept: a session holds loaded objects only weakly
        assert pending.status == AgentStatus.pending_review
        assert client.post(f"/agents/{agent['id']}/approve", params={"owner": "ali"}, headers=admin).status_code == 200
        with pytest.raises(HTTPException) as refused:
            reject_registration(agent["id"], db=stale)
    assert refused.value.status_code == 409
    assert client.get(f"/agents/{agent['id']}", headers=admin).json()["status"] == "active"
    with session_factory() as db:
        assert db.get(AgentKey, sdk.key.key_id) is not None and db.get(RetiredKey, sdk.key.key_id) is None


def test_a_stale_approval_cannot_reactivate_a_disabled_agent(client, admin, make_agent, session_factory):
    # One administrator opens a pending agent to approve it; meanwhile another approves it and then
    # disables it (suspected misuse). The first approval must not switch it back on.
    _, agent = make_agent(name="ops-bot", approve=False)
    with session_factory() as stale:
        pending = stale.get(Agent, agent["id"])  # noqa: F841 (kept: a session holds loaded objects only weakly)
        assert client.post(f"/agents/{agent['id']}/approve", params={"owner": "ali"}, headers=admin).status_code == 200
        assert client.post(f"/agents/{agent['id']}/status", json={"status": "disabled"}, headers=admin).status_code == 200
        with pytest.raises(HTTPException) as refused:
            approve_agent(agent["id"], owner="mallory", db=stale)
    assert refused.value.status_code == 409
    after = client.get(f"/agents/{agent['id']}", headers=admin).json()
    assert (after["status"], after["owner"]) == ("disabled", "ali")


def test_approval_after_a_concurrent_rejection_is_404(client, admin, make_agent, session_factory):
    _, agent = make_agent(name="ops-bot", approve=False)
    with session_factory() as stale:
        pending = stale.get(Agent, agent["id"])  # noqa: F841 (kept: a session holds loaded objects only weakly)
        assert client.delete(f"/agents/{agent['id']}", headers=admin).status_code == 204
        with pytest.raises(HTTPException) as refused:  # was a 500 (StaleDataError)
            approve_agent(agent["id"], owner="ali", db=stale)
    assert refused.value.status_code == 404


def test_servers_starting_together_do_not_crash_on_the_upgrade_marker(session_factory, monkeypatch):
    # Two workers upgrade the same database; the other one records the marker just before this one
    # commits its own. This one must start anyway (the upgrade is the same).
    real_refresh = utils.refresh_fingerprints

    def other_worker_commits_first(db):
        real_refresh(db)

        @event.listens_for(db, "before_commit", once=True)
        def insert_marker(session):
            with session_factory() as other:
                other.add(SystemSetting(key="fingerprint_format", value=FINGERPRINT_FORMAT))
                other.commit()

    monkeypatch.setattr(utils, "refresh_fingerprints", other_worker_commits_first)
    with session_factory() as db:
        ensure_current_fingerprints(db)
        assert db.get(SystemSetting, "fingerprint_format").value == FINGERPRINT_FORMAT


def test_servers_starting_together_do_not_crash_creating_tables(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'fresh.db'}")
    real_create_all, calls = Base.metadata.create_all, []

    def another_process_got_there_first(bind):
        calls.append(bind)
        if len(calls) == 1:
            raise OperationalError("CREATE TABLE agents", {}, Exception("table agents already exists"))
        real_create_all(bind=bind)

    monkeypatch.setattr(Base.metadata, "create_all", another_process_got_there_first)
    create_tables(engine)
    assert "agents" in inspect(engine).get_table_names()
    engine.dispose()


def count_queries(session_factory):
    """Collect the SQL statements run while the returned list is in use."""
    statements = []
    event.listen(session_factory.kw["bind"], "before_cursor_execute",
                 lambda conn, cursor, statement, *args: statements.append(statement))
    return statements


def test_listing_agents_takes_the_same_queries_however_many_there_are(client, admin, make_agent, session_factory):
    statements = count_queries(session_factory)
    make_agent(name="a")
    statements.clear()
    client.get("/agents", headers=admin)
    with_one = len(statements)
    for name in "bcdef":
        make_agent(name=name)
    statements.clear()
    listed = client.get("/agents", headers=admin).json()
    assert len(listed) == 6 and all(agent["active_key_id"] for agent in listed)
    assert len(statements) == with_one


def test_a_key_bound_during_a_rejection_is_retired_too(client, admin, session_factory):
    from secentic_sdk import AgentKey as SdkKey
    from app.identity import key_was_used
    agent = client.post("/agents/register", json={"name": "payroll-bot"}).json()  # pending, no key
    with session_factory() as stale:
        pending = stale.get(Agent, agent["id"])  # kept: a session holds loaded objects only weakly
        assert pending.keys == []  # the rejection read the agent (no keys yet) ...
        key = SdkKey.generate()                          # ... then an administrator bound one
        assert client.post(f"/agents/{agent['id']}/keys", json={"public_key": key.public_key}, headers=admin).status_code == 201
        reject_registration(agent["id"], db=stale)
    with session_factory() as db:
        assert key_was_used(db, key.key_id)  # it can never be enrolled again


def test_sqlite_enforces_foreign_keys(session_factory):
    engine = session_factory.kw["bind"]
    if engine.dialect.name != "sqlite":
        pytest.skip("PostgreSQL always enforces them")
    with engine.connect() as connection:
        assert connection.exec_driver_sql("PRAGMA foreign_keys").scalar() == 1


def test_a_key_cannot_be_bound_to_an_agent_rejected_meanwhile(client, admin, session_factory):
    # An administrator binds a key to a pending agent while another rejects it. The key must not end
    # up pointing at an agent that no longer exists.
    from secentic_sdk import AgentKey as SdkKey
    from app.routers.identity import bind_key
    from app.schemas import PublicKeyRequest
    agent = client.post("/agents/register", json={"name": "payroll-bot"}).json()
    key = SdkKey.generate()
    with session_factory() as stale:
        pending = stale.get(Agent, agent["id"])  # noqa: F841 (kept: a session holds loaded objects only weakly)
        assert client.delete(f"/agents/{agent['id']}", headers=admin).status_code == 204
        with pytest.raises(HTTPException) as refused:
            bind_key(agent["id"], PublicKeyRequest(public_key=key.public_key), db=stale)
    assert refused.value.status_code == 409
    with session_factory() as db:
        assert db.get(AgentKey, key.key_id) is None
