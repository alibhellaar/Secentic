import base64
import json
import time
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import httpx
import pytest
from sqlalchemy import event

from app import crypto, identity
from app.models import Agent, AgentKey as AgentKeyRow, AgentStatus, KeyStatus, RegistrationSource, UsedNonce
from secentic_sdk import AgentKey, RotationInterrupted, SecenticClient, canonical_request, sign_request

SIGNED_WITHOUT_KEY = ("A signed registration must include the public_key it was"
                      " signed with; only an existing agent's enrolled key can sign without it")


def post_signed(client, key, path, body: dict, signed_body: dict | None = None):
    """POST `body`, signed with `key` over `signed_body` (defaults to the same body)."""
    raw = json.dumps(body).encode()
    signed_raw = raw if signed_body is None else json.dumps(signed_body).encode()
    headers, _ = sign_request(key, "POST", path, body=signed_raw)
    return client.post(path, content=raw, headers={**headers, "Content-Type": "application/json"})


def test_sdk_and_server_agree_on_canonical_format():
    args = ("post", "/agents/register", "source=sdk", "kid", "1700000000", "n" * 16, b"{}")
    assert canonical_request(*args) == crypto.canonical_request(*args)


# --- Enrollment -----------------------------------------------------------------------

def test_register_with_key_binds_identity_but_stays_pending(make_agent):
    sdk, agent = make_agent(approve=False)
    assert agent["status"] == "pending_review"
    assert agent["active_key_id"] == sdk.key.key_id


def test_register_with_key_must_be_signed(client):
    key = AgentKey.generate()
    response = client.post("/agents/register", json={"name": "bot", "public_key": key.public_key})
    assert response.status_code == 401


def test_cannot_enrol_a_public_key_you_do_not_hold(client):
    victim, attacker = AgentKey.generate(), AgentKey.generate()
    response = post_signed(client, attacker, "/agents/register", {"name": "bot", "public_key": victim.public_key})
    assert response.status_code == 401


def test_invalid_public_key_rejected(client):
    response = client.post("/agents/register", json={"name": "bot", "public_key": "not-a-key"})
    assert response.status_code == 422


SMALL_ORDER_KEYS = sorted(crypto._SMALL_ORDER_KEYS)


@pytest.mark.parametrize("raw", SMALL_ORDER_KEYS + [k[:31] + bytes([k[31] | 0x80]) for k in SMALL_ORDER_KEYS])
def test_small_order_keys_refused(client, admin, raw):
    public_key = base64.b64encode(raw).decode()
    assert client.post("/agents/register", json={"name": "bot", "public_key": public_key}).status_code == 422
    agent = client.post("/agents/", json={"name": "ops", "owner": "ali"}, headers=admin).json()
    assert client.post(f"/agents/{agent['id']}/keys", json={"public_key": public_key}, headers=admin).status_code == 422


def test_forged_signature_for_identity_point_key_refused():
    # For this key, R = identity and S = 0 is a valid signature on every message.
    identity_point = base64.b64encode(bytes([1]) + bytes(31)).decode()
    forged = base64.b64encode(bytes([1]) + bytes(63)).decode()
    assert not crypto.verify_signature(identity_point, forged, b"any message")


def test_pending_agent_cannot_authenticate(make_agent):
    sdk, _ = make_agent(approve=False)
    assert sdk.request("GET", "/identity/whoami").status_code == 403


def test_approved_agent_authenticates(make_agent):
    sdk, agent = make_agent()
    me = sdk.whoami()
    assert me["id"] == agent["id"]
    assert me["active_key_id"] == sdk.key.key_id


# --- Impersonation ----------------------------------------------------------------------

def test_another_key_cannot_take_over_an_enrolled_agent(client, make_agent):
    sdk, agent = make_agent(name="billing-bot", environment="prod")

    impostor = AgentKey.generate()
    body = {"name": "billing-bot", "environment": "prod", "public_key": impostor.public_key}
    assert post_signed(client, impostor, "/agents/register", body).status_code == 409
    assert client.post("/agents/register", json={"name": "billing-bot", "environment": "prod"}).status_code == 409

    # The real agent can still re-register (a signed observation that refreshes last_seen).
    assert sdk.register("billing-bot", environment="prod")["id"] == agent["id"]


def test_cannot_attach_a_key_to_someone_elses_pending_agent(client, admin):
    legit = client.post("/agents/register", json={"name": "bot", "environment": "prod"}).json()
    attacker = AgentKey.generate()
    body = {"name": "bot", "environment": "prod", "public_key": attacker.public_key}
    assert post_signed(client, attacker, "/agents/register", body).status_code == 409
    assert client.get(f"/agents/{legit['id']}", headers=admin).json()["active_key_id"] is None


def test_cannot_self_enrol_a_key_on_an_approved_agent(client, admin):
    client.post("/agents/", json={"name": "ops-bot", "owner": "bakhtiar"}, headers=admin)
    attacker = AgentKey.generate()
    body = {"name": "ops-bot", "public_key": attacker.public_key}
    assert post_signed(client, attacker, "/agents/register", body).status_code == 409


def test_agent_keys_do_not_grant_admin_access(make_agent):
    sdk, _ = make_agent()
    assert sdk.request("GET", "/agents/").status_code == 401


# --- Request integrity and replay -------------------------------------------------------

def test_unsigned_request_rejected(client):
    assert client.get("/identity/whoami").status_code == 401


def test_unknown_key_rejected(client):
    headers, _ = sign_request(AgentKey.generate(), "GET", "/identity/whoami")
    response = client.get("/identity/whoami", headers=headers)
    assert response.status_code == 401 and response.json()["detail"] == "Invalid signature"


def test_key_status_is_not_revealed_without_a_valid_signature(client, admin, make_agent):
    # Someone who knows a key ID but cannot sign learns nothing about the key: unknown, revoked
    # and active keys all get the same answer to a bad signature.
    sdk, agent = make_agent()
    client.post(f"/agents/{agent['id']}/keys/{sdk.key.key_id}/revoke", headers=admin)
    headers, _ = sign_request(AgentKey.generate(), "GET", "/identity/whoami")
    headers["X-Secentic-Key-Id"] = sdk.key.key_id  # a revoked key's ID, signed by someone else
    assert client.get("/identity/whoami", headers=headers).json()["detail"] == "Invalid signature"


def test_tampered_query_rejected(client, make_agent):
    sdk, _ = make_agent()
    headers, _ = sign_request(sdk.key, "GET", "/identity/whoami")
    assert client.get("/identity/whoami?impersonate=admin", headers=headers).status_code == 401


def test_tampered_body_rejected(client, make_agent):
    # On an endpoint with no other check that could refuse it, so only the signature can.
    sdk, _ = make_agent()
    signed_body = {"tool": "crm", "action": "read", "resource": "crm:accounts/1"}
    sent_body = {"tool": "crm", "action": "read", "resource": "crm:accounts/2"}
    response = post_signed(client, sdk.key, "/gateway/authorize", sent_body, signed_body)
    assert response.status_code == 401 and response.json()["detail"] == "Invalid signature"


def test_replayed_request_rejected(client, make_agent):
    sdk, _ = make_agent()
    headers, _ = sign_request(sdk.key, "GET", "/identity/whoami")
    assert client.get("/identity/whoami", headers=headers).status_code == 200
    replay = client.get("/identity/whoami", headers=headers)
    assert replay.status_code == 401
    assert "already been used" in replay.json()["detail"]


def test_replay_at_the_edge_of_the_window_rejected(client, make_agent, monkeypatch):
    sdk, _ = make_agent()
    ts = int(time.time())
    headers, _ = sign_request(sdk.key, "GET", "/identity/whoami", timestamp=ts)
    assert client.get("/identity/whoami", headers=headers).status_code == 200

    # The replay passes the timestamp check at the last accepted second, and a nonce sweep
    # runs a moment later. The original nonce must still be remembered at that point.
    monkeypatch.setattr(identity, "_next_nonce_purge", 0.0)
    monkeypatch.setattr(identity, "time", SimpleNamespace(time=lambda: ts + identity.MAX_CLOCK_SKEW, monotonic=lambda: 1e12))
    monkeypatch.setattr(identity, "utcnow", lambda: datetime.fromtimestamp(ts + identity.MAX_CLOCK_SKEW + 1, tz=timezone.utc))
    assert client.get("/identity/whoami", headers=headers).status_code == 401


def test_last_seen_moves_only_on_verified_requests(client, admin, make_agent, monkeypatch):
    monkeypatch.setattr(identity, "LAST_SEEN_RESOLUTION", timedelta(0))
    sdk, agent = make_agent()
    seen = lambda: client.get(f"/agents/{agent['id']}", headers=admin).json()["last_seen"]
    before = seen()

    headers, _ = sign_request(sdk.key, "GET", "/identity/whoami")
    headers["X-Secentic-Signature"] = AgentKey.generate().sign(b"something else")
    assert client.get("/identity/whoami", headers=headers).status_code == 401
    assert seen() == before

    sdk.whoami()
    assert seen() > before


def test_last_seen_is_written_at_most_once_a_minute(client, admin, make_agent):
    sdk, agent = make_agent()
    sdk.whoami()  # the first request after approval refreshes it (approval did not)
    first = client.get(f"/agents/{agent['id']}", headers=admin).json()["last_seen"]
    sdk.whoami()
    assert client.get(f"/agents/{agent['id']}", headers=admin).json()["last_seen"] == first


def test_disabled_agent_cannot_refresh_itself_by_re_registering(client, admin, make_agent):
    sdk, agent = make_agent(name="billing-bot", environment="prod")
    client.post(f"/agents/{agent['id']}/status", json={"status": "disabled"}, headers=admin)
    before = client.get(f"/agents/{agent['id']}", headers=admin).json()["last_seen"]
    response = sdk.request("POST", "/agents/register", {"name": "billing-bot", "environment": "prod",
                                                        "public_key": sdk.key.public_key})
    assert response.status_code == 403
    assert client.get(f"/agents/{agent['id']}", headers=admin).json()["last_seen"] == before


def test_re_registration_signed_with_the_enrolled_key_needs_no_public_key(client, admin, make_agent):
    sdk, agent = make_agent(name="billing-bot", environment="prod")
    response = sdk.request("POST", "/agents/register", {"name": "billing-bot", "environment": "prod"})
    assert response.status_code == 200 and response.json()["id"] == agent["id"]

    unsigned = client.post("/agents/register", json={"name": "billing-bot", "environment": "prod"})
    assert unsigned.status_code == 409  # the name is taken
    other = SecenticClient("http://testserver", AgentKey.generate(), http=client)
    signed_by_another_key = other.request("POST", "/agents/register", {"name": "billing-bot", "environment": "prod"})
    assert signed_by_another_key.status_code == 401  # a signature nobody can check: see the test below

    body = json.dumps({"name": "billing-bot", "environment": "prod"}).encode()
    headers, _ = sign_request(sdk.key, "POST", "/agents/register", body=body)
    headers["Content-Type"] = "application/json"
    assert client.post("/agents/register", content=body, headers=headers).status_code == 200
    replay = client.post("/agents/register", content=body, headers=headers)
    assert (replay.status_code, replay.json()["detail"]) == (401, SIGNED_WITHOUT_KEY)  # the same answer as any other key


def test_stale_timestamp_rejected(client, make_agent):
    sdk, _ = make_agent()
    headers, _ = sign_request(sdk.key, "GET", "/identity/whoami", timestamp=int(time.time()) - 600)
    assert client.get("/identity/whoami", headers=headers).status_code == 401


def test_disabled_agent_cannot_authenticate(client, admin, make_agent):
    sdk, agent = make_agent()
    client.post(f"/agents/{agent['id']}/status", json={"status": "disabled"}, headers=admin)
    assert sdk.request("GET", "/identity/whoami").status_code == 403


# --- Rotation ---------------------------------------------------------------------------

def test_rotation_switches_keys(client, make_agent):
    sdk, _ = make_agent()
    old_key = sdk.key
    new_key = sdk.rotate_key()
    assert sdk.whoami()["active_key_id"] == new_key.key_id

    old = SecenticClient("http://testserver", old_key, http=client)
    response = old.request("GET", "/identity/whoami")
    assert response.status_code == 401
    assert "rotated" in response.json()["detail"]


def test_rotation_requires_proof_of_the_new_key(make_agent):
    sdk, _ = make_agent()
    new_key = AgentKey.generate()
    body = {"public_key": new_key.public_key}
    assert sdk.request("POST", "/identity/rotate", body).status_code == 401
    assert sdk.request("POST", "/identity/rotate", body, proof_key=AgentKey.generate()).status_code == 401
    assert sdk.whoami()["active_key_id"] == sdk.key.key_id


class LoseResponses(httpx.BaseTransport):
    """Delivers requests to the app but drops the response for one path, like a lost connection."""

    def __init__(self, inner: httpx.BaseTransport, path: str):
        self.inner, self.path = inner, path

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        response = self.inner.handle_request(request)
        if request.url.path == self.path:
            raise httpx.ReadError("connection reset", request=request)
        return response


def test_interrupted_rotation_hands_back_the_new_key(client, make_agent):
    sdk, _ = make_agent()
    old_key = sdk.key
    sdk.http = httpx.Client(transport=LoseResponses(client._transport, "/identity/rotate"), base_url="http://testserver")

    with pytest.raises(RotationInterrupted) as interrupted:
        sdk.rotate_key()
    assert sdk.key is old_key

    # The server did apply it, and the key carried by the exception is the one that works now.
    recovered = SecenticClient("http://testserver", interrupted.value.new_key, http=client)
    assert recovered.whoami()["active_key_id"] == interrupted.value.new_key.key_id


def test_revocation_during_a_rotation_is_not_overwritten(admin, make_agent, session_factory, monkeypatch):
    # A thief with a stolen key starts a rotation; the administrator revokes that key while the
    # rotation is in flight. The revocation must stand and the thief's new key must not be enrolled.
    sdk, agent = make_agent()
    stolen = sdk.key
    real_verify, calls = crypto.verify_signature, []

    def verify_then_revoke(public_key, signature, message):
        calls.append(public_key)
        if len(calls) == 2:  # the proof check: the request is already authenticated
            with session_factory() as db:
                db.get(AgentKeyRow, stolen.key_id).status = KeyStatus.revoked
                db.commit()
        return real_verify(public_key, signature, message)

    monkeypatch.setattr(crypto, "verify_signature", verify_then_revoke)
    new_key = AgentKey.generate()
    response = sdk.request("POST", "/identity/rotate", {"public_key": new_key.public_key}, proof_key=new_key)
    assert response.status_code == 409
    with session_factory() as db:
        assert db.get(AgentKeyRow, stolen.key_id).status == KeyStatus.revoked
        assert db.get(AgentKeyRow, new_key.key_id) is None


def test_malformed_proof_header_refused(make_agent):
    sdk, _ = make_agent()
    new_key = AgentKey.generate()
    response = sdk.http.send(sdk.http.build_request("POST", "/identity/rotate", json={"public_key": new_key.public_key}))
    assert response.status_code == 401  # unsigned
    signed = sdk.request("POST", "/identity/rotate", {"public_key": new_key.public_key})
    assert signed.status_code == 401  # signed, but no proof
    body = json.dumps({"public_key": new_key.public_key}).encode()
    headers, _ = sign_request(sdk.key, "POST", "/identity/rotate", body=body)
    headers["X-Secentic-Proof"] = "x" * 5000
    request = sdk.http.build_request("POST", "/identity/rotate", content=body,
                                     headers={**headers, "Content-Type": "application/json"})
    assert sdk.http.send(request).status_code == 422


def test_rotation_back_to_an_old_key_rejected(make_agent):
    sdk, _ = make_agent()
    old_key = sdk.key
    sdk.rotate_key()
    response = sdk.request("POST", "/identity/rotate", {"public_key": old_key.public_key}, proof_key=old_key)
    assert response.status_code == 409


# --- Revocation and admin key binding ---------------------------------------------------

def test_revoked_key_stops_working_and_agent_can_be_recovered(client, admin, make_agent):
    sdk, agent = make_agent()
    keys_url = f"/agents/{agent['id']}/keys"

    revoked = client.post(f"{keys_url}/{sdk.key.key_id}/revoke", json={"reason": "host compromised"}, headers=admin)
    assert revoked.json()["status"] == "revoked"
    assert sdk.request("GET", "/identity/whoami").status_code == 401

    # A revoked key can never be bound again; a fresh one can.
    assert client.post(keys_url, json={"public_key": sdk.key.public_key}, headers=admin).status_code == 409
    sdk.key = AgentKey.generate()
    assert client.post(keys_url, json={"public_key": sdk.key.public_key}, headers=admin).status_code == 201
    assert sdk.whoami()["id"] == agent["id"]

    assert [k["status"] for k in client.get(keys_url, headers=admin).json()] == ["revoked", "active"]


def test_revoking_twice_or_on_wrong_agent(client, admin, make_agent):
    sdk, agent = make_agent(name="a")
    _, other = make_agent(name="b")
    assert client.post(f"/agents/{other['id']}/keys/{sdk.key.key_id}/revoke", headers=admin).status_code == 404
    assert client.post(f"/agents/{agent['id']}/keys/{sdk.key.key_id}/revoke", headers=admin).status_code == 200
    again = client.post(f"/agents/{agent['id']}/keys/{sdk.key.key_id}/revoke", headers=admin)
    assert again.status_code == 409
    assert again.json()["detail"] == "Key is not active (revoked); the agent has no active key. Revoke that key, or disable the agent"


def test_revoking_a_key_that_was_rotated_away_names_the_key_in_use(client, admin, make_agent):
    # A thief rotated a stolen key to one of their own. Revoking the stolen key would cut nothing
    # off, so it must not report success: the answer names the key that is actually in use.
    sdk, agent = make_agent()
    stolen = sdk.key
    thiefs = sdk.rotate_key()
    response = client.post(f"/agents/{agent['id']}/keys/{stolen.key_id}/revoke", headers=admin)
    assert response.status_code == 409
    assert f"the agent's active key is {thiefs.key_id}" in response.json()["detail"]
    assert sdk.whoami()["active_key_id"] == thiefs.key_id  # nothing changed
    assert client.post(f"/agents/{agent['id']}/keys/{thiefs.key_id}/revoke", headers=admin).status_code == 200
    assert sdk.request("GET", "/identity/whoami").status_code == 401


def test_rejected_registration_key_can_never_be_enrolled_again(client, admin, make_agent):
    sdk, agent = make_agent(name="payroll-bot", approve=False)  # squatting another team's name
    assert client.delete(f"/agents/{agent['id']}", headers=admin).status_code == 204
    for name in ("payroll-bot", "something-else"):
        response = sdk.request("POST", "/agents/register", {"name": name, "public_key": sdk.key.public_key})
        assert response.status_code == 409
        assert response.json()["detail"] == "This public key has already been used; generate a new key pair"
    _, fresh = make_agent(name="payroll-bot", approve=False)  # the name itself is free again
    assert fresh["name"] == "payroll-bot"


def test_admin_binds_key_for_manually_onboarded_agent(client, admin):
    agent = client.post("/agents/", json={"name": "ops-bot", "owner": "bakhtiar"}, headers=admin).json()
    sdk = SecenticClient("http://testserver", AgentKey.generate(), http=client)
    keys_url = f"/agents/{agent['id']}/keys"

    assert client.post(keys_url, json={"public_key": sdk.key.public_key}, headers=admin).status_code == 201
    assert sdk.whoami()["id"] == agent["id"]

    # One active key per agent: a second must wait until the first is revoked.
    second = AgentKey.generate()
    assert client.post(keys_url, json={"public_key": second.public_key}, headers=admin).status_code == 409


def test_private_key_round_trips_through_pem():
    key = AgentKey.generate()
    assert AgentKey.from_pem(key.to_pem()).key_id == key.key_id


def test_signed_registration_of_a_new_agent_without_its_key_is_refused(client, admin):
    # The signature cannot be checked without the key; it must not be silently ignored.
    body = json.dumps({"name": "fresh-bot"}).encode()
    headers, _ = sign_request(AgentKey.generate(), "POST", "/agents/register", body=body)
    headers["X-Secentic-Signature"] = base64.b64encode(b"\x01" * 64).decode()  # well formed, but wrong
    response = client.post("/agents/register", content=body, headers=headers | {"Content-Type": "application/json"})
    assert response.status_code == 401
    assert response.json()["detail"] == SIGNED_WITHOUT_KEY
    assert client.get("/agents", headers=admin).json() == []


def test_signed_registrations_reveal_nothing_about_which_names_exist(client, admin, make_agent):
    # An unsigned registration of a new name creates a record, visible in the review queue. A signed
    # one without a key must not become a silent way to find out which names are taken: it gets
    # the same answer whether or not the name exists, and leaves nothing behind.
    make_agent(name="secret-bot", environment="prod")
    prober = AgentKey.generate()
    answers = []
    for name in ("secret-bot", "no-such-bot"):
        body = json.dumps({"name": name, "environment": "prod"}).encode()
        headers, _ = sign_request(prober, "POST", "/agents/register", body=body)
        response = client.post("/agents/register", content=body, headers=headers | {"Content-Type": "application/json"})
        answers.append((response.status_code, response.json()["detail"]))
    assert answers == [(401, SIGNED_WITHOUT_KEY)] * 2
    assert [a["name"] for a in client.get("/agents", headers=admin).json()] == ["secret-bot"]


def test_re_registration_refreshes_last_seen_in_the_same_commit_as_the_nonce(client, admin, make_agent, session_factory):
    sdk, agent = make_agent(name="billing-bot", environment="prod")
    commits = []
    event.listen(session_factory.kw["bind"], "commit", lambda conn: commits.append(1))
    before = client.get(f"/agents/{agent['id']}", headers=admin).json()["last_seen"]
    commits.clear()
    for body in ({"name": "billing-bot", "environment": "prod"},                                 # signed, no key
                 {"name": "billing-bot", "environment": "prod", "public_key": sdk.key.public_key}):  # as the SDK does
        assert sdk.request("POST", "/agents/register", body).status_code == 200
    assert len(commits) == 2  # one per re-registration
    assert client.get(f"/agents/{agent['id']}", headers=admin).json()["last_seen"] > before


@pytest.mark.parametrize("header, value, detail", [
    ("X-Secentic-Key-Id", "x" * 64, "Key ID must be 64 lowercase hexadecimal characters"),
    ("X-Secentic-Key-Id", "a" * 5000, "Key ID must be 64 lowercase hexadecimal characters"),
    ("X-Secentic-Signature", "garbage", "Signature must be 88 base64 characters (an Ed25519 signature)"),
    ("X-Secentic-Signature", "A" * 5000, "Signature must be 88 base64 characters (an Ed25519 signature)"),
])
def test_signature_headers_are_bounded(client, make_agent, header, value, detail):
    sdk, _ = make_agent()
    headers, _ = sign_request(sdk.key, "GET", "/identity/whoami")
    response = client.get("/identity/whoami", headers=headers | {header: value})
    assert response.status_code == 401 and response.json()["detail"] == detail


def test_an_authenticated_request_reads_the_agent_and_key_once(make_agent, session_factory):
    # Spending the nonce commits; the agent and key just read must not be read again afterwards.
    sdk, _ = make_agent()
    statements = []
    event.listen(session_factory.kw["bind"], "before_cursor_execute",
                 lambda conn, cursor, statement, *args: statements.append(statement))
    assert sdk.authorize("crm", "read", "crm:accounts/1")["decision"] == "deny"  # no tools assigned
    assert sum("FROM agents" in s for s in statements) == 1
    assert sum("FROM agent_keys" in s for s in statements) == 1


def test_sdk_signs_paths_the_way_the_server_reads_them(make_agent):
    # The server ignores a trailing slash and percent-decodes the path; the SDK signs that form.
    sdk, agent = make_agent()
    for path in ("/identity/whoami/", "/identity/who%61mi"):
        response = sdk.request("GET", path)
        assert response.status_code == 200 and response.json()["id"] == agent["id"], path


def test_a_signature_cannot_be_redirected_through_the_host_header(client, make_agent):
    # Signed for /identity/whoami, sent to /identity/delegations with a Host header crafted so that
    # a URL rebuilt from it would read /identity/whoami. The signature covers the routed path.
    sdk, _ = make_agent()
    headers, _ = sign_request(sdk.key, "GET", "/identity/whoami")
    response = client.get("/identity/delegations", headers=headers | {"Host": "testserver/identity/whoami#"})
    assert response.status_code == 401


def test_the_signed_path_does_not_depend_on_request_url(client, make_agent, monkeypatch):
    # Older Starlette versions rebuilt request.url from the Host header, so it could name another
    # path than the one routed. Simulate that: the signature must still cover the routed path.
    from starlette.datastructures import URL
    from starlette.requests import HTTPConnection
    sdk, _ = make_agent()
    headers, _ = sign_request(sdk.key, "GET", "/identity/whoami")
    monkeypatch.setattr(HTTPConnection, "url", property(lambda self: URL("http://testserver/identity/whoami")))
    assert client.get("/identity/delegations", headers=headers).status_code == 401


def test_retrying_a_rotation_that_was_applied_keeps_the_new_key(client, make_agent):
    # The rotation went through but its answer was lost; the client still holds the old key and
    # retries. The server says the old key was rotated; the SDK must hand back the new key.
    sdk, _ = make_agent()
    old, new = sdk.key, AgentKey.generate()
    sdk.rotate_key(new)
    sdk.key = old
    with pytest.raises(RotationInterrupted) as interrupted:
        sdk.rotate_key(new)
    assert interrupted.value.new_key is new
    sdk.key = new
    assert sdk.whoami()["active_key_id"] == new.key_id


def test_a_registration_racing_for_the_same_key_says_the_key_was_used(client, admin, make_agent, session_factory, monkeypatch):
    import app.routers.agents as agents_router
    other = client.post("/agents", json={"name": "other-bot", "owner": "ali"}, headers=admin).json()
    real_new_agent_key = agents_router.new_agent_key

    def same_key_enrolled_meanwhile(db, agent, public_key):
        key = real_new_agent_key(db, agent, public_key)  # the key was free when checked ...
        with session_factory() as concurrent:             # ... then another registration took it
            concurrent.add(AgentKeyRow(key_id=key.key_id, agent_id=other["id"], public_key=public_key,
                                       status=KeyStatus.revoked))
            concurrent.commit()
        return key

    monkeypatch.setattr(agents_router, "new_agent_key", same_key_enrolled_meanwhile)
    sdk = SecenticClient("http://testserver", AgentKey.generate(), http=client)
    response = sdk.request("POST", "/agents/register", {"name": "new-bot", "public_key": sdk.key.public_key})
    assert response.status_code == 409
    assert response.json()["detail"] == "This public key has already been used; generate a new key pair"


def test_a_rejection_landing_mid_request_is_refused_cleanly(client, admin, make_agent, monkeypatch):
    sdk, agent = make_agent(approve=False)
    real_verify, rejected = crypto.verify_signature, []

    def reject_meanwhile(public_key, signature, message):
        if not rejected:  # the key was read; now an administrator rejects the registration
            rejected.append(client.delete(f"/agents/{agent['id']}", headers=admin).status_code)
        return real_verify(public_key, signature, message)

    monkeypatch.setattr(crypto, "verify_signature", reject_meanwhile)
    response = sdk.request("GET", "/identity/whoami")
    assert rejected == [204]
    assert response.status_code == 401 and response.json()["detail"] == "Invalid signature"


def test_spending_a_nonce_never_commits_other_changes(session_factory):
    # The nonce is committed at once, on the request's own connection. Authentication comes before
    # any change, so pending changes at that point are a programming error: refused, not committed.
    key = AgentKey.generate()
    headers, message = sign_request(key, "POST", "/agents/register")
    signed = identity.SignedRequest(key_id=key.key_id, timestamp=int(headers["X-Secentic-Timestamp"]),
                                    nonce=headers["X-Secentic-Nonce"], signature=headers["X-Secentic-Signature"],
                                    canonical=message)
    with session_factory() as db:
        db.add(Agent(name="half-done", environment="prod", fingerprint="f", status=AgentStatus.pending_review,
                     registration_source=RegistrationSource.api))
        with pytest.raises(RuntimeError):
            identity.verify_signed_request(db, signed, key.public_key, key.key_id)
        db.rollback()  # the request fails
    with session_factory() as db:
        assert db.query(Agent).count() == 0
        assert db.get(UsedNonce, (key.key_id, signed.nonce)) is None


def test_a_signed_request_needs_one_database_connection(session_factory, monkeypatch):
    # With a pool of one connection, a signed request must still succeed: holding one connection
    # while waiting for a second would stall every request once the pool is busy.
    from fastapi.testclient import TestClient
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from app.database import get_db
    from app.main import app
    url = session_factory.kw["bind"].url.render_as_string(hide_password=False)
    args = {"check_same_thread": False} if url.startswith("sqlite") else {}
    engine = create_engine(url, connect_args=args, pool_size=1, max_overflow=0, pool_timeout=2)
    tiny = sessionmaker(autocommit=False, autoflush=False, bind=engine)

    def one_connection_db():
        with tiny() as db:
            yield db

    monkeypatch.setenv("SECENTIC_ADMIN_TOKEN", "test-admin-token")
    monkeypatch.setitem(app.dependency_overrides, get_db, one_connection_db)
    try:
        client = TestClient(app)
        sdk = SecenticClient("http://testserver", AgentKey.generate(), http=client)
        agent = sdk.register("tiny-pool-bot", owner="ali")
        client.post(f"/agents/{agent['id']}/approve", params={"owner": "ali"},
                    headers={"Authorization": "Bearer test-admin-token"}).raise_for_status()
        assert sdk.whoami()["id"] == agent["id"]
    finally:  # also when an assertion fails: a leaked connection would block the PostgreSQL teardown
        engine.dispose()


def test_a_replay_neither_undoes_nor_repeats_the_purge(client, make_agent, session_factory, monkeypatch):
    # The purge of expired nonces commits on its own. A replay refused afterwards does not roll it
    # back, so it is not due again: replays cannot make every request repeat it.
    sdk, _ = make_agent()
    headers, _ = sign_request(sdk.key, "GET", "/identity/whoami")
    assert client.get("/identity/whoami", headers=headers).status_code == 200
    with session_factory() as db:
        db.add(UsedNonce(key_id=sdk.key.key_id, nonce="expired-nonce-0123456789",
                         expires_at=datetime.now(timezone.utc) - timedelta(hours=1)))
        db.commit()
    monkeypatch.setattr(identity, "_next_nonce_purge", 0.0)  # a purge is due
    assert client.get("/identity/whoami", headers=headers).status_code == 401  # the replay is refused ...
    with session_factory() as db:                                              # ... but the purge stands
        assert db.get(UsedNonce, (sdk.key.key_id, "expired-nonce-0123456789")) is None
    assert identity._next_nonce_purge > 0.0  # and is not due again


def test_a_rotation_racing_an_enrolment_of_the_same_key_says_the_key_was_used(client, admin, make_agent, session_factory,
                                                                               monkeypatch):
    # The new key was free when the rotation checked it, and enrolled elsewhere before it committed.
    # (Simulated by letting the check miss a key that is already there: on SQLite, writers take
    # turns, so the two cannot interleave for real.)
    sdk, _ = make_agent()
    other = client.post("/agents", json={"name": "other-bot", "owner": "ali"}, headers=admin).json()
    new_key = AgentKey.generate()
    with session_factory() as concurrent:
        concurrent.add(AgentKeyRow(key_id=new_key.key_id, agent_id=other["id"], public_key=new_key.public_key, status=KeyStatus.revoked))
        concurrent.commit()
    monkeypatch.setattr(identity, "key_was_used", lambda db, key_id: False)  # only the check inside new_agent_key
    response = sdk.request("POST", "/identity/rotate", {"public_key": new_key.public_key}, proof_key=new_key)
    assert response.status_code == 409
    assert response.json()["detail"] == "This public key has already been used; generate a new key pair"