"""Malformed, oversized or hostile input is refused with a 4xx, never a server error.

TestClient re-raises server exceptions, so any of these that crashed would fail with the error.
Some only crashed on PostgreSQL (NUL characters); run the suite there too.
"""
from datetime import datetime, timedelta, timezone

import pytest

from app.request_guards import MAX_BODY_BYTES

NUL = "\u0000"


def in_days(days: float) -> str:
    return (datetime.now(timezone.utc) + timedelta(days=days)).isoformat()


# --- Control characters (NUL included) --------------------------------------------------------

@pytest.mark.parametrize("field, value", [
    ("name", f"a{NUL}b"), ("environment", f"p{NUL}"), ("owner", f"x{NUL}"),
    ("name", "line1\nline2"), ("name", "tab\there"), ("name", "bell\x07"),
])
def test_control_characters_refused_in_registration(client, field, value):
    assert client.post("/agents/register", json={"name": "bot"} | {field: value}).status_code == 422


def test_control_characters_refused_in_admin_input(client, admin, make_agent):
    _, pending = make_agent(name="pending", approve=False)
    assert client.post(f"/agents/{pending['id']}/approve", params={"owner": f"a{NUL}"}, headers=admin).status_code == 422

    sdk, agent = make_agent()
    a = agent["id"]
    assert client.post("/agents/", json={"name": f"o{NUL}", "owner": "ali"}, headers=admin).status_code == 422
    assert client.put(f"/agents/{a}/owner", json={"owner": f"a{NUL}"}, headers=admin).status_code == 422
    revoke_key = f"/agents/{a}/keys/{sdk.key.key_id}/revoke"
    assert client.post(revoke_key, json={"reason": f"r{NUL}"}, headers=admin).status_code == 422

    delegation = {"delegator": "ali", "task": "t", "actions": ["read"], "resources": ["crm:a"], "expires_at": in_days(1)}
    for field in ("delegator", "task"):
        assert client.post(f"/agents/{a}/delegations", json=delegation | {field: f"x{NUL}"}, headers=admin).status_code == 422
    created = client.post(f"/agents/{a}/delegations", json=delegation, headers=admin).json()
    revoke_delegation = f"/agents/{a}/delegations/{created['id']}/revoke"
    assert client.post(revoke_delegation, json={"reason": f"r{NUL}"}, headers=admin).status_code == 422


def test_malformed_ids_in_paths_not_found(client, admin, make_agent):
    # Only well-formed IDs match a route, so anything else is a 404 that never reaches the database.
    _, agent = make_agent()
    a = agent["id"]
    for method, path in [
        ("GET", "/agents/%00"),
        ("DELETE", "/agents/%00"),
        ("GET", "/agents/%00/keys"),
        ("POST", f"/agents/{a}/keys/%00/revoke"),
        ("GET", f"/agents/{a}/delegations/%00"),
        ("POST", f"/agents/{a}/delegations/%00/revoke"),
        ("GET", "/agents/" + "a" * 65),
    ]:
        assert client.request(method, path, headers=admin).status_code == 404, path


# --- Size -------------------------------------------------------------------------------------

def test_text_length_limits(client, admin, make_agent):
    assert client.post("/agents/register", json={"name": "n" * 200}).status_code == 200
    assert client.post("/agents/register", json={"name": "m" * 201}).status_code == 422

    _, agent = make_agent()
    delegation = {"delegator": "ali", "actions": ["read"], "resources": ["crm:a"], "expires_at": in_days(1)}
    assert client.post(f"/agents/{agent['id']}/delegations", json=delegation | {"task": "t" * 500}, headers=admin).status_code == 201
    assert client.post(f"/agents/{agent['id']}/delegations", json=delegation | {"task": "t" * 501}, headers=admin).status_code == 422


def test_oversized_body_refused(client):
    body = b'{"name": "' + b"x" * MAX_BODY_BYTES + b'"}'
    response = client.post("/agents/register", content=body, headers={"Content-Type": "application/json"})
    assert response.status_code == 413


def test_oversized_body_without_content_length_refused(client):
    def chunks():  # an iterator is sent chunked, with no Content-Length to check up front
        yield b'{"name": "'
        for _ in range(MAX_BODY_BYTES // 1024 + 1):
            yield b"x" * 1024
        yield b'"}'
    response = client.post("/agents/register", content=chunks(), headers={"Content-Type": "application/json"})
    assert response.status_code == 413


def test_body_just_under_the_limit_accepted(client):
    body = b'{"name": "bot"' + b" " * (MAX_BODY_BYTES - 100) + b"}"
    assert client.post("/agents/register", content=body, headers={"Content-Type": "application/json"}).status_code == 200


@pytest.mark.parametrize("depth", [1_000, 5_000, 30_000])
def test_deeply_nested_json_refused_without_server_error(client, depth):
    body = b"[" * depth + b"]" * depth
    response = client.post("/agents/register", content=body, headers={"Content-Type": "application/json"})
    assert response.status_code in (400, 422)



@pytest.mark.parametrize("path, body", [
    ("/agents/register", '{"name": "\\ud800"}'),                                        # one-line text
    ("/agents/register", '{"name": "bot", "environment": "\\udfff"}'),                  # environment
    ("/agents/register", '{"name": "bot", "public_key": "\\ud800"}'),                   # public key
    ("/agents", '{"name": "bot", "owner": "a\\ud83d"}'),                                # admin onboarding
])
def test_lone_surrogates_are_refused_without_server_error(client, admin, path, body):
    # Valid JSON, but no valid text: refused, and the 422 does not try to echo it back.
    response = client.post(path, content=body.encode(), headers={"Content-Type": "application/json"} | admin)
    assert response.status_code == 422
    assert all("input" not in error for error in response.json()["detail"])


@pytest.mark.parametrize("body, content_type", [
    (b"\xff\xfe{", "text/plain"),                     # not UTF-8, and not declared as JSON
    (b"\xff\xfe{", "application/octet-stream"),
    (b"\xff\xfe{", None),
    (b'{"name": NaN}', "application/json"),           # Python's JSON parser accepts these ...
    (b'{"name": -Infinity}', "application/json"),     # ... but a JSON response cannot carry them
    (b'{"name": 1e999}', "application/json"),
    (b'{"name": ' + b"9" * 4000 + b"}", "application/json"),
])
def test_invalid_input_json_cannot_carry_is_refused_without_server_error(client, body, content_type):
    headers = {"Content-Type": content_type} if content_type else {}
    response = client.post("/agents/register", content=body, headers=headers)
    assert response.status_code in (400, 422)
    assert all("input" not in error or isinstance(error["input"], (int, str)) for error in response.json()["detail"])


# --- Routing ------------------------------------------------------------------------------------

def test_wrong_method_gets_405_with_every_allowed_method(client, admin, make_agent):
    _, agent = make_agent()
    for method, path, allowed in [
        ("GET", "/agents/register", "POST"),
        ("DELETE", "/agents/review-queue", "GET"),
        ("PATCH", f"/agents/{agent['id']}", "DELETE, GET"),
        ("PUT", "/agents/", "GET, POST"),
        ("DELETE", f"/agents/{agent['id']}/keys", "GET, POST"),
        ("POST", "/docs", "GET, HEAD"),
        ("POST", "/openapi.json", "GET, HEAD"),
        ("PUT", "/health", "GET, HEAD"),
    ]:
        response = client.request(method, path, headers=admin)
        assert response.status_code == 405, (method, path)
        assert response.headers["allow"] == allowed, (method, path)


@pytest.mark.parametrize("path", ["/agents", "/agents/", "/tools", "/tools/", "/agents/review-queue/", "/policy/"])
def test_trailing_slash_is_ignored_without_a_redirect(client, admin, path):
    response = client.get(path, headers=admin, follow_redirects=False)
    assert response.status_code == 200
    assert client.get(path, follow_redirects=False).status_code == 401  # and still needs the admin token


def test_trailing_slash_creates_like_the_plain_path(client, admin):
    assert client.post("/agents/", json={"name": "ops", "owner": "ali"}, headers=admin).status_code == 201
    assert client.post("/agents", json={"name": "ops2", "owner": "ali"}, headers=admin).status_code == 201


def test_every_route_is_declared_once(client):
    # Trailing slashes are handled in one place, so no route has a hidden twin to keep in sync.
    paths = client.get("/openapi.json").json()["paths"]
    assert not [path for path in paths if path != "/" and path.endswith("/")]


def test_health_answers_head_requests(client):
    response = client.head("/health")
    assert response.status_code == 200 and response.content == b""


def test_timestamps_must_be_strings(client, admin, make_agent):
    # A Unix time one day ahead would be a valid window if numbers were read as timestamps.
    _, agent = make_agent()
    tomorrow = int(datetime.now(timezone.utc).timestamp()) + 86_400
    body = {"delegator": "ali", "task": "t", "actions": ["read"], "resources": ["crm:a"], "expires_at": tomorrow}
    assert client.post(f"/agents/{agent['id']}/delegations", json=body, headers=admin).status_code == 422
    check = {"action": "read", "resource": "crm:a", "at": tomorrow}
    assert client.post(f"/agents/{agent['id']}/check-authority", json=check, headers=admin).status_code == 422


def test_the_forbidden_character_table_covers_this_pythons_unicode():
    # app.schemas.FORBIDDEN_RANGES was generated once; a newer Python may know new format
    # characters. If this fails, regenerate the table from forbidden_code_points().
    from app.schemas import FORBIDDEN_RANGES, forbidden_code_points
    table = set()
    for first, last in FORBIDDEN_RANGES:
        table.update(range(first, last + 1))
    assert forbidden_code_points() <= table
