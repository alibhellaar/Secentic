import pytest

CRM = {"name": "crm", "kind": "tool", "provider": "internal", "endpoint": "https://crm.internal.example/api",
       "version": "2.1.0", "capabilities": ["read", "crm:update"], "resources": ["crm:*"], "description": "Customer records"}


@pytest.fixture
def register(client, admin):
    def _register(**overrides):
        return client.post("/tools", json=CRM | overrides, headers=admin)
    return _register


def definition(**overrides):
    """CRM's definition without its name, as PUT /tools/{name} takes it."""
    return {k: v for k, v in (CRM | overrides).items() if k != "name"}


# --- Registry ---------------------------------------------------------------------------------

def test_registered_tool_starts_unknown(register):
    response = register()
    assert response.status_code == 201
    tool = response.json()
    assert tool["trust_state"] == "unknown"
    assert tool["capabilities"] == ["read", "crm:update"]


def test_tool_names_are_unique(register):
    register()
    assert register().status_code == 409


def test_mcp_server_can_be_registered(register):
    mcp = register(name="github-mcp", kind="mcp_server", endpoint="stdio: npx @modelcontextprotocol/server-github",
                   capabilities=["github.create_issue", "github.read_repo"])
    assert mcp.status_code == 201 and mcp.json()["kind"] == "mcp_server"


@pytest.mark.parametrize("name", ["CRM", "my tool", "", "-crm", "c" * 65, "crm/x"])
def test_malformed_tool_names_refused(register, name):
    assert register(name=name).status_code == 422


@pytest.mark.parametrize("capabilities", [[], ["*"], ["read*"], ["send email"]])
def test_malformed_capabilities_refused(register, capabilities):
    assert register(capabilities=capabilities).status_code == 422


@pytest.mark.parametrize("resources", [[], ["*"], ["crm:accounts/../x"], ["crm:accounts//x"], ["crm accounts"]])
def test_malformed_tool_resources_refused(register, resources):
    assert register(resources=resources).status_code == 422


def test_resources_are_required_and_part_of_the_reviewed_definition(client, admin, register):
    assert register(resources=None).status_code == 422
    original = register().json()
    assert original["resources"] == ["crm:*"]
    widened = client.put("/tools/crm", json=definition(resources=["crm:*", "hr:*"]), headers=admin).json()
    assert widened["definition_hash"] != original["definition_hash"]


def test_list_get_and_filter_tools(client, admin, register, trust):
    register()
    register(name="mail", capabilities=["email.send"])
    trust("mail")
    assert [t["name"] for t in client.get("/tools", headers=admin).json()] == ["crm", "mail"]
    assert [t["name"] for t in client.get("/tools", params={"trust_state": "trusted"}, headers=admin).json()] == ["mail"]
    assert client.get("/tools/crm", headers=admin).json()["version"] == "2.1.0"
    assert client.get("/tools/nope", headers=admin).status_code == 404
    assert client.get("/tools/NOT-A-NAME", headers=admin).status_code == 404


def test_trust_review_is_recorded(register, trust):
    register()
    tool = trust("crm", reason="Reviewed by security team")
    assert tool["trust_state"] == "trusted" and tool["trust_reason"] == "Reviewed by security team"


def test_trusting_requires_the_reviewed_definition(client, admin, register):
    current = register().json()["definition_hash"]
    url = "/tools/crm/trust"
    assert client.post(url, json={"trust_state": "trusted"}, headers=admin).status_code == 422
    assert client.post(url, json={"trust_state": "trusted", "reviewed_definition": "0" * 64}, headers=admin).status_code == 409
    assert client.post(url, json={"trust_state": "trusted", "reviewed_definition": current}, headers=admin).status_code == 200
    # Blocking or suspecting a tool never needs it, so it is never held up.
    assert client.post(url, json={"trust_state": "blocked"}, headers=admin).status_code == 200


def test_a_review_of_an_older_definition_cannot_trust_a_newer_one(client, admin, register):
    reviewed = register().json()["definition_hash"]  # the reviewer looks at version 2.1.0 ...
    client.put("/tools/crm", json=definition(endpoint="https://evil.example/api"), headers=admin)  # ... it changes ...
    response = client.post("/tools/crm/trust", json={"trust_state": "trusted", "reviewed_definition": reviewed}, headers=admin)
    assert response.status_code == 409  # ... so the approval does not apply to what is there now
    assert client.get("/tools/crm", headers=admin).json()["trust_state"] == "unknown"


def test_an_approval_racing_an_update_cannot_trust_the_new_definition(client, admin, register, session_factory, monkeypatch):
    # The reviewer approves version 2.1.0 while an update to an unreviewed endpoint is being saved.
    # Whichever lands second must not leave the tool trusted with the new definition.
    import app.routers.tools as tools_router
    from app.models import Tool, TrustState
    reviewed = register().json()["definition_hash"]
    real_update = tools_router.definition_update

    def approve_meanwhile(tool, definition):
        values = real_update(tool, definition)
        response = client.post("/tools/crm/trust", json={"trust_state": "trusted", "reviewed_definition": reviewed}, headers=admin)
        assert response.status_code == 200  # the approval of what was reviewed lands first
        return values

    monkeypatch.setattr(tools_router, "definition_update", approve_meanwhile)
    response = client.put("/tools/crm", json=definition(endpoint="https://evil.example/api"), headers=admin)
    assert response.status_code == 409
    with session_factory() as db:
        tool = db.get(Tool, "crm")
        assert tool.trust_state == TrustState.trusted and tool.endpoint == "https://crm.internal.example/api"


def test_definition_hash_tracks_only_the_reviewed_fields(client, admin, register):
    original = register().json()["definition_hash"]
    assert client.put("/tools/crm", json=definition(description="New words"), headers=admin).json()["definition_hash"] == original
    assert client.put("/tools/crm", json=definition(version="2.2.0"), headers=admin).json()["definition_hash"] != original


# --- Rug pull: a trusted tool cannot change what it is without a new review ----------------------

@pytest.mark.parametrize("change", [{"version": "2.2.0"}, {"endpoint": "https://evil.example/api"},
                                    {"capabilities": ["read", "crm:update", "crm:delete"]}, {"provider": "someone-else"},
                                    {"resources": ["crm:*", "hr:*"]},
                                    {"kind": "mcp_server"}])
def test_changing_a_trusted_tool_resets_its_trust(client, admin, register, trust, change):
    register()
    trust("crm")
    tool = client.put("/tools/crm", json=definition(**change), headers=admin).json()
    assert tool["trust_state"] == "unknown"
    assert tool["trust_reason"].startswith("Definition changed")


def test_unchanged_or_description_only_update_keeps_trust(client, admin, register, trust):
    register()
    trust("crm")
    assert client.put("/tools/crm", json=definition(), headers=admin).json()["trust_state"] == "trusted"
    assert client.put("/tools/crm", json=definition(description="Better words"), headers=admin).json()["trust_state"] == "trusted"


def test_changing_a_blocked_tool_does_not_unblock_it(client, admin, register):
    register()
    client.post("/tools/crm/trust", json={"trust_state": "blocked", "reason": "exfiltration seen"}, headers=admin)
    assert client.put("/tools/crm", json=definition(version="9.9.9"), headers=admin).json()["trust_state"] == "blocked"


# --- Which agent may use which tool -------------------------------------------------------------

def test_assign_list_and_unassign_tools(client, admin, register, make_agent):
    register()
    _, agent = make_agent()
    url = f"/agents/{agent['id']}/tools/crm"
    first = client.put(url, headers=admin)
    assert first.status_code == 200
    assert client.put(url, headers=admin).json()["assigned_at"] == first.json()["assigned_at"]  # idempotent
    assert [t["name"] for t in client.get(f"/agents/{agent['id']}/tools", headers=admin).json()] == ["crm"]
    assert client.delete(url, headers=admin).status_code == 204
    assert client.delete(url, headers=admin).status_code == 404
    assert client.get(f"/agents/{agent['id']}/tools", headers=admin).json() == []


def test_assignment_refused_for_pending_agents_blocked_or_unknown_tools(client, admin, register, make_agent):
    register()
    _, pending = make_agent(name="pending", approve=False)
    assert client.put(f"/agents/{pending['id']}/tools/crm", headers=admin).status_code == 409
    _, agent = make_agent()
    assert client.put(f"/agents/{agent['id']}/tools/nope", headers=admin).status_code == 404
    client.post("/tools/crm/trust", json={"trust_state": "blocked"}, headers=admin)
    assert client.put(f"/agents/{agent['id']}/tools/crm", headers=admin).status_code == 409


def test_agent_sees_only_its_own_tools(client, admin, register, make_agent):
    register()
    register(name="mail", capabilities=["email.send"])
    sdk_a, a = make_agent(name="a")
    _, b = make_agent(name="b")
    client.put(f"/agents/{a['id']}/tools/crm", headers=admin)
    client.put(f"/agents/{b['id']}/tools/mail", headers=admin)
    assert [t["name"] for t in sdk_a.tools()] == ["crm"]
    assert client.get("/identity/tools").status_code == 401


def test_agents_cannot_manage_the_registry(make_agent):
    sdk, agent = make_agent()
    assert sdk.request("POST", "/tools", CRM).status_code == 401
    assert sdk.request("PUT", f"/agents/{agent['id']}/tools/crm").status_code == 401
