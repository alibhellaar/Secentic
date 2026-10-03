from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_register_new_agent():
    response = client.post("/agents/register?source=api", json={
        "name": "test-agent-1", "owner": "areeb", "environment": "test"
    })
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "active"


def test_duplicate_registration_does_not_create_second_row():
    payload = {"name": "test-agent-dedup", "owner": "bhellar", "environment": "test"}
    r1 = client.post("/agents/register?source=api", json=payload)
    r2 = client.post("/agents/register?source=api", json=payload)
    assert r1.json()["id"] == r2.json()["id"]


def test_unowned_agent_goes_to_review_queue():
    response = client.post("/agents/register?source=sdk", json={
        "name": "shadow-agent", "environment": "test"
    })
    assert response.json()["status"] == "pending_review"