import os

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import sessionmaker

from app.database import Base, get_db, make_engine
from app.main import app
from secentic_sdk import AgentKey, SecenticClient

ADMIN_TOKEN = "test-admin-token"


@pytest.fixture
def session_factory(tmp_path):
    """Sessions on a fresh database per test, never the configured one.

    Uses a temporary SQLite file, or TEST_DATABASE_URL (e.g. a PostgreSQL database whose
    tables are dropped after each test) when set.
    """
    engine = make_engine(os.getenv("TEST_DATABASE_URL") or f"sqlite:///{tmp_path / 'test.db'}")
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.drop_all(bind=engine)
    engine.dispose()


@pytest.fixture
def client(session_factory, monkeypatch):
    monkeypatch.setenv("SECENTIC_ADMIN_TOKEN", ADMIN_TOKEN)

    def override_get_db():
        db = session_factory()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    yield TestClient(app)
    app.dependency_overrides.clear()


@pytest.fixture
def admin():
    return {"Authorization": f"Bearer {ADMIN_TOKEN}"}


@pytest.fixture
def trust(client, admin):
    """Mark a tool trusted, naming the definition that was reviewed (as a reviewer would)."""
    def _trust(name, reason="Reviewed"):
        reviewed = client.get(f"/tools/{name}", headers=admin).json()["definition_hash"]
        response = client.post(f"/tools/{name}/trust", headers=admin,
                               json={"trust_state": "trusted", "reviewed_definition": reviewed, "reason": reason})
        response.raise_for_status()
        return response.json()
    return _trust


@pytest.fixture
def make_agent(client, admin):
    """Registers an agent with a fresh key through the SDK, approving it unless told not to."""
    def _make(name="agent", environment="test", approve=True):
        sdk = SecenticClient("http://testserver", AgentKey.generate(), http=client)
        agent = sdk.register(name, environment=environment, owner="ali")
        if approve:
            r = client.post(f"/agents/{agent['id']}/approve", params={"owner": "ali"}, headers=admin)
            r.raise_for_status()
            agent = r.json()
        return sdk, agent
    return _make
