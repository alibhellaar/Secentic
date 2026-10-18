"""What every router shares: the admin dependency, path ID types, and small database helpers."""
from collections.abc import Callable
from typing import Annotated

from fastapi import Depends, HTTPException, Path
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from starlette.convertors import Convertor, register_url_convertor

from ..admin_auth import require_admin
from ..models import Agent
from ..schemas import KEY_ID_REGEX, UUID_REGEX

# Control-plane endpoints declare `dependencies=ADMIN`; agent endpoints depend on authenticate_agent.
ADMIN = [Depends(require_admin)]
ADMIN_ERRORS = (401, 503)


class PathIdConvertor(Convertor):
    """Matches only well-formed IDs in paths. A path like /agents/register is then never read as
    an agent ID (it gets 405 for the wrong method instead of 404), and malformed IDs, NUL
    characters included, get 404 without reaching the database."""

    def __init__(self, regex: str):
        self.regex = regex

    def convert(self, value: str) -> str:
        return value

    def to_string(self, value: str) -> str:
        return value


register_url_convertor("uuid_id", PathIdConvertor(UUID_REGEX))
register_url_convertor("key_id", PathIdConvertor(KEY_ID_REGEX))

# Path parameter types; routes write them as {agent_id:uuid_id}, {delegation_id:uuid_id}, {key_id:key_id}.
AgentId = Annotated[str, Path(pattern=f"^{UUID_REGEX}$", description="Agent ID (UUID)")]
DelegationId = Annotated[str, Path(pattern=f"^{UUID_REGEX}$", description="Delegation ID (UUID)")]
KeyId = Annotated[str, Path(pattern=f"^{KEY_ID_REGEX}$", description="Key ID: SHA-256 (hex) of the public key")]


def get_or_404(db: Session, model, key, detail: str, agent_id: str | None = None):
    """The row with this primary key, or 404 with `detail`. With `agent_id`, the row must also belong
    to that agent (the same 404 otherwise, so other agents' IDs reveal nothing)."""
    row = db.get(model, key)
    if row is None or (agent_id is not None and row.agent_id != agent_id):
        raise HTTPException(status_code=404, detail=detail)
    return row


def get_agent_or_404(db: Session, agent_id: str) -> Agent:
    return get_or_404(db, Agent, agent_id, "Agent not found")


def update_one(db: Session, query, values: dict) -> bool:
    """Apply `values` with one conditional UPDATE of the single row `query` selects. Its filter
    states what must still hold (e.g. status == 'active'), so a concurrent change can never be
    overwritten: when no row matches, everything is rolled back and the result is False."""
    if query.update(values, synchronize_session=False) == 1:
        return True
    db.rollback()
    return False


def commit_or_409(db: Session, detail: str | Callable[[], str]) -> None:
    """Commit, turning a unique-constraint clash with a concurrent request into a 409. When several
    constraints could clash, `detail` is a function, called after the rollback, that says which."""
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail=detail() if callable(detail) else detail) from None
