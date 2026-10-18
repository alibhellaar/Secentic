from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..database import get_db
from ..delegation import check_authority, delegations_in_state
from ..identity import SIGNED_REQUEST, AgentPrincipal, authenticate_agent
from ..models import AgentStatus, Delegation, DelegationState, DelegationStatus, utcnow
from ..schemas import (
    AuthorityCheckRequest, AuthorityCheckResponse, DelegationCreate, DelegationResponse, RevokeRequest, error_responses,
)
from .common import ADMIN, ADMIN_ERRORS, AgentId, DelegationId, get_agent_or_404, get_or_404, update_one

router = APIRouter(tags=["delegation"])


def get_delegation_or_404(db: Session, agent_id: str, delegation_id: str) -> Delegation:
    return get_or_404(db, Delegation, delegation_id, "Delegation not found", agent_id=agent_id)


# --- Control plane: administrators record, inspect and revoke delegations -----------------

@router.post("/agents/{agent_id:uuid_id}/delegations", response_model=DelegationResponse, status_code=201,
             dependencies=ADMIN, responses=error_responses(*ADMIN_ERRORS, 404, 409, 400, 413))
def create_delegation(agent_id: AgentId, payload: DelegationCreate, db: Session = Depends(get_db)):
    """Record that a human delegates scoped, time-bound authority to an agent."""
    agent = get_agent_or_404(db, agent_id)
    if agent.status == AgentStatus.pending_review:
        raise HTTPException(status_code=409, detail="Pending agents cannot receive authority; approve the agent first")
    delegation = Delegation(agent_id=agent.id, **payload.model_dump())
    db.add(delegation)
    db.commit()
    db.refresh(delegation)
    return delegation


@router.get("/agents/{agent_id:uuid_id}/delegations", response_model=list[DelegationResponse], dependencies=ADMIN,
            responses=error_responses(*ADMIN_ERRORS, 404))
def list_delegations(agent_id: AgentId, state: DelegationState | None = None, db: Session = Depends(get_db)):
    return delegations_in_state(db, get_agent_or_404(db, agent_id).id, state, utcnow())


@router.get("/agents/{agent_id:uuid_id}/delegations/{delegation_id:uuid_id}", response_model=DelegationResponse,
            dependencies=ADMIN, responses=error_responses(*ADMIN_ERRORS, 404))
def get_delegation(agent_id: AgentId, delegation_id: DelegationId, db: Session = Depends(get_db)):
    return get_delegation_or_404(db, agent_id, delegation_id)


@router.post("/agents/{agent_id:uuid_id}/delegations/{delegation_id:uuid_id}/revoke", response_model=DelegationResponse,
             dependencies=ADMIN, responses=error_responses(*ADMIN_ERRORS, 404, 409, 400, 413))
def revoke_delegation(agent_id: AgentId, delegation_id: DelegationId, payload: RevokeRequest | None = None, db: Session = Depends(get_db)):
    """Withdraw a delegation. It stops granting authority immediately."""
    delegation = get_delegation_or_404(db, agent_id, delegation_id)
    # Only while it is still active, so a revocation landing at the same moment keeps its own time
    # and reason instead of being overwritten.
    active = db.query(Delegation).filter(Delegation.id == delegation.id, Delegation.status == DelegationStatus.active)
    if not update_one(db, active, {Delegation.status: DelegationStatus.revoked, Delegation.revoked_at: utcnow(),
                                   Delegation.revocation_reason: payload.reason if payload else None}):
        raise HTTPException(status_code=409, detail="Delegation is already revoked")
    db.commit()
    db.refresh(delegation)
    return delegation


@router.post("/agents/{agent_id:uuid_id}/check-authority", response_model=AuthorityCheckResponse,
             dependencies=ADMIN, responses=error_responses(*ADMIN_ERRORS, 404, 400, 413))
def check_agent_authority(agent_id: AgentId, payload: AuthorityCheckRequest, db: Session = Depends(get_db)):
    """Dry run: may the agent perform this action on this resource, now or at `at`? Nothing is
    executed or recorded; the M5 gateway makes the same decision for real requests."""
    agent = get_agent_or_404(db, agent_id)
    at = payload.at or utcnow()
    result = check_authority(db, agent, payload.action, payload.resource, at)
    return AuthorityCheckResponse(
        allowed=result.allowed,
        reason=result.reason,
        delegation_id=result.delegation.id if result.delegation else None,
        at=at,
    )


# --- Agent-facing: an agent can see the authority it holds ----------------------------------

@router.get("/identity/delegations", response_model=list[DelegationResponse], responses=error_responses(401, 403, 503),
            openapi_extra=SIGNED_REQUEST)
def my_delegations(principal: AgentPrincipal = Depends(authenticate_agent), db: Session = Depends(get_db)):
    """The calling agent's delegations that are in force now."""
    return delegations_in_state(db, principal.agent.id, DelegationState.active, utcnow())
