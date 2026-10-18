from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import delete
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, selectinload

from ..crypto import load_public_key
from ..database import get_db
from ..identity import (
    KEY_ALREADY_USED, OPTIONALLY_SIGNED_REQUEST, SignedRequest, key_was_used, new_agent_key, optional_signed_request,
    signed_by_enrolled_key, verify_signed_request,
)
from ..models import Agent, AgentKey, AgentStatus, RegistrationSource, RetiredKey, utcnow
from ..schemas import (
    AgentOnboardRequest, AgentRegisterRequest, AgentResponse, AgentStatusUpdate, NonBlankStr,
    OwnerUpdate, SelfRegistrationSource, error_responses,
)
from ..utils import compute_fingerprint
from .common import ADMIN, ADMIN_ERRORS, AgentId, commit_or_409, get_agent_or_404, update_one


router = APIRouter(prefix="/agents", tags=["agents"])
SWITCHED_OFF = (AgentStatus.inactive, AgentStatus.disabled)
SIGNED_WITHOUT_KEY = ("A signed registration must include the public_key it was signed with; only an existing agent's "
                      "enrolled key can sign without it")


@router.post("/register", response_model=AgentResponse, responses=error_responses(401, 403, 409, 400, 413, 503),
             openapi_extra=OPTIONALLY_SIGNED_REQUEST)
def register_agent(
    payload: AgentRegisterRequest,
    source: SelfRegistrationSource = SelfRegistrationSource.api,
    signed: SignedRequest | None = Depends(optional_signed_request),
    db: Session = Depends(get_db),
):
    """Self-registration by an agent. New agents wait in the review queue, even if they claim an
    owner; an administrator confirms the owner through /approve. Once registered, an agent can
    only re-register (refreshing last_seen) with a request signed by its enrolled key.

    When `public_key` is sent, the request must be signed with that key (all four signature headers).
    An existing agent may also leave it out and simply sign with its enrolled key."""
    fingerprint = compute_fingerprint(payload.name, payload.environment)
    agent = db.query(Agent).filter(Agent.fingerprint == fingerprint).first()
    # Signed with the agent's enrolled key, it is refreshed as alive in the commit that spends the
    # nonce; a switched-off agent never is.
    refresh = agent if agent is not None and agent.status not in SWITCHED_OFF else None

    key_id = None
    if payload.public_key:
        # Proof of possession: the registration must be signed by the key being enrolled.
        _, key_id = load_public_key(payload.public_key)
        enrolled = agent is not None and agent.active_key_id == key_id
        verify_signed_request(db, signed, payload.public_key, key_id, seen=refresh if enrolled else None)
    elif signed is not None:
        # Signed, without a key to check the signature against: only an existing agent's enrolled
        # key can be checked. Every other case, replays included, gets one answer whether or not
        # the name exists, so signatures cannot be used to find out which names are taken.
        if agent is None or not signed_by_enrolled_key(db, agent, signed, seen=refresh):
            raise HTTPException(status_code=401, detail=SIGNED_WITHOUT_KEY)
        key_id = agent.active_key_id

    if agent is not None:
        # Only the agent's own enrolled key speaks for an existing record. Every other case gets
        # the same answer, so callers learn nothing about its owner, status or keys, and cannot
        # attach a key to it or fake its liveness. Keys for existing agents are bound by an admin.
        if key_id is None or agent.active_key_id != key_id:
            raise HTTPException(status_code=409, detail="Agent is already registered; re-registration must be signed with its enrolled key")
        if agent.status in SWITCHED_OFF:
            # Only the agent's own key gets this far. A switched-off agent is not refreshed as alive.
            raise HTTPException(status_code=403, detail=f"Agent is {agent.status.value}")
        return agent  # last_seen was refreshed together with the nonce

    now = utcnow()
    agent = Agent(
        name=payload.name,
        owner=payload.owner,
        environment=payload.environment,
        fingerprint=fingerprint,
        status=AgentStatus.pending_review,
        registration_source=RegistrationSource(source.value),
        first_seen=now,
        last_seen=now,
    )
    db.add(agent)
    if payload.public_key:
        new_agent_key(db, agent, payload.public_key)
    # A concurrent registration may have taken the name, or enrolled the same key under another name.
    commit_or_409(db, lambda: KEY_ALREADY_USED if key_id and key_was_used(db, key_id) else "Agent is already registered")
    db.refresh(agent)
    return agent


@router.post("", response_model=AgentResponse, status_code=201, dependencies=ADMIN,
             responses=error_responses(*ADMIN_ERRORS, 409, 400, 413))
def onboard_agent(payload: AgentOnboardRequest, db: Session = Depends(get_db)):
    """Manual onboarding by an administrator. The agent is created already approved."""
    fingerprint = compute_fingerprint(payload.name, payload.environment)
    if db.query(Agent).filter(Agent.fingerprint == fingerprint).first():
        raise HTTPException(status_code=409, detail="Agent is already in the inventory")

    now = utcnow()
    agent = Agent(
        name=payload.name,
        owner=payload.owner,
        environment=payload.environment,
        fingerprint=fingerprint,
        status=AgentStatus.active,
        registration_source=RegistrationSource.manual,
        first_seen=now,
        last_seen=now,
    )
    db.add(agent)
    commit_or_409(db, "Agent is already in the inventory")
    db.refresh(agent)
    return agent


@router.get("", response_model=list[AgentResponse], dependencies=ADMIN,
            responses=error_responses(*ADMIN_ERRORS))
def list_agents(status: AgentStatus | None = None, db: Session = Depends(get_db)):
    query = db.query(Agent).options(selectinload(Agent.active_key))  # active_key_id, without a query per agent
    if status:
        query = query.filter(Agent.status == status)
    return query.all()


@router.get("/review-queue", response_model=list[AgentResponse], dependencies=ADMIN,
            responses=error_responses(*ADMIN_ERRORS))
def review_queue(db: Session = Depends(get_db)):
    return db.query(Agent).options(selectinload(Agent.active_key)).filter(Agent.status == AgentStatus.pending_review).all()


@router.get("/{agent_id:uuid_id}", response_model=AgentResponse, dependencies=ADMIN,
            responses=error_responses(*ADMIN_ERRORS, 404))
def get_agent(agent_id: AgentId, db: Session = Depends(get_db)):
    return get_agent_or_404(db, agent_id)


@router.delete("/{agent_id:uuid_id}", status_code=204, dependencies=ADMIN,
               responses=error_responses(*ADMIN_ERRORS, 404, 409))
def reject_registration(agent_id: AgentId, db: Session = Depends(get_db)):
    """Reject a pending registration: the record is deleted, freeing the name (e.g. after someone
    registered under another team's agent name). Its key is retired for good, so it can never be
    enrolled again, under this name or any other."""
    agent = get_agent_or_404(db, agent_id)
    if agent.status != AgentStatus.pending_review:
        raise HTTPException(status_code=409, detail="Only pending registrations can be rejected; disable approved agents instead")
    changed = HTTPException(status_code=409, detail="The registration was approved or rejected while this rejection "
                                                    "was in progress; nothing was changed")
    try:
        # The keys are retired from the very rows deleted (DELETE ... RETURNING), so a key bound
        # meanwhile cannot be deleted without being retired.
        key_ids = db.execute(delete(AgentKey).where(AgentKey.agent_id == agent.id).returning(AgentKey.key_id)).scalars().all()
        # Only while it is still pending: an approval landing at the same moment must not be undone.
        deleted = (db.query(Agent).filter(Agent.id == agent.id, Agent.status == AgentStatus.pending_review)
                   .delete(synchronize_session=False))
    except IntegrityError:  # e.g. a key bound to it at that very moment (PostgreSQL)
        db.rollback()
        raise changed from None
    if deleted != 1:
        db.rollback()
        raise changed
    db.add_all(RetiredKey(key_id=key_id, reason=f"Registration of '{agent.name}' ({agent.environment}) was rejected")
               for key_id in key_ids)
    commit_or_409(db, "The registration was rejected concurrently; nothing was changed")


@router.post("/{agent_id:uuid_id}/approve", response_model=AgentResponse, dependencies=ADMIN,
             responses=error_responses(*ADMIN_ERRORS, 404, 409))
def approve_agent(agent_id: AgentId, owner: Annotated[NonBlankStr, Query()], db: Session = Depends(get_db)):
    agent = get_agent_or_404(db, agent_id)
    if agent.status != AgentStatus.pending_review:
        raise HTTPException(status_code=409, detail=f"Only pending_review agents can be approved (agent is {agent.status.value})")
    # Only while it is still pending, so a rejection or another approval landing at the same moment
    # is never overwritten.
    pending = db.query(Agent).filter(Agent.id == agent.id, Agent.status == AgentStatus.pending_review)
    if not update_one(db, pending, {Agent.owner: owner, Agent.status: AgentStatus.active}):
        status = db.query(Agent.status).filter(Agent.id == agent_id).scalar()
        if status is None:
            raise HTTPException(status_code=404, detail="Agent not found")
        raise HTTPException(status_code=409, detail=f"Only pending_review agents can be approved (agent is {status.value})")
    db.commit()
    db.refresh(agent)
    return agent


@router.put("/{agent_id:uuid_id}/owner", response_model=AgentResponse, dependencies=ADMIN,
            responses=error_responses(*ADMIN_ERRORS, 404, 409, 400, 413))
def change_owner(agent_id: AgentId, payload: OwnerUpdate, db: Session = Depends(get_db)):
    """Correct or reassign the owner of an approved agent."""
    agent = get_agent_or_404(db, agent_id)
    if agent.status == AgentStatus.pending_review:
        raise HTTPException(status_code=409, detail="Pending agents get their owner through /approve")
    agent.owner = payload.owner
    db.commit()
    db.refresh(agent)
    return agent


@router.post("/{agent_id:uuid_id}/status", response_model=AgentResponse, dependencies=ADMIN,
             responses=error_responses(*ADMIN_ERRORS, 404, 409, 400, 413))
def set_agent_status(agent_id: AgentId, payload: AgentStatusUpdate, db: Session = Depends(get_db)):
    """Move an approved agent between active, inactive and disabled."""
    agent = get_agent_or_404(db, agent_id)
    if agent.status == AgentStatus.pending_review:
        # Every non-pending agent has an owner an admin confirmed; this keeps it that way.
        raise HTTPException(status_code=409, detail="Pending agents must be approved via /approve first")
    agent.status = AgentStatus(payload.status.value)
    db.commit()
    db.refresh(agent)
    return agent
