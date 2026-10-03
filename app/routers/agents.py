from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from datetime import datetime, timezone

from ..database import get_db
from ..models import Agent, AgentStatus, RegistrationSource
from ..schemas import AgentRegisterRequest, AgentResponse
from ..utils import compute_fingerprint

router = APIRouter(prefix="/agents", tags=["agents"])


@router.post("/register", response_model=AgentResponse)
def register_agent(
    payload: AgentRegisterRequest,
    source: RegistrationSource = RegistrationSource.api,
    db: Session = Depends(get_db),
):
    fingerprint = compute_fingerprint(payload.name, payload.owner, payload.environment)

    existing = db.query(Agent).filter(Agent.fingerprint == fingerprint).first()
    if existing:
        existing.last_seen = datetime.now(timezone.utc)
        db.commit()
        db.refresh(existing)
        return existing

    status = AgentStatus.pending_review if not payload.owner else AgentStatus.active

    new_agent = Agent(
        name=payload.name,
        owner=payload.owner,
        environment=payload.environment,
        fingerprint=fingerprint,
        status=status,
        registration_source=source,
    )
    db.add(new_agent)
    db.commit()
    db.refresh(new_agent)
    return new_agent


@router.get("/", response_model=list[AgentResponse])
def list_agents(status: AgentStatus | None = None, db: Session = Depends(get_db)):
    query = db.query(Agent)
    if status:
        query = query.filter(Agent.status == status)
    return query.all()


@router.get("/review-queue", response_model=list[AgentResponse])
def review_queue(db: Session = Depends(get_db)):
    return db.query(Agent).filter(Agent.status == AgentStatus.pending_review).all()


@router.post("/{agent_id}/approve", response_model=AgentResponse)
def approve_agent(agent_id: str, owner: str, db: Session = Depends(get_db)):
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    agent.owner = owner
    agent.status = AgentStatus.active
    db.commit()
    db.refresh(agent)
    return agent