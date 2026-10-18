import logging
import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from ..database import get_db
from ..gateway import FAIL_CLOSED_REASON, decide
from ..identity import SIGNED_REQUEST, AgentPrincipal, authenticate_agent
from ..models import Decision, GatewayDecision, utcnow
from ..schemas import UUID_PATTERN, ActionRequest, DecisionResponse, SimulationRequest, error_responses
from .common import ADMIN, ADMIN_ERRORS, get_agent_or_404

router = APIRouter(prefix="/gateway", tags=["gateway"])
logger = logging.getLogger("secentic.gateway")


@router.post("/authorize", response_model=DecisionResponse, responses=error_responses(401, 403, 400, 413, 503),
             openapi_extra=SIGNED_REQUEST)
def authorize(payload: ActionRequest, principal: AgentPrincipal = Depends(authenticate_agent), db: Session = Depends(get_db)):
    """Ask before acting: may the calling agent use this tool to perform this action on this
    resource? Proceed only on `allow`. Every decision is recorded. If the gateway cannot decide it
    answers 503, which the agent must treat as a denial (fail closed)."""
    try:
        result = decide(db, principal.agent, payload.tool, payload.action, payload.resource)
        record = GatewayDecision(
            id=str(uuid.uuid4()),
            decided_at=utcnow(),
            agent_id=principal.agent.id,
            key_id=principal.key.key_id,
            tool=payload.tool,
            action=payload.action,
            resource=payload.resource,
            decision=result.decision,
            reasons=result.reasons,
            matched_rules=result.matched_rules,
            delegation_id=result.delegation_id,
            policy_version=result.policy_version,
        )
        # The answer is built from the record before it is stored: once the commit succeeds, the
        # agent is told exactly what the decision log says, and nothing is read back afterwards
        # (a failure there would deny an action the log shows as allowed).
        answer = DecisionResponse.model_validate(record)
        db.add(record)
        db.commit()
    except Exception:  # anything unexpected: no decision can be trusted, so deny
        db.rollback()
        logger.exception("Gateway could not decide; failing closed")
        raise HTTPException(status_code=503, detail=FAIL_CLOSED_REASON) from None
    return answer


@router.post("/simulate", response_model=DecisionResponse, dependencies=ADMIN,
             responses=error_responses(*ADMIN_ERRORS, 404, 400, 413))
def simulate(payload: SimulationRequest, db: Session = Depends(get_db)):
    """Dry run for administrators: the decision the gateway would make for this agent, now or at
    `at`. With `at`, the delegations and the policy version in force at that moment are used; the
    agent's status, its tools and their trust are taken as they are now (they keep no history yet).
    Nothing is recorded and nothing is executed."""
    agent = get_agent_or_404(db, payload.agent_id)
    at = payload.at or utcnow()
    try:
        result = decide(db, agent, payload.tool, payload.action, payload.resource, at)
    except Exception:
        logger.exception("Gateway simulation could not decide")
        raise HTTPException(status_code=503, detail=FAIL_CLOSED_REASON) from None
    return DecisionResponse(
        id=None, agent_id=agent.id, tool=payload.tool, action=payload.action, resource=payload.resource,
        decision=result.decision, reasons=result.reasons, matched_rules=result.matched_rules,
        delegation_id=result.delegation_id, policy_version=result.policy_version, decided_at=at,
    )


@router.get("/decisions", response_model=list[DecisionResponse], dependencies=ADMIN,
            responses=error_responses(*ADMIN_ERRORS))
def list_decisions(
    agent_id: Annotated[str | None, Query(pattern=UUID_PATTERN)] = None,
    decision: Decision | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
    db: Session = Depends(get_db),
):
    """Recorded gateway decisions, newest first."""
    query = db.query(GatewayDecision)
    if agent_id:
        query = query.filter(GatewayDecision.agent_id == agent_id)
    if decision:
        query = query.filter(GatewayDecision.decision == decision)
    return query.order_by(GatewayDecision.decided_at.desc(), GatewayDecision.id).limit(limit).all()
