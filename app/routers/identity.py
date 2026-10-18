from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException
from sqlalchemy.orm import Session

from .. import crypto
from ..database import get_db
from ..identity import (
    HEADER_PROOF, KEY_ALREADY_USED, SIGNED_REQUEST, AgentPrincipal, authenticate_agent, key_was_used, new_agent_key,
)
from ..models import AgentKey, KeyStatus, utcnow
from ..schemas import SIGNATURE_REGEX, AgentKeyResponse, AgentResponse, PublicKeyRequest, RevokeRequest, error_responses
from .common import ADMIN, ADMIN_ERRORS, AgentId, KeyId, commit_or_409, get_agent_or_404, get_or_404, update_one

router = APIRouter(tags=["identity"])


# --- Control plane: administrators manage agent keys -------------------------------------

@router.get("/agents/{agent_id:uuid_id}/keys", response_model=list[AgentKeyResponse], dependencies=ADMIN,
            responses=error_responses(*ADMIN_ERRORS, 404))
def list_keys(agent_id: AgentId, db: Session = Depends(get_db)):
    return get_agent_or_404(db, agent_id).keys


@router.post("/agents/{agent_id:uuid_id}/keys", response_model=AgentKeyResponse, status_code=201, dependencies=ADMIN,
             responses=error_responses(*ADMIN_ERRORS, 404, 409, 400, 413))
def bind_key(agent_id: AgentId, payload: PublicKeyRequest, db: Session = Depends(get_db)):
    """Bind a public key supplied out of band by the agent's operator. Used for manually
    onboarded agents and to recover an agent after its key was revoked."""
    agent = get_agent_or_404(db, agent_id)
    if agent.active_key is not None:
        raise HTTPException(status_code=409, detail="Agent already has an active key; revoke it first")
    key = new_agent_key(db, agent, payload.public_key)
    key_id = key.key_id
    commit_or_409(db, lambda: KEY_ALREADY_USED if key_was_used(db, key_id)
                  else "The agent's keys changed concurrently; check them and retry")
    db.refresh(key)
    return key


@router.post("/agents/{agent_id:uuid_id}/keys/{key_id:key_id}/revoke", response_model=AgentKeyResponse,
             dependencies=ADMIN, responses=error_responses(*ADMIN_ERRORS, 404, 409, 400, 413))
def revoke_key(agent_id: AgentId, key_id: KeyId, payload: RevokeRequest | None = None, db: Session = Depends(get_db)):
    """Revoke the agent's active key. It stops authenticating immediately and can never be bound
    again. A key that is no longer active is refused, naming the agent's current key: if a stolen key
    was already rotated away, revoking the old one would cut nothing off."""
    key = get_or_404(db, AgentKey, key_id, "Key not found", agent_id=agent_id)
    # Only while it is still active, so a rotation that lands at the same moment cannot leave a
    # successor key active behind a revocation that reports success.
    active = db.query(AgentKey).filter(AgentKey.key_id == key.key_id, AgentKey.status == KeyStatus.active)
    if not update_one(db, active, {AgentKey.status: KeyStatus.revoked, AgentKey.revoked_at: utcnow(),
                                   AgentKey.revocation_reason: payload.reason if payload else None}):
        db.expire_all()
        current = get_agent_or_404(db, agent_id).active_key
        successor = f"the agent's active key is {current.key_id}" if current else "the agent has no active key"
        raise HTTPException(status_code=409, detail=f"Key is not active ({db.get(AgentKey, key_id).status.value}); "
                                                    f"{successor}. Revoke that key, or disable the agent")
    db.commit()
    db.refresh(key)
    return key


# --- Agent-facing: every request is signed with the agent's key --------------------------

@router.get("/identity/whoami", response_model=AgentResponse, responses=error_responses(401, 403, 503), openapi_extra=SIGNED_REQUEST)
def whoami(principal: AgentPrincipal = Depends(authenticate_agent)):
    """Lets an agent confirm its key works and see its own inventory record."""
    return principal.agent


@router.post("/identity/rotate", response_model=AgentKeyResponse, responses=error_responses(401, 403, 409, 400, 413, 503),
             openapi_extra=SIGNED_REQUEST)
def rotate_key(
    payload: PublicKeyRequest,
    proof: Annotated[str | None, Header(alias=HEADER_PROOF, pattern=SIGNATURE_REGEX,
                                        description="The new key's base64 signature over the same canonical request")] = None,
    principal: AgentPrincipal = Depends(authenticate_agent),
    db: Session = Depends(get_db),
):
    """Replace the calling agent's key. The request is signed with the current key, and the
    X-Secentic-Proof header carries the new key's signature over the same canonical request,
    so the agent proves it holds both. The old key stops working immediately."""
    if not proof or not crypto.verify_signature(payload.public_key, proof, principal.request.canonical):
        raise HTTPException(status_code=401, detail="Missing or invalid proof of possession for the new key")

    # Retire the old key only if it is still active. An administrator's revocation (or another
    # rotation) that landed after this request was authenticated must win, never be overwritten.
    active = db.query(AgentKey).filter(AgentKey.key_id == principal.key.key_id, AgentKey.status == KeyStatus.active)
    if not update_one(db, active, {AgentKey.status: KeyStatus.rotated, AgentKey.rotated_at: utcnow()}):
        raise HTTPException(status_code=409, detail="The key was revoked or rotated while this rotation was in progress; nothing was changed")

    new_key = new_agent_key(db, principal.agent, payload.public_key)
    new_key_id = new_key.key_id
    # A concurrent rotation by the same agent won the race, or the same new key was enrolled
    # elsewhere at that moment: this one is refused, not half-applied, and the answer says which.
    commit_or_409(db, lambda: KEY_ALREADY_USED if key_was_used(db, new_key_id) else "The key was rotated by a concurrent request")
    db.refresh(new_key)
    return new_key
