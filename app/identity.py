"""M2 — Agent request authentication.

An agent proves its identity by signing each request with its Ed25519 private key
(canonical format in crypto.py). The server checks, in order:

  1. the timestamp is within MAX_CLOCK_SKEW of server time,
  2. the key exists and the signature over method, path, query, body hash, timestamp and nonce
     is valid (one answer for both, so nothing about a key leaks to someone who cannot sign),
  3. the key is active (not rotated or revoked),
  4. the nonce has not been used before by this key (replay protection),
  5. the agent itself is active (an approved, non-disabled inventory record).

`authenticate_agent` is the FastAPI dependency other modules (e.g. the M5 gateway) use.
"""
import re
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from fastapi import Depends, HTTPException, Request
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from . import crypto
from .database import get_db
from .models import Agent, AgentKey, AgentStatus, KeyStatus, RetiredKey, UsedNonce, as_utc, utcnow
from .schemas import KEY_ID_REGEX, SIGNATURE_REGEX

MAX_CLOCK_SKEW = 300  # seconds
# Nonces are kept a full window longer than their timestamp stays acceptable, so a request
# that has just passed the timestamp check can never find its earlier copy already purged.
NONCE_RETENTION = 2 * MAX_CLOCK_SKEW
NONCE_PURGE_INTERVAL = 60  # seconds between sweeps of expired nonces
_next_nonce_purge = 0.0
# last_seen is refreshed at most this often, so busy agents do not rewrite their row on every request.
LAST_SEEN_RESOLUTION = timedelta(seconds=60)

HEADER_KEY_ID = "X-Secentic-Key-Id"
HEADER_TIMESTAMP = "X-Secentic-Timestamp"
HEADER_NONCE = "X-Secentic-Nonce"
HEADER_SIGNATURE = "X-Secentic-Signature"
HEADER_PROOF = "X-Secentic-Proof"  # signature by a second key, proving possession of it (rotation)

NONCE_MIN_LENGTH, NONCE_MAX_LENGTH = 16, 128
TIMESTAMP_PATTERN = re.compile(r"[0-9]{1,12}")
NONCE_PATTERN = re.compile(rf"[A-Za-z0-9_-]{{{NONCE_MIN_LENGTH},{NONCE_MAX_LENGTH}}}")
KEY_ID_PATTERN = re.compile(KEY_ID_REGEX)
SIGNATURE_PATTERN = re.compile(SIGNATURE_REGEX.strip("^$"))

# How signed requests appear in the OpenAPI schema: four header schemes, all required together.
SIGNATURE_SECURITY_SCHEMES = {
    f"AgentSignature{part}": {"type": "apiKey", "in": "header", "name": header, "description": description}
    for part, header, description in (
        ("KeyId", HEADER_KEY_ID, "SHA-256 (hex) of the agent's Ed25519 public key"),
        ("Timestamp", HEADER_TIMESTAMP, f"Unix seconds, within {MAX_CLOCK_SKEW} s of server time"),
        ("Nonce", HEADER_NONCE, f"{NONCE_MIN_LENGTH}-{NONCE_MAX_LENGTH} characters [A-Za-z0-9_-], never reused"),
        ("Signature", HEADER_SIGNATURE, "Base64 Ed25519 signature over the canonical request (see docs)"),
    )
}
_ALL_SIGNATURE_HEADERS = {name: [] for name in SIGNATURE_SECURITY_SCHEMES}
SIGNED_REQUEST = {"security": [_ALL_SIGNATURE_HEADERS]}
OPTIONALLY_SIGNED_REQUEST = {"security": [{}, _ALL_SIGNATURE_HEADERS]}  # no auth, or all four headers


@dataclass
class SignedRequest:
    key_id: str
    timestamp: int
    nonce: str
    signature: str
    canonical: bytes


@dataclass
class AgentPrincipal:
    agent: Agent
    key: AgentKey
    request: SignedRequest


def _unauthorized(detail: str) -> HTTPException:
    return HTTPException(status_code=401, detail=detail)


async def signed_request(request: Request) -> SignedRequest:
    headers = request.headers
    key_id = headers.get(HEADER_KEY_ID)
    timestamp = headers.get(HEADER_TIMESTAMP)
    nonce = headers.get(HEADER_NONCE)
    signature = headers.get(HEADER_SIGNATURE)
    if not (key_id and timestamp and nonce and signature):
        raise _unauthorized(f"Missing signature headers ({HEADER_KEY_ID}, {HEADER_TIMESTAMP}, {HEADER_NONCE}, {HEADER_SIGNATURE})")
    # Bounded before anything uses them, like every other input.
    if not KEY_ID_PATTERN.fullmatch(key_id):
        raise _unauthorized("Key ID must be 64 lowercase hexadecimal characters")
    if not SIGNATURE_PATTERN.fullmatch(signature):
        raise _unauthorized("Signature must be 88 base64 characters (an Ed25519 signature)")

    if not TIMESTAMP_PATTERN.fullmatch(timestamp):
        raise _unauthorized("Timestamp must be integer Unix seconds")
    if abs(time.time() - int(timestamp)) > MAX_CLOCK_SKEW:
        raise _unauthorized("Request timestamp is outside the accepted window")
    if not NONCE_PATTERN.fullmatch(nonce):
        raise _unauthorized(f"Nonce must be {NONCE_MIN_LENGTH}-{NONCE_MAX_LENGTH} URL-safe characters")

    body = await request.body()
    # The path and query the router actually serves (percent-decoded path, raw query), not
    # request.url: that URL is rebuilt from the Host header, which some Starlette versions do not
    # check, so a crafted Host could make a signature for one path verify on another.
    path, query = request.scope["path"], request.scope["query_string"].decode("latin-1")
    canonical = crypto.canonical_request(request.method, path, query, key_id, timestamp, nonce, body)
    return SignedRequest(key_id=key_id, timestamp=int(timestamp), nonce=nonce, signature=signature, canonical=canonical)


async def optional_signed_request(request: Request) -> SignedRequest | None:
    if HEADER_KEY_ID not in request.headers and HEADER_SIGNATURE not in request.headers:
        return None
    return await signed_request(request)


def _consume_nonce(db: Session, signed: SignedRequest, seen: Agent | None = None) -> None:
    """Spend the nonce and commit at once, on the request's own connection (a second connection per
    request could exhaust the pool under load): it is spent the moment the signature checks out,
    whatever the endpoint does next. The primary key makes concurrent replays fail here too. If
    `seen` is given, that agent's last_seen is refreshed in the same commit.

    Authentication runs before an endpoint changes anything, so nothing else can be pending in the
    session. If something is, that is a programming error: it is refused, never committed along."""
    if db.new or db.dirty or db.deleted:
        raise RuntimeError("A nonce must be spent before the request changes anything; refusing to commit pending changes")
    global _next_nonce_purge
    now = utcnow()
    # What was just read (the key, the agent) stays loaded instead of expiring with these commits, so
    # the endpoint does not read it again.
    expire_on_commit, db.expire_on_commit = db.expire_on_commit, False
    try:
        if time.monotonic() >= _next_nonce_purge:
            # A commit of its own: a replay refused below neither undoes the purge nor leaves it due,
            # so replays cannot make every request repeat it.
            db.query(UsedNonce).filter(UsedNonce.expires_at < now).delete(synchronize_session=False)
            db.commit()
            _next_nonce_purge = time.monotonic() + NONCE_PURGE_INTERVAL
        expires_at = datetime.fromtimestamp(signed.timestamp + NONCE_RETENTION, tz=timezone.utc)
        db.add(UsedNonce(key_id=signed.key_id, nonce=signed.nonce, expires_at=expires_at))
        if seen is not None:
            seen.last_seen = now
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            raise _unauthorized("Nonce has already been used (replayed request)") from None
    finally:
        db.expire_on_commit = expire_on_commit


def verify_signed_request(db: Session, signed: SignedRequest | None, public_key: str, key_id: str,
                          seen: Agent | None = None) -> None:
    """Check that `signed` was made with `public_key` and has not been seen before. `seen`: an agent
    whose last_seen is refreshed in the same commit that spends the nonce."""
    if signed is None:
        raise _unauthorized("Request must be signed with the key being presented")
    if signed.key_id != key_id:
        raise _unauthorized("Signature key ID does not match the key being presented")
    if not crypto.verify_signature(public_key, signed.signature, signed.canonical):
        raise _unauthorized("Invalid signature")
    _consume_nonce(db, signed, seen)


def signed_by_enrolled_key(db: Session, agent: Agent, signed: SignedRequest | None, seen: Agent | None = None) -> bool:
    """Whether `signed` is a valid, fresh request signed with `agent`'s active key. Spends the nonce
    (refreshing `seen`'s last_seen in the same commit) when it is; anything else is simply False,
    so callers can give one answer to every failure."""
    key = agent.active_key
    if signed is None or key is None or signed.key_id != key.key_id:
        return False
    if not crypto.verify_signature(key.public_key, signed.signature, signed.canonical):
        return False
    try:
        _consume_nonce(db, signed, seen)
    except HTTPException:  # a replay: refused with the same answer as every other failure
        return False
    return True


def authenticate_agent(signed: SignedRequest = Depends(signed_request), db: Session = Depends(get_db)) -> AgentPrincipal:
    key = db.get(AgentKey, signed.key_id)
    # Nothing about a key (whether it exists, was rotated or revoked) is revealed to anyone who
    # cannot sign with it: an unknown key and a bad signature get the same answer.
    if key is None or not crypto.verify_signature(key.public_key, signed.signature, signed.canonical):
        raise _unauthorized("Invalid signature")
    if key.status != KeyStatus.active:
        raise _unauthorized(f"Key has been {key.status.value}")

    agent = key.agent
    if agent is None:  # the agent was deleted (its registration rejected) after the key was read
        raise _unauthorized("Invalid signature")
    stale = agent.last_seen is None or utcnow() - as_utc(agent.last_seen) >= LAST_SEEN_RESOLUTION
    _consume_nonce(db, signed, seen=agent if agent.status == AgentStatus.active and stale else None)

    if agent.status != AgentStatus.active:
        raise HTTPException(status_code=403, detail=f"Agent is {agent.status.value}")
    return AgentPrincipal(agent=agent, key=key, request=signed)


KEY_ALREADY_USED = "This public key has already been used; generate a new key pair"


def key_was_used(db: Session, key_id: str) -> bool:
    """Whether the key was ever bound (to any agent, in any state) or retired."""
    return db.get(AgentKey, key_id) is not None or db.get(RetiredKey, key_id) is not None


def new_agent_key(db: Session, agent: Agent, public_key: str) -> AgentKey:
    """Add an active key for `agent` to the session. The caller commits.

    Refuses (409) a public key that was ever bound before, so rotated, revoked and rejected keys
    stay dead.
    """
    _, key_id = crypto.load_public_key(public_key)
    if key_was_used(db, key_id):
        raise HTTPException(status_code=409, detail=KEY_ALREADY_USED)
    key = AgentKey(key_id=key_id, public_key=public_key, agent=agent)
    db.add(key)
    return key
