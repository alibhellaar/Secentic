"""M3 — Delegated authority: what an agent may do, and why.

An agent holds no authority of its own. A human delegates it explicitly: these actions, on these
resources, for this task, until this time. `check_authority` answers "may this agent perform this
action on this resource now?" deterministically, with a reason a person can read. The M5 gateway
calls it for every consequential action.

Resource identifiers look like "crm:accounts/42" (system, colon, path). A delegation may name
them exactly or with a prefix pattern ending in "*" right after "/" or ":", e.g. "crm:accounts/*".
"/" and ":" both separate segments, so every input is normalised to one spelling, the system, ":"
and a "/"-separated path ("crm:accounts:42" becomes "crm:accounts/42"), and actions to lower case.
Every module stores and compares only normalised values.
"""
import re
from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import and_, or_
from sqlalchemy.orm import Session

from .models import Agent, AgentStatus, Delegation, DelegationState, DelegationStatus, as_utc, utcnow

MAX_DELEGATION_LIFETIME = timedelta(days=30)
# starts_at may lie this far in the past (clocks differ a little); otherwise a delegation created
# now could claim to have been in force before it existed.
MAX_BACKDATING = timedelta(minutes=5)

# A restricted alphabet: no spaces, no "%" (encoded characters), no "?" or "#".
_RESOURCE = re.compile(r"[A-Za-z0-9._~:/@+=,-]{1,256}")
ACTION_CHARS = "A-Za-z0-9_.:-"
ACTION_CORE = rf"[A-Za-z][{ACTION_CHARS}]*"  # an action name: a letter, then letters, digits, _ . : -

# The same rules as regular expressions, published in the OpenAPI schema. tests/test_openapi.py
# checks that each accepts exactly what the matching validate_* function accepts.
_SEGMENT_CHARS = "A-Za-z0-9._~@+=,-"  # a segment sits between "/" or ":" separators
_NOT_DOT = "A-Za-z0-9_~@+=,-"
_SEGMENT = rf"(?:[{_NOT_DOT}][{_SEGMENT_CHARS}]*|\.[{_NOT_DOT}][{_SEGMENT_CHARS}]*|\.\.[{_SEGMENT_CHARS}]+)"  # not empty, ".", ".."
IDENTIFIER_PATTERN = rf"{_SEGMENT}(?:[/:]{_SEGMENT})*"
RESOURCE_REGEX = rf"^{IDENTIFIER_PATTERN}$"
RESOURCE_PATTERN_REGEX = rf"^(?:{IDENTIFIER_PATTERN}|[{_SEGMENT_CHARS}]*[A-Za-z0-9][{_SEGMENT_CHARS}]*(?:[/:]{_SEGMENT})*[/:]\*)$"
ACTION_REGEX = rf"^{ACTION_CORE}$"
MAX_RESOURCE_LENGTH = 256
MAX_ACTION_LENGTH = 100
_ACTION = re.compile(rf"[A-Za-z][{ACTION_CHARS}]{{0,{MAX_ACTION_LENGTH - 1}}}")


def validate_resource(resource: str) -> str:
    """Raise ValueError unless `resource` is a well-formed resource identifier (no wildcards)."""
    if not _RESOURCE.fullmatch(resource):
        raise ValueError("resource must be 1-256 characters from A-Z a-z 0-9 . _ ~ : / @ + = , -")
    segments = re.split(r"[/:]", resource)  # both "/" and ":" separate segments
    if "" in segments:
        # "crm:accounts//secret" is another spelling of "crm:accounts/secret": it would fall under a
        # delegation for "crm:accounts/*" yet slip past a policy rule on "crm:accounts/secret*".
        raise ValueError("resource must not contain empty segments (a leading, trailing or doubled '/' or ':')")
    if any(segment in (".", "..") for segment in segments):
        # "crm:accounts/../admin" must never fall under a grant for "crm:accounts/*", nor
        # "crm:../admin" under "crm:*".
        raise ValueError("resource must not contain '.' or '..' path segments")
    return resource


def validate_resource_pattern(pattern: str) -> str:
    """Raise ValueError unless `pattern` is an identifier, optionally ending in a "/*" or ":*" wildcard
    whose first segment (the system name) contains a letter or digit."""
    if not pattern.endswith("*"):
        return validate_resource(pattern)
    prefix = pattern[:-1]
    first_segment = re.split(r"[/:]", prefix)[0]
    if not prefix or prefix[-1] not in "/:" or not re.search(r"[A-Za-z0-9]", first_segment):
        raise ValueError("'*' is only allowed at the end, right after '/' or ':', following a system name "
                         "(e.g. 'crm:accounts/*'); blanket grants such as '*' are not allowed")
    if len(pattern) > MAX_RESOURCE_LENGTH:
        raise ValueError(f"resource pattern must be at most {MAX_RESOURCE_LENGTH} characters")
    validate_resource(prefix[:-1])  # everything before the final separator
    return pattern


def validate_action(action: str) -> str:
    if not _ACTION.fullmatch(action):
        raise ValueError("action must be a name such as 'read' or 'email.send' (letters, digits, _ . : -); "
                         "wildcards are not allowed")
    return action


def canonical_form(identifier: str) -> str:
    """One spelling for the segments of `identifier`: the first segment (the system), then ':', then
    the rest joined with '/'. Case is kept: resource IDs are often case-sensitive."""
    first, *rest = re.split(r"[/:]", identifier)
    return first + (":" + "/".join(rest) if rest else "")


def normalize_resource(resource: str) -> str:
    """Validate `resource` and return its canonical spelling ('crm:accounts:42' -> 'crm:accounts/42')."""
    return canonical_form(validate_resource(resource))


def canonical_pattern(pattern: str) -> str:
    """The canonical spelling of an identifier, or of a prefix pattern ending in '*' (also '*' alone)."""
    return canonical_form(pattern[:-1]) + "*" if pattern.endswith("*") else canonical_form(pattern)


def normalize_resource_pattern(pattern: str) -> str:
    """Validate `pattern` and return its canonical spelling ('crm/accounts:*' -> 'crm:accounts/*')."""
    return canonical_pattern(validate_resource_pattern(pattern))


def normalize_action(action: str) -> str:
    """Validate `action` and return it in lower case: action names are ours, so 'CRM:Update' and
    'crm:update' are one action."""
    return validate_action(action).lower()


def pattern_matches(pattern: str, value: str) -> bool:
    """Exact match, or prefix match for a pattern ending in "*". Used for delegation resources and
    for policy (M6) actions and resources alike, so both always agree on what a pattern covers."""
    if pattern.endswith("*"):
        return value.startswith(pattern[:-1])
    return value == pattern


@dataclass
class AuthorityCheck:
    allowed: bool
    reason: str
    delegation: Delegation | None = None  # the delegation that allows the request


def _iso(moment: datetime) -> str:
    return as_utc(moment).isoformat(timespec="seconds").replace("+00:00", "Z")


# How many of an agent's latest delegations a denial searches for one that would have covered it.
EXPLANATION_HISTORY = 100


def _in_state(state: DelegationState, at: datetime):
    """SQL condition equivalent to Delegation.state_at(at) == state."""
    revoked = Delegation.status == DelegationStatus.revoked
    if state == DelegationState.revoked:
        return and_(revoked, or_(Delegation.revoked_at.is_(None), Delegation.revoked_at <= at))
    live = or_(Delegation.status == DelegationStatus.active, and_(revoked, Delegation.revoked_at > at))  # not revoked yet at `at`
    if state == DelegationState.scheduled:
        return and_(live, Delegation.starts_at > at)
    if state == DelegationState.expired:
        return and_(live, Delegation.starts_at <= at, Delegation.expires_at <= at)
    return and_(live, Delegation.starts_at <= at, Delegation.expires_at > at)


def delegations_in_state(db: Session, agent_id: str, state: DelegationState | None, at: datetime) -> list[Delegation]:
    """The agent's delegations in `state` at `at` (all of them when `state` is None), oldest first,
    filtered by the database rather than by loading the agent's whole history."""
    query = db.query(Delegation).filter(Delegation.agent_id == agent_id)
    if state is not None:
        query = query.filter(_in_state(state, as_utc(at)))
    return query.order_by(Delegation.created_at, Delegation.id).all()


def check_authority(db: Session, agent: Agent, action: str, resource: str, at: datetime | None = None) -> AuthorityCheck:
    """Decide whether `agent` may perform `action` on `resource` at `at` (default: now).

    Allowed only if a delegation in force at that moment lists the action and a matching resource.
    When several do, the oldest decides. Anything invalid or unknown is denied (fail closed).
    """
    try:
        at = as_utc(at or utcnow())
    except OverflowError:
        return AuthorityCheck(False, "Invalid request: time out of range")
    if agent.status != AgentStatus.active:
        return AuthorityCheck(False, f"Agent is {agent.status.value}")
    try:
        action, resource = normalize_action(action), normalize_resource(resource)
    except ValueError as exc:
        return AuthorityCheck(False, f"Invalid request: {exc}")
    return authority_in_force(db, agent.id, action, resource, at)


def authority_in_force(db: Session, agent_id: str, action: str, resource: str, at: datetime) -> AuthorityCheck:
    """The lookup behind check_authority, for callers that have already checked that the agent is
    active and normalised the request (the gateway). `at` is in UTC."""

    def covers(d: Delegation) -> bool:
        return action in d.actions and any(pattern_matches(p, resource) for p in d.resources)

    # The common case: only the delegations in force at `at` are loaded.
    in_force = delegations_in_state(db, agent_id, DelegationState.active, at)
    for d in in_force:
        if covers(d):
            return AuthorityCheck(
                True,
                f"Allowed by delegation {d.id}: task '{d.task}', delegated by {d.delegator}, "
                f"valid until {_iso(d.expires_at)}",
                d,
            )

    # Denied. The explanation names the newest delegation that would have covered the request.
    # Only the most recent ones are searched, so a long history never makes a denial slower.
    recent = (
        db.query(Delegation).filter(Delegation.agent_id == agent_id)
        .order_by(Delegation.created_at.desc(), Delegation.id.desc()).limit(EXPLANATION_HISTORY).all()
    )
    d = next((d for d in recent if covers(d)), None)  # never one in force: none of those covers it
    if d is not None:
        why = {
            DelegationState.revoked: "was revoked",
            DelegationState.expired: f"expired at {_iso(d.expires_at)}",
            DelegationState.scheduled: f"only starts at {_iso(d.starts_at)}",
        }.get(d.state_at(at), "is not in force")
        return AuthorityCheck(False, f"Delegation {d.id} covers this request but {why}")

    if not in_force:
        return AuthorityCheck(False, "The agent has no delegated authority in force")
    patterns = sorted({p for d in in_force if action in d.actions for p in d.resources})
    if patterns:
        return AuthorityCheck(False, f"'{action}' is delegated only on {', '.join(patterns)}, not on '{resource}'")
    return AuthorityCheck(False, f"No delegation in force grants the action '{action}'")
