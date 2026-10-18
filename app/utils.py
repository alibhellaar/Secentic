import functools
import hashlib
import json
import unicodedata

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .models import Agent, AgentStatus, SystemSetting

# 1: sha256("name|environment"), ambiguous when a value contains "|"; 2: sha256 of a JSON array
# of lower-cased values; 3: the same, with names compared by identity_text().
FINGERPRINT_FORMAT = "3"


@functools.lru_cache(maxsize=4096)  # policy rules compare the same few names on every decision
def identity_text(text: str) -> str:
    """The form in which names and environments are compared: Unicode NFKC with full case folding
    (NFKC_Casefold), so 'Billing', 'BILLING', 'ｂｉｌｌｉｎｇ' and 'billing' are one name, as are
    'straße' and 'strasse'. Plain lower() folded only some pairs, depending on the characters."""
    return unicodedata.normalize("NFKC", unicodedata.normalize("NFKC", text).casefold())


def comparable_name(text: str) -> str:
    """How agent names and environments are compared everywhere, in the inventory and in policy
    rules: trimmed (new values cannot have surrounding spaces, rows from older versions can), then
    identity_text."""
    return identity_text(text.strip())


def compute_fingerprint(name: str, environment: str) -> str:
    # Owner is deliberately excluded: it is an attribute that changes (e.g. on approval),
    # not part of what makes two observations the same agent. A JSON array keeps the two fields
    # apart: joined with "|", 'a|b' in 'c' and 'a' in 'b|c' were the same agent. (Values cannot
    # start or end with spaces any more; strip() only matters for rows written by old versions.)
    raw = json.dumps([comparable_name(name), comparable_name(environment)], ensure_ascii=False)
    return hashlib.sha256(raw.encode()).hexdigest()


def ensure_current_fingerprints(db: Session) -> None:
    """Run at startup. Recomputes stored fingerprints only when the database records an older
    fingerprint format (or none); afterwards it is a single lookup."""
    marker = db.get(SystemSetting, "fingerprint_format")
    if marker is not None and marker.value == FINGERPRINT_FORMAT:
        return
    refresh_fingerprints(db)
    if marker is None:
        db.add(SystemSetting(key="fingerprint_format", value=FINGERPRINT_FORMAT))
    else:
        marker.value = FINGERPRINT_FORMAT
    try:
        db.commit()
    except IntegrityError:
        # Another server process starting at the same moment recorded it first, after running the
        # same upgrade (it is idempotent).
        db.rollback()


def _original_fingerprint(agent: Agent) -> str:
    """What the first M1 version stored: name, owner and environment, lower-cased, joined with "|"."""
    raw = f"{agent.name.lower().strip()}|{(agent.owner or '').lower().strip()}|{agent.environment.lower().strip()}"
    return hashlib.sha256(raw.encode()).hexdigest()


def refresh_fingerprints(db: Session) -> None:
    """Recompute every stored fingerprint in the current format (older versions hashed the owner
    too, or joined fields with "|"), so existing agents keep matching their re-registrations.

    The first M1 version also activated any agent that merely claimed an owner. Such agents still
    carry that version's fingerprint, computed with the claimed owner; they were never reviewed, so
    they go back to the review queue."""
    for agent in db.query(Agent):
        if agent.status == AgentStatus.active and agent.owner and agent.fingerprint == _original_fingerprint(agent):
            agent.status = AgentStatus.pending_review
        fingerprint = compute_fingerprint(agent.name, agent.environment)
        if agent.fingerprint != fingerprint:
            agent.fingerprint = fingerprint
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise RuntimeError(
            "The inventory already holds duplicate agents (same name and environment) created by an "
            "older version of Secentic. Delete the duplicates or the database, then restart."
        ) from None
