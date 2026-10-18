import hashlib
import json
import uuid
import enum
from datetime import datetime, timezone
from sqlalchemy import JSON, Column, String, DateTime, Enum, ForeignKey, Index, Integer, text
from sqlalchemy.types import CHAR
from sqlalchemy.orm import relationship
from .database import Base


def utcnow():
    return datetime.now(timezone.utc)


def as_utc(value: datetime) -> datetime:
    """SQLite returns stored UTC timestamps without a timezone; treat those as UTC."""
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


class AgentStatus(str, enum.Enum):
    pending_review = "pending_review"
    active = "active"
    inactive = "inactive"
    disabled = "disabled"


class RegistrationSource(str, enum.Enum):
    api = "api"
    sdk = "sdk"
    manual = "manual"


class KeyStatus(str, enum.Enum):
    active = "active"
    rotated = "rotated"  # replaced by the agent through key rotation
    revoked = "revoked"  # withdrawn by an administrator (e.g. suspected compromise)


class DelegationStatus(str, enum.Enum):
    active = "active"
    revoked = "revoked"


class DelegationState(str, enum.Enum):
    """Whether a delegation is in force at a given moment (derived, not stored)."""
    scheduled = "scheduled"  # starts in the future
    active = "active"
    expired = "expired"
    revoked = "revoked"


class Agent(Base):
    __tablename__ = "agents"

    id = Column(CHAR(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String, nullable=False)
    owner = Column(String, nullable=True)  # claimed at self-registration; confirmed by an admin on approval
    environment = Column(String, nullable=False, default="development")
    fingerprint = Column(String, unique=True, nullable=False, index=True)
    status = Column(Enum(AgentStatus), default=AgentStatus.pending_review, nullable=False)
    registration_source = Column(Enum(RegistrationSource), nullable=False)

    first_seen = Column(DateTime(timezone=True), default=utcnow)
    last_seen = Column(DateTime(timezone=True), default=utcnow)

    keys = relationship("AgentKey", back_populates="agent", order_by="AgentKey.created_at", cascade="all, delete-orphan")
    # Only the active key, loaded when used (AgentResponse needs only active_key_id).
    active_key = relationship(
        "AgentKey",
        primaryjoin="and_(Agent.id == AgentKey.agent_id, AgentKey.status == 'active')",
        uselist=False,
        viewonly=True,
    )

    delegations = relationship("Delegation", back_populates="agent", order_by="Delegation.created_at", cascade="all, delete-orphan")
    tool_assignments = relationship("AgentTool", back_populates="agent", cascade="all, delete-orphan")

    @property
    def active_key_id(self):
        return self.active_key.key_id if self.active_key else None


class AgentKey(Base):
    """An Ed25519 public key bound to an agent. The private key never leaves the agent."""

    __tablename__ = "agent_keys"
    __table_args__ = (
        # At most one active key per agent, enforced by the database as well as the code.
        Index(
            "uq_agent_keys_one_active",
            "agent_id",
            unique=True,
            sqlite_where=text("status = 'active'"),
            postgresql_where=text("status = 'active'"),
        ),
    )

    # SHA-256 thumbprint of the raw public key. Unique across all keys ever bound, so a
    # rotated or revoked key can never be enrolled again.
    key_id = Column(String(64), primary_key=True)
    agent_id = Column(CHAR(36), ForeignKey("agents.id"), nullable=False, index=True)
    algorithm = Column(String, nullable=False, default="ed25519")
    public_key = Column(String, nullable=False)  # base64 of the raw 32-byte key
    status = Column(Enum(KeyStatus), default=KeyStatus.active, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow)
    rotated_at = Column(DateTime(timezone=True), nullable=True)
    revoked_at = Column(DateTime(timezone=True), nullable=True)
    revocation_reason = Column(String, nullable=True)

    agent = relationship("Agent", back_populates="keys")


class UsedNonce(Base):
    """Nonces seen on signed requests, kept for NONCE_RETENTION past the request's timestamp
    (see identity.py); after that the timestamp check alone rejects a replay."""

    __tablename__ = "used_nonces"

    key_id = Column(String(64), primary_key=True)
    nonce = Column(String(128), primary_key=True)
    expires_at = Column(DateTime(timezone=True), nullable=False, index=True)


class Delegation(Base):
    """Authority a named human delegated to an agent: these actions, on these resources, for this
    task, within this time window. Agents hold no other authority (M3)."""

    __tablename__ = "delegations"

    id = Column(CHAR(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    agent_id = Column(CHAR(36), ForeignKey("agents.id"), nullable=False, index=True)
    delegator = Column(String, nullable=False)  # the human whose authority is delegated
    task = Column(String, nullable=False)
    actions = Column(JSON, nullable=False)  # exact action names
    resources = Column(JSON, nullable=False)  # resource identifiers or prefix patterns ending in "*"
    starts_at = Column(DateTime(timezone=True), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    status = Column(Enum(DelegationStatus), default=DelegationStatus.active, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow)
    revoked_at = Column(DateTime(timezone=True), nullable=True)
    revocation_reason = Column(String, nullable=True)

    agent = relationship("Agent", back_populates="delegations")

    def state_at(self, moment: datetime) -> DelegationState:
        """The state at `moment`. A revoked delegation counts as revoked from `revoked_at` on, so a
        question about an earlier moment gets the answer that was true then."""
        moment = as_utc(moment)
        if self.status == DelegationStatus.revoked and (self.revoked_at is None or moment >= as_utc(self.revoked_at)):
            return DelegationState.revoked
        if moment < as_utc(self.starts_at):
            return DelegationState.scheduled
        if moment >= as_utc(self.expires_at):
            return DelegationState.expired
        return DelegationState.active

    @property
    def state(self) -> DelegationState:
        return self.state_at(utcnow())


class ToolKind(str, enum.Enum):
    tool = "tool"
    mcp_server = "mcp_server"


class TrustState(str, enum.Enum):
    trusted = "trusted"        # reviewed and approved for use
    unknown = "unknown"        # not reviewed yet, or changed since the last review
    suspicious = "suspicious"  # under investigation
    blocked = "blocked"        # must never be used


class Tool(Base):
    """A tool or MCP server agents can call, with where it comes from and how far it is trusted (M4)."""

    __tablename__ = "tools"

    name = Column(String(64), primary_key=True)  # lowercase, unique: one tool per name, no shadowing
    kind = Column(Enum(ToolKind), nullable=False)
    provider = Column(String, nullable=False)
    endpoint = Column(String, nullable=False)
    version = Column(String, nullable=False)
    capabilities = Column(JSON, nullable=False)  # the action names the tool performs
    resources = Column(JSON, nullable=False)  # identifiers or prefix patterns ("crm:*") the tool works on
    description = Column(String, nullable=True)
    trust_state = Column(Enum(TrustState), default=TrustState.unknown, nullable=False)
    trust_reason = Column(String, nullable=True)
    trust_changed_at = Column(DateTime(timezone=True), default=utcnow)
    created_at = Column(DateTime(timezone=True), default=utcnow)
    updated_at = Column(DateTime(timezone=True), default=utcnow)

    assignments = relationship("AgentTool", back_populates="tool", cascade="all, delete-orphan")

    # What a reviewer approves when marking the tool trusted.
    REVIEWED_FIELDS = ("kind", "provider", "endpoint", "version", "capabilities", "resources")

    @property
    def definition_hash(self) -> str:
        """SHA-256 of the reviewed fields. Trusting a tool names the hash that was reviewed, so a
        definition that changed in the meantime cannot be trusted by mistake."""
        reviewed = {field: getattr(self, field) for field in self.REVIEWED_FIELDS}
        reviewed["kind"] = ToolKind(reviewed["kind"]).value
        canonical = json.dumps(reviewed, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        return hashlib.sha256(canonical.encode()).hexdigest()


class AgentTool(Base):
    """An agent may use a tool (M4). Without this row, the gateway denies every call to the tool."""

    __tablename__ = "agent_tools"

    agent_id = Column(CHAR(36), ForeignKey("agents.id"), primary_key=True)
    tool_name = Column(String(64), ForeignKey("tools.name"), primary_key=True)
    assigned_at = Column(DateTime(timezone=True), default=utcnow)

    agent = relationship("Agent", back_populates="tool_assignments")
    tool = relationship("Tool", back_populates="assignments")


class PolicyVersion(Base):
    """One immutable version of the policy rule set (M6). The highest version is in force."""

    __tablename__ = "policy_versions"

    version = Column(Integer, primary_key=True, autoincrement=False)
    rules = Column(JSON, nullable=False)
    comment = Column(String, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow)


class Decision(str, enum.Enum):
    allow = "allow"
    require_approval = "require_approval"
    deny = "deny"


class GatewayDecision(Base):
    """A decision the gateway made for an agent's request, with every reason (M5)."""

    __tablename__ = "gateway_decisions"

    id = Column(CHAR(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    agent_id = Column(CHAR(36), ForeignKey("agents.id"), nullable=False, index=True)
    key_id = Column(String(64), nullable=True)  # the key that signed the request
    tool = Column(String(64), nullable=False)
    action = Column(String(100), nullable=False)
    resource = Column(String(256), nullable=False)
    decision = Column(Enum(Decision), nullable=False)
    reasons = Column(JSON, nullable=False)
    matched_rules = Column(JSON, nullable=False)
    delegation_id = Column(CHAR(36), nullable=True)
    policy_version = Column(Integer, nullable=False)
    decided_at = Column(DateTime(timezone=True), default=utcnow, index=True)


class SystemSetting(Base):
    """Small key/value facts about the database itself, e.g. which fingerprint format it uses."""

    __tablename__ = "system_settings"

    key = Column(String(64), primary_key=True)
    value = Column(String, nullable=False)


class RetiredKey(Base):
    """Keys deleted together with a rejected registration. They stay unusable forever, like
    rotated and revoked keys, so a rejected key cannot simply be enrolled again."""

    __tablename__ = "retired_keys"

    key_id = Column(String(64), primary_key=True)
    reason = Column(String, nullable=False)
    retired_at = Column(DateTime(timezone=True), default=utcnow)
