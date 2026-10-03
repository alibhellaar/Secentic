import uuid
import enum
from datetime import datetime, timezone
from sqlalchemy import Column, String, DateTime, Enum
from sqlalchemy.types import CHAR
from sqlalchemy.orm import declarative_mixin
from .database import Base


class AgentStatus(str, enum.Enum):
    pending_review = "pending_review"
    active = "active"
    inactive = "inactive"
    disabled = "disabled"


class RegistrationSource(str, enum.Enum):
    api = "api"
    sdk = "sdk"
    manual = "manual"


class Agent(Base):
    __tablename__ = "agents"

    id = Column(CHAR(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String, nullable=False)
    owner = Column(String, nullable=True)
    environment = Column(String, nullable=False, default="development")
    fingerprint = Column(String, unique=True, nullable=False, index=True)
    status = Column(Enum(AgentStatus), default=AgentStatus.pending_review, nullable=False)
    registration_source = Column(Enum(RegistrationSource), nullable=False)

    first_seen = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    last_seen = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))