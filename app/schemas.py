from pydantic import BaseModel
from datetime import datetime
from .models import AgentStatus, RegistrationSource


class AgentRegisterRequest(BaseModel):
    name: str
    owner: str | None = None
    environment: str = "development"


class AgentResponse(BaseModel):
    id: str
    name: str
    owner: str | None
    environment: str
    status: AgentStatus
    registration_source: RegistrationSource
    first_seen: datetime
    last_seen: datetime

    class Config:
        from_attributes = True