from pydantic import BaseModel
from datetime import datetime


class AgentCreate(BaseModel):
    name: str
    agent_type: str


class AgentResponse(BaseModel):
    id: int
    name: str
    agent_type: str
    active: bool

    class Config:
        from_attributes = True


class ActivityCreate(BaseModel):
    agent_id: int
    action: str
    resource: str
    status: str
    details: str | None = None


class ActivityResponse(BaseModel):
    id: int
    agent_id: int
    action: str
    resource: str
    status: str
    details: str | None
    timestamp: datetime | None

    class Config:
        from_attributes = True
