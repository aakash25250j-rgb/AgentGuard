from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text
from datetime import datetime

from .database import Base


class Agent(Base):
    __tablename__ = "agents"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, nullable=False)
    agent_type = Column(String, nullable=False)
    active = Column(Boolean, default=True)


class ActivityLog(Base):
    __tablename__ = "activity_logs"

    id = Column(Integer, primary_key=True, index=True)
    agent_id = Column(Integer, nullable=False)
    action = Column(String, nullable=False)
    resource = Column(String, nullable=False)
    status = Column(String, nullable=False)
    details = Column(Text, nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
