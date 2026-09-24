from sqlalchemy.orm import Session

from . import models, schemas


def create_agent(db: Session, agent: schemas.AgentCreate):
    db_agent = models.Agent(
        name=agent.name,
        agent_type=agent.agent_type
    )

    db.add(db_agent)
    db.commit()
    db.refresh(db_agent)

    return db_agent


def get_agents(db: Session):
    return db.query(models.Agent).all()


def create_activity(db: Session, activity: schemas.ActivityCreate):
    db_activity = models.ActivityLog(
        agent_id=activity.agent_id,
        action=activity.action,
        resource=activity.resource,
        status=activity.status,
        details=activity.details
    )

    db.add(db_activity)
    db.commit()
    db.refresh(db_activity)

    return db_activity


def get_activities(db: Session):
    return (
        db.query(models.ActivityLog)
        .order_by(models.ActivityLog.timestamp.desc())
        .all()
    )
