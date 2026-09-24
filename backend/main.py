from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from .database import engine, Base, get_db
from . import models, schemas, crud
from . import models, schemas, crud

from security.security_engine import evaluate_event

Base.metadata.create_all(bind=engine)


app = FastAPI(
    title="AgentGuard Backend",
    description="Backend API for AgentGuard",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://localhost:3000"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def root():
    return {
        "project": "AgentGuard",
        "status": "Backend running"
    }


@app.get("/health")
def health_check():
    return {
        "status": "ok",
        "service": "AgentGuard Backend"
    }


@app.post("/agents", response_model=schemas.AgentResponse)
def create_agent(
    agent: schemas.AgentCreate,
    db: Session = Depends(get_db)
):
    return crud.create_agent(db, agent)


@app.get("/agents", response_model=list[schemas.AgentResponse])
def get_agents(db: Session = Depends(get_db)):
    return crud.get_agents(db)


@app.post("/activities")
def create_activity(
    payload: schemas.ActivityPayload,
    db: Session = Depends(get_db)
):
    agent = (
        db.query(models.Agent)
        .filter(models.Agent.name == payload.agent)
        .first()
    )

    if not agent:
        raise HTTPException(
            status_code=404,
            detail=f"Agent '{payload.agent}' not found"
        )

    event = {
        "agent": payload.agent,
        "task": payload.task,
        "action": payload.action,
        "resource": payload.resource,
        "activity": {
            "api_calls": payload.api_calls,
            "db_queries": payload.db_queries,
            "files_accessed": payload.files_accessed,
            "data_mb": payload.data_mb
        },
        "action_history": payload.action_history
    }

    security_result = evaluate_event(event)

    activity = schemas.ActivityCreate(
        agent_id=agent.id,
        task=payload.task,
        action=payload.action,
        resource=payload.resource,
        activity={
            "api_calls": payload.api_calls,
            "db_queries": payload.db_queries,
            "files_accessed": payload.files_accessed,
            "data_mb": payload.data_mb
        },
        action_history=payload.action_history
    )

    db_activity = crud.create_activity(db, activity)

    return {
        "activity_id": db_activity.id,
        "agent": payload.agent,
        "task": payload.task,
        "action": payload.action,
        "resource": payload.resource,
        "risk_score": security_result["risk"]["score"],
        "severity": security_result["risk"]["severity"],
        "decision": security_result["decision"],
        "signals": security_result["signals"],
        "permission": security_result["permission"],
        "intent": security_result["intent"],
        "reason": security_result["reason"]
    }


@app.get("/activities", response_model=list[schemas.ActivityResponse])
def get_activities(db: Session = Depends(get_db)):
    return crud.get_activities(db)
