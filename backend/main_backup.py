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


@app.post("/activities", response_model=schemas.ActivityResponse)
def create_activity(
    activity: schemas.ActivityCreate,
    db: Session = Depends(get_db)
):
    return crud.create_activity(db, activity)


@app.get("/activities", response_model=list[schemas.ActivityResponse])
def get_activities(db: Session = Depends(get_db)):
    return crud.get_activities(db)
