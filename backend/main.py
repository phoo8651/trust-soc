from fastapi import FastAPI
from db import Base, engine

import auth_router
import policy_router
import ingest_router
import jobs_router
import export_router
import webhook_router

Base.metadata.create_all(bind=engine)

app = FastAPI(title="SOC Backend PoC")

app.include_router(auth_router.router)
app.include_router(policy_router.router)
app.include_router(ingest_router.router)
app.include_router(jobs_router.router)
app.include_router(export_router.router)
app.include_router(webhook_router.router)

@app.get("/health")
def health():
    return {"status": "ok"}
