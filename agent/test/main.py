# -*- coding: utf-8 -*-
from fastapi import FastAPI
from db import Base, engine

import auth_router
import policy_router
import ingest_router
import export_router

from jobs_router import router as jobs_router
from webhook_router import router as webhook_router
Base.metadata.create_all(bind=engine)


app = FastAPI(title="SOC Backend PoC")
app.include_router(auth_router.router)
app.include_router(policy_router.router)
app.include_router(ingest_router.router)
app.include_router(export_router.router)
app.include_router(jobs_router)        # 객체
app.include_router(webhook_router)     # 객체
@app.get("/health")
def health():
    return {"status": "ok"}
