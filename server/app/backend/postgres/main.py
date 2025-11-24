import asyncio
import contextlib
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

from db import Base, engine
import ilm
from tenant_middleware import TenantContextMiddleware

import auth_router
import policy_router
import ingest_router
import robs_router
import export_router
import webhook_router
import console_router
from ops_alerts import run_operational_checks

ILM_INTERVAL_SECONDS = int(os.getenv("ILM_SCHEDULE_SECONDS", "21600"))      
OPS_ALERT_INTERVAL   = int(os.getenv("OPS_ALERT_INTERVAL_SECONDS", "900"))  

async def _ilm_scheduler():
    while True:
        await asyncio.to_thread(ilm.ensure_partitions, engine)
        await asyncio.to_thread(ilm.apply_ilm, engine)
        await asyncio.sleep(ILM_INTERVAL_SECONDS)

async def _ops_alert_scheduler():
    while True:
        await asyncio.to_thread(run_operational_checks, engine)
        await asyncio.sleep(OPS_ALERT_INTERVAL)

@asynccontextmanager
async def lifespan(app: FastAPI):
    await asyncio.to_thread(Base.metadata.create_all, bind=engine)
    await asyncio.to_thread(ilm.ensure_partitions, engine)
    await asyncio.to_thread(ilm.apply_ilm, engine)

    ilm_task = asyncio.create_task(_ilm_scheduler())
    ops_task = asyncio.create_task(_ops_alert_scheduler())

    try:
        yield
    finally:
        for task in (ilm_task, ops_task):
            task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await ilm_task
        with contextlib.suppress(asyncio.CancelledError):
            await ops_task

app = FastAPI(title="SOC Backend PoC", lifespan=lifespan)
app.add_middleware(TenantContextMiddleware)

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request, exc: RequestValidationError):
    return JSONResponse(
        status_code=422,
        content={
            "detail": "schema_invalid",
            "errors": exc.errors(),
        },
    )

app.include_router(auth_router.router)
app.include_router(policy_router.router)
app.include_router(ingest_router.router)
app.include_router(robs_router.router)
app.include_router(export_router.router)
app.include_router(webhook_router.router)
app.include_router(console_router.router)

@app.get("/health")
def health():
    return {"status": "ok"}

@app.get("/metrics")
def metrics():
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)
