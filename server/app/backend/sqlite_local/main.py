from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from db import Base, engine
import ilm

import auth_router
import policy_router
import ingest_router
import robs_router
import export_router
import webhook_router
import console_router

Base.metadata.create_all(bind=engine)
ilm.ensure_partitions(engine)
ilm.apply_ilm(engine)

app = FastAPI(title="SOC Backend PoC")


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
