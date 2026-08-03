"""Test app with short sync/report intervals for the integration test."""

import os

from fastapi import FastAPI, HTTPException, Security

from microauth_fastapi import Customer, MicroAuth

app = FastAPI(title="SDK Test API")

auth = MicroAuth(
    app,
    base_url=os.environ["MICROAUTH_BASE_URL"],
    redis_url=os.environ.get("MICROAUTH_REDIS_URL"),
    sync_interval=5.0,
    report_interval=2.0,
    verify_negative_ttl=5.0,
)


@app.get("/public")
async def public():
    return {"ok": True}


@app.get("/hello")
async def hello(customer: Customer = Security(auth)):
    return {"customer": customer.id, "rps": customer.rps}


@app.get("/notfound")
async def notfound(customer: Customer = Security(auth)):
    raise HTTPException(404, "nothing here")


@app.get("/maybe")
async def maybe(customer: Customer | None = Security(auth.optional)):
    return {"authenticated": customer is not None}
