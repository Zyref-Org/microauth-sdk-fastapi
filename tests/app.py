"""Test app with short sync/report intervals for the integration test."""

import dataclasses
import os

from fastapi import FastAPI, HTTPException, Security
from fastapi.encoders import jsonable_encoder

from microauth_fastapi import Customer, MicroAuth, UsageReceipt, UsageRejection

app = FastAPI(title="SDK Test API")

receipts: list[UsageReceipt] = []
rejections: list[UsageRejection] = []


async def keep_receipts(batch: list[UsageReceipt]) -> None:
    receipts.extend(batch)


async def keep_rejections(batch: list[UsageRejection]) -> None:
    rejections.extend(batch)


auth = MicroAuth(
    app,
    base_url=os.environ["MICROAUTH_BASE_URL"],
    redis_url=os.environ.get("MICROAUTH_REDIS_URL"),
    sync_interval=5.0,
    report_interval=float(os.environ.get("REPORT_INTERVAL", "2.0")),
    verify_negative_ttl=5.0,
    on_receipts=keep_receipts,
    on_rejections=keep_rejections,
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


@app.get("/_ledger", include_in_schema=False)
async def ledger():
    """Everything this process delivered, for the test to reconcile."""

    return jsonable_encoder(
        {
            "stats": dataclasses.asdict(auth.usage_stats()),
            "receipts": [
                {**dataclasses.asdict(r), "charge_matches": r.charge_matches} for r in receipts
            ],
            "rejections": [dataclasses.asdict(r) for r in rejections],
        }
    )
