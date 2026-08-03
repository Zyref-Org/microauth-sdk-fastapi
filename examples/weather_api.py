"""A minimal weather API protected by MicroAuth.

Run with:
    MICROAUTH_SECRET_KEY=mas_... uvicorn examples.weather_api:app --reload
"""

import os
import random

from fastapi import FastAPI, HTTPException, Security

from microauth_fastapi import Customer, MicroAuth

app = FastAPI(title="ProWeather API", version="1.0.0")

auth = MicroAuth(
    app,
    base_url=os.environ.get("MICROAUTH_BASE_URL", "https://api.microauth.com"),
    redis_url=os.environ.get("MICROAUTH_REDIS_URL"),  # optional
)

CITIES = {
    "amsterdam": {"temp_c": 14, "condition": "cloudy"},
    "dubai": {"temp_c": 41, "condition": "sunny"},
    "islamabad": {"temp_c": 31, "condition": "clear"},
    "london": {"temp_c": 17, "condition": "rain"},
}


@app.get("/")
async def index():
    """Public route — no API key required."""
    return {"service": "ProWeather", "docs": "/docs"}


@app.get("/v1/weather/{city}")
async def weather(city: str, customer: Customer = Security(auth)):
    """Current weather. Requires an API key; billable on success."""
    data = CITIES.get(city.lower())
    if data is None:
        raise HTTPException(404, f"no data for {city!r}")
    return {"city": city.lower(), **data}


@app.get("/v1/forecast/{city}")
async def forecast(city: str, days: int = 3, customer: Customer = Security(auth)):
    """Multi-day forecast, showing the principal you get for free."""
    if city.lower() not in CITIES:
        raise HTTPException(404, f"no data for {city!r}")
    base = CITIES[city.lower()]["temp_c"]
    return {
        "city": city.lower(),
        "days": [{"day": d + 1, "temp_c": base + random.randint(-3, 3)} for d in range(days)],
        "plan": customer.billing_model,
        "rate_limit_rps": customer.rps,
    }


@app.get("/v1/account")
async def account(customer: Customer = Security(auth)):
    """Who am I? Handy for customers debugging their integration."""
    return {
        "customer_id": customer.id,
        "status": customer.status,
        "billing_model": customer.billing_model,
        "credit_balance_usd": customer.credit_balance_micro / 1_000_000,
        "rps": customer.rps,
        "monthly_quota": customer.monthly_quota,
    }
