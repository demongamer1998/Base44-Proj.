"""SentinelPulse ingestion API — foundation sprint skeleton (in-memory, not production).

Run: pip install fastapi uvicorn && uvicorn main:app --reload
Tenant identity comes from the server-side API key, never from the client payload.
TODO: PostgreSQL with RLS, durable queue, encrypted object storage.
"""
import hashlib
from datetime import datetime, timezone
from urllib.parse import unquote_plus

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

app = FastAPI(title="SentinelPulse API", version="0.1.0")

API_KEYS = {"dev-key-acme": "acme-demo"}  # placeholder; use a secret manager
EVENTS: dict[str, list[dict]] = {}
QUARANTINE: dict[str, int] = {}


class EventIn(BaseModel):
    event_id: str = Field(min_length=1, max_length=128)
    asset: str = Field(min_length=1, max_length=253)
    path: str = Field(max_length=2048)
    observed_at: datetime


def tenant_for(key: str | None) -> str:
    tenant = API_KEYS.get(key or "")
    if not tenant:
        raise HTTPException(401, "invalid credentials")
    return tenant


def sev_label(n: int) -> str:
    return "Informational" if n < 20 else "Low" if n < 40 else "Medium" if n < 60 else "High" if n < 80 else "Critical"


@app.post("/v1/events", status_code=202)
async def ingest(ev: EventIn, x_api_key: str | None = Header(default=None)):
    tenant = tenant_for(x_api_key)
    bucket = EVENTS.setdefault(tenant, [])
    if any(e["event_id"] == ev.event_id for e in bucket):
        return {"status": "duplicate"}  # idempotent
    raw = ev.model_dump_json().encode()
    # Normalize before matching: percent-encoded payloads must be decoded, or
    # "%27 OR %271%27%3D%271" never matches a signature.
    p = unquote_plus(ev.path).lower()
    sev, conf, cat = (72, 55, "SQL injection") if "' or " in p else (55, 70, "XSS") if "<script" in p else (10, 20, "Unclassified")
    bucket.insert(0, {
        "event_id": ev.event_id, "asset": ev.asset, "category": cat,
        "severity": sev, "severity_label": sev_label(sev), "confidence": conf,
        "sha256": hashlib.sha256(raw).hexdigest(), "original": raw.decode(),
        "ingested_at": datetime.now(timezone.utc).isoformat(), "mitigation": "none (detection-only)",
    })
    return {"status": "accepted"}


@app.get("/v1/events")
async def list_events(x_api_key: str | None = Header(default=None)):
    return EVENTS.get(tenant_for(x_api_key), [])
