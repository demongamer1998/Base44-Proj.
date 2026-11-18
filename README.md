# SentinelPulse

SOC command-center dashboard for a security-monitoring platform: ingest telemetry, detect, triage.

## What runs

`index.html` is a self-contained static dashboard (no build step). Open it, or serve the repo root on port 3000.
All data is **simulated demo data stored in your browser's localStorage** — no backend is called, and nothing
leaves the page.

Sprint path it demonstrates:

- validate → normalize → preserve the original → SHA-256 → detect → display
- invalid events are quarantined; duplicate deliveries are ignored and audited
- "Tamper last original" + "Verify all" shows hash-mismatch detection
- severity and confidence are shown as separate signals
- telemetry health distinguishes `healthy` / `degraded` / `unknown`, so missing telemetry is never read as "no attack"
- detection-only mode: mitigation is always reported as `none` (no blocking, no credential attack, no real-target testing)

Cloudflare Logpush and Linux-agent health rows are placeholders until those sources are connected.

## Backend skeleton

`backend/main.py` is a FastAPI foundation skeleton: API-key tenant lookup (tenant never taken from the payload),
schema validation, idempotent ingestion and original-event hashing. It keeps events **in memory only**.

```sh
cd backend && pip install -r requirements.txt && uvicorn main:app --reload
```

Not yet built: PostgreSQL with row-level security, durable queue/broker, encrypted object storage, the detector
service and the read API the dashboard would consume.
