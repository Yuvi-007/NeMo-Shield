"""FastAPI entry point for NeMo-Shield.

Run:  uvicorn backend.main:app --reload
"""

from __future__ import annotations

from dotenv import load_dotenv

# Load .env before importing anything that reads env vars (DB, rails, admin key).
load_dotenv()

import os  # noqa: E402
from contextlib import asynccontextmanager  # noqa: E402

from fastapi import FastAPI  # noqa: E402
from fastapi.middleware.cors import CORSMiddleware  # noqa: E402

from backend.database import audit_store  # noqa: E402
from backend.routes import get_rails, router  # noqa: E402
from backend.security import configured_admin_key  # noqa: E402

ALLOWED_ORIGINS = [
    origin.strip()
    for origin in os.getenv("ALLOWED_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173").split(",")
    if origin.strip()
]


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Pre-warm: parse the Colang config and build LLMRails once at startup.
    app.state.rails = get_rails()
    if configured_admin_key() is None:
        print(
            "[NeMo-Shield] WARNING: ADMIN_API_KEY is unset or uses the legacy default; "
            "/telemetry and /audit/logs will return 503.",
            flush=True,
        )
    await audit_store.connect()
    yield
    await audit_store.close()


app = FastAPI(
    title="NeMo-Shield",
    description="Enterprise AI safety and guardrails gateway built on NVIDIA NeMo Guardrails.",
    version="0.2.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)
