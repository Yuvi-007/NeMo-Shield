"""FastAPI entry point for NeMo-Shield.

Run:  uvicorn backend.main:app --reload
"""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.routes import get_rails, router


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Pre-warm: parse the Colang config and build LLMRails once at startup.
    app.state.rails = get_rails()
    yield


app = FastAPI(
    title="NeMo-Shield",
    description="Enterprise AI safety and guardrails gateway built on NVIDIA NeMo Guardrails.",
    version="0.2.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)
