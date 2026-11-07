"""Pydantic v2 request/response schemas for the NeMo-Shield API."""

from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class ChatRequest(BaseModel):
    prompt: str = Field(..., min_length=1, max_length=2000)
    stream: bool = False
    session_id: Optional[str] = None


class SafetyVerdict(str, Enum):
    ALLOWED = "ALLOWED"
    INPUT_BLOCKED = "INPUT_BLOCKED"
    OUTPUT_ALTERED = "OUTPUT_ALTERED"


class ChatResponse(BaseModel):
    reply: str
    verdict: SafetyVerdict
    threat_category: Optional[str] = None
    confidence: float = 0.0
    latency_ms: float = 0.0
    timestamp: str


class ABTestRequest(BaseModel):
    prompt: str = Field(..., min_length=1, max_length=2000)


class ABTestResponse(BaseModel):
    unguarded_reply: str
    guarded_reply: str
    intervened: bool
    latency_delta_ms: float
