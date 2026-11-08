"""Pydantic v2 request/response schemas for the NeMo-Shield API."""

from __future__ import annotations

from enum import Enum
from typing import Dict, List, Literal, Optional

from pydantic import BaseModel, Field, model_validator

MAX_TURN_CHARS = 2000
MAX_TURNS = 20


class ChatTurn(BaseModel):
    role: Literal["user", "assistant"]
    content: str = Field(..., min_length=1, max_length=MAX_TURN_CHARS)


class ChatRequest(BaseModel):
    """A single `prompt`, or a conversation in `messages` ending on a user turn."""

    prompt: Optional[str] = Field(None, min_length=1, max_length=MAX_TURN_CHARS)
    messages: Optional[List[ChatTurn]] = Field(None, min_length=1, max_length=MAX_TURNS)
    stream: bool = False
    session_id: Optional[str] = Field(None, pattern=r"^[A-Za-z0-9._:-]{1,128}$")

    @model_validator(mode="after")
    def _one_input_ending_on_user(self) -> "ChatRequest":
        if (self.prompt is None) == (self.messages is None):
            raise ValueError("send exactly one of 'prompt' or 'messages'")
        if self.messages is not None and self.messages[-1].role != "user":
            raise ValueError("the last turn in 'messages' must have role 'user'")
        return self

    @property
    def turns(self) -> List[ChatTurn]:
        """The conversation; a bare `prompt` is a single user turn."""
        if self.messages is not None:
            return list(self.messages)
        return [ChatTurn(role="user", content=self.prompt)]


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


class AuditLogEntry(BaseModel):
    id: str
    timestamp: str
    prompt: str
    reply: str
    verdict: SafetyVerdict
    threat_category: Optional[str] = None
    confidence: float
    latency_ms: float
    client_ip: Optional[str] = None
    session_id: Optional[str] = None


class TelemetrySummary(BaseModel):
    total_requests: int
    blocked_requests: int
    altered_requests: int
    clean_requests: int
    block_rate_pct: float
    avg_latency_ms: float
    threat_distribution: Dict[str, int]
