"""Pydantic v2 request/response schemas for the NeMo-Shield API."""

from __future__ import annotations

from enum import Enum
from typing import Dict, List, Literal, Optional

from pydantic import BaseModel, Field, field_validator, model_validator

MAX_TURN_CHARS = 2000
MAX_TURNS = 20


def _reject_blank(value: Optional[str]) -> Optional[str]:
    """Whitespace-only text passes `min_length=1` but carries no request."""
    if value is not None and not value.strip():
        raise ValueError("must not be empty or whitespace-only")
    return value


class ChatTurn(BaseModel):
    role: Literal["user", "assistant"]
    content: str = Field(..., min_length=1, max_length=MAX_TURN_CHARS)

    _content_not_blank = field_validator("content")(_reject_blank)


class ChatRequest(BaseModel):
    """A single `prompt`, or a conversation in `messages` ending on a user turn."""

    prompt: Optional[str] = Field(None, min_length=1, max_length=MAX_TURN_CHARS)
    messages: Optional[List[ChatTurn]] = Field(None, min_length=1, max_length=MAX_TURNS)
    stream: bool = False
    session_id: Optional[str] = Field(None, pattern=r"^[A-Za-z0-9._:-]{1,128}$")

    _prompt_not_blank = field_validator("prompt")(_reject_blank)

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


class RailPath(str, Enum):
    """Which layer decided the request.

    FAST_PATH:     gateway classifier blocked it before the Colang runtime ran (<1 ms).
    COLANG_INPUT:  the Colang input rail aborted the turn.
    COLANG_OUTPUT: the reply went through the model and PII was redacted on the way out.
    PASSTHROUGH:   the full Colang pipeline ran and nothing was changed.
    """

    FAST_PATH = "FAST_PATH"
    COLANG_INPUT = "COLANG_INPUT"
    COLANG_OUTPUT = "COLANG_OUTPUT"
    PASSTHROUGH = "PASSTHROUGH"


class ChatResponse(BaseModel):
    reply: str
    verdict: SafetyVerdict
    threat_category: Optional[str] = None
    confidence: float = 0.0
    latency_ms: float = 0.0
    rail_path: RailPath = RailPath.PASSTHROUGH
    timestamp: str


class ABTestRequest(BaseModel):
    prompt: str = Field(..., min_length=1, max_length=MAX_TURN_CHARS)

    _prompt_not_blank = field_validator("prompt")(_reject_blank)


class ABTestResponse(BaseModel):
    # The unguarded side is always the offline MockLLM, never a real model, so
    # this public endpoint cannot be used to query a model without rails.
    baseline: Literal["deterministic-mock"] = "deterministic-mock"
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
    # None on records written before rail attribution existed.
    rail_path: Optional[RailPath] = None
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
    # Rail breakdown. Blocks on records without `rail_path` (older entries)
    # are in blocked_requests but in neither split.
    fast_path_blocks: int = 0
    colang_blocks: int = 0
    sanitized_outputs: int = 0
    # Nearest-rank latency percentiles over every audited request.
    p50_latency_ms: float = 0.0
    p99_latency_ms: float = 0.0
    # Request counts per latency zone: under_1ms (fast path),
    # 1_to_100ms (Colang budget), over_100ms.
    latency_zones: Dict[str, int] = Field(
        default_factory=lambda: {"under_1ms": 0, "1_to_100ms": 0, "over_100ms": 0}
    )
