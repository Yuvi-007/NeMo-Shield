"""API routes for the NeMo-Shield guardrails gateway."""

from __future__ import annotations

import importlib.util
import os
import sys
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional, Tuple
from uuid import uuid4

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, Request, status
from nemoguardrails import LLMRails, RailsConfig
from nemoguardrails.types import ChatMessage, Role

from backend.database import audit_store
from backend.models import (
    ABTestRequest,
    ABTestResponse,
    AuditLogEntry,
    ChatRequest,
    ChatResponse,
    SafetyVerdict,
    TelemetrySummary,
)

ROOT = Path(__file__).resolve().parent.parent
CONFIG_DIR = ROOT / "config"

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from mock_llm import MockLLM  # noqa: E402

BLOCK_MESSAGE = (
    "Request blocked by NeMo-Shield Input Rail: "
    "Malicious prompt injection pattern detected (OWASP LLM01)."
)
REDACTION_TOKENS = ("[REDACTED_EMAIL]", "[REDACTED_CC]", "[REDACTED_KEY]")
PII_CATEGORY = "PII_LEAKAGE"
UNGUARDED_SYSTEM_PROMPT = "You are a helpful assistant."


def _load_actions_module():
    """Load config/actions.py by path (avoids clashing with any `config` package)."""
    spec = importlib.util.spec_from_file_location("nemo_shield_actions", CONFIG_DIR / "actions.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_actions = _load_actions_module()
classify_threat = _actions.classify_threat
mask_sensitive_entities = _actions.mask_sensitive_entities
OWASP_LLM01 = _actions.OWASP_LLM01

router = APIRouter(prefix="/api/v1")

RATE_LIMIT_MAX_REQUESTS = 60
RATE_LIMIT_WINDOW_SECONDS = 60.0
RATE_LIMIT_DETAIL = f"Rate limit exceeded: max {RATE_LIMIT_MAX_REQUESTS} requests/min"


class SlidingWindowRateLimiter:
    """In-memory, per-IP sliding-window limiter (single process only)."""

    def __init__(self, max_requests: int, window_seconds: float) -> None:
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._hits: Dict[str, Deque[float]] = defaultdict(deque)

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        hits = self._hits[key]
        while hits and now - hits[0] >= self.window_seconds:
            hits.popleft()
        if len(hits) >= self.max_requests:
            return False
        hits.append(now)
        return True

    def reset(self) -> None:
        self._hits.clear()


rate_limiter = SlidingWindowRateLimiter(RATE_LIMIT_MAX_REQUESTS, RATE_LIMIT_WINDOW_SECONDS)


async def enforce_rate_limit(request: Request) -> None:
    client_ip = request.client.host if request.client else "unknown"
    if not rate_limiter.allow(client_ip):
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=RATE_LIMIT_DETAIL)

_rails: Optional[LLMRails] = None
_base_llm = MockLLM()


def use_mock_llm() -> bool:
    return os.getenv("NEMO_SHIELD_FORCE_MOCK") == "1" or not os.getenv("OPENAI_API_KEY")


def get_rails() -> LLMRails:
    """Return the shared LLMRails instance, building it on first use."""
    global _rails
    if _rails is None:
        config = RailsConfig.from_path(str(CONFIG_DIR))
        _rails = LLMRails(config, llm=MockLLM()) if use_mock_llm() else LLMRails(config)
    return _rails


async def _run_guarded(prompt: str) -> str:
    """Run the full Colang input -> dialog -> output rail pipeline."""
    result: Any = await get_rails().generate_async(messages=[{"role": "user", "content": prompt}])
    return result["content"] if isinstance(result, dict) else str(result)


async def _guard(prompt: str) -> Tuple[str, float, Dict[str, Any]]:
    """Classify first; block high-confidence injections before NeMo runs.

    The classifier is the same ClassifyThreatAction the Colang input rail calls,
    so a BLOCKED score here is a verdict the rail would reach anyway. Skipping
    the Colang runtime for it saves ~100 ms. Everything else (benign, FLAGGED,
    and PII output checks) still goes through the full rails.
    """
    start = time.perf_counter()
    threat = await classify_threat(prompt)
    if threat["rail_action"] == "BLOCKED":
        reply = BLOCK_MESSAGE
    else:
        reply = await _run_guarded(prompt)
    latency_ms = (time.perf_counter() - start) * 1000
    return reply, latency_ms, threat


async def _run_unguarded(prompt: str) -> Tuple[str, float]:
    start = time.perf_counter()
    response = await _base_llm.generate_async(
        [
            ChatMessage(role=Role.SYSTEM, content=UNGUARDED_SYSTEM_PROMPT),
            ChatMessage.from_user(prompt),
        ]
    )
    latency_ms = (time.perf_counter() - start) * 1000
    return (response.content or "").strip(), latency_ms


def _classify_reply(reply: str, threat: Dict[str, Any]) -> Tuple[SafetyVerdict, Optional[str], float]:
    """Map a rails reply plus the input classifier result to a verdict."""
    if reply.strip() == BLOCK_MESSAGE:
        return SafetyVerdict.INPUT_BLOCKED, OWASP_LLM01, max(threat["confidence"], 0.0)
    if any(token in reply for token in REDACTION_TOKENS):
        return SafetyVerdict.OUTPUT_ALTERED, PII_CATEGORY, 1.0
    category = threat["owasp_tag"] if threat["rail_action"] == "FLAGGED" else None
    return SafetyVerdict.ALLOWED, category, threat["confidence"]


@router.get("/health")
async def health() -> Dict[str, Any]:
    return {"status": "healthy", "service": "NeMo-Shield", "rails_active": True}


async def _record_audit_log(entry: AuditLogEntry) -> None:
    await audit_store.insert_audit_log(entry.model_dump(mode="json"))


async def _record_telemetry_snapshot(summary: TelemetrySummary) -> None:
    snapshot = summary.model_dump(mode="json")
    snapshot["timestamp"] = datetime.now(timezone.utc).isoformat()
    await audit_store.insert_telemetry_snapshot(snapshot)


@router.post(
    "/guard/chat", response_model=ChatResponse, dependencies=[Depends(enforce_rate_limit)]
)
async def guard_chat(
    request: ChatRequest, http_request: Request, background_tasks: BackgroundTasks
) -> ChatResponse:
    reply, latency_ms, threat = await _guard(request.prompt)
    verdict, category, confidence = _classify_reply(reply, threat)
    response = ChatResponse(
        reply=reply,
        verdict=verdict,
        threat_category=category,
        confidence=round(confidence, 4),
        latency_ms=round(latency_ms, 2),
        timestamp=datetime.now(timezone.utc).isoformat(),
    )
    entry = AuditLogEntry(
        id=uuid4().hex,
        timestamp=response.timestamp,
        # Never persist raw user PII to the audit store.
        prompt=await mask_sensitive_entities(request.prompt),
        reply=response.reply,
        verdict=response.verdict,
        threat_category=response.threat_category,
        confidence=response.confidence,
        latency_ms=response.latency_ms,
        client_ip=http_request.client.host if http_request.client else None,
    )
    background_tasks.add_task(_record_audit_log, entry)
    return response


@router.get("/audit/logs", response_model=List[AuditLogEntry])
async def get_audit_logs(
    limit: int = Query(50, ge=1, le=500),
    skip: int = Query(0, ge=0),
    verdict: Optional[SafetyVerdict] = None,
) -> List[AuditLogEntry]:
    records = await audit_store.find_audit_logs(
        limit=limit, skip=skip, verdict=verdict.value if verdict else None
    )
    return [AuditLogEntry(**record) for record in records]


@router.get("/telemetry", response_model=TelemetrySummary)
async def get_telemetry(background_tasks: BackgroundTasks) -> TelemetrySummary:
    summary = TelemetrySummary(**await audit_store.telemetry_summary())
    background_tasks.add_task(_record_telemetry_snapshot, summary)
    return summary


@router.post(
    "/guard/ab-test", response_model=ABTestResponse, dependencies=[Depends(enforce_rate_limit)]
)
async def guard_ab_test(request: ABTestRequest) -> ABTestResponse:
    unguarded_reply, unguarded_ms = await _run_unguarded(request.prompt)
    guarded_reply, guarded_ms, threat = await _guard(request.prompt)
    verdict, _, _ = _classify_reply(guarded_reply, threat)
    return ABTestResponse(
        unguarded_reply=unguarded_reply,
        guarded_reply=guarded_reply,
        intervened=verdict != SafetyVerdict.ALLOWED,
        latency_delta_ms=round(guarded_ms - unguarded_ms, 2),
    )
