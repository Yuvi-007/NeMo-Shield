"""API routes for the NeMo-Shield guardrails gateway."""

from __future__ import annotations

import importlib.util
import os
import sys
import time
import unicodedata
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Deque, Dict, List, Optional, Sequence, Tuple
from uuid import uuid4

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, Request, status
from nemoguardrails import LLMRails, RailsConfig
from nemoguardrails.types import ChatMessage, Role

from backend.database import audit_store
from backend.security import canonicalize_text, verify_admin_key
from backend.models import (
    ABTestRequest,
    ABTestResponse,
    AuditLogEntry,
    ChatRequest,
    ChatResponse,
    ChatTurn,
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
HISTORY_CONTEXT_KEY = _actions.HISTORY_CONTEXT_KEY

router = APIRouter(prefix="/api/v1")

RATE_LIMIT_MAX_REQUESTS = 60
RATE_LIMIT_WINDOW_SECONDS = 60.0
RATE_LIMIT_DETAIL = f"Rate limit exceeded: max {RATE_LIMIT_MAX_REQUESTS} requests/min"


class SlidingWindowRateLimiter:
    """In-memory, per-IP sliding-window limiter (single process only)."""

    def __init__(
        self, max_requests: int, window_seconds: float, clock: Callable[[], float] = time.monotonic
    ) -> None:
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._clock = clock
        self._hits: Dict[str, Deque[float]] = defaultdict(deque)
        self._last_sweep = clock()

    def _sweep(self, now: float) -> None:
        """Drop keys with no hits inside the window, at most once per window."""
        if now - self._last_sweep < self.window_seconds:
            return
        self._last_sweep = now
        idle = [k for k, hits in self._hits.items() if not hits or now - hits[-1] >= self.window_seconds]
        for key in idle:
            del self._hits[key]

    def tracked_keys(self) -> int:
        return len(self._hits)

    def allow(self, key: str) -> bool:
        now = self._clock()
        self._sweep(now)
        hits = self._hits[key]
        while hits and now - hits[0] >= self.window_seconds:
            hits.popleft()
        if len(hits) >= self.max_requests:
            return False
        hits.append(now)
        return True

    def reset(self) -> None:
        self._hits.clear()
        self._last_sweep = self._clock()


rate_limiter = SlidingWindowRateLimiter(RATE_LIMIT_MAX_REQUESTS, RATE_LIMIT_WINDOW_SECONDS)


def behind_trusted_proxy() -> bool:
    return os.getenv("BEHIND_TRUSTED_PROXY") == "1"


def trusted_proxy_hops() -> int:
    """Number of proxies we control in front of the app (TRUSTED_PROXY_HOPS, default 1)."""
    try:
        hops = int(os.getenv("TRUSTED_PROXY_HOPS", "1"))
    except ValueError:
        return 1
    return hops if hops >= 1 else 1


def get_client_ip(request: Request) -> str:
    """Resolve the client IP, trusting X-Forwarded-For only behind our own proxies.

    Each proxy appends the address it saw, so only the rightmost entries are
    written by infrastructure we trust. Anything to the left is client-supplied
    and spoofable. With N trusted proxies, the client IP is the Nth from the right.
    """
    peer = request.client.host if request.client else "unknown"
    if not behind_trusted_proxy():
        return peer
    entries = [e.strip() for e in request.headers.get("x-forwarded-for", "").split(",") if e.strip()]
    hops = trusted_proxy_hops()
    if len(entries) < hops:
        return peer
    return entries[-hops]


async def enforce_rate_limit(request: Request) -> None:
    client_ip = get_client_ip(request)
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


async def _run_guarded(prompt: str, history: Sequence[Dict[str, str]] = ()) -> str:
    """Run the full Colang input -> dialog -> output rail pipeline for one turn.

    Colang 2.x rejects `assistant` messages and treats every `user` message as
    a new turn (one model call each), so prior turns travel as a context
    update instead. GenerateAnswerAction reads them back from the context.
    The context is always sent, even when empty, so nothing carries over
    between requests.
    """
    messages = [
        {"role": "context", "content": {HISTORY_CONTEXT_KEY: [dict(turn) for turn in history]}},
        {"role": "user", "content": prompt},
    ]
    result: Any = await get_rails().generate_async(messages=messages)
    return result["content"] if isinstance(result, dict) else str(result)


async def _scan_conversation(turns: Sequence[ChatTurn]) -> Dict[str, Any]:
    """Score the latest turn first, then everything else the model will see.

    History is client-supplied and is sent to the model, so an injection in an
    earlier turn, a forged assistant turn, or an attack split across user
    turns must be caught here too. The latest turn is scored first, so the
    common single-turn block costs the same as before.

    User turns are scored once, joined: any signature inside one turn is also
    inside the joined text, and extra signals only raise the combined score.
    Assistant turns (which a client can forge) are scored one by one, not
    joined with user text, so model output cannot combine with user words
    into a false positive.
    """
    latest = await classify_threat(canonicalize_text(turns[-1].content))
    if latest["rail_action"] == "BLOCKED" or len(turns) == 1:
        return latest
    texts = [" ".join(turn.content for turn in turns if turn.role == "user")]
    texts += [turn.content for turn in turns[:-1] if turn.role == "assistant"]
    worst = latest
    for text in texts:
        result = await classify_threat(canonicalize_text(text))
        if result["confidence"] > worst["confidence"]:
            worst = result
        if worst["rail_action"] == "BLOCKED":
            break
    return worst


async def _guard(turns: Sequence[ChatTurn]) -> Tuple[str, float, Dict[str, Any]]:
    """Classify first; block high-confidence injections before NeMo runs.

    The classifier is the same ClassifyThreatAction the Colang input rail calls,
    so a BLOCKED score here is a verdict the rail would reach anyway. Skipping
    the Colang runtime for it saves ~100 ms. Everything else (benign, FLAGGED,
    and PII output checks) still goes through the full rails.

    The canonical form is for detection only. It strips combining marks and
    folds homoglyphs, which corrupts non-Latin scripts (Devanagari vowel signs,
    Arabic harakat, Japanese dakuten, Cyrillic), so the rails and the LLM get
    the user's original text, NFC-normalized. Security is unchanged: anything
    the canonical form would block has already been blocked here.
    """
    start = time.perf_counter()
    threat = await _scan_conversation(turns)
    if threat["rail_action"] == "BLOCKED":
        reply = BLOCK_MESSAGE
    else:
        latest = unicodedata.normalize("NFC", turns[-1].content)
        history = [
            {"role": turn.role, "content": unicodedata.normalize("NFC", turn.content)} for turn in turns[:-1]
        ]
        # Defense in depth: re-mask whatever the rails return, so PII never
        # leaves the gateway even if the Colang output rail misses it.
        reply = await mask_sensitive_entities(await _run_guarded(latest, history))
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
    turns = request.turns
    reply, latency_ms, threat = await _guard(turns)
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
        prompt=await mask_sensitive_entities(turns[-1].content),
        reply=response.reply,
        verdict=response.verdict,
        threat_category=response.threat_category,
        confidence=response.confidence,
        latency_ms=response.latency_ms,
        client_ip=get_client_ip(http_request),
        session_id=request.session_id,
    )
    background_tasks.add_task(_record_audit_log, entry)
    return response


@router.get(
    "/audit/logs",
    response_model=List[AuditLogEntry],
    dependencies=[Depends(enforce_rate_limit), Depends(verify_admin_key)],
)
async def get_audit_logs(
    limit: int = Query(50, ge=1, le=500),
    skip: int = Query(0, ge=0),
    verdict: Optional[SafetyVerdict] = None,
) -> List[AuditLogEntry]:
    records = await audit_store.find_audit_logs(
        limit=limit, skip=skip, verdict=verdict.value if verdict else None
    )
    return [AuditLogEntry(**record) for record in records]


@router.get(
    "/telemetry", response_model=TelemetrySummary, dependencies=[Depends(enforce_rate_limit), Depends(verify_admin_key)]
)
async def get_telemetry(background_tasks: BackgroundTasks) -> TelemetrySummary:
    summary = TelemetrySummary(**await audit_store.telemetry_summary())
    background_tasks.add_task(_record_telemetry_snapshot, summary)
    return summary


@router.post(
    "/guard/ab-test", response_model=ABTestResponse, dependencies=[Depends(enforce_rate_limit)]
)
async def guard_ab_test(request: ABTestRequest) -> ABTestResponse:
    unguarded_reply, unguarded_ms = await _run_unguarded(request.prompt)
    guarded_reply, guarded_ms, threat = await _guard([ChatTurn(role="user", content=request.prompt)])
    verdict, _, _ = _classify_reply(guarded_reply, threat)
    return ABTestResponse(
        unguarded_reply=unguarded_reply,
        guarded_reply=guarded_reply,
        intervened=verdict != SafetyVerdict.ALLOWED,
        latency_delta_ms=round(guarded_ms - unguarded_ms, 2),
    )
