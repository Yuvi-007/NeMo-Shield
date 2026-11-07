"""Offline fallback LLM for NeMo-Shield.

Implements NeMo Guardrails' `LLMModel` protocol with deterministic, keyword-based
replies, so the rails can be exercised without an API key or network access.
"""

from __future__ import annotations

import asyncio
from typing import AsyncIterator, List, Optional, Union

from nemoguardrails.types import ChatMessage, LLMResponse, LLMResponseChunk

_SQL_NOSQL_ANSWER = (
    "Core SQL vs NoSQL trade-offs:\n"
    "1. Schema: SQL enforces a fixed schema; NoSQL allows flexible, evolving documents.\n"
    "2. Consistency: SQL offers ACID transactions; many NoSQL stores favor eventual consistency (BASE).\n"
    "3. Scaling: SQL usually scales vertically; NoSQL is built to shard horizontally.\n"
    "4. Querying: SQL has rich joins and ad-hoc queries; NoSQL is optimized for known access patterns.\n"
    "Choose SQL for relational integrity, NoSQL for scale and schema flexibility."
)

# Synthetic test data only: used to prove the output rail redacts PII.
_PII_LEAK_ANSWER = (
    "Contact the on-call engineer at oncall.engineer@example.com. "
    "Staging card: 4111-1111-1111-1111. "
    "Staging key: sk-test4f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c."
)

_GENERIC_ANSWER = "[mock-llm] This is a deterministic offline response."


def _last_user_text(prompt: Union[str, List[ChatMessage]]) -> str:
    if isinstance(prompt, str):
        return prompt
    for message in reversed(prompt):
        role = getattr(message.role, "value", message.role)
        if role == "user" and isinstance(message.content, str):
            return message.content
    return ""


class MockLLM:
    """Deterministic stand-in for the main LLM."""

    @property
    def model_name(self) -> str:
        return "nemo-shield-mock"

    @property
    def provider_name(self) -> Optional[str]:
        return "mock"

    @property
    def provider_url(self) -> Optional[str]:
        return None

    def _reply(self, prompt: Union[str, List[ChatMessage]]) -> str:
        text = _last_user_text(prompt).lower()
        if "sql" in text:
            return _SQL_NOSQL_ANSWER
        if any(word in text for word in ("contact", "credential", "staging")):
            return _PII_LEAK_ANSWER
        return _GENERIC_ANSWER

    async def generate_async(self, prompt, *, stop=None, **kwargs) -> LLMResponse:
        return LLMResponse(content=self._reply(prompt), model=self.model_name)

    async def stream_async(self, prompt, *, stop=None, **kwargs) -> AsyncIterator[LLMResponseChunk]:
        words = self._reply(prompt).split(" ")
        for index, word in enumerate(words):
            await asyncio.sleep(0)
            yield LLMResponseChunk(delta_content=word + (" " if index < len(words) - 1 else ""))
