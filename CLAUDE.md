# Project 1: NeMo-Shield (Enterprise AI Safety & Guardrails Engine)

## Target Role
AI Associate Prompt Engineer at NVIDIA. Standalone full-stack portfolio system demonstrating LLM runtime safety, NeMo Guardrails (Colang), deterministic JSON output, and audit logging.

## Stack
- Python 3.10+ / FastAPI / Uvicorn
- NVIDIA NeMo Guardrails (nemoguardrails, Colang 2.x)
- MongoDB (motor async client)
- Pytest

## Rules for Claude
1. Always explain code changes step-by-step to Yuvraj before executing.
2. Implement strict unit tests for prompt injection and PII mitigation before pushing endpoints.
3. Use clean conventional git commits (feat:, fix:, test:, docs:).
