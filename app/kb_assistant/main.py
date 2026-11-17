"""HTTP API. Run with: uvicorn --factory kb_assistant.main:create_app"""
from __future__ import annotations

import hmac
import json
import logging
import sys
import threading
import time
from collections import defaultdict, deque

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from . import __version__
from .config import Settings, load_settings
from .guardrails import check_input, check_output, llama_guard_check, sanitize_context
from .llm import ClaudeGenerator, ExtractiveGenerator, Generator
from .rag import Index

SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Embedder-Policy": "require-corp",
    "Cache-Control": "no-store",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
}
BLOCKED = {"detail": "Request blocked by security policy"}

security_log = logging.getLogger("kb_assistant.security")


def _setup_logging() -> None:
    if not security_log.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(logging.Formatter("%(message)s"))
        security_log.addHandler(handler)
        security_log.setLevel(logging.INFO)
        security_log.propagate = False


def log_event(event: str, **fields) -> None:
    """One JSON line per security event, picked up by the log shipper (Wazuh / ELK)."""
    security_log.info(json.dumps({"ts": time.time(), "event": event, **fields}, ensure_ascii=False))


class RateLimiter:
    def __init__(self, per_minute: int):
        self.per_minute = per_minute
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            hits = self._hits[key]
            while hits and now - hits[0] > 60:
                hits.popleft()
            if len(hits) >= self.per_minute:
                return False
            hits.append(now)
            return True


class AskRequest(BaseModel):
    question: str = Field(min_length=1, max_length=4000)


class AskResponse(BaseModel):
    answer: str
    sources: list[str]


def create_app(settings: Settings | None = None, generator: Generator | None = None) -> FastAPI:
    _setup_logging()
    settings = settings or load_settings()
    index = Index.from_dir(settings.kb_dir)
    if generator is None:
        generator = (
            ClaudeGenerator(settings.llm_model, settings.canary, api_key=settings.llm_api_key)
            if settings.llm_api_key
            else ExtractiveGenerator()
        )
    limiter = RateLimiter(settings.rate_limit_per_minute)

    # No interactive API docs in a production service.
    app = FastAPI(title="kb-assistant", version=__version__, docs_url=None, redoc_url=None, openapi_url=None)

    @app.middleware("http")
    async def harden(request: Request, call_next):
        declared = request.headers.get("content-length")
        if declared and (not declared.isdigit() or int(declared) > settings.max_body_bytes):
            response = JSONResponse({"detail": "Payload too large"}, status_code=413)
        else:
            response = await call_next(request)
        response.headers.update(SECURITY_HEADERS)
        return response

    @app.get("/")
    def root() -> dict:
        return {"service": "kb-assistant", "version": __version__}

    @app.get("/healthz")
    def healthz() -> dict:
        return {"status": "ok"}

    @app.post("/api/v1/ask", response_model=AskResponse)
    def ask(body: AskRequest, request: Request):
        client = request.client.host if request.client else "unknown"
        if not limiter.allow(client):
            log_event("rate_limited", client=client)
            return JSONResponse({"detail": "Too many requests"}, status_code=429)

        question = body.question.strip()
        if len(question) > settings.max_question_chars:
            return JSONResponse({"detail": "Question is too long"}, status_code=422)

        verdict = check_input(question)
        if not verdict.blocked and settings.llama_guard_url:
            verdict = llama_guard_check(
                question,
                settings.llama_guard_url,
                settings.llama_guard_model,
                fail_closed=settings.llama_guard_fail_closed,
            )
        if verdict.blocked:
            log_event("guardrail_block", layer="input", reasons=verdict.reasons, client=client)
            return JSONResponse(BLOCKED, status_code=400)

        token = request.headers.get("x-staff-token", "")
        is_staff = bool(settings.staff_token) and hmac.compare_digest(token, settings.staff_token or "")
        chunks = index.search(question, audience="internal" if is_staff else "public")

        passages = []
        for chunk in chunks:
            text, removed = sanitize_context(chunk.text)
            if removed:
                log_event("guardrail_sanitize", layer="retrieval", doc=chunk.doc, removed_lines=removed)
            passages.append((chunk, text))

        answer, out_verdict = check_output(generator.answer(question, passages), settings.canary)
        if out_verdict.blocked:
            log_event("guardrail_block", layer="output", reasons=out_verdict.reasons, client=client)
            return JSONResponse(BLOCKED, status_code=400)
        if out_verdict.reasons:
            log_event("guardrail_redact", layer="output", reasons=out_verdict.reasons, client=client)

        return AskResponse(answer=answer, sources=sorted({c.doc for c, _ in passages}))

    return app
