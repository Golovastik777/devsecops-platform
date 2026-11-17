"""Runtime settings, read from the environment once at startup."""
from __future__ import annotations

import os
import secrets
from dataclasses import dataclass
from pathlib import Path

DEFAULT_KB_DIR = Path(__file__).resolve().parent.parent / "kb"


def _bool(value: str | None, default: bool) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _read_secret(name: str) -> str | None:
    """Prefer <NAME>_FILE (mounted secret) over a plain environment variable."""
    path = os.getenv(f"{name}_FILE")
    if path and Path(path).is_file():
        return Path(path).read_text(encoding="utf-8").strip() or None
    return os.getenv(name) or None


@dataclass(frozen=True)
class Settings:
    kb_dir: Path = DEFAULT_KB_DIR
    max_question_chars: int = 1000
    max_body_bytes: int = 8192
    rate_limit_per_minute: int = 30
    staff_token: str | None = None
    llm_api_key: str | None = None
    llm_model: str = "claude-opus-5-5"
    llama_guard_url: str | None = None
    llama_guard_model: str = "llama-guard3:1b"
    llama_guard_fail_closed: bool = True
    canary: str = ""


def load_settings() -> Settings:
    return Settings(
        kb_dir=Path(os.getenv("KB_DIR", str(DEFAULT_KB_DIR))),
        max_question_chars=int(os.getenv("MAX_QUESTION_CHARS", "1000")),
        max_body_bytes=int(os.getenv("MAX_BODY_BYTES", "8192")),
        rate_limit_per_minute=int(os.getenv("RATE_LIMIT_PER_MINUTE", "30")),
        staff_token=_read_secret("STAFF_TOKEN"),
        llm_api_key=_read_secret("ANTHROPIC_API_KEY"),
        llm_model=os.getenv("LLM_MODEL", "claude-opus-5-5"),
        llama_guard_url=os.getenv("LLAMA_GUARD_URL") or None,
        llama_guard_model=os.getenv("LLAMA_GUARD_MODEL", "llama-guard3:1b"),
        llama_guard_fail_closed=_bool(os.getenv("LLAMA_GUARD_FAIL_CLOSED"), True),
        # A per-process canary token is planted in the system prompt; seeing it in
        # an answer means the prompt leaked.
        canary=os.getenv("PROMPT_CANARY") or f"cnry-{secrets.token_hex(8)}",
    )
