"""Layered guardrails around the LLM call.

1. Input rail      - heuristic prompt-injection / jailbreak detector (always on, no network).
2. Moderation rail - optional Llama Guard classifier served by Ollama (LLAMA_GUARD_URL).
3. Retrieval rail  - retrieved chunks are untrusted data: instruction-like lines are removed
                     before they reach the model (indirect prompt injection).
4. Output rail     - canary-token leak detection and redaction of secrets / card numbers.

The heuristics are a cheap first line, not a complete defence: paraphrased attacks get
through them, which is why the moderation rail and retrieval-time access control exist.
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field

import httpx

# Zero-width characters and Unicode "tag" characters are a common way to hide instructions.
INVISIBLE_RE = re.compile("[​-‏⁠-⁤﻿\U000e0000-\U000e007f]")

INJECTION_PATTERNS: dict[str, re.Pattern[str]] = {
    "override_instructions": re.compile(
        r"\b(ignore|disregard|forget|override|bypass)\b[\w\s,'\"-]{0,40}?"
        r"\b(previous|prior|above|earlier|all|any|system|your)\b[\w\s,'\"-]{0,30}?"
        r"\b(instructions?|rules|prompts?|guidelines|polic(y|ies)|directives)\b",
        re.IGNORECASE,
    ),
    "prompt_exfiltration": re.compile(
        r"\b(reveal|show|print|repeat|output|leak|dump|display|tell me)\b[\w\s,'\"-]{0,40}?"
        r"\b(system|hidden|initial|original|developer|secret)\s+(prompt|instructions?|message|rules)\b",
        re.IGNORECASE,
    ),
    "role_hijack": re.compile(
        r"\b(you are now|from now on you are|pretend (to be|you are)|act as)\b[\w\s,'\"-]{0,40}?"
        r"\b(dan|jailbroken|unfiltered|unrestricted|uncensored|developer mode|evil)\b",
        re.IGNORECASE,
    ),
    "jailbreak_mode": re.compile(r"\b(developer|god|jailbreak|dan|sudo)\s+mode\b", re.IGNORECASE),
    "chat_template_tokens": re.compile(
        r"<\|?(im_start|im_end|system|endoftext|eot_id|start_header_id)\|?>|\[/?(INST|SYS)\]",
        re.IGNORECASE,
    ),
    "fake_role_prefix": re.compile(r"^\s*#*\s*(system|assistant|developer)\s*:", re.IGNORECASE | re.MULTILINE),
    "override_instructions_ru": re.compile(
        r"(игнорируй|проигнорируй|забудь|отмени|не обращай внимания на)[\w\s,'\"-]{0,40}?"
        r"(инструкци|правил|указани|ограничени|промпт)",
        re.IGNORECASE,
    ),
    "prompt_exfiltration_ru": re.compile(
        r"(покажи|выведи|раскрой|повтори|напиши)[\w\s,'\"-]{0,40}?"
        r"(системн\w*\s+(промпт|подсказк|инструкци|сообщени)|скрыт\w*\s+(промпт|инструкци))",
        re.IGNORECASE,
    ),
    "encoded_payload": re.compile(r"[A-Za-z0-9+/]{120,}={0,2}"),
}


@dataclass
class Verdict:
    blocked: bool
    reasons: list[str] = field(default_factory=list)


def normalize(text: str) -> tuple[str, bool]:
    """NFKC-normalise and strip invisible characters. Returns (text, had_invisible)."""
    folded = unicodedata.normalize("NFKC", text)
    cleaned = INVISIBLE_RE.sub("", folded)
    return cleaned, cleaned != folded


def check_input(text: str) -> Verdict:
    cleaned, had_invisible = normalize(text)
    reasons = [name for name, pattern in INJECTION_PATTERNS.items() if pattern.search(cleaned)]
    if had_invisible:
        reasons.append("invisible_characters")
    return Verdict(blocked=bool(reasons), reasons=reasons)


# --- Llama Guard (Ollama) -----------------------------------------------------------

def llama_guard_check(
    text: str,
    base_url: str,
    model: str = "llama-guard3:1b",
    fail_closed: bool = True,
    client: httpx.Client | None = None,
    timeout: float = 5.0,
) -> Verdict:
    """Classify a user message with Llama Guard. Its reply is 'safe' or 'unsafe\\nS1,S10'."""
    http = client or httpx.Client(timeout=timeout)
    try:
        response = http.post(
            f"{base_url.rstrip('/')}/api/chat",
            json={"model": model, "stream": False, "messages": [{"role": "user", "content": text}]},
        )
        response.raise_for_status()
        content = response.json()["message"]["content"].strip()
    except (httpx.HTTPError, KeyError, ValueError) as exc:
        return Verdict(blocked=fail_closed, reasons=[f"llama_guard_unavailable:{type(exc).__name__}"])
    finally:
        if client is None:
            http.close()

    first, _, rest = content.partition("\n")
    label = first.strip().lower()
    if label == "safe":
        return Verdict(blocked=False)
    if label == "unsafe":
        categories = [c.strip() for c in rest.replace("\n", ",").split(",") if c.strip()]
        return Verdict(blocked=True, reasons=[f"llama_guard:{c}" for c in categories] or ["llama_guard:unsafe"])
    return Verdict(blocked=fail_closed, reasons=["llama_guard_unparseable"])


# --- Retrieval rail -------------------------------------------------------------------

def sanitize_context(text: str) -> tuple[str, int]:
    """Drop instruction-like lines from a retrieved chunk. Returns (text, removed_lines)."""
    cleaned, _ = normalize(text)
    kept, removed = [], 0
    for line in cleaned.splitlines():
        if check_input(line).blocked:
            kept.append("[removed: instruction-like content]")
            removed += 1
        else:
            kept.append(line)
    return "\n".join(kept), removed


# --- Output rail ----------------------------------------------------------------------

SECRET_PATTERNS: dict[str, re.Pattern[str]] = {
    "private_key": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"),
    "aws_access_key": re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    "credential_assignment": re.compile(
        r"(?i)\b(api[_-]?key|secret|token|password|passwd)\b\s*[:=]\s*['\"]?[^\s'\"]{8,}"
    ),
}
CARD_CANDIDATE_RE = re.compile(r"\b(?:\d[ -]?){13,19}\b")


def _luhn_ok(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        n = int(ch)
        if i % 2 == 1:
            n = n * 2 - 9 if n > 4 else n * 2
        total += n
    return total % 10 == 0


def check_output(text: str, canary: str) -> tuple[str, Verdict]:
    """Block answers that leak the system prompt; redact secrets and card numbers."""
    if canary and canary in text:
        return "", Verdict(blocked=True, reasons=["system_prompt_leak"])
    reasons: list[str] = []
    for name, pattern in SECRET_PATTERNS.items():
        text, count = pattern.subn(f"[REDACTED:{name}]", text)
        if count:
            reasons.append(f"redacted:{name}")

    def _card(match: re.Match[str]) -> str:
        digits = re.sub(r"\D", "", match.group(0))
        if 13 <= len(digits) <= 19 and _luhn_ok(digits):
            reasons.append("redacted:card_number")
            return "[REDACTED:card_number]"
        return match.group(0)

    text = CARD_CANDIDATE_RE.sub(_card, text)
    return text, Verdict(blocked=False, reasons=sorted(set(reasons)))
