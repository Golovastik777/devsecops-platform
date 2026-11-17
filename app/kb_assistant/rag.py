"""Small retrieval layer over a markdown knowledge base.

Every document declares an audience in its front matter (``public`` or ``internal``).
Access control is enforced here, at retrieval time: a public caller never gets an
internal chunk into the model context, so no prompt can talk the model into leaking it.
Documents without front matter are treated as internal (deny by default).
"""
from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

TOKEN_RE = re.compile(r"[a-zа-яё0-9]+", re.IGNORECASE)
FRONT_MATTER_RE = re.compile(r"\A---\n(.*?)\n---\n", re.DOTALL)
AUDIENCES = ("public", "internal")


@dataclass(frozen=True)
class Chunk:
    doc: str
    audience: str
    text: str


def _stem(token: str) -> str:
    # Crude English plural folding: "withdrawals" -> "withdrawal". Good enough for a FAQ.
    return token[:-1] if len(token) > 3 and token.endswith("s") and not token.endswith("ss") else token


def tokenize(text: str) -> list[str]:
    return [_stem(t.lower()) for t in TOKEN_RE.findall(text)]


def parse_document(path: Path) -> list[Chunk]:
    raw = path.read_text(encoding="utf-8")
    audience = "internal"
    match = FRONT_MATTER_RE.match(raw)
    if match:
        for line in match.group(1).splitlines():
            key, _, value = line.partition(":")
            if key.strip() == "audience" and value.strip() in AUDIENCES:
                audience = value.strip()
        raw = raw[match.end():]
    paragraphs = [p.strip() for p in re.split(r"\n\s*\n", raw)]
    return [Chunk(path.stem, audience, p) for p in paragraphs if p and not p.startswith("#")]


class Index:
    def __init__(self, chunks: list[Chunk]):
        self.chunks = chunks
        self._tf = [Counter(tokenize(c.text)) for c in chunks]
        df = Counter(term for tf in self._tf for term in tf)
        n = max(len(chunks), 1)
        self._idf = {term: math.log(1 + n / count) for term, count in df.items()}

    @classmethod
    def from_dir(cls, kb_dir: Path) -> "Index":
        chunks: list[Chunk] = []
        for path in sorted(Path(kb_dir).rglob("*.md")):
            chunks.extend(parse_document(path))
        return cls(chunks)

    def search(self, query: str, audience: str = "public", k: int = 3) -> list[Chunk]:
        allowed = {"public"} if audience != "internal" else {"public", "internal"}
        terms = set(tokenize(query))
        scored: list[tuple[float, int]] = []
        for i, (chunk, tf) in enumerate(zip(self.chunks, self._tf)):
            if chunk.audience not in allowed:
                continue
            length = sum(tf.values()) or 1
            score = sum(tf[t] * self._idf.get(t, 0.0) for t in terms) / math.sqrt(length)
            if score > 0:
                scored.append((score, i))
        scored.sort(reverse=True)
        return [self.chunks[i] for _, i in scored[:k]]
