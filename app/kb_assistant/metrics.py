"""Prometheus metrics.

Served on a separate port (METRICS_PORT, 9100 in the image) so /metrics is never reachable
through the public ingress; the NetworkPolicy lets only the monitoring namespace scrape it.
"""
from __future__ import annotations

import threading

from prometheus_client import Counter, Histogram, start_http_server

REQUESTS = Counter("kb_assistant_requests", "HTTP requests", ["endpoint", "method", "status"])
LATENCY = Histogram(
    "kb_assistant_request_duration_seconds",
    "Request latency",
    ["endpoint"],
    buckets=(0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10),
)
GUARDRAIL = Counter("kb_assistant_guardrail_events", "Guardrail decisions", ["layer", "action"])
RATE_LIMITED = Counter("kb_assistant_rate_limited", "Requests rejected by the rate limiter")

# Unknown paths (scanners, typos) collapse into one label value so they cannot blow up cardinality.
KNOWN_ENDPOINTS = {"/", "/healthz", "/api/v1/ask"}

_lock = threading.Lock()
_started_port: int | None = None


def endpoint_label(path: str) -> str:
    return path if path in KNOWN_ENDPOINTS else "other"


def start_metrics_server(port: int) -> None:
    global _started_port
    with _lock:
        if _started_port is None:
            start_http_server(port)
            _started_port = port
