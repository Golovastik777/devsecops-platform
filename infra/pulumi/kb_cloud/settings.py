from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Settings:
    name: str = "kb-assistant"
    # Networks allowed to reach the Kubernetes API endpoint. Never 0.0.0.0/0.
    admin_cidrs: list[str] = field(default_factory=lambda: ["198.51.100.0/24"])
    kubernetes_version: str = "1.34"
    node_count_min: int = 2
    node_count_max: int = 4
    gcp_project: str = "kb-assistant-prod"
    gcp_region: str = "europe-west3"

    def __post_init__(self) -> None:
        if not self.admin_cidrs or any(c in ("0.0.0.0/0", "::/0") for c in self.admin_cidrs):
            raise ValueError("adminCidrs must list specific networks, not the whole internet")
