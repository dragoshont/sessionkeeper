"""Configuration loading.

Global settings come from environment variables; provider definitions come from
a small JSON/YAML-ish config file (JSON only in v0.1, to stay dependency-free).
Secrets (vault API key) come from the environment, never the config file.

Env:
  SESSIONKEEPER_VAULT_URL       default http://vaultkeeper.default.svc:8087
  SESSIONKEEPER_VAULT_API_KEY   optional Bearer for a guarded vaultkeeper
  SESSIONKEEPER_PROVIDERS_FILE  default /config/providers.json
  SESSIONKEEPER_INTERVAL        scheduler tick seconds (default 300)
  SESSIONKEEPER_PORT            metrics/health port (default 9090)

providers.json:
  [
    {
      "id": "example",
      "vault_item": "machine-managed/example-session",
      "refresh_margin_seconds": 2700,
      "ttl_hint_seconds": 3600,
      "settings": { "base_url": "...", "refresh_path": "...", ... }
    }
  ]
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field

from .provider import ProviderConfig


@dataclass
class AppConfig:
    vault_url: str
    vault_api_key: str | None
    providers_file: str
    interval_seconds: float
    port: int
    providers: list[ProviderConfig] = field(default_factory=list)


def _load_providers(path: str) -> list[ProviderConfig]:
    if not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8") as fh:
        raw = json.load(fh)
    if not isinstance(raw, list):
        raise ValueError(f"{path}: expected a JSON array of providers")
    out: list[ProviderConfig] = []
    for entry in raw:
        out.append(
            ProviderConfig(
                id=entry["id"],
                vault_item=entry["vault_item"],
                refresh_margin_seconds=int(entry.get("refresh_margin_seconds", 45 * 60)),
                ttl_hint_seconds=int(entry.get("ttl_hint_seconds", 60 * 60)),
                settings=entry.get("settings", {}) or {},
            )
        )
    return out


def load() -> AppConfig:
    providers_file = os.environ.get("SESSIONKEEPER_PROVIDERS_FILE", "/config/providers.json")
    return AppConfig(
        vault_url=os.environ.get("SESSIONKEEPER_VAULT_URL", "http://vaultkeeper.default.svc:8087"),
        vault_api_key=os.environ.get("SESSIONKEEPER_VAULT_API_KEY") or None,
        providers_file=providers_file,
        interval_seconds=float(os.environ.get("SESSIONKEEPER_INTERVAL", "300")),
        port=int(os.environ.get("SESSIONKEEPER_PORT", "9090")),
        providers=_load_providers(providers_file),
    )
