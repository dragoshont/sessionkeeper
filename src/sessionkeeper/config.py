"""Configuration loading.

Global settings come from environment variables; provider definitions come from
a small JSON/YAML-ish config file (JSON only in v0.1, to stay dependency-free).
Secrets (vault API key) come from the environment, never the config file.

Env:
  SESSIONKEEPER_VAULT_BACKEND   azure_kv (default) | vaultkeeper
  SESSIONKEEPER_VAULT_URL       azure_kv: https://<name>.vault.azure.net
                                vaultkeeper: http://vaultkeeper.default.svc:8087
  SESSIONKEEPER_VAULT_API_KEY   optional Bearer for a guarded vaultkeeper
  SESSIONKEEPER_PROVIDERS_FILE  default /config/providers.json
  SESSIONKEEPER_INTERVAL        scheduler tick seconds (default 300)
  SESSIONKEEPER_PORT            metrics/health port (default 9090)

Azure Workload Identity (when backend=azure_kv) is read from the standard
AZURE_* env injected by the workload-identity webhook — no secret on disk.

providers.json:
  [
    {
      "id": "example",
      "vault_item": "machine-managed-example-session",
      "refresh_margin_seconds": 2700,
      "ttl_hint_seconds": 3600,
      "min_seconds_between_logins": 300,
      "max_logins_per_day": 24,
      "settings": { "strategy": "http_refresh", "base_url": "...", ... }
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
    vault_backend: str
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
                min_seconds_between_logins=int(entry.get("min_seconds_between_logins", 5 * 60)),
                max_logins_per_day=int(entry.get("max_logins_per_day", 24)),
                settings=entry.get("settings", {}) or {},
            )
        )
    return out


def load() -> AppConfig:
    providers_file = os.environ.get("SESSIONKEEPER_PROVIDERS_FILE", "/config/providers.json")
    backend = os.environ.get("SESSIONKEEPER_VAULT_BACKEND", "azure_kv").strip().lower()
    default_url = "" if backend == "azure_kv" else "http://vaultkeeper.default.svc:8087"
    return AppConfig(
        vault_backend=backend,
        vault_url=os.environ.get("SESSIONKEEPER_VAULT_URL", default_url),
        vault_api_key=os.environ.get("SESSIONKEEPER_VAULT_API_KEY") or None,
        providers_file=providers_file,
        interval_seconds=float(os.environ.get("SESSIONKEEPER_INTERVAL", "300")),
        port=int(os.environ.get("SESSIONKEEPER_PORT", "9090")),
        providers=_load_providers(providers_file),
    )
