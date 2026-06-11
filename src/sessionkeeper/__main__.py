"""Entrypoint: wire config -> vault + providers + metrics -> server + scheduler."""
from __future__ import annotations

import logging
import signal
import threading

from . import __version__, config
from .metrics import Metrics
from .providers import BrowserCookieHarvestProvider, HttpRefreshProvider
from .recipe import RecipeError, order_provider_configs
from .scheduler import Scheduler
from .server import serve
from .vault import VaultClient
from .vault_azure import AzureKeyVaultClient

log = logging.getLogger("sessionkeeper")


def _build_vault(cfg: config.AppConfig):
    if cfg.vault_backend == "azure_kv":
        return AzureKeyVaultClient(cfg.vault_url)
    return VaultClient(cfg.vault_url, api_key=cfg.vault_api_key)


def _build_provider(pc: config.ProviderConfig, vault):
    strategy = str((pc.settings or {}).get("strategy", "http_refresh"))
    if strategy == "browser_cookie_harvest":
        # The harvester pulls login credentials JIT from the vault (cold-login
        # form-drive) and never persists them.
        return BrowserCookieHarvestProvider(pc, secret_resolver=vault.get_secret)
    return HttpRefreshProvider(pc)


def _build_providers(cfg: config.AppConfig, vault) -> list:
    # Keep identity providers warm before their dependents (recipe DAG, §3.1).
    ordered = order_provider_configs(cfg.providers)
    return [_build_provider(pc, vault) for pc in ordered]


def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    log.info("sessionkeeper %s starting", __version__)

    cfg = config.load()
    metrics = Metrics()
    ready = threading.Event()
    serve(metrics, cfg.port, ready)

    vault = _build_vault(cfg)
    try:
        providers = _build_providers(cfg, vault)
    except RecipeError as e:
        log.error("provider config invalid: %s", e)
        return 2
    if not providers:
        log.warning("no providers configured (%s) — idling, serving health only",
                    cfg.providers_file)
    else:
        log.info("vault backend=%s, %d provider(s): %s",
                 cfg.vault_backend, len(providers), ", ".join(p.id for p in providers))

    scheduler = Scheduler(providers, vault, metrics, interval_seconds=cfg.interval_seconds)

    def _shutdown(*_a) -> None:
        log.info("shutdown signal received")
        scheduler.stop()

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    ready.set()
    scheduler.run_forever()
    log.info("stopped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
