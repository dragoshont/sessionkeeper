"""Entrypoint: wire config -> vault + providers + metrics -> server + scheduler."""
from __future__ import annotations

import logging
import signal
import threading

from . import __version__, config
from .metrics import Metrics
from .providers import HttpRefreshProvider
from .scheduler import Scheduler
from .server import serve
from .vault import VaultClient


def _build_providers(cfg: config.AppConfig) -> list:
    # v0.1 has a single adapter type; future adapters select on a settings key.
    return [HttpRefreshProvider(pc) for pc in cfg.providers]


def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    log = logging.getLogger("sessionkeeper")
    log.info("sessionkeeper %s starting", __version__)

    cfg = config.load()
    metrics = Metrics()
    ready = threading.Event()
    serve(metrics, cfg.port, ready)

    vault = VaultClient(cfg.vault_url, api_key=cfg.vault_api_key)
    providers = _build_providers(cfg)
    if not providers:
        log.warning("no providers configured (%s) — idling, serving health only",
                    cfg.providers_file)

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
