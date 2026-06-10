"""The refresh loop.

For each provider, one ``tick``:
  read latest session from vault
   -> probe (state + expiry)
   -> if due (within refresh margin), refresh and persist the rotated session back
   -> update metrics
NeedsLogin -> mark needs-human + alert hook. Any other error -> stale, retried next tick.
The loop holds no session state itself; the vault is the source of truth.
"""
from __future__ import annotations

import logging
import threading
import time
from typing import Callable, Iterable, Optional

from .metrics import Metrics
from .provider import DEAD, HEALTHY, NEEDS_HUMAN, NeedsLogin, Provider, STALE
from .vault import VaultClient, VaultError

log = logging.getLogger("sessionkeeper.scheduler")

# Called with (provider_id, reason) when a provider needs a human re-login.
AlertHook = Callable[[str, str], None]


class Scheduler:
    def __init__(
        self,
        providers: Iterable[Provider],
        vault: VaultClient,
        metrics: Metrics,
        *,
        interval_seconds: float = 300.0,
        clock: Callable[[], float] = time.time,
        sleep: Callable[[float], None] = time.sleep,
        alert: Optional[AlertHook] = None,
    ) -> None:
        self._providers = list(providers)
        self._vault = vault
        self._metrics = metrics
        self._interval = interval_seconds
        self._clock = clock
        self._sleep = sleep
        self._alert = alert
        self._stop = threading.Event()

    def tick_provider(self, provider: Provider) -> None:
        pid = provider.id
        try:
            session = self._vault.get_session(provider.config.vault_item)
        except VaultError as e:
            log.warning("%s: vault read failed: %s", pid, e)
            self._metrics.set_state(pid, STALE)
            self._metrics.inc_refresh(pid, "vault_error")
            return

        state, expiry = provider.probe(session)
        now = self._clock()
        remaining = (expiry - now) if expiry is not None else None
        self._metrics.set_expiry(pid, remaining)

        due = remaining is not None and remaining <= provider.config.refresh_margin_seconds
        if state == NEEDS_HUMAN:
            self._needs_human(pid, "no usable session")
            return
        if not due and state == HEALTHY:
            self._metrics.set_state(pid, HEALTHY)
            return

        # Due (or already stale/dead but a refresh token may save it): refresh.
        try:
            rotated = provider.refresh(session)
        except NeedsLogin as e:
            self._needs_human(pid, str(e))
            return
        except Exception as e:  # noqa: BLE001 — technical failure, retry next tick
            log.warning("%s: refresh failed: %s", pid, e)
            self._metrics.set_state(pid, DEAD if state == DEAD else STALE)
            self._metrics.inc_refresh(pid, "error")
            return

        try:
            self._vault.put_session(provider.config.vault_item, rotated)
        except VaultError as e:
            log.error("%s: refreshed but vault write FAILED: %s", pid, e)
            self._metrics.inc_refresh(pid, "write_error")
            # Don't mark healthy — the rotated token isn't durably persisted.
            self._metrics.set_state(pid, STALE)
            return

        self._metrics.set_state(pid, HEALTHY)
        self._metrics.inc_refresh(pid, "success")
        new_state, new_exp = provider.probe(rotated)
        self._metrics.set_expiry(pid, (new_exp - self._clock()) if new_exp is not None else None)
        log.info("%s: refreshed", pid)

    def tick(self) -> None:
        for provider in self._providers:
            self.tick_provider(provider)

    def run_forever(self) -> None:
        log.info("scheduler started: %d provider(s), interval %.0fs",
                 len(self._providers), self._interval)
        while not self._stop.is_set():
            self.tick()
            self._stop.wait(self._interval)

    def stop(self) -> None:
        self._stop.set()

    def _needs_human(self, pid: str, reason: str) -> None:
        log.warning("%s: NEEDS HUMAN re-login: %s", pid, reason)
        self._metrics.set_state(pid, NEEDS_HUMAN)
        self._metrics.inc_refresh(pid, "needs_login")
        if self._alert is not None:
            try:
                self._alert(pid, reason)
            except Exception:  # noqa: BLE001 — alerting must never crash the loop
                log.exception("%s: alert hook failed", pid)
