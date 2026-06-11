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
from .session import Session
from .vault import VaultClient, VaultError, VaultItemNotFound

log = logging.getLogger("sessionkeeper.scheduler")

# Called with (provider_id, reason) when a provider needs a human re-login.
AlertHook = Callable[[str, str], None]


class _LoginBreaker:
    """Per-provider rate limiter for the expensive login() arm (spec §8).

    Prevents relogin storms (which escalate reCAPTCHA invisible -> hard challenge
    -> account flag): never relogin more often than ``min_gap`` seconds, and cap
    total relogins per UTC day. When blocked, the caller goes needs-human rather
    than hammering the provider.
    """

    def __init__(self, min_gap_seconds: float, max_per_day: int, clock: Callable[[], float]) -> None:
        self._min_gap = min_gap_seconds
        self._max_per_day = max_per_day
        self._clock = clock
        self._last: Optional[float] = None
        self._day = -1
        self._count = 0

    def allow(self) -> "tuple[bool, str]":
        now = self._clock()
        day = int(now // 86400)
        if day != self._day:
            self._day, self._count = day, 0
        if self._count >= self._max_per_day:
            return False, f"max_logins_per_day={self._max_per_day} reached"
        if self._last is not None and (now - self._last) < self._min_gap:
            return False, f"min_seconds_between_logins={self._min_gap:.0f}s not elapsed"
        return True, ""

    def record(self) -> None:
        self._last = self._clock()
        self._count += 1


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
        self._breakers: dict[str, _LoginBreaker] = {}
        self._locks: dict[str, threading.Lock] = {}

    def tick_provider(self, provider: Provider) -> None:
        pid = provider.id
        try:
            session = self._vault.get_session(provider.config.vault_item)
        except VaultItemNotFound:
            # First-run bootstrap: no bundle exists yet. Start from an empty
            # session so probe() returns dead -> we escalate to login(), which
            # harvests the first session and put_session() CREATES the item.
            log.info("%s: no session bundle yet -> bootstrapping via login", pid)
            session = Session()
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
            self._escalate(provider, str(e))
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

    # -- escalation: refresh died -> autonomous harvester login (spec §8) -----
    def _breaker_for(self, provider: Provider) -> _LoginBreaker:
        b = self._breakers.get(provider.id)
        if b is None:
            cfg = provider.config
            b = _LoginBreaker(cfg.min_seconds_between_logins, cfg.max_logins_per_day, self._clock)
            self._breakers[provider.id] = b
        return b

    def _lock_for(self, pid: str) -> threading.Lock:
        lk = self._locks.get(pid)
        if lk is None:
            lk = threading.Lock()
            self._locks[pid] = lk
        return lk

    def _escalate(self, provider: Provider, reason: str) -> None:
        """A cheap refresh raised NeedsLogin: try the expensive login() arm once,
        guarded by single-flight + circuit breaker. Only a genuine dead-end (or a
        suppressed/blocked breaker) reaches needs-human -> Sev-3 alert (§6)."""
        pid = provider.id
        lock = self._lock_for(pid)
        if not lock.acquire(blocking=False):
            log.info("%s: login already in flight; skipping escalation", pid)
            return
        try:
            self._metrics.set_state(pid, DEAD)  # transient while we relogin
            allowed, why = self._breaker_for(provider).allow()
            if not allowed:
                self._needs_human(pid, f"login suppressed ({why}); prior: {reason}")
                return
            self._breaker_for(provider).record()
            self._metrics.inc_login(pid, "attempt")
            log.info("%s: refresh dead (%s) -> escalating to harvester login", pid, reason)
            try:
                session = provider.login()
            except NeedsLogin as e:
                self._metrics.inc_login(pid, "needs_human")
                self._needs_human(pid, str(e))
                return
            except Exception as e:  # noqa: BLE001 — technical login failure, retry next tick
                self._metrics.inc_login(pid, "error")
                log.warning("%s: harvester login failed: %s", pid, e)
                self._metrics.set_state(pid, DEAD)
                return
            try:
                self._vault.put_session(provider.config.vault_item, session)
            except VaultError as e:
                self._metrics.inc_login(pid, "write_error")
                log.error("%s: re-logged in but vault write FAILED: %s", pid, e)
                self._metrics.set_state(pid, STALE)
                return
            self._metrics.inc_login(pid, "success")
            self._metrics.set_state(pid, HEALTHY)
            _st, exp = provider.probe(session)
            self._metrics.set_expiry(pid, (exp - self._clock()) if exp is not None else None)
            log.info("%s: re-logged in via harvester", pid)
        finally:
            lock.release()

    def _needs_human(self, pid: str, reason: str) -> None:
        log.warning("%s: NEEDS HUMAN re-login: %s", pid, reason)
        self._metrics.set_state(pid, NEEDS_HUMAN)
        self._metrics.inc_refresh(pid, "needs_login")
        if self._alert is not None:
            try:
                self._alert(pid, reason)
            except Exception:  # noqa: BLE001 — alerting must never crash the loop
                log.exception("%s: alert hook failed", pid)
