"""``browser_cookie_harvest`` strategy — Regina Maria class (spec §4.1, proven).

The session lives in the warm browser profile as cookies (some httpOnly). There
is no cheap JSON refresh endpoint, so the keep-warm ladder is:

  * ``refresh()`` — cheap, captcha-free: re-read the cookies from the *already
    warm* profile over CDP (the persistent profile keeps itself logged in). If
    the success cookie is still present, that is the rotated bundle.
  * ``login()``   — the rare, expensive arm: the profile is logged out. The
    cold-login form-drive is a documented extension point (Phase 2, needs creds);
    until it lands, an unauthenticated profile raises ``NeedsLogin`` so the
    scheduler surfaces a Sev-3 ``needs_human`` alert (spec §6) — never a silent
    wrong-state.

``success_when`` is asserted on every harvest so a logged-out profile fails loud
rather than persisting an empty bundle. Supported form: ``{"cookie": "<name>"}``.
"""
from __future__ import annotations

import time
from typing import Callable, Optional

from ..cdp import CdpClient
from ..provider import DEAD, HEALTHY, NEEDS_HUMAN, STALE, NeedsLogin, ProviderConfig
from ..recipe import Recipe
from ..session import Session


class BrowserCookieHarvestProvider:
    def __init__(
        self,
        config: ProviderConfig,
        *,
        cdp: Optional[CdpClient] = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.config = config
        self.id = config.id
        self._recipe = Recipe.from_provider_config(config)
        self._clock = clock
        s = config.settings or {}
        self._cdp = cdp or CdpClient(str(s.get("cdp_url", "http://127.0.0.1:9222")))
        self._access_cookie = s.get("access_cookie_name", "")
        self._refresh_cookie = s.get("refresh_cookie_name", "")

    # -- contract -------------------------------------------------------------
    def probe(self, session: Session) -> "tuple[int, Optional[float]]":
        if not self._success_met(self._jar_of(session)):
            return DEAD, None
        harvested_at = session.extra.get("harvested_at")
        base = float(harvested_at) if isinstance(harvested_at, (int, float)) else self._clock()
        exp = base + self.config.ttl_hint_seconds
        return (HEALTHY if exp > self._clock() else STALE), exp

    def refresh(self, session: Session) -> Session:
        cookies = self._cdp.get_cookies(list(self._recipe.domains))
        jar = {c.get("name", ""): c.get("value", "") for c in cookies if c.get("name")}
        if not self._success_met(jar):
            raise NeedsLogin(f"{self.id}: warm profile logged out; interactive login required")
        return self._bundle(jar)

    def login(self, assist: Optional[Callable[[dict], dict]] = None) -> Session:
        # Phase 2: an assisted cold login would drive the login form here using
        # creds pulled just-in-time from the vault, then fall through to harvest.
        # Until then, only a profile that is *already* authenticated can be
        # harvested; otherwise this is a genuine dead-end -> needs_human (§6).
        cookies = self._cdp.get_cookies(list(self._recipe.domains))
        jar = {c.get("name", ""): c.get("value", "") for c in cookies if c.get("name")}
        if not self._success_met(jar):
            raise NeedsLogin(
                f"{self.id}: warm profile not authenticated; one-time human login required"
            )
        return self._bundle(jar)

    # -- internals ------------------------------------------------------------
    def _jar_of(self, session: Session) -> dict:
        """Reconstruct the full cookie jar from a stored bundle (the access/refresh
        tokens were lifted out of ``cookies`` into their own fields by ``_bundle``)."""
        jar = dict(session.cookies)
        if self._access_cookie and session.access_token:
            jar[self._access_cookie] = session.access_token
        if self._refresh_cookie and session.refresh_token:
            jar[self._refresh_cookie] = session.refresh_token
        return jar

    def _success_met(self, jar: dict) -> bool:
        cond = self._recipe.success_when
        if not cond:
            return bool(jar)
        cookie_name = cond.get("cookie")
        if cookie_name:
            return bool(jar.get(cookie_name))
        return bool(jar)

    def _bundle(self, jar: dict) -> Session:
        access = jar.get(self._access_cookie, "") if self._access_cookie else ""
        refresh = jar.get(self._refresh_cookie, "") if self._refresh_cookie else ""
        rest = {
            k: v
            for k, v in jar.items()
            if k not in (self._access_cookie, self._refresh_cookie)
        }
        return Session(
            access_token=access,
            refresh_token=refresh,
            cookies=rest,
            extra={"harvested_at": self._clock()},
        )
