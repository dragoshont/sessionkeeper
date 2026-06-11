"""``browser_cookie_harvest`` strategy — Regina Maria class (spec §4.1, proven).

The session lives in the warm browser profile as cookies (some httpOnly). There
is no cheap JSON refresh endpoint, so the keep-warm ladder is:

  * ``refresh()`` — cheap, captcha-free: re-read the cookies from the *already
    warm* profile over CDP (the persistent profile keeps itself logged in). If
    the success cookie is still present, that is the rotated bundle.
  * ``login()``   — the rare arm: the profile is logged out. If the recipe has a
    ``login`` form-drive block, the harvester logs in **automatically** — no
    manual human step — by driving the warm headful browser over CDP with
    credentials pulled JIT from the vault, then harvests. If it has no login
    block (or the automated login still can't satisfy ``success_when``), it
    raises ``NeedsLogin`` so the scheduler surfaces a Sev-3 alert (spec §6).

``success_when`` is asserted on every harvest so a logged-out profile fails loud
rather than persisting an empty bundle. Supported form: ``{"cookie": "<name>"}``.

Credentials are NEVER logged or persisted: they are read from the vault at the
moment of login and injected into the page via a JSON-encoded eval. reCAPTCHA is
avoided by running in the *warm* persistent profile, where (for Regina Maria,
proven 2026-06-11) no challenge appears — never a fresh/cold profile.
"""
from __future__ import annotations

import json
import logging
import time
from typing import Callable, Optional

from ..cdp import CdpClient
from ..provider import DEAD, HEALTHY, STALE, NeedsLogin, ProviderConfig
from ..recipe import Recipe
from ..session import Session

log = logging.getLogger("sessionkeeper.harvest")

# Resolve a vault secret name -> raw value (username/password), pulled JIT.
SecretResolver = Callable[[str], str]


class BrowserCookieHarvestProvider:
    def __init__(
        self,
        config: ProviderConfig,
        *,
        cdp: Optional[CdpClient] = None,
        secret_resolver: Optional[SecretResolver] = None,
        clock: Callable[[], float] = time.time,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.config = config
        self.id = config.id
        self._recipe = Recipe.from_provider_config(config)
        self._clock = clock
        self._sleep = sleep
        self._secret = secret_resolver
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
        jar = self._harvest_jar()
        if not self._success_met(jar):
            raise NeedsLogin(f"{self.id}: warm profile logged out; login required")
        return self._bundle(jar)

    def login(self, assist: Optional[Callable[[dict], dict]] = None) -> Session:
        """Autonomous (re)login. If the recipe carries a ``login`` form-drive and
        a secret resolver is wired, log in automatically in the warm headful
        browser; otherwise only an already-authenticated profile can be harvested.
        A genuine dead-end raises NeedsLogin -> Sev-3 alert (spec §6)."""
        login = self._recipe.login
        if login.enabled and self._secret is not None:
            self._drive_login(login)
        jar = self._harvest_jar()
        if not self._success_met(jar):
            if login.enabled:
                raise NeedsLogin(
                    f"{self.id}: automated login did not satisfy success_when "
                    f"(provider may have prompted MFA/CAPTCHA); needs a human login"
                )
            raise NeedsLogin(
                f"{self.id}: warm profile not authenticated and no login form-drive configured"
            )
        return self._bundle(jar)

    # -- internals ------------------------------------------------------------
    def _drive_login(self, login) -> None:
        """Drive the warm headful browser to log in. Credentials pulled JIT from
        the vault and injected via a JSON-encoded eval; NEVER logged."""
        username = self._secret(login.username_ref)
        password = self._secret(login.password_ref)
        if not username or not password:
            raise NeedsLogin(
                f"{self.id}: missing credentials in vault "
                f"({login.username_ref!r}/{login.password_ref!r})"
            )
        log.info("%s: warm profile logged out -> automated login drive", self.id)
        self._cdp.navigate(login.url)
        # Fill both fields + submit in one eval. Values JSON-encoded so a quote or
        # backslash in a password can't break out of the string or inject script.
        fill_js = (
            "(function(){"
            f"var u=document.querySelector({json.dumps(login.username_selector)});"
            f"var p=document.querySelector({json.dumps(login.password_selector)});"
            f"var b=document.querySelector({json.dumps(login.submit_selector)});"
            "if(!u||!p||!b){return false;}"
            f"u.focus();u.value={json.dumps(username)};"
            "u.dispatchEvent(new Event('input',{bubbles:true}));"
            "u.dispatchEvent(new Event('change',{bubbles:true}));"
            f"p.focus();p.value={json.dumps(password)};"
            "p.dispatchEvent(new Event('input',{bubbles:true}));"
            "p.dispatchEvent(new Event('change',{bubbles:true}));"
            "b.click();return true;})()"
        )
        ok = self._cdp.eval_js(fill_js)
        # Wipe local refs; never keep credentials in memory longer than needed.
        username = password = fill_js = ""  # noqa: F841
        if ok is False:
            raise NeedsLogin(f"{self.id}: login form selectors did not match the page")
        # Poll for the success cookie to appear after the form POST + redirect.
        # Bounded by iteration count (not wall-clock) so it always terminates.
        settle = max(login.settle_seconds, 0.0)
        attempts = max(1, int(login.timeout_seconds / settle)) if settle > 0 else 1
        for _ in range(attempts):
            self._sleep(settle)
            if self._success_met(self._harvest_jar()):
                log.info("%s: automated login succeeded", self.id)
                return
        log.warning("%s: automated login did not reach success_when within ~%.0fs",
                    self.id, login.timeout_seconds)

    def _harvest_jar(self) -> dict:
        cookies = self._cdp.get_cookies(list(self._recipe.domains))
        return {c.get("name", ""): c.get("value", "") for c in cookies if c.get("name")}

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
