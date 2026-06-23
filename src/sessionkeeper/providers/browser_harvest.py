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
import urllib.request
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
        # Optional liveness oracle (ADR 0024): the rotator (the consuming MCP /
        # Tessera) is the only component that truthfully knows whether the refresh
        # CHAIN is alive. When configured, its verdict overrides the optimistic
        # ttl_hint timer in probe()/refresh().
        self._liveness_url = str(s.get("liveness_probe_url", ""))
        self._liveness_method = str(s.get("liveness_probe_method", "POST")).upper()
        self._liveness_timeout = float(s.get("liveness_timeout_seconds", 3.0))
        self._liveness_cache_s = float(s.get("liveness_cache_seconds", 10.0))
        self._liveness_cache: "tuple[float, Optional[bool]]" = (0.0, None)

    # -- contract -------------------------------------------------------------
    def probe(self, session: Session) -> "tuple[int, Optional[float]]":
        if not self._success_met(self._jar_of(session)):
            return DEAD, None
        # The success cookie is present, but it can be present while the refresh
        # chain is dead server-side. If a liveness oracle is configured and the
        # rotator says the chain is dead, that truth overrides the optimistic
        # ttl_hint timer (ADR 0024) — the silent-death bug this closes.
        if self._liveness_url and self._query_liveness() is False:
            return DEAD, None
        harvested_at = session.extra.get("harvested_at")
        base = float(harvested_at) if isinstance(harvested_at, (int, float)) else self._clock()
        exp = base + self.config.ttl_hint_seconds
        return (HEALTHY if exp > self._clock() else STALE), exp

    def refresh(self, session: Session) -> Session:
        # A dead-chain verdict must force the real login() re-seed, not a no-op
        # re-harvest of the same dead cookies (which would still satisfy
        # success_when and never heal). See ADR 0024.
        if self._liveness_url and self._query_liveness() is False:
            raise NeedsLogin(f"{self.id}: rotator reports session dead; re-seed required")
        jar = self._harvest_jar()
        if not self._success_met(jar):
            raise NeedsLogin(f"{self.id}: warm profile logged out; login required")
        return self._bundle(jar)

    def login(self, assist: Optional[Callable[[dict], dict]] = None) -> Session:
        """Autonomous (re)login. If the recipe carries a ``login`` form-drive and
        a secret resolver is wired, log in automatically in the warm headful
        browser; otherwise only an already-authenticated profile can be harvested.
        A genuine dead-end raises NeedsLogin -> Sev-3 alert (spec §6).

        After a successful harvest the browser is **parked** off the provider
        (``park_url``, default about:blank) so its SPA stops background-refreshing
        the provider's single-use rotating refresh token — otherwise the browser
        and the consuming MCP both rotate the same chain and invalidate each
        other (the rotation race, spec §4). Parking makes the MCP the sole
        rotation owner."""
        login = self._recipe.login
        if login.enabled and self._secret is not None:
            self._drive_login(login)
        # Verify the session is live BEFORE parking.
        if not self._success_met(self._harvest_jar()):
            if login.enabled:
                raise NeedsLogin(
                    f"{self.id}: automated login did not satisfy success_when "
                    f"(provider may have prompted MFA/CAPTCHA); needs a human login"
                )
            raise NeedsLogin(
                f"{self.id}: warm profile not authenticated and no login form-drive configured"
            )
        # PARK FIRST, then harvest. Navigating off the provider destroys its SPA
        # so it can't rotate the single-use token any further; the cookie jar is
        # then frozen, so the values we harvest are exactly what the MCP will use
        # (no rotate-between-harvest-and-park window). Cookies survive navigation
        # (domain-scoped, not page-scoped).
        self._park()
        jar = self._harvest_jar()
        if not self._success_met(jar):
            # Parking unexpectedly cleared the success cookie — fall back to a
            # pre-park harvest so we still return a usable bundle.
            jar = self._harvest_jar()
        return self._bundle(jar)

    def _park(self) -> None:
        """Navigate the browser off the provider so it stops competing for the
        rotating token. Best-effort: never fail a successful harvest over this."""
        park_url = str((self.config.settings or {}).get("park_url", "about:blank"))
        if not park_url:
            return
        try:
            self._cdp.navigate(park_url)
            log.info("%s: browser parked at %s (MCP is now sole rotator)", self.id, park_url)
        except Exception as e:  # noqa: BLE001 — parking is best-effort
            log.warning("%s: could not park browser: %s", self.id, e)

    # -- internals ------------------------------------------------------------
    def _query_liveness(self) -> Optional[bool]:
        """Ask the rotator (the consuming MCP / Tessera) whether the session's
        refresh CHAIN is really alive. Returns True/False, or None when no oracle
        is configured or it cannot be reached/parsed. NEVER raises and never blocks
        past the timeout — an unknown verdict must not crash or stall keep-warm.

        The verdict is cached for ``liveness_cache_seconds`` so a single tick's
        probe()+refresh() share ONE upstream call (the oracle may refresh the
        session server-side, so it must not be hammered). (ADR 0024 / SDD-42.)"""
        if not self._liveness_url:
            return None
        now = self._clock()
        ts, cached = self._liveness_cache
        if ts > 0.0 and (now - ts) < self._liveness_cache_s:
            return cached
        verdict: Optional[bool] = None
        try:
            data = b"{}" if self._liveness_method == "POST" else None
            req = urllib.request.Request(
                self._liveness_url,
                data=data,
                method=self._liveness_method,
                headers={"Content-Type": "application/json", "Accept": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=self._liveness_timeout) as resp:
                body = resp.read(4096)
            payload = json.loads(body.decode("utf-8", "replace"))
            if isinstance(payload, dict) and isinstance(payload.get("alive"), bool):
                verdict = bool(payload["alive"])
        except Exception as e:  # noqa: BLE001 — an unknown verdict must never crash the loop
            log.debug("%s: liveness oracle %s unavailable: %s", self.id, self._liveness_url, e)
            verdict = None
        self._liveness_cache = (now, verdict)
        return verdict

    def _drive_login(self, login) -> None:
        """Drive the warm headful browser to log in. Credentials pulled JIT from
        the vault and injected via CDP key input; NEVER logged.

        When the recipe sets ``mint_fresh: true`` (the right choice for providers
        with single-use rotating refresh tokens, e.g. Regina Maria), the browser's
        provider cookies are cleared FIRST so a brand-new token is minted by a
        real form login — never harvesting a session the browser may already have
        rotated past (which would seed the consumer a dead token)."""
        username = self._secret(login.username_ref)
        password = self._secret(login.password_ref)
        if not username or not password:
            raise NeedsLogin(
                f"{self.id}: missing credentials in vault "
                f"({login.username_ref!r}/{login.password_ref!r})"
            )
        mint_fresh = bool((self.config.settings or {}).get("mint_fresh", False))
        if mint_fresh and self._recipe.domains:
            n = self._cdp.clear_cookies(list(self._recipe.domains))
            log.info("%s: mint_fresh -> cleared %d provider cookie(s) to force a fresh login", self.id, n)
        self._cdp.navigate(login.url)
        # A warm profile may already be authenticated (RememberMe auto-login) —
        # then the login URL redirects to the app and no form renders. Unless
        # mint_fresh forced a logout above, harvest that existing session directly.
        if not mint_fresh and self._success_met(self._harvest_jar()):
            log.info("%s: warm profile already authenticated; harvesting existing session", self.id)
            return
        log.info("%s: warm profile logged out -> automated login drive", self.id)
        settle = max(login.settle_seconds, 0.0)
        attempts = max(1, int(login.timeout_seconds / settle)) if settle > 0 else 1
        # Wait for the login form to render. The page may be a SPA that mounts
        # the inputs AFTER document.readyState=complete, so poll for the username
        # field to exist before filling (else querySelector returns null).
        present_js = (
            "(function(){return !!(document.querySelector("
            f"{json.dumps(login.username_selector)})"
            f"&&document.querySelector({json.dumps(login.password_selector)}));}})()"
        )
        for _ in range(attempts):
            if self._cdp.eval_js(present_js) is True:
                break
            self._sleep(settle)
        else:
            raise NeedsLogin(
                f"{self.id}: login form did not render within ~{login.timeout_seconds:.0f}s "
                f"(selectors {login.username_selector!r}/{login.password_selector!r})"
            )
        # Type credentials like a real user (CDP Input.insertText) so framework
        # forms (Angular/Kendo/React) register the value, then click submit.
        # Direct .value assignment does NOT update those models, so the submit
        # would post an empty form. Credentials are never logged.
        typed_u = self._cdp.type_text(login.username_selector, username)
        typed_p = self._cdp.type_text(login.password_selector, password)
        clicked = self._cdp.click(login.submit_selector)
        # Wipe local refs; never keep credentials in memory longer than needed.
        username = password = ""  # noqa: F841
        if not (typed_u and typed_p and clicked):
            raise NeedsLogin(f"{self.id}: login form selectors did not match the page")
        # Poll for the success cookie to appear after the form POST + redirect.
        # Bounded by iteration count (not wall-clock) so it always terminates.
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
