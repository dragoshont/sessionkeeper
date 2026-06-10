"""Generic cookie/token refresh adapter.

Covers the common shape of a *custom* (non-OAuth) login: the service issues a
short-lived access token + a longer-lived refresh token (as cookies and/or JSON),
and exposes a refresh endpoint that, given the current pair, returns a rotated
pair. This adapter is fully config-driven so a new such service is just a
``settings`` block — no code.

settings keys (all optional unless noted):
  base_url            (required) e.g. "https://api.example.com/v3/"
  refresh_path        (required) e.g. "Account/RefreshToken"
  method              default "POST"
  access_cookie_name  default "AccessToken"   — cookie name for the access token
  refresh_cookie_name default "RefreshToken"  — cookie name for the refresh token
  access_json_field   default "accessToken"   — response JSON field for new access
  refresh_json_field  default "refreshToken"  — response JSON field for new refresh
  headers             dict of static extra headers (e.g. an API gateway key)
  user_agent          optional fixed UA string
"""
from __future__ import annotations

import json
import time
from typing import Callable, Optional

from ..http import Transport, urllib_transport
from ..provider import (
    DEAD,
    HEALTHY,
    NEEDS_HUMAN,
    NeedsLogin,
    ProviderConfig,
    SessionError,
    STALE,
)
from ..session import Session, jwt_expiry


class HttpRefreshProvider:
    def __init__(self, config: ProviderConfig, *, transport: Transport = urllib_transport):
        self.config = config
        self.id = config.id
        self._http = transport
        s = config.settings
        self._base = str(s.get("base_url", "")).rstrip("/")
        self._refresh_path = str(s.get("refresh_path", "")).lstrip("/")
        if not self._base or not self._refresh_path:
            raise ValueError(f"provider {self.id!r}: base_url and refresh_path are required")
        self._method = s.get("method", "POST")
        self._access_cookie = s.get("access_cookie_name", "AccessToken")
        self._refresh_cookie = s.get("refresh_cookie_name", "RefreshToken")
        self._access_field = s.get("access_json_field", "accessToken")
        self._refresh_field = s.get("refresh_json_field", "refreshToken")
        self._static_headers = dict(s.get("headers", {}) or {})
        self._user_agent = s.get("user_agent")

    # -- contract -------------------------------------------------------------
    def probe(self, session: Session) -> "tuple[int, Optional[float]]":
        if not session.refresh_token and not session.access_token:
            return NEEDS_HUMAN, None
        exp = jwt_expiry(session.access_token)
        if exp is None:
            # Unknown expiry — assume the configured TTL from now (best effort).
            return HEALTHY, time.time() + self.config.ttl_hint_seconds
        if exp <= time.time():
            # Access token already dead, but a refresh token may still save it.
            return (STALE if session.refresh_token else DEAD), exp
        return HEALTHY, exp

    def refresh(self, session: Session) -> Session:
        if not session.refresh_token:
            raise NeedsLogin(f"{self.id}: no refresh token; interactive login required")

        headers = self._headers(session)
        url = f"{self._base}/{self._refresh_path}"
        status, rheaders, text = self._http(self._method, url, headers, b"")

        if status in (401, 403):
            raise NeedsLogin(f"{self.id}: refresh rejected (HTTP {status}); login required")
        if status >= 400:
            raise SessionError(f"{self.id}: refresh failed HTTP {status}: {text[:200]}")

        rotated = self._absorb(session, rheaders, text)
        if not rotated.access_token and not rotated.refresh_token:
            raise SessionError(f"{self.id}: refresh returned no tokens")
        return rotated

    def login(self, assist: Optional[Callable[[dict], dict]] = None) -> Session:
        # Assisted/interactive login is v0.2 (escalation + browser profile).
        raise NeedsLogin(f"{self.id}: interactive login not implemented in v0.1")

    # -- internals ------------------------------------------------------------
    def _headers(self, session: Session) -> dict:
        h = dict(self._static_headers)
        h.setdefault("Accept", "application/json")
        h["Content-Type"] = "application/json"
        if self._user_agent:
            h["User-Agent"] = self._user_agent
        cookie = session.cookie_header(
            access_name=self._access_cookie, refresh_name=self._refresh_cookie
        )
        if cookie:
            h["Cookie"] = cookie
        return h

    def _absorb(self, prev: Session, rheaders: dict, text: str) -> Session:
        new = Session(
            access_token=prev.access_token,
            refresh_token=prev.refresh_token,
            cookies=dict(prev.cookies),
            extra=dict(prev.extra),
        )
        # 1) JSON body fields
        try:
            data = json.loads(text) if text.strip() else {}
        except json.JSONDecodeError:
            data = {}
        if isinstance(data, dict):
            if data.get(self._access_field):
                new.access_token = data[self._access_field]
            if data.get(self._refresh_field):
                new.refresh_token = data[self._refresh_field]
        # 2) Set-Cookie rotation (some providers rotate via cookies)
        set_cookie = rheaders.get("Set-Cookie") or rheaders.get("set-cookie") or ""
        for part in set_cookie.split(","):
            seg = part.strip()
            if "=" not in seg:
                continue
            name, val = seg.split("=", 1)
            name = name.strip()
            val = val.split(";", 1)[0]
            if name == self._access_cookie:
                new.access_token = val
            elif name == self._refresh_cookie:
                new.refresh_token = val
        return new
