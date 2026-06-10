import base64
import json
import time

import pytest

from sessionkeeper.provider import (
    DEAD,
    HEALTHY,
    NEEDS_HUMAN,
    NeedsLogin,
    ProviderConfig,
    SessionError,
    STALE,
)
from sessionkeeper.providers import HttpRefreshProvider
from sessionkeeper.session import Session
from conftest import FakeHTTP


def _jwt(exp: float) -> str:
    p = base64.urlsafe_b64encode(json.dumps({"exp": int(exp)}).encode()).rstrip(b"=").decode()
    return f"h.{p}.s"


def _cfg(**settings):
    base = {"base_url": "https://api.example.com/v3", "refresh_path": "Auth/Refresh"}
    base.update(settings)
    return ProviderConfig(id="example", vault_item="machine-managed/example", settings=base)


def _provider(routes, **settings):
    return HttpRefreshProvider(_cfg(**settings), transport=FakeHTTP(routes)), 


def test_requires_base_url_and_path():
    with pytest.raises(ValueError):
        HttpRefreshProvider(ProviderConfig(id="x", vault_item="i", settings={}))


def test_probe_healthy_with_future_jwt():
    p = HttpRefreshProvider(_cfg(), transport=FakeHTTP({}))
    state, exp = p.probe(Session(access_token=_jwt(time.time() + 3600), refresh_token="r"))
    assert state == HEALTHY and exp > time.time()


def test_probe_stale_when_access_expired_but_refresh_present():
    p = HttpRefreshProvider(_cfg(), transport=FakeHTTP({}))
    state, _ = p.probe(Session(access_token=_jwt(time.time() - 10), refresh_token="r"))
    assert state == STALE


def test_probe_dead_when_expired_and_no_refresh():
    p = HttpRefreshProvider(_cfg(), transport=FakeHTTP({}))
    state, _ = p.probe(Session(access_token=_jwt(time.time() - 10)))
    assert state == DEAD


def test_probe_needs_human_when_empty():
    p = HttpRefreshProvider(_cfg(), transport=FakeHTTP({}))
    state, exp = p.probe(Session())
    assert state == NEEDS_HUMAN and exp is None


def test_probe_uses_ttl_hint_for_opaque_token():
    p = HttpRefreshProvider(_cfg(), transport=FakeHTTP({}))
    state, exp = p.probe(Session(access_token="opaque-not-jwt", refresh_token="r"))
    assert state == HEALTHY and exp is not None and exp > time.time()


def test_refresh_rotates_from_json_body():
    http = FakeHTTP({("POST", "/Auth/Refresh"): (200, {}, {"accessToken": "AT2", "refreshToken": "RT2"})})
    p = HttpRefreshProvider(_cfg(), transport=http)
    out = p.refresh(Session(access_token="AT1", refresh_token="RT1"))
    assert out.access_token == "AT2" and out.refresh_token == "RT2"
    # the request carried the old tokens as cookies
    assert "AccessToken=AT1" in http.calls[-1][2]["Cookie"]
    assert "RefreshToken=RT1" in http.calls[-1][2]["Cookie"]


def test_refresh_absorbs_set_cookie_rotation():
    rh = {"Set-Cookie": "AccessToken=ATnew; Path=/, RefreshToken=RTnew; HttpOnly"}
    http = FakeHTTP({("POST", "/Auth/Refresh"): (200, rh, "")})
    p = HttpRefreshProvider(_cfg(), transport=http)
    out = p.refresh(Session(access_token="old", refresh_token="oldr"))
    assert out.access_token == "ATnew" and out.refresh_token == "RTnew"


def test_refresh_custom_field_and_cookie_names():
    http = FakeHTTP({("POST", "/Auth/Refresh"): (200, {}, {"jwt": "J2", "rt": "R2"})})
    p = HttpRefreshProvider(_cfg(access_json_field="jwt", refresh_json_field="rt",
                                 access_cookie_name="TokenSSO", refresh_cookie_name="RefreshSSO"),
                            transport=http)
    out = p.refresh(Session(access_token="J1", refresh_token="R1"))
    assert out.access_token == "J2" and out.refresh_token == "R2"
    assert "TokenSSO=J1" in http.calls[-1][2]["Cookie"]


def test_refresh_sends_static_headers():
    http = FakeHTTP({("POST", "/Auth/Refresh"): (200, {}, {"accessToken": "x"})})
    p = HttpRefreshProvider(_cfg(headers={"X-Api-Key": "k"}, user_agent="UA/1"), transport=http)
    p.refresh(Session(access_token="a", refresh_token="r"))
    hdrs = http.calls[-1][2]
    assert hdrs["X-Api-Key"] == "k" and hdrs["User-Agent"] == "UA/1"


def test_refresh_401_raises_needs_login():
    http = FakeHTTP({("POST", "/Auth/Refresh"): (401, {}, "nope")})
    p = HttpRefreshProvider(_cfg(), transport=http)
    with pytest.raises(NeedsLogin):
        p.refresh(Session(access_token="a", refresh_token="r"))


def test_refresh_500_raises_session_error_not_needs_login():
    http = FakeHTTP({("POST", "/Auth/Refresh"): (500, {}, "boom")})
    p = HttpRefreshProvider(_cfg(), transport=http)
    with pytest.raises(SessionError):
        p.refresh(Session(access_token="a", refresh_token="r"))


def test_refresh_without_refresh_token_needs_login():
    p = HttpRefreshProvider(_cfg(), transport=FakeHTTP({}))
    with pytest.raises(NeedsLogin):
        p.refresh(Session(access_token="a"))


def test_login_not_implemented_v01():
    p = HttpRefreshProvider(_cfg(), transport=FakeHTTP({}))
    with pytest.raises(NeedsLogin):
        p.login()
