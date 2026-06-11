"""browser_cookie_harvest provider: probe / refresh / login with a fake CDP."""
import pytest

from sessionkeeper.provider import DEAD, HEALTHY, NeedsLogin, ProviderConfig
from sessionkeeper.providers.browser_harvest import BrowserCookieHarvestProvider
from sessionkeeper.session import Session


class FakeCdp:
    def __init__(self, cookies):
        self._cookies = cookies
        self.calls = 0

    def get_cookies(self, domains=None):
        self.calls += 1
        return self._cookies


def _cfg(**settings):
    base = {
        "strategy": "browser_cookie_harvest",
        "domains": ["reginamaria.ro"],
        "success_when": {"cookie": "TokenSSO"},
        "access_cookie_name": "TokenSSO",
        "refresh_cookie_name": "RefreshTokenSSO",
    }
    base.update(settings)
    return ProviderConfig(id="rm", vault_item="rm-session", ttl_hint_seconds=3600, settings=base)


def _provider(cookies, clock=1000.0):
    return BrowserCookieHarvestProvider(_cfg(), cdp=FakeCdp(cookies), clock=lambda: clock)


def test_refresh_harvests_and_maps_tokens():
    cookies = [
        {"name": "TokenSSO", "value": "AAA", "domain": "www.reginamaria.ro"},
        {"name": "RefreshTokenSSO", "value": "BBB", "domain": "www.reginamaria.ro"},
        {"name": "other", "value": "ccc", "domain": "www.reginamaria.ro"},
    ]
    p = _provider(cookies)
    sess = p.refresh(Session())
    assert sess.access_token == "AAA"
    assert sess.refresh_token == "BBB"
    assert sess.cookies == {"other": "ccc"}  # success/refresh cookies lifted out
    assert "harvested_at" in sess.extra


def test_refresh_raises_needs_login_when_success_cookie_absent():
    p = _provider([{"name": "other", "value": "x", "domain": "www.reginamaria.ro"}])
    with pytest.raises(NeedsLogin, match="logged out"):
        p.refresh(Session())


def test_login_raises_needs_login_when_profile_unauthenticated():
    p = _provider([])
    with pytest.raises(NeedsLogin, match="not authenticated"):
        p.login()


def test_login_harvests_when_authenticated():
    p = _provider([{"name": "TokenSSO", "value": "Z", "domain": "www.reginamaria.ro"}])
    assert p.login().access_token == "Z"


def test_probe_healthy_for_fresh_harvested_session():
    p = _provider([], clock=2000.0)
    sess = Session(access_token="Z", extra={"harvested_at": 2000.0})  # TokenSSO via access field
    state, exp = p.probe(sess)
    assert state == HEALTHY
    assert exp == 2000.0 + 3600


def test_probe_dead_when_success_cookie_missing():
    p = _provider([])
    state, exp = p.probe(Session(cookies={"other": "x"}))
    assert state == DEAD
    assert exp is None
