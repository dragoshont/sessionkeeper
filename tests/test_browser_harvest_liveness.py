"""Liveness-oracle behaviour for browser_cookie_harvest (ADR 0024 / SDD-42).

The oracle (the rotator's truthful ``rm_session_status``) overrides the optimistic
``ttl_hint``: a dead verdict must make ``probe()`` return DEAD *and* ``refresh()``
escalate to a real re-seed, while an unknown/unreachable oracle must NEVER force a
re-seed (fail-safe). With no oracle configured, behaviour is unchanged.
"""
import pytest

from sessionkeeper.provider import DEAD, HEALTHY, NeedsLogin, ProviderConfig
from sessionkeeper.providers.browser_harvest import BrowserCookieHarvestProvider
from sessionkeeper.session import Session


class FakeCdp:
    def __init__(self, cookies):
        self._cookies = cookies

    def get_cookies(self, domains=None):
        return self._cookies


def _provider(cookies, *, clock=1000.0, **extra_settings):
    settings = {
        "strategy": "browser_cookie_harvest",
        "domains": ["reginamaria.ro"],
        "success_when": {"cookie": "TokenSSO"},
        "access_cookie_name": "TokenSSO",
        "refresh_cookie_name": "RefreshTokenSSO",
    }
    settings.update(extra_settings)
    cfg = ProviderConfig(id="rm", vault_item="rm-session", ttl_hint_seconds=3600, settings=settings)
    return BrowserCookieHarvestProvider(cfg, cdp=FakeCdp(cookies), clock=lambda: clock)


ALIVE_COOKIES = [{"name": "TokenSSO", "value": "AAA", "domain": "www.reginamaria.ro"}]
# Success cookie PRESENT (so the optimistic probe would say HEALTHY) yet the chain
# may be dead — exactly the silent-death case ADR 0024 closes.
HEALTHY_SESS = Session(access_token="AAA", extra={"harvested_at": 1000.0})


# -- probe(): the oracle's truth overrides the optimistic timer ----------------

def test_probe_dead_when_oracle_reports_dead():
    p = _provider(ALIVE_COOKIES, liveness_probe_url="http://oracle.test/status")
    p._query_liveness = lambda: False                     # rotator: chain is dead
    state, exp = p.probe(HEALTHY_SESS)
    assert state == DEAD and exp is None                  # was HEALTHY pre-ADR-0024


def test_probe_healthy_when_oracle_alive():
    p = _provider(ALIVE_COOKIES, clock=1000.0, liveness_probe_url="http://oracle.test/status")
    p._query_liveness = lambda: True
    state, exp = p.probe(HEALTHY_SESS)
    assert state == HEALTHY and exp == 1000.0 + 3600


def test_probe_failsafe_when_oracle_unreachable():
    p = _provider(ALIVE_COOKIES, clock=1000.0, liveness_probe_url="http://oracle.test/status")
    p._query_liveness = lambda: None                      # unknown -> do NOT force DEAD
    state, _ = p.probe(HEALTHY_SESS)
    assert state == HEALTHY


def test_probe_unchanged_without_oracle():
    p = _provider(ALIVE_COOKIES, clock=1000.0)            # no liveness_probe_url

    def _boom():
        raise AssertionError("oracle must not be consulted when unconfigured")

    p._query_liveness = _boom                             # would raise if called
    state, exp = p.probe(HEALTHY_SESS)
    assert state == HEALTHY and exp == 1000.0 + 3600      # short-circuited, never consulted


# -- refresh(): a dead verdict forces the real re-seed, not a no-op harvest -----

def test_refresh_raises_needs_login_when_oracle_dead():
    p = _provider(ALIVE_COOKIES, liveness_probe_url="http://oracle.test/status")
    p._query_liveness = lambda: False
    with pytest.raises(NeedsLogin, match="reports session dead"):
        p.refresh(Session())


def test_refresh_proceeds_when_oracle_alive():
    p = _provider(ALIVE_COOKIES, liveness_probe_url="http://oracle.test/status")
    p._query_liveness = lambda: True
    assert p.refresh(Session()).access_token == "AAA"


def test_refresh_proceeds_when_oracle_unreachable():
    p = _provider(ALIVE_COOKIES, liveness_probe_url="http://oracle.test/status")
    p._query_liveness = lambda: None
    assert p.refresh(Session()).access_token == "AAA"


# -- _query_liveness(): HTTP parse + fail-safe + cache -------------------------

class _FakeResp:
    def __init__(self, body):
        self._body = body

    def read(self, n=-1):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_query_liveness_parses_alive_false(monkeypatch):
    calls = {"n": 0}

    def fake_urlopen(req, timeout=None):
        calls["n"] += 1
        return _FakeResp(b'{"alive": false, "detail": "dead"}')

    monkeypatch.setattr(
        "sessionkeeper.providers.browser_harvest.urllib.request.urlopen", fake_urlopen
    )
    p = _provider([], liveness_probe_url="http://oracle.test/status", liveness_cache_seconds=0)
    assert p._query_liveness() is False
    assert calls["n"] == 1


def test_query_liveness_failsafe_on_error(monkeypatch):
    def boom(req, timeout=None):
        raise OSError("connection refused")

    monkeypatch.setattr(
        "sessionkeeper.providers.browser_harvest.urllib.request.urlopen", boom
    )
    p = _provider([], liveness_probe_url="http://oracle.test/status", liveness_cache_seconds=0)
    assert p._query_liveness() is None                    # never raises; unknown


def test_query_liveness_cached_within_window(monkeypatch):
    calls = {"n": 0}

    def fake_urlopen(req, timeout=None):
        calls["n"] += 1
        return _FakeResp(b'{"alive": true}')

    monkeypatch.setattr(
        "sessionkeeper.providers.browser_harvest.urllib.request.urlopen", fake_urlopen
    )
    p = _provider([], clock=5000.0, liveness_probe_url="http://oracle.test/status",
                  liveness_cache_seconds=10)
    assert p._query_liveness() is True
    assert p._query_liveness() is True
    assert calls["n"] == 1                                # second consult served from cache
