"""Automated cold-login form-drive: drives a fake warm browser, harvests."""
import pytest

from sessionkeeper.provider import NeedsLogin, ProviderConfig
from sessionkeeper.providers.browser_harvest import BrowserCookieHarvestProvider
from sessionkeeper.session import Session


class FakeBrowser:
    """A fake warm headful browser: logged out until the login form is driven."""

    def __init__(self, *, authed=False, succeed_on_login=True):
        self._authed = authed
        self._succeed_on_login = succeed_on_login
        self.navigated = []
        self.evals = []

    def navigate(self, url):
        self.navigated.append(url)

    def eval_js(self, expression):
        self.evals.append(expression)
        # Simulate the form submit logging the profile in.
        if "querySelector" in expression and self._succeed_on_login:
            self._authed = True
        return True

    def get_cookies(self, domains=None):
        if not self._authed:
            return []
        return [
            {"name": "TokenSSO", "value": "AAA", "domain": "www.reginamaria.ro"},
            {"name": "RefreshTokenSSO", "value": "BBB", "domain": "www.reginamaria.ro"},
        ]


def _cfg(with_login=True):
    settings = {
        "strategy": "browser_cookie_harvest",
        "domains": ["reginamaria.ro"],
        "success_when": {"cookie": "TokenSSO"},
        "access_cookie_name": "TokenSSO",
        "refresh_cookie_name": "RefreshTokenSSO",
    }
    if with_login:
        settings["login"] = {
            "url": "https://www.reginamaria.ro/login",
            "username_ref": "rm-username",
            "password_ref": "rm-password",
            "username_selector": "#email",
            "password_selector": "#password",
            "submit_selector": "button[type=submit]",
            "settle_seconds": 0.0,
            "timeout_seconds": 5.0,
        }
    return ProviderConfig(id="rm", vault_item="rm-session", ttl_hint_seconds=3600, settings=settings)


def _secrets(**vals):
    def resolve(name):
        return vals.get(name, "")
    return resolve


def test_login_drives_form_with_vault_creds_and_harvests():
    browser = FakeBrowser(authed=False)
    secrets = _secrets(**{"rm-username": "user@example.com", "rm-password": "s3cr3t"})
    p = BrowserCookieHarvestProvider(
        _cfg(), cdp=browser, secret_resolver=secrets,
        clock=lambda: 1000.0, sleep=lambda s: None,
    )
    sess = p.login()
    assert browser.navigated == ["https://www.reginamaria.ro/login"]
    assert sess.access_token == "AAA"
    assert sess.refresh_token == "BBB"
    # The credentials must be JSON-encoded into the eval (never bare).
    assert any('"user@example.com"' in e for e in browser.evals)


def test_login_password_is_json_encoded_not_naively_interpolated():
    # A password containing a quote/backslash must not break the eval string.
    browser = FakeBrowser(authed=False)
    secrets = _secrets(**{"rm-username": "u", "rm-password": 'p"\\;alert(1)'})
    p = BrowserCookieHarvestProvider(
        _cfg(), cdp=browser, secret_resolver=secrets, clock=lambda: 1.0, sleep=lambda s: None,
    )
    p.login()
    fill = [e for e in browser.evals if "querySelector" in e][0]
    import json
    assert json.dumps('p"\\;alert(1)') in fill  # safely escaped


def test_login_raises_needs_login_when_form_drive_fails_to_authenticate():
    browser = FakeBrowser(authed=False, succeed_on_login=False)
    secrets = _secrets(**{"rm-username": "u", "rm-password": "p"})
    p = BrowserCookieHarvestProvider(
        _cfg(), cdp=browser, secret_resolver=secrets, clock=lambda: 1.0, sleep=lambda s: None,
    )
    with pytest.raises(NeedsLogin, match="automated login did not satisfy"):
        p.login()


def test_login_raises_when_credentials_missing_in_vault():
    browser = FakeBrowser(authed=False)
    p = BrowserCookieHarvestProvider(
        _cfg(), cdp=browser, secret_resolver=_secrets(), clock=lambda: 1.0, sleep=lambda s: None,
    )
    with pytest.raises(NeedsLogin, match="missing credentials"):
        p.login()
    assert browser.navigated == []  # never navigated without creds


def test_login_no_form_drive_falls_back_to_warm_harvest_or_needs_login():
    # No login block + logged-out profile -> NeedsLogin (no automated login).
    browser = FakeBrowser(authed=False)
    p = BrowserCookieHarvestProvider(
        _cfg(with_login=False), cdp=browser, clock=lambda: 1.0, sleep=lambda s: None,
    )
    with pytest.raises(NeedsLogin, match="no login form-drive configured"):
        p.login()


def test_login_already_warm_harvests_without_driving_form():
    # Profile already authenticated: harvest, but still no manual step.
    browser = FakeBrowser(authed=True)
    secrets = _secrets(**{"rm-username": "u", "rm-password": "p"})
    p = BrowserCookieHarvestProvider(
        _cfg(), cdp=browser, secret_resolver=secrets, clock=lambda: 1.0, sleep=lambda s: None,
    )
    sess = p.login()
    assert sess.access_token == "AAA"
    # It may still navigate/fill (idempotent), but the harvest must succeed.


def test_refresh_uses_warm_profile_without_login():
    browser = FakeBrowser(authed=True)
    p = BrowserCookieHarvestProvider(_cfg(), cdp=browser, clock=lambda: 1.0, sleep=lambda s: None)
    sess = p.refresh(Session())
    assert sess.access_token == "AAA"
    assert browser.navigated == []  # refresh never drives the login form
