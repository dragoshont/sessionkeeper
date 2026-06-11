"""Automated cold-login form-drive: drives a fake warm browser, harvests."""
import pytest

from sessionkeeper.provider import NeedsLogin, ProviderConfig
from sessionkeeper.providers.browser_harvest import BrowserCookieHarvestProvider
from sessionkeeper.session import Session


class FakeBrowser:
    """A fake warm headful browser: logged out until the login form is driven.

    Models the two eval kinds the harvester uses: the form-presence check
    (``!!(document.querySelector(...))``) and the fill+submit (contains
    ``.click()``). ``form_renders`` lets a test simulate a form that never mounts.
    """

    def __init__(self, *, authed=False, succeed_on_login=True, form_renders=True):
        self._authed = authed
        self._succeed_on_login = succeed_on_login
        self._form_renders = form_renders
        self.navigated = []
        self.evals = []

    def navigate(self, url):
        self.navigated.append(url)

    def eval_js(self, expression):
        self.evals.append(expression)
        if "return !!(" in expression:           # form-presence poll
            return self._form_renders
        return True

    def type_text(self, selector, text):
        self.evals.append("type:" + selector + "=" + text)
        return self._form_renders

    def click(self, selector):
        self.evals.append("click:" + selector)
        if not self._form_renders:
            return False
        if self._succeed_on_login:
            self._authed = True
        return True

    def clear_cookies(self, domains):
        self.evals.append("clear_cookies:" + ",".join(domains))
        self._authed = False  # logged out -> form will render
        return 2

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
    assert browser.navigated[0] == "https://www.reginamaria.ro/login"
    assert browser.navigated[-1] == "about:blank"  # parked after harvest
    assert sess.access_token == "AAA"
    assert sess.refresh_token == "BBB"
    # Credentials are typed via type_text (raw), and submit is clicked.
    assert any(e == "type:#email=user@example.com" for e in browser.evals)
    assert any(e.startswith("click:") for e in browser.evals)


def test_login_password_typed_raw_never_embedded_in_js():
    # The password is sent via CDP Input.insertText (raw protocol field), never
    # concatenated into a JS eval string — so quotes/backslashes can't break out
    # or inject script. Assert it reaches type_text raw and is absent from evals
    # that look like JS (querySelector/eval expressions).
    browser = FakeBrowser(authed=False)
    pw = 'p"\\;alert(1)'
    secrets = _secrets(**{"rm-username": "u", "rm-password": pw})
    p = BrowserCookieHarvestProvider(
        _cfg(), cdp=browser, secret_resolver=secrets, clock=lambda: 1.0, sleep=lambda s: None,
    )
    p.login()
    assert any(e == "type:#password=" + pw for e in browser.evals)  # raw
    assert not any("querySelector" in e and pw in e for e in browser.evals)  # not in JS


def test_login_raises_when_form_never_renders():
    # SPA form never mounts -> the pre-fill presence poll times out -> NeedsLogin.
    browser = FakeBrowser(authed=False, form_renders=False)
    secrets = _secrets(**{"rm-username": "u", "rm-password": "p"})
    p = BrowserCookieHarvestProvider(
        _cfg(), cdp=browser, secret_resolver=secrets, clock=lambda: 1.0, sleep=lambda s: None,
    )
    with pytest.raises(NeedsLogin, match="did not render"):
        p.login()


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


def test_login_mint_fresh_clears_cookies_and_drives_form_even_if_authed():
    # mint_fresh: even an already-authenticated profile must be logged out + the
    # form re-driven so a brand-new single-use token is minted (not a stale one
    # the browser may already have rotated past).
    browser = FakeBrowser(authed=True)  # starts authenticated
    secrets = _secrets(**{"rm-username": "u", "rm-password": "p"})
    cfg = _cfg()
    cfg.settings["mint_fresh"] = True
    p = BrowserCookieHarvestProvider(
        cfg, cdp=browser, secret_resolver=secrets, clock=lambda: 1.0, sleep=lambda s: None,
    )
    sess = p.login()
    assert sess.access_token == "AAA"
    assert any(e.startswith("clear_cookies:") for e in browser.evals)  # forced logout
    assert any(e.startswith("type:") for e in browser.evals)           # drove the form


def test_login_already_warm_harvests_without_typing():
    # Profile already authenticated (RememberMe auto-login): navigating to the
    # login URL redirects to the app, no form renders -> harvest the existing
    # session directly, never type credentials.
    browser = FakeBrowser(authed=True)
    secrets = _secrets(**{"rm-username": "u", "rm-password": "p"})
    p = BrowserCookieHarvestProvider(
        _cfg(), cdp=browser, secret_resolver=secrets, clock=lambda: 1.0, sleep=lambda s: None,
    )
    sess = p.login()
    assert sess.access_token == "AAA"
    assert not any(e.startswith("type:") for e in browser.evals)  # no form drive
    assert browser.navigated[-1] == "about:blank"  # still parked


def test_refresh_uses_warm_profile_without_login():
    browser = FakeBrowser(authed=True)
    p = BrowserCookieHarvestProvider(_cfg(), cdp=browser, clock=lambda: 1.0, sleep=lambda s: None)
    sess = p.refresh(Session())
    assert sess.access_token == "AAA"
    assert browser.navigated == []  # refresh never drives the login form
