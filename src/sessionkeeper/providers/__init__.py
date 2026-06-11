"""Adapters live here.

* ``HttpRefreshProvider`` — generic config-driven cookie/token refresh.
* ``BrowserCookieHarvestProvider`` — CDP cookie harvest from a warm profile.
"""
from .browser_harvest import BrowserCookieHarvestProvider
from .http_refresh import HttpRefreshProvider

__all__ = ["HttpRefreshProvider", "BrowserCookieHarvestProvider"]
