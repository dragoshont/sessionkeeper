"""Tiny HTTP transport seam.

A ``Transport`` is any callable ``(method, url, headers, body) -> (status,
headers, text)``. The default uses ``urllib`` (stdlib, zero deps); tests inject
a fake so the request/response shaping is verified offline with no network.
"""
from __future__ import annotations

import urllib.error
import urllib.request
from typing import Callable, Optional

# (method, url, headers, body) -> (status, response_headers, text)
Transport = Callable[[str, str, dict, Optional[bytes]], "tuple[int, dict, str]"]


def urllib_transport(method: str, url: str, headers: dict, body: Optional[bytes],
                     timeout: float = 30.0) -> "tuple[int, dict, str]":
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, dict(resp.headers), resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers or {}), e.read().decode("utf-8", "replace")
