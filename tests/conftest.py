"""Shared test helpers: a programmable fake HTTP transport."""
from __future__ import annotations

import json


class FakeHTTP:
    """Records requests; returns canned responses keyed by (METHOD, url-suffix).

    routes: dict[(method, suffix)] -> (status, headers, body)  where body is a
    str or a JSON-serialisable object.
    """

    def __init__(self, routes: dict):
        self.routes = routes
        self.calls: list[tuple] = []  # (method, url, headers, body)

    def __call__(self, method, url, headers, body):
        self.calls.append((method, url, headers, body))
        for (m, suffix), resp in self.routes.items():
            if m == method and url.endswith(suffix):
                status, rheaders, payload = resp
                text = payload if isinstance(payload, str) else json.dumps(payload)
                return status, rheaders, text
        return 404, {}, '{"error":"no route"}'

    def last_body_json(self):
        return json.loads(self.calls[-1][3].decode()) if self.calls[-1][3] else None
