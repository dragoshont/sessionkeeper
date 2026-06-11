"""Vault I/O against a vaultkeeper (`bw serve`) REST endpoint.

sessionkeeper is stateless: the durable copy of every rotating session lives in
the vault, written into a dedicated ``machine-managed/`` folder. This client:

  get_session(item_name)        -> Session     (read latest)
  put_session(item_name, sess)  -> None         (persist rotated)

The session payload is stored as JSON in the item's secure ``notes`` field; the
access token is also mirrored into ``login.password`` so simple consumers that
only read a password still work. The HTTP layer is injectable for offline tests.
"""
from __future__ import annotations

import json
from typing import Any, Optional

from .http import Transport, urllib_transport
from .session import Session


class VaultError(RuntimeError):
    pass


class VaultItemNotFound(VaultError):
    pass


class VaultClient:
    def __init__(self, base_url: str, *, api_key: Optional[str] = None,
                 transport: Transport = urllib_transport):
        if not base_url:
            raise ValueError("vault base_url is required")
        self._base = base_url.rstrip("/")
        self._api_key = api_key
        self._http = transport

    # -- low level ------------------------------------------------------------
    def _headers(self, *, json_body: bool = False) -> dict:
        h: dict[str, str] = {"Accept": "application/json"}
        if json_body:
            h["Content-Type"] = "application/json"
        if self._api_key:
            h["Authorization"] = f"Bearer {self._api_key}"
        return h

    def _call(self, method: str, path: str, body: Any = None) -> dict:
        raw = json.dumps(body).encode("utf-8") if body is not None else None
        status, _rh, text = self._http(
            method, f"{self._base}{path}", self._headers(json_body=body is not None), raw
        )
        if status >= 400:
            raise VaultError(f"{method} {path} -> HTTP {status}: {text[:300]}")
        data = json.loads(text) if text.strip() else {}
        if isinstance(data, dict) and data.get("success") is False:
            raise VaultError(f"{method} {path} -> success=false: {str(data)[:300]}")
        return data

    # -- item helpers ---------------------------------------------------------
    def _find_item(self, item_name: str) -> dict:
        """Return the raw vault item whose name matches (case-insensitive)."""
        from urllib.parse import quote
        data = self._call("GET", f"/list/object/items?search={quote(item_name)}")
        items = data.get("data", {})
        items = items.get("data", items) if isinstance(items, dict) else items
        if not isinstance(items, list):
            raise VaultItemNotFound(f"no items for {item_name!r}")
        for item in items:
            if str(item.get("name", "")).lower() == item_name.lower():
                return item
        raise VaultItemNotFound(f"no vault item named {item_name!r}")

    # -- public API -----------------------------------------------------------
    def get_session(self, item_name: str) -> Session:
        item = self._find_item(item_name)
        notes = item.get("notes")
        if notes:
            try:
                return Session.from_json(notes)
            except (ValueError, json.JSONDecodeError):
                pass  # fall through to login.password mirror
        login = item.get("login") or {}
        return Session(access_token=login.get("password", "") or "")

    def get_secret(self, item_name: str) -> str:
        """Return a raw secret value (login.password) JIT for the cold-login
        form-drive. Never persisted, never logged (parity with the KV backend)."""
        item = self._find_item(item_name)
        login = item.get("login") or {}
        return login.get("password", "") or ""

    def put_session(self, item_name: str, session: Session) -> None:
        """Persist the rotated session back onto the item (read-modify-write)."""
        item = self._find_item(item_name)
        item_id = item.get("id")
        if not item_id:
            raise VaultError(f"vault item {item_name!r} has no id; cannot update")
        item["notes"] = session.to_json()
        login = item.get("login")
        if isinstance(login, dict):
            login["password"] = session.access_token  # mirror for simple readers
        self._call("PUT", f"/object/item/{item_id}", body=item)
