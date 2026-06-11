"""Azure Key Vault backend — the single vault for all providers (spec §7).

sessionkeeper is the **rotation owner**, so it both reads and *writes* rotated
session bundles. ESO only syncs KV->cluster one-way for the consuming MCPs; the
write-back path is this client, talking the KV REST API directly and
authenticating with **Azure Workload Identity** (a federated ServiceAccount token
exchanged for an AAD token — no static client secret on disk).

Interface mirrors ``vault.VaultClient`` (``get_session`` / ``put_session`` /
``VaultError``) so it is a drop-in. The whole ``Session`` JSON is stored as the
secret value. Both the HTTP transport and the token provider are injectable so
the request shaping is unit-tested offline with no Azure and no network.
"""
from __future__ import annotations

import json
import os
import time
import urllib.parse
from typing import Callable, Optional

from .http import Transport, urllib_transport
from .session import Session
from .vault import VaultError, VaultItemNotFound

TokenProvider = Callable[[], str]


class WorkloadIdentityToken:
    """Acquire (and cache) an AAD access token via workload-identity federation.

    Reads the projected SA token from ``AZURE_FEDERATED_TOKEN_FILE`` and exchanges
    it at the AAD token endpoint for a ``https://vault.azure.net/.default`` token.
    These env vars are injected by the Azure Workload Identity webhook when the
    pod's ServiceAccount is annotated; nothing secret is committed or mounted.
    """

    def __init__(
        self,
        *,
        transport: Transport = urllib_transport,
        scope: str = "https://vault.azure.net/.default",
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._http = transport
        self._scope = scope
        self._clock = clock
        self._token = ""
        self._exp = 0.0

    def __call__(self) -> str:
        now = self._clock()
        if self._token and now < self._exp - 60:
            return self._token
        tenant = os.environ.get("AZURE_TENANT_ID")
        client_id = os.environ.get("AZURE_CLIENT_ID")
        token_file = os.environ.get("AZURE_FEDERATED_TOKEN_FILE")
        authority = os.environ.get("AZURE_AUTHORITY_HOST", "https://login.microsoftonline.com").rstrip("/")
        if not (tenant and client_id and token_file):
            raise VaultError(
                "workload identity not configured "
                "(AZURE_TENANT_ID / AZURE_CLIENT_ID / AZURE_FEDERATED_TOKEN_FILE)"
            )
        try:
            with open(token_file, "r", encoding="utf-8") as fh:
                assertion = fh.read().strip()
        except OSError as e:
            raise VaultError(f"cannot read federated token file: {e}") from e

        body = urllib.parse.urlencode(
            {
                "client_id": client_id,
                "grant_type": "client_credentials",
                "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                "client_assertion": assertion,
                "scope": self._scope,
            }
        ).encode()
        status, _rh, text = self._http(
            "POST",
            f"{authority}/{tenant}/oauth2/v2.0/token",
            {"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"},
            body,
        )
        if status >= 400:
            raise VaultError(f"AAD token exchange failed HTTP {status}: {text[:200]}")
        data = json.loads(text) if text.strip() else {}
        token = data.get("access_token")
        if not token:
            raise VaultError("AAD token response had no access_token")
        self._token = token
        self._exp = now + float(data.get("expires_in", 3600))
        return token


class AzureKeyVaultClient:
    def __init__(
        self,
        vault_url: str,
        *,
        transport: Transport = urllib_transport,
        token_provider: Optional[TokenProvider] = None,
        api_version: str = "7.4",
    ) -> None:
        if not vault_url:
            raise ValueError("vault_url is required, e.g. https://<name>.vault.azure.net")
        self._base = vault_url.rstrip("/")
        self._http = transport
        self._token = token_provider or WorkloadIdentityToken(transport=transport)
        self._api = api_version

    def _headers(self, *, json_body: bool = False) -> dict:
        h = {"Authorization": f"Bearer {self._token()}", "Accept": "application/json"}
        if json_body:
            h["Content-Type"] = "application/json"
        return h

    def get_session(self, item_name: str) -> Session:
        url = f"{self._base}/secrets/{urllib.parse.quote(item_name)}?api-version={self._api}"
        status, _rh, text = self._http("GET", url, self._headers(), None)
        if status == 404:
            raise VaultItemNotFound(f"no KV secret named {item_name!r}")
        if status >= 400:
            raise VaultError(f"KV get {item_name!r} -> HTTP {status}: {text[:200]}")
        value = (json.loads(text) if text.strip() else {}).get("value", "")
        return Session.from_json(value)

    def put_session(self, item_name: str, session: Session) -> None:
        url = f"{self._base}/secrets/{urllib.parse.quote(item_name)}?api-version={self._api}"
        body = json.dumps({"value": session.to_json()}).encode()
        status, _rh, text = self._http("PUT", url, self._headers(json_body=True), body)
        if status >= 400:
            raise VaultError(f"KV set {item_name!r} -> HTTP {status}: {text[:200]}")
