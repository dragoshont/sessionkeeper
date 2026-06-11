"""Azure Key Vault backend: token exchange + secret get/put (offline)."""
import json

import pytest

from sessionkeeper.session import Session
from sessionkeeper.vault import VaultError, VaultItemNotFound
from sessionkeeper.vault_azure import (
    AzureKeyVaultClient,
    ServicePrincipalToken,
    WorkloadIdentityToken,
    make_token_provider,
)


class FakeHTTP:
    def __init__(self, routes):
        # routes: list of (predicate(method,url) -> (status, headers, body))
        self.routes = routes
        self.calls = []

    def __call__(self, method, url, headers, body):
        self.calls.append((method, url, headers, body))
        for pred, resp in self.routes:
            if pred(method, url):
                status, rh, payload = resp
                text = payload if isinstance(payload, str) else json.dumps(payload)
                return status, rh, text
        return 404, {}, '{"error":"no route"}'


def test_workload_identity_token_exchanges_and_caches(tmp_path, monkeypatch):
    token_file = tmp_path / "token"
    token_file.write_text("FEDERATED-SA-JWT")
    monkeypatch.setenv("AZURE_TENANT_ID", "tenant-123")
    monkeypatch.setenv("AZURE_CLIENT_ID", "client-abc")
    monkeypatch.setenv("AZURE_FEDERATED_TOKEN_FILE", str(token_file))
    monkeypatch.setenv("AZURE_AUTHORITY_HOST", "https://login.microsoftonline.com")

    http = FakeHTTP([
        (lambda m, u: u.endswith("/oauth2/v2.0/token"),
         (200, {}, {"access_token": "AAD-TOKEN", "expires_in": 3600})),
    ])
    clock = [1000.0]
    tok = WorkloadIdentityToken(transport=http, clock=lambda: clock[0])

    assert tok() == "AAD-TOKEN"
    body = http.calls[-1][3].decode()
    assert "client_assertion=FEDERATED-SA-JWT" in body
    assert "scope=https%3A%2F%2Fvault.azure.net%2F.default" in body
    # cached: second call within validity does NOT re-exchange
    assert tok() == "AAD-TOKEN"
    assert len(http.calls) == 1


def test_workload_identity_token_missing_env_raises(monkeypatch):
    for k in ("AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_FEDERATED_TOKEN_FILE"):
        monkeypatch.delenv(k, raising=False)
    with pytest.raises(VaultError, match="workload identity not configured"):
        WorkloadIdentityToken(transport=FakeHTTP([]))()


def test_service_principal_token_uses_client_secret_grant(monkeypatch):
    monkeypatch.setenv("AZURE_TENANT_ID", "tenant-123")
    monkeypatch.setenv("AZURE_CLIENT_ID", "client-abc")
    monkeypatch.setenv("AZURE_CLIENT_SECRET", "sp-secret-xyz")
    http = FakeHTTP([
        (lambda m, u: u.endswith("/oauth2/v2.0/token"),
         (200, {}, {"access_token": "SP-TOKEN", "expires_in": 3600})),
    ])
    clock = [1000.0]
    tok = ServicePrincipalToken(transport=http, clock=lambda: clock[0])
    assert tok() == "SP-TOKEN"
    body = http.calls[-1][3].decode()
    assert "grant_type=client_credentials" in body
    assert "client_secret=sp-secret-xyz" in body
    assert "scope=https%3A%2F%2Fvault.azure.net%2F.default" in body
    # cached: no re-exchange within validity
    assert tok() == "SP-TOKEN"
    assert len(http.calls) == 1


def test_service_principal_token_missing_secret_raises(monkeypatch):
    monkeypatch.setenv("AZURE_TENANT_ID", "t")
    monkeypatch.setenv("AZURE_CLIENT_ID", "c")
    monkeypatch.delenv("AZURE_CLIENT_SECRET", raising=False)
    with pytest.raises(VaultError, match="service principal not configured"):
        ServicePrincipalToken(transport=FakeHTTP([]))()


def test_make_token_provider_prefers_service_principal_when_secret_present(monkeypatch):
    monkeypatch.setenv("AZURE_CLIENT_SECRET", "sp-secret")
    assert isinstance(make_token_provider(), ServicePrincipalToken)


def test_make_token_provider_falls_back_to_workload_identity(monkeypatch):
    monkeypatch.delenv("AZURE_CLIENT_SECRET", raising=False)
    assert isinstance(make_token_provider(), WorkloadIdentityToken)


def test_get_session_round_trips_whole_bundle():
    sess = Session(access_token="AT", refresh_token="RT", cookies={"c": "1"}, extra={"x": 2})
    http = FakeHTTP([
        (lambda m, u: m == "GET" and "/secrets/rm-session" in u,
         (200, {}, {"value": sess.to_json()})),
    ])
    kv = AzureKeyVaultClient("https://vault.vault.azure.net", transport=http, token_provider=lambda: "t")
    got = kv.get_session("rm-session")
    assert got.access_token == "AT"
    assert got.refresh_token == "RT"
    assert got.cookies == {"c": "1"}
    assert "Bearer t" == http.calls[-1][2]["Authorization"]


def test_get_session_404_raises_not_found():
    http = FakeHTTP([(lambda m, u: True, (404, {}, '{"error":{"code":"SecretNotFound"}}'))])
    kv = AzureKeyVaultClient("https://vault.vault.azure.net", transport=http, token_provider=lambda: "t")
    with pytest.raises(VaultItemNotFound):
        kv.get_session("missing")


def test_put_session_sends_value_as_session_json():
    captured = {}

    def http(method, url, headers, body):
        captured["method"] = method
        captured["body"] = json.loads(body.decode())
        return 200, {}, "{}"

    kv = AzureKeyVaultClient("https://vault.vault.azure.net", transport=http, token_provider=lambda: "t")
    sess = Session(access_token="NEW", refresh_token="NEWR")
    kv.put_session("rm-session", sess)
    assert captured["method"] == "PUT"
    assert captured["body"]["value"] == sess.to_json()


def test_put_session_http_error_raises_vault_error():
    http = FakeHTTP([(lambda m, u: True, (403, {}, "Forbidden"))])
    kv = AzureKeyVaultClient("https://vault.vault.azure.net", transport=http, token_provider=lambda: "t")
    with pytest.raises(VaultError, match="HTTP 403"):
        kv.put_session("rm-session", Session(access_token="x"))


def test_get_secret_returns_raw_value():
    http = FakeHTTP([
        (lambda m, u: m == "GET" and "/secrets/rm-password" in u, (200, {}, {"value": "s3cr3t"})),
    ])
    kv = AzureKeyVaultClient("https://vault.vault.azure.net", transport=http, token_provider=lambda: "t")
    assert kv.get_secret("rm-password") == "s3cr3t"


def test_get_secret_404_raises_not_found():
    http = FakeHTTP([(lambda m, u: True, (404, {}, '{"error":{"code":"SecretNotFound"}}'))])
    kv = AzureKeyVaultClient("https://vault.vault.azure.net", transport=http, token_provider=lambda: "t")
    with pytest.raises(VaultItemNotFound):
        kv.get_secret("missing")
