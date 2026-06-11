# Operating sessionkeeper

How to deploy and run the engine against a real provider. This is the **generic**
operator guide; it uses placeholder names only (`svc`, `account-a`,
`playwright-1`). Real provider recipes, account bindings, and secrets live in your
own **private** overlay — never in this repo (see [SECURITY.md](../SECURITY.md)).

> **One principle above all:** recipes hold **references** (vault secret *names*),
> never secret values. The only place a credential value exists is your vault.
> "Reproduce after a wipe" therefore means *re-create the identity + re-apply the
> manifests* — the secrets already survive in the vault.

## Auth to the vault: Service Principal vs Workload Identity

The Azure Key Vault backend needs an AAD token. The engine picks the mechanism
from the environment (`make_token_provider`):

| Env present | Mechanism | Use when |
|---|---|---|
| `AZURE_CLIENT_SECRET` (+ `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`) | **Service Principal** (client-credentials) | clusters **without** a public OIDC issuer (e.g. MicroK8s, whose issuer is the internal `kubernetes.default.svc`) |
| `AZURE_FEDERATED_TOKEN_FILE` (+ tenant/client) | **Workload Identity** | managed clusters whose OIDC tokens Azure AD can validate (AKS, etc.) |

Least privilege: the **harvester** (which *writes* rotated bundles) needs
`Key Vault Secrets Officer`; pure consumers that only *read* a seed get
`Key Vault Secrets User`. Keep them as **separate** identities.

## Bootstrap a write-capable Service Principal (scripted, idempotent)

A classic SP lives in Entra ID (not ARM), so create it with a script, not IaC.
The pattern (adapt names to your environment):

```bash
az login
SP=sessionkeeper-kv VAULT=<your-vault>
APP_ID=$(az ad sp create-for-rbac --name "$SP" --skip-assignment --query appId -o tsv)
VAULT_ID=$(az keyvault show --name "$VAULT" --query id -o tsv)
az role assignment create --assignee "$APP_ID" --role "Key Vault Secrets Officer" --scope "$VAULT_ID"
```

Then put `AZURE_TENANT_ID` / `AZURE_CLIENT_ID` / `AZURE_CLIENT_SECRET` into an
encrypted Secret (SOPS, sealed-secrets, your operator's mechanism) and mount them
on the harvester. **Encrypt by the file's deploy path**, not a temp path — e.g.
SOPS chooses recipients by matching the input path against `.sops.yaml`
creation_rules, so encrypt with `--filename-override <final-path>` if you build
from a tempfile, or you'll get `no matching creation rules found`.

> The homelab reference deployment ships a fully worked, idempotent version of
> all of this as committed shell scripts (SP bootstrap, selector capture, health
> verify, pool activation). Mirror that shape in your private overlay.

## Anatomy of a `browser_cookie_harvest` recipe

```jsonc
{
  "id": "svc-account-a",
  "vault_item": "svc-account-a-session",        // where the harvested bundle is written
  "ttl_hint_seconds": 3600,
  "min_seconds_between_logins": 300,              // circuit breaker
  "max_logins_per_day": 24,
  "settings": {
    "strategy": "browser_cookie_harvest",
    "cdp_url": "http://127.0.0.1:9222",           // loopback — harvester runs in-pod
    "profile": "playwright-1",                    // the warm-browser slot
    "domains": ["svc.example"],
    "success_when": { "cookie": "SessionToken" }, // asserted on every harvest
    "access_cookie_name": "SessionToken",
    "refresh_cookie_name": "RefreshToken",
    "login": {                                     // arm these to enable AUTOMATED login
      "url": "https://svc.example/login",
      "username_ref": "svc-username",             // vault secret NAMES, never values
      "password_ref": "svc-password",
      "username_selector": "#email",
      "password_selector": "#password",
      "submit_selector": "button[type=submit]"
    }
  }
}
```

Capture the three selectors from the **live** login page (read-only DOM dump) so
you don't guess — the homelab reference ships a `capture-selectors` script that
execs the engine's CDP client in-pod to list every input/button. Until the
selectors are armed, a cold session correctly raises a Sev-3 `needs_human` instead
of guessing.

## In-pod harvester (why a sidecar)

Chrome binds CDP to `127.0.0.1:9222` only (it ignores `0.0.0.0` since Chrome 111),
so the debugger is **never** reachable off-pod. Run the harvester as a **sidecar
in the warm-browser pod** — it reaches CDP over loopback, drives the automated
login, harvests the cookies, and writes the bundle to the vault. Nothing exposes
`:9222`.

## Rotation ownership (avoid the race)

A rotating refresh-token chain must have **exactly one** rotator. If a consuming
app already refreshes the token in its own process (many do, via the provider's
silent refresh), let **it** own steady-state rotation and use the harvester for
**seed/re-seed only** (`browser_cookie_harvest` reads cookies; it does not
HTTP-rotate). Two rotators on one chain invalidate each other. Don't pair an
`http_refresh` keeper and a self-refreshing consumer on the same token.

## Verify

The deployment is healthy when:
- `sessionkeeper_session_state{provider="svc-account-a"} == 0` (healthy),
- the vault holds a fresh `svc-account-a-session` bundle,
- the consumer reads it and its calls succeed.

A `== 3` (needs-human) means automation is exhausted — a one-time human login is
genuinely required (provider MFA/captcha, or un-armed selectors). That is the
Sev-3 alert, by design — not a silent failure.
