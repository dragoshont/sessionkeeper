# AGENTS.md — sessionkeeper

> Working guide for AI agents and contributors in this repo. Pairs with
> [README.md](README.md) (what/why, plain terms), [docs/harvester-spec.md](docs/harvester-spec.md)
> (the adapter + harvester design), and [docs/operating.md](docs/operating.md) (running it).

## What this is

`sessionkeeper` is a **refresh engine**: a scheduler plus small per-provider
**adapters** that keep custom-login (non-OAuth) sessions warm — they run each
provider's silent refresh on a timer and persist the rotated session back to a
**pluggable vault** (Azure Key Vault by default). It holds **no secrets at rest**.
The runtime is **stdlib-only** (no runtime dependencies) to keep the image tiny and
the secret-handling surface auditable.

## Build / test / lint

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[test]"      # runtime is dependency-free; tests need pytest
pytest -q                     # fully offline — no network, no real vault, no browser
ruff check . && ruff format --check .   # lint locally (not currently a CI gate)
```

- Tests are **fully offline** — adapters take injectable transports/openers, so no
  test hits a real vault, CDP browser, or upstream. Keep it that way: any new
  adapter must be unit-testable with a fake transport.
- CI (`.github/workflows/build.yml`): the `test` job runs `pytest -q` on Python
  3.12 for every push/PR; the `image` job (non-PR) builds and pushes a
  **multi-arch** (amd64 + arm64) image to `ghcr.io/<owner>/sessionkeeper`.

## Releasing — and the version-truth rule

`__version__` is **derived from installed package metadata**
(`importlib.metadata.version("sessionkeeper")` in `src/sessionkeeper/__init__.py`),
**not** a hand-edited constant. The harvester logs it at startup
(`sessionkeeper <ver> starting`). This exists because a hardcoded constant once
drifted — a released image kept announcing an old version. **Do not reintroduce a
hardcoded version string.**

To cut a release:

1. Bump `version` in `pyproject.toml` (the single source of truth).
2. Commit, then `git tag vX.Y.Z && git push origin main vX.Y.Z`.
3. CI (`tags: ["v*"]`) builds `ghcr.io/<owner>/sessionkeeper:X.Y.Z` (plus `X.Y`
   and `latest`) via `docker/metadata-action` **semver** tags — **semver only,
   never git-sha tags.**
4. Consumers pin the new `X.Y.Z` and redeploy.

Because the version comes from installed metadata, the startup log always matches
the image tag — verify a deploy by reading the container's first log line.

## The adapter contract

Each provider adapter implements three methods (see `docs/harvester-spec.md`):

| Method | Contract |
|---|---|
| `probe(session)` | cheap read-only check → `healthy` / `stale` / `dead` |
| `refresh(session)` | run the provider's silent refresh; return the rotated session, or raise `NeedsLogin` |
| `login(assist)` | autonomous (re)login via the harvester (warm browser → CDP cookie harvest); raise `NeedsLogin` only on a genuine dead-end |

The scheduler wakes before expiry, calls `refresh()`, writes the rotated session
back to the vault, exports an expiry metric, and — when `refresh()` raises
`NeedsLogin` — escalates to `login()` under a **single-flight lock** plus a
per-provider **circuit breaker** (`min_seconds_between_logins`,
`max_logins_per_day`) so a relogin storm can't trip reCAPTCHA or flag the account.

Two strategies ship:
- **`http_refresh`** — services with a clean refresh endpoint (cookie/token POST).
- **`browser_cookie_harvest`** — services whose refresh needs a real browser (cold
  login, often reCAPTCHA-gated): drives a warm headful browser over CDP, optionally
  form-driving the login from vault creds, and harvests fresh cookies.

## Liveness-oracle auto-heal (the probe upgrade)

A `browser_cookie_harvest` probe can be **liveness-oracle-based** instead of
TTL-hint-based: set `liveness_probe_url` in the recipe and the probe POSTs that URL
each tick to get the *consumer's own* truthful verdict (which actually exercises a
refresh) rather than trusting a cookie's mere presence. This closes the classic
failure where a present-but-server-side-expired token reads "healthy" and the
session dies unnoticed. On a genuine `dead` verdict the scheduler re-seeds via
`login()`, breaker-gated; if the login is blocked, `mfa.on_blocked: alert_sev3`
raises an alert instead of looping. Tests: `tests/test_browser_harvest_liveness.py`.

## How it is deployed (generic)

The engine runs as a **sidecar** next to the consumer that reads the session (plus,
for `browser_cookie_harvest`, a warm headful-browser container). The operator's
**private overlay** supplies the per-provider recipe (`liveness_probe_url`, `login`
selectors, credential refs) and pins the image by **semver** — **real targets and
credentials never live in this public repo.**

> ⚠️ **Multi-container gotcha** (for operators): as a sidecar the pod has several
> containers, and `kubectl logs`/`get` defaults to the **first** one. Target the
> harvester container explicitly (`-c <harvester-container-name>`) or you will read
> the wrong image/logs.

## Safety invariants (do not violate)

- **One rotation owner per session.** A service with single-use rotating refresh
  tokens must have **exactly one** component refreshing it. If the consumer already
  rotates, configure this engine to **seed/re-seed only** (no `http_refresh`) — two
  rotators corrupt the chain.
- **Secrets are just-in-time and never logged.** Creds are pulled from the vault at
  login time and never written to logs, metrics, or any bundle echo. The engine
  holds nothing at rest.
- **The breaker is load-bearing.** Never bypass `min_seconds_between_logins` /
  `max_logins_per_day` — re-login against a real (possibly sensitive) account is a
  lockout / bot-detection risk.
- **Keep the public repo clean.** No real hostnames, account identifiers, vault
  names, or personal data in code, tests, docs, or commit messages — use
  placeholders. Real wiring lives only in the operator's private overlay.
