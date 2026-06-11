# Security policy

`sessionkeeper` transiently handles **live session material** for potentially
sensitive third-party accounts. It is designed to be treated as high-value
infrastructure. This document is the public security posture; the full
threat-model matrix lives in [`docs/harvester-spec.md` §16](docs/harvester-spec.md).

## Reporting a vulnerability

Please report suspected vulnerabilities **privately**, not via a public issue:

- Open a [GitHub security advisory](https://github.com/dragoshont/sessionkeeper/security/advisories/new), **or**
- email the maintainer listed on the GitHub profile.

Include reproduction steps and impact. You'll get an acknowledgement; please
allow a reasonable window for a fix before any public disclosure.

## Threat model (summary)

Full matrix (14 threats mapped to **RFC 9700**, the **OWASP Top 10 for LLM Apps
2025**, and the OWASP Secrets-Management / MCP-Security cheat sheets) is in the
spec. The controls that matter most here:

| Area | Control |
|---|---|
| **Prompt injection / excessive agency** (LLM01, LLM06) | Login/harvest is **never** an agent-callable tool; consuming MCPs expose domain tools only. An injected page cannot trigger a login. |
| **No ROPC** (RFC 9700 §2.4) | The agent/MCP never sees a password; only the isolated harvester handles credentials, pulled just-in-time from the vault. |
| **Token theft / replay** (RFC 9700 §2.2/§4.14) | Refresh-token **rotation**; short access TTL; TLS in transit; KV at rest; versioned/compare-and-set bundle writes detect rotation races. |
| **Secret disclosure to the LLM / logs** (LLM02) | Scrub middleware strips cookies/bearer/keys from every LLM-visible path; audit logs status, never token values. `*_DEBUG` flags are off by default and documented as PII-leaking. |
| **Relogin storm → CAPTCHA escalation** | Refresh-first ladder; **single-flight** + **circuit breaker** (`min_seconds_between_logins`, `max_logins_per_day`); one persistent warm profile, no fingerprint rotation. |
| **Unattended operation** | No Approve/Deny gate, no notification app. A genuine auth dead-end raises a **Sev-3** alert; a human does a one-time login at their convenience. |
| **Side channels** | CDP bound to **loopback in-pod only**; harvester runs in-pod, never exposes `:9222`; NetworkPolicy allows egress to the vault + metrics only, **no ingress**. |
| **Supply chain** (LLM03) | Public repo ships **engine + generic example recipes only** — no secrets, no PII, no real per-account overlays. Images are semver-tagged (digest-pinned for prod); deps are stdlib-only. |

## What is *not* in this repo

Per the public-repo readiness gate (spec §17): **no secrets, no PII, no real
per-account recipes, and no medical/health-provider recipe.** Real targets and
their per-account bindings live in a **private overlay**, never here. The public
repo ships only a generic `browser_cookie_harvest` example against `example.com`.

## Knowing deviations

We are a *user-side client* of providers with no published security model, so a
few RFC 9700 *SHOULD*s are impossible to enforce unilaterally (e.g. DPoP/mTLS
sender-constraining of tokens). These are **documented and compensated** (rotation
+ short TTL + on-cluster-only egress + rotation-break detection) in spec §16.3.
No shortcut hides an un-mitigated high risk.
