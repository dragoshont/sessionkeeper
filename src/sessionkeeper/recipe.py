"""Provider recipes + their dependency DAG.

A *recipe* is the typed view of one provider entry: which auth strategy keeps it
warm, which cookie domains carry its session, how to tell a login succeeded, the
browser profile it rides, and which other recipes it depends on (e.g. an OLX
recipe ``depends_on`` a Google identity recipe via "Sign in with Google").

Recipes form a directed acyclic graph. ``resolve_order`` topologically sorts them
so an identity provider is always kept warm *before* its dependents, and rejects
cycles and dangling dependencies loudly at load time (never silently mis-order).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

from .provider import ProviderConfig


class RecipeError(ValueError):
    """A recipe set is malformed: a dependency cycle or a missing dependency."""


@dataclass(frozen=True)
class MfaPolicy:
    """How a provider's own MFA is treated. We never gate or script around it.

    ``expected``    — the provider may prompt for MFA on a cold login.
    ``on_blocked``  — what to do if an unattended login can't proceed because of
                      it. The only supported value is ``alert_sev3``: surface a
                      Sev-3 alert and let a human do the one-time login. There is
                      no Approve/Deny gate and no notification app (see spec §6).
    """

    expected: bool = False
    on_blocked: str = "alert_sev3"


@dataclass(frozen=True)
class Recipe:
    id: str
    strategy: str
    depends_on: tuple[str, ...] = ()
    domains: tuple[str, ...] = ()
    success_when: dict[str, Any] = field(default_factory=dict)
    profile: str = ""
    mfa: MfaPolicy = field(default_factory=MfaPolicy)
    settings: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_provider_config(cls, cfg: ProviderConfig) -> "Recipe":
        s = cfg.settings or {}
        mfa_raw = s.get("mfa") or {}
        return cls(
            id=cfg.id,
            strategy=str(s.get("strategy", "http_refresh")),
            depends_on=tuple(s.get("depends_on", []) or []),
            domains=tuple(s.get("domains", []) or []),
            success_when=dict(s.get("success_when", {}) or {}),
            profile=str(s.get("profile", "")),
            mfa=MfaPolicy(
                expected=bool(mfa_raw.get("expected", False)),
                on_blocked=str(mfa_raw.get("on_blocked", "alert_sev3")),
            ),
            settings=s,
        )


def resolve_order(items: Iterable[tuple[str, Iterable[str]]]) -> list[str]:
    """Topologically sort ``(id, depends_on)`` pairs; dependencies come first.

    Raises ``RecipeError`` on a missing dependency or any cycle. Deterministic:
    ties are broken by id so the order is stable across runs.
    """
    deps: dict[str, set[str]] = {}
    for node, node_deps in items:
        deps.setdefault(node, set())
        for d in node_deps:
            deps[node].add(d)

    for node, node_deps in deps.items():
        missing = node_deps - deps.keys()
        if missing:
            raise RecipeError(
                f"recipe {node!r} depends on unknown recipe(s): {sorted(missing)}"
            )

    ordered: list[str] = []
    resolved: set[str] = set()
    # Kahn's algorithm with stable (sorted) selection of ready nodes.
    while len(resolved) < len(deps):
        ready = sorted(n for n in deps if n not in resolved and deps[n] <= resolved)
        if not ready:
            stuck = sorted(n for n in deps if n not in resolved)
            raise RecipeError(f"dependency cycle among recipes: {stuck}")
        for n in ready:
            ordered.append(n)
            resolved.add(n)
    return ordered


def order_provider_configs(configs: list[ProviderConfig]) -> list[ProviderConfig]:
    """Return ``configs`` reordered so dependencies are kept warm first."""
    by_id = {c.id: c for c in configs}
    if len(by_id) != len(configs):
        dupes = sorted({c.id for c in configs if list(c.id for c in configs).count(c.id) > 1})
        raise RecipeError(f"duplicate provider id(s): {dupes}")
    pairs = [(c.id, list((c.settings or {}).get("depends_on", []) or [])) for c in configs]
    return [by_id[i] for i in resolve_order(pairs)]
