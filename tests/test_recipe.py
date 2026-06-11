"""Recipe DAG: topological order, cycle + missing-dep rejection, typed view."""
import pytest

from sessionkeeper.provider import ProviderConfig
from sessionkeeper.recipe import (
    MfaPolicy,
    Recipe,
    RecipeError,
    order_provider_configs,
    resolve_order,
)


def test_resolve_order_dependencies_come_first():
    order = resolve_order([("olx", ["google"]), ("google", []), ("rm", [])])
    assert order.index("google") < order.index("olx")
    assert set(order) == {"olx", "google", "rm"}


def test_resolve_order_is_stable_by_id():
    # No deps -> deterministic alphabetical order.
    assert resolve_order([("c", []), ("a", []), ("b", [])]) == ["a", "b", "c"]


def test_resolve_order_rejects_missing_dependency():
    with pytest.raises(RecipeError, match="unknown recipe"):
        resolve_order([("olx", ["google"])])  # google not declared


def test_resolve_order_rejects_cycle():
    with pytest.raises(RecipeError, match="cycle"):
        resolve_order([("a", ["b"]), ("b", ["a"])])


def test_resolve_order_rejects_self_cycle():
    with pytest.raises(RecipeError, match="cycle"):
        resolve_order([("a", ["a"])])


def test_recipe_from_provider_config_parses_fields():
    pc = ProviderConfig(
        id="olx",
        vault_item="olx-session",
        settings={
            "strategy": "browser_token_harvest",
            "depends_on": ["google"],
            "domains": ["olx.ro"],
            "success_when": {"cookie": "access_token"},
            "profile": "playwright-primary",
            "mfa": {"expected": True, "on_blocked": "alert_sev3"},
        },
    )
    r = Recipe.from_provider_config(pc)
    assert r.id == "olx"
    assert r.strategy == "browser_token_harvest"
    assert r.depends_on == ("google",)
    assert r.domains == ("olx.ro",)
    assert r.success_when == {"cookie": "access_token"}
    assert r.profile == "playwright-primary"
    assert r.mfa == MfaPolicy(expected=True, on_blocked="alert_sev3")


def test_recipe_defaults_to_http_refresh_no_mfa_gate():
    r = Recipe.from_provider_config(ProviderConfig(id="x", vault_item="x"))
    assert r.strategy == "http_refresh"
    assert r.depends_on == ()
    assert r.mfa.on_blocked == "alert_sev3"  # never an Approve/Deny gate


def test_order_provider_configs_orders_by_depends_on():
    olx = ProviderConfig(id="olx", vault_item="olx", settings={"depends_on": ["google"]})
    google = ProviderConfig(id="google", vault_item="google", settings={})
    ordered = order_provider_configs([olx, google])
    assert [c.id for c in ordered] == ["google", "olx"]


def test_order_provider_configs_rejects_cycle():
    a = ProviderConfig(id="a", vault_item="a", settings={"depends_on": ["b"]})
    b = ProviderConfig(id="b", vault_item="b", settings={"depends_on": ["a"]})
    with pytest.raises(RecipeError):
        order_provider_configs([a, b])
