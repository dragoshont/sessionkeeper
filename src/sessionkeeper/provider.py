"""Provider contract + shared types.

Every service sessionkeeper keeps warm is one *adapter* implementing this small
contract. The scheduler, vault I/O, metrics, and alerting are generic and shared;
an adapter only encodes how ONE service's custom auth works.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Optional, Protocol, runtime_checkable

from .session import Session

# Session state codes (mirrored by the Prometheus gauge).
HEALTHY = 0
STALE = 1
DEAD = 2
NEEDS_HUMAN = 3

STATE_NAMES = {HEALTHY: "healthy", STALE: "stale", DEAD: "dead", NEEDS_HUMAN: "needs-human"}


class SessionError(RuntimeError):
    """A refresh failed for a recoverable/technical reason (retry later)."""


class NeedsLogin(SessionError):
    """The session is dead and a real human (re)login is required.

    The scheduler flips the provider to ``needs-human`` and alerts; it never
    attempts to script around a human gate (CAPTCHA / 2FA / federated consent).
    """


@dataclass
class ProviderConfig:
    id: str
    vault_item: str
    # Refresh proactively once the access token has less than this many seconds
    # of life left (default 45 min — comfortably inside a ~1 h access token).
    refresh_margin_seconds: int = 45 * 60
    # Fallback lifetime when the access token is not a decodable JWT.
    ttl_hint_seconds: int = 60 * 60
    # Circuit breaker for the expensive login() arm (spec §8): never relogin more
    # often than this, and cap total relogins per day, to avoid reCAPTCHA
    # escalation / account flagging. On the cap, the provider goes needs-human.
    min_seconds_between_logins: int = 5 * 60
    max_logins_per_day: int = 24
    settings: dict[str, Any] = field(default_factory=dict)


@runtime_checkable
class Provider(Protocol):
    id: str
    config: ProviderConfig

    def probe(self, session: Session) -> "tuple[int, Optional[float]]":
        """Return (state, expiry_epoch). expiry_epoch may be None if unknown."""

    def refresh(self, session: Session) -> Session:
        """Silently refresh; return the rotated session or raise NeedsLogin."""

    def login(self, assist: Optional[Callable[[dict], dict]] = None) -> Session:
        """Full (re)login. May require human assistance. (Implemented in v0.2.)"""
