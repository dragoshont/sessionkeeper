"""Session model + JWT expiry helper.

A ``Session`` is the rotating credential material for one provider: a short-lived
access token, a longer-lived refresh token, any cookies, and a free-form ``extra``
bag. It is serialised to/from JSON for storage in the vault.
"""
from __future__ import annotations

import base64
import binascii
import json
import time
from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class Session:
    access_token: str = ""
    refresh_token: str = ""
    cookies: dict[str, str] = field(default_factory=dict)
    extra: dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> str:
        return json.dumps(
            {
                "access_token": self.access_token,
                "refresh_token": self.refresh_token,
                "cookies": self.cookies,
                "extra": self.extra,
            },
            separators=(",", ":"),
            sort_keys=True,
        )

    @classmethod
    def from_json(cls, raw: str) -> "Session":
        data = json.loads(raw) if raw and raw.strip() else {}
        return cls(
            access_token=data.get("access_token", "") or "",
            refresh_token=data.get("refresh_token", "") or "",
            cookies=data.get("cookies", {}) or {},
            extra=data.get("extra", {}) or {},
        )

    def cookie_header(self, *, access_name: str, refresh_name: str) -> str:
        """Render a Cookie header from the named access/refresh tokens + cookies."""
        parts: list[str] = []
        if access_name and self.access_token:
            parts.append(f"{access_name}={self.access_token}")
        if refresh_name and self.refresh_token:
            parts.append(f"{refresh_name}={self.refresh_token}")
        for k, v in self.cookies.items():
            parts.append(f"{k}={v}")
        return "; ".join(parts)


def jwt_expiry(token: str) -> Optional[float]:
    """Return the ``exp`` claim (epoch seconds) of a JWT, or None.

    None means "not a decodable JWT with an exp" — callers then fall back to a
    configured TTL hint rather than assuming the token is valid forever.
    """
    if not token or token.count(".") != 2:
        return None
    payload_b64 = token.split(".", 2)[1]
    # JWT uses base64url without padding; restore padding before decoding.
    padding = "=" * (-len(payload_b64) % 4)
    try:
        decoded = base64.urlsafe_b64decode(payload_b64 + padding)
        claims = json.loads(decoded)
    except (binascii.Error, ValueError, json.JSONDecodeError):
        return None
    exp = claims.get("exp")
    if isinstance(exp, (int, float)):
        return float(exp)
    return None


def seconds_until(expiry_epoch: Optional[float], *, now: Optional[float] = None) -> Optional[float]:
    if expiry_epoch is None:
        return None
    return expiry_epoch - (now if now is not None else time.time())
