"""Hand-rolled Prometheus text-exposition registry (zero dependencies).

Only the three metrics the README documents, kept thread-safe so the scheduler
thread can update while the HTTP thread renders.
"""
from __future__ import annotations

import threading
from typing import Optional

from .provider import STATE_NAMES


class Metrics:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._state: dict[str, int] = {}
        self._expiry: dict[str, float] = {}
        self._refresh_total: dict[tuple[str, str], int] = {}

    def set_state(self, provider: str, state: int) -> None:
        with self._lock:
            self._state[provider] = state

    def set_expiry(self, provider: str, seconds: Optional[float]) -> None:
        with self._lock:
            if seconds is None:
                self._expiry.pop(provider, None)
            else:
                self._expiry[provider] = float(seconds)

    def inc_refresh(self, provider: str, result: str) -> None:
        with self._lock:
            key = (provider, result)
            self._refresh_total[key] = self._refresh_total.get(key, 0) + 1

    def render(self) -> str:
        with self._lock:
            lines: list[str] = []
            lines.append("# HELP sessionkeeper_session_state Session state (0 healthy,1 stale,2 dead,3 needs-human).")
            lines.append("# TYPE sessionkeeper_session_state gauge")
            for provider, state in sorted(self._state.items()):
                name = STATE_NAMES.get(state, "unknown")
                lines.append(f'sessionkeeper_session_state{{provider="{provider}",state="{name}"}} {state}')

            lines.append("# HELP sessionkeeper_session_expiry_seconds Seconds until the current session expires.")
            lines.append("# TYPE sessionkeeper_session_expiry_seconds gauge")
            for provider, secs in sorted(self._expiry.items()):
                lines.append(f'sessionkeeper_session_expiry_seconds{{provider="{provider}"}} {secs:.0f}')

            lines.append("# HELP sessionkeeper_refresh_total Refresh attempts by outcome.")
            lines.append("# TYPE sessionkeeper_refresh_total counter")
            for (provider, result), count in sorted(self._refresh_total.items()):
                lines.append(f'sessionkeeper_refresh_total{{provider="{provider}",result="{result}"}} {count}')

            return "\n".join(lines) + "\n"
