"""Adapters live here. v0.1 ships one generic, config-driven adapter."""
from .http_refresh import HttpRefreshProvider

__all__ = ["HttpRefreshProvider"]
