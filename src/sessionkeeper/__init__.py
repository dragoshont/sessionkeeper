"""sessionkeeper — keep custom-login sessions warm by scheduled refresh.

Stateless refresh engine: reads the latest session from the vault, runs each
provider's silent refresh before expiry, and persists the rotated session back
to the vault. See README.md for the architecture.
"""

__version__ = "0.3.3"
