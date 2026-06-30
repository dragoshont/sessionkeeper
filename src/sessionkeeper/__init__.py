"""sessionkeeper — keep custom-login sessions warm by scheduled refresh.

Stateless refresh engine: reads the latest session from the vault, runs each
provider's silent refresh before expiry, and persists the rotated session back
to the vault. See README.md for the architecture.
"""

from importlib.metadata import PackageNotFoundError, version as _pkg_version

# Single source of truth = pyproject.toml. Deriving the version from the
# installed package metadata (the image always `pip install`s the package)
# prevents the hardcoded-string drift that left the harvester logging an old
# version after every release.
try:
    __version__ = _pkg_version("sessionkeeper")
except PackageNotFoundError:  # running from a source tree without an install
    __version__ = "0.0.0+unknown"
