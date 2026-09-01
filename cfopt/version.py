"""Runtime version discovery for extracted desktop release packages."""

from __future__ import annotations

from .resources import package_root


DEFAULT_VERSION = "1.0.1"


def package_version() -> str:
    """Read the version injected at ZIP build time, with a source-tree fallback."""

    version_file = package_root() / "VERSION"
    try:
        value = version_file.read_text(encoding="utf-8").strip()
    except OSError:
        return DEFAULT_VERSION
    if not value or len(value) > 80:
        return DEFAULT_VERSION
    allowed = "0123456789.-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    return value if all(char in allowed for char in value) else DEFAULT_VERSION


VERSION = package_version()
