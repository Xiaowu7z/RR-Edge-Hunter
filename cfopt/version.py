"""Runtime version discovery for extracted desktop release packages."""

from __future__ import annotations

from pathlib import Path


DEFAULT_VERSION = "0.1.0"


def package_version() -> str:
    """Read the version injected at ZIP build time, with a source-tree fallback."""

    version_file = Path(__file__).resolve().parents[1] / "VERSION"
    try:
        value = version_file.read_text(encoding="utf-8").strip()
    except OSError:
        return DEFAULT_VERSION
    if not value or len(value) > 80:
        return DEFAULT_VERSION
    allowed = "0123456789.-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    return value if all(char in allowed for char in value) else DEFAULT_VERSION


VERSION = package_version()
