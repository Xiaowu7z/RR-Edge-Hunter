"""Resolve files bundled beside the desktop application."""

from __future__ import annotations

from pathlib import Path
import sys


def package_root() -> Path:
    """Return the source root or PyInstaller's extracted resource directory."""

    bundled_root = getattr(sys, "_MEIPASS", None)
    if bundled_root:
        return Path(bundled_root)
    return Path(__file__).resolve().parents[1]
