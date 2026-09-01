from __future__ import annotations

import json
import os
import platform
from pathlib import Path
from typing import Any


_PRIVATE_RESULT_FIELDS = frozenset({
    "network_fingerprint",
    "network_fingerprints",
    "target_host",
    "ws_path",
})


def _without_private_result_fields(value: Any) -> Any:
    """Return history-safe data, including when an older file contains private fields."""
    if isinstance(value, dict):
        return {
            key: _without_private_result_fields(item)
            for key, item in value.items()
            if key not in _PRIVATE_RESULT_FIELDS
        }
    if isinstance(value, list):
        return [_without_private_result_fields(item) for item in value]
    return value


def data_dir() -> Path:
    system = platform.system()
    if system == "Windows":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
        return base / "RR-Edge-Hunter"
    if system == "Darwin":
        return Path.home() / "Library" / "Application Support" / "RR-Edge-Hunter"
    return Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share")) / "rr-edge-hunter"


def history_path() -> Path:
    return data_dir() / "history.json"


def load_history(limit: int = 50) -> list[dict[str, Any]]:
    path = history_path()
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    if not isinstance(value, list):
        return []
    return [
        _without_private_result_fields(item)
        for item in value
        if isinstance(item, dict)
    ][:limit]


def save_history(entry: dict[str, Any], limit: int = 50) -> None:
    rows = [_without_private_result_fields(entry), *load_history(limit)]
    path = history_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(rows[:limit], ensure_ascii=False, indent=2), encoding="utf-8")
    temporary.replace(path)
