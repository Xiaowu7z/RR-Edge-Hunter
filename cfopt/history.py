from __future__ import annotations

import json
import math
import os
import platform
from pathlib import Path
from typing import Any


_PRIVATE_RESULT_FIELDS = frozenset({
    "network_fingerprint",
    "network_fingerprints",
    "target_host",
    "node_sni",
    "node_host",
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


def _verified_node_history(value: Any) -> dict[str, Any] | None:
    """Keep only rows proven by the mandatory full-node delay gate."""

    if not isinstance(value, dict) or value.get("purpose") != "argo":
        return None
    sanitized = _without_private_result_fields(value)
    families = sanitized.get("families")
    if not isinstance(families, list):
        return None
    verified_count = 0
    clean_families: list[dict[str, Any]] = []
    for family in families:
        if not isinstance(family, dict):
            continue
        clean_family = dict(family)
        for key in ("ranked", "asia_ranked"):
            rows = family.get(key)
            verified_rows: list[dict[str, Any]] = []
            if isinstance(rows, list):
                for row in rows:
                    if not isinstance(row, dict):
                        continue
                    try:
                        delay = float(row.get("node_delay_ms", -1))
                    except (TypeError, ValueError):
                        continue
                    if math.isfinite(delay) and 0 < delay < 10_000:
                        verified_rows.append(row)
            clean_family[key] = verified_rows
            verified_count += len(verified_rows)
        clean_families.append(clean_family)
    if verified_count == 0:
        return None
    sanitized["families"] = clean_families
    return sanitized


def load_history(limit: int = 50) -> list[dict[str, Any]]:
    path = history_path()
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    if not isinstance(value, list):
        return []
    verified = (_verified_node_history(item) for item in value)
    return [item for item in verified if item is not None][:limit]


def save_history(entry: dict[str, Any], limit: int = 50) -> None:
    verified_entry = _verified_node_history(entry)
    if verified_entry is None:
        return
    rows = [verified_entry, *load_history(limit)]
    path = history_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(rows[:limit], ensure_ascii=False, indent=2), encoding="utf-8")
    temporary.replace(path)
