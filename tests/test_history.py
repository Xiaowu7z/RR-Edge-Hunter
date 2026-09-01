from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cfopt.history import load_history, save_history


class HistoryPrivacyTest(unittest.TestCase):
    def test_legacy_network_fingerprints_are_removed_on_load_and_save(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "history.json"
            path.write_text(json.dumps([{
                "created_at": "old",
                "network_fingerprints": {"IPv4": "private-digest"},
                "nested": {"network_fingerprint": "private-digest"},
            }]), encoding="utf-8")
            with patch("cfopt.history.history_path", return_value=path):
                loaded = load_history()
                self.assertNotIn("network_fingerprints", loaded[0])
                self.assertNotIn("network_fingerprint", loaded[0]["nested"])
                save_history({
                    "created_at": "new",
                    "network_fingerprints": {"IPv4": "another-private-digest"},
                    "target_host": "private-route.example",
                    "ws_path": "/private-path",
                })
            persisted = path.read_text(encoding="utf-8")
            self.assertNotIn("private-digest", persisted)
            self.assertNotIn("network_fingerprint", persisted)
            self.assertNotIn("private-route.example", persisted)
            self.assertNotIn("private-path", persisted)


if __name__ == "__main__":
    unittest.main()
