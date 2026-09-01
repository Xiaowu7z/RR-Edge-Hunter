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
                "purpose": "argo",
                "network_fingerprints": {"IPv4": "private-digest"},
                "nested": {"network_fingerprint": "private-digest"},
                "families": [{
                    "family": "IPv4",
                    "ranked": [{"ip": "104.16.0.1", "node_delay_ms": 123}],
                    "asia_ranked": [{"ip": "104.16.0.1", "node_delay_ms": 123}],
                }],
            }]), encoding="utf-8")
            with patch("cfopt.history.history_path", return_value=path):
                loaded = load_history()
                self.assertNotIn("network_fingerprints", loaded[0])
                self.assertNotIn("network_fingerprint", loaded[0]["nested"])
                save_history({
                    "created_at": "new",
                    "purpose": "argo",
                    "network_fingerprints": {"IPv4": "another-private-digest"},
                    "target_host": "private-route.example",
                    "node_sni": "private-route.example",
                    "node_host": "private-host.example",
                    "ws_path": "/private-path",
                    "families": [{
                        "family": "IPv4",
                        "ranked": [{"ip": "104.17.0.1", "node_delay_ms": 88}],
                        "asia_ranked": [{"ip": "104.17.0.1", "node_delay_ms": 88}],
                    }],
                })
            persisted = path.read_text(encoding="utf-8")
            self.assertNotIn("private-digest", persisted)
            self.assertNotIn("network_fingerprint", persisted)
            self.assertNotIn("private-route.example", persisted)
            self.assertNotIn("private-host.example", persisted)
            self.assertNotIn("private-path", persisted)

    def test_unverified_or_non_argo_history_is_never_copyable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "history.json"
            path.write_text(json.dumps([
                {
                    "created_at": "legacy",
                    "families": [{"family": "IPv4", "ranked": [{"ip": "104.16.0.2"}]}],
                },
                {
                    "created_at": "direct",
                    "purpose": "direct",
                    "families": [{"family": "IPv4", "ranked": [{"ip": "104.16.0.3", "node_delay_ms": 25}]}],
                },
                {
                    "created_at": "mixed",
                    "purpose": "argo",
                    "families": [{
                        "family": "IPv4",
                        "ranked": [
                            {"ip": "104.16.0.4", "node_delay_ms": -1},
                            {"ip": "104.16.0.5", "node_delay_ms": 91},
                        ],
                        "asia_ranked": [{"ip": "104.16.0.4", "node_delay_ms": 0}],
                    }],
                },
            ]), encoding="utf-8")
            with patch("cfopt.history.history_path", return_value=path):
                loaded = load_history()
        self.assertEqual(len(loaded), 1)
        self.assertEqual([row["ip"] for row in loaded[0]["families"][0]["ranked"]], ["104.16.0.5"])
        self.assertEqual(loaded[0]["families"][0]["asia_ranked"], [])


if __name__ == "__main__":
    unittest.main()
