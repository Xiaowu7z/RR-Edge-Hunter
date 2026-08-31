from __future__ import annotations

import json
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

from cfopt.webapp import RuntimeState, make_handler


class CapturingState(RuntimeState):
    submitted_config: dict[str, object] | None = None
    automation_config: dict[str, object] | None = None
    automation_interval: int | None = None

    def start(self, config):
        self.submitted_config = config
        return True, "优选已开始"

    def start_automation(self, config, interval_minutes):
        self.automation_config = config
        self.automation_interval = interval_minutes
        return True, "定时自动优选已开启"


class WebApiTest(unittest.TestCase):
    def setUp(self) -> None:
        self.token = "local-test-token"
        self.state = CapturingState()
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(self.state, self.token, {"127.0.0.1"}))
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def _post(self, path: str, body: dict[str, object], token: str | None = None):
        request = urllib.request.Request(self.base + path, data=json.dumps(body).encode("utf-8"), method="POST", headers={"Content-Type": "application/json", "X-RR-Request-Token": token or self.token})
        return urllib.request.urlopen(request, timeout=2)

    def test_config_exposes_session_token_and_ip_limits(self) -> None:
        with urllib.request.urlopen(self.base + "/api/config", timeout=2) as response:
            body = json.load(response)
        self.assertEqual(body["version"], "0.1.0")
        self.assertEqual(body["request_token"], self.token)
        self.assertGreater(body["max_custom_ips"], 0)

    def test_parse_ip_endpoint(self) -> None:
        with self._post("/api/ips/parse", {"text": "104.16.0.1\n2606:4700::1111", "filename": "ips.txt"}) as response:
            body = json.load(response)
        self.assertEqual(body["ips"], ["104.16.0.1", "2606:4700::1111"])

    def test_post_requires_session_token(self) -> None:
        with self.assertRaises(urllib.error.HTTPError) as raised:
            self._post("/api/ips/parse", {"text": "104.16.0.1"}, token="wrong")
        self.assertEqual(raised.exception.code, 403)

    def test_custom_start_passes_only_normalized_user_ips(self) -> None:
        with self._post("/api/start", {"mode": "balanced", "family": "ipv4", "operator": "中国移动", "target_host": "speed.cloudflare.com", "source": "custom", "ips": ["104.16.0.1", "104.16.0.1", "2606:4700::1111"], "confirmed": True}) as response:
            body = json.load(response)
        self.assertTrue(body["ok"])
        self.assertEqual(self.state.submitted_config["_ips"], ["104.16.0.1", "2606:4700::1111"])
        self.assertEqual(self.state.submitted_config["source"], "我的 IP 名单")
        self.assertGreater(self.state.submitted_config["traffic_upper_bound_mb"], 0)

    def test_start_requires_explicit_traffic_confirmation(self) -> None:
        with self.assertRaises(urllib.error.HTTPError) as raised:
            self._post("/api/start", {"mode": "balanced", "family": "ipv4", "target_host": "speed.cloudflare.com", "source": "dns"})
        self.assertEqual(raised.exception.code, 400)

    def test_automation_start_receives_bounded_interval(self) -> None:
        body = {
            "mode": "asia", "family": "dual", "operator": "自动", "target_host": "speed.cloudflare.com",
            "source": "dns", "confirmed": True, "interval_minutes": 30,
        }
        with self._post("/api/automation/start", body) as response:
            result = json.load(response)
        self.assertTrue(result["ok"])
        self.assertEqual(self.state.automation_interval, 30)
        self.assertTrue(self.state.automation_config["automation_enabled"])
        self.assertGreater(self.state.automation_config["traffic_upper_bound_mb"], 0)

    def test_runtime_scheduler_runs_once_then_stop_cancels_future_runs(self) -> None:
        class SchedulerState(RuntimeState):
            def __init__(self) -> None:
                super().__init__()
                self.started = threading.Event()
                self.calls: list[tuple[dict[str, object], bool]] = []

            def start(self, config, *, scheduled=False):
                self.calls.append((config, scheduled))
                self.started.set()
                return True, "定时优选已开始"

        state = SchedulerState()
        ok, _message = state.start_automation({"mode": "balanced", "family": "ipv4"}, 5)
        self.assertTrue(ok)
        self.assertTrue(state.started.wait(timeout=1))
        stopped, _message = state.stop()
        self.assertTrue(stopped)
        if state.automation_worker:
            state.automation_worker.join(timeout=1)
        self.assertEqual(len(state.calls), 1)
        self.assertFalse(state.snapshot()["automation"]["enabled"])


if __name__ == "__main__":
    unittest.main()
