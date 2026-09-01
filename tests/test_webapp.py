from __future__ import annotations

import json
import threading
import time
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from cfopt.cloudflare_dns import DnsSyncPlan, DnsSyncResult
from cfopt.reference_process import ReferenceResult
from cfopt.webapp import RuntimeState, make_handler


ROOT = Path(__file__).resolve().parents[1]


class CapturingState(RuntimeState):
    submitted: tuple[str, bool, int] | None = None
    automatic: tuple[str, bool, int, int, dict[str, str] | None] | None = None

    def start_scan(self, *, family: str, use_tls: bool, bandwidth: int):
        self.submitted = (family, use_tls, bandwidth)
        return True, "任务已开始"

    def start_automation(
        self,
        *,
        family: str,
        use_tls: bool,
        bandwidth: int,
        interval_hours: int,
        dns_sync: dict[str, str] | None,
    ):
        self.automatic = (family, use_tls, bandwidth, interval_hours, dns_sync)
        return True, "自动任务已开始"


class WebApiTest(unittest.TestCase):
    def setUp(self) -> None:
        self.token = "local-request-token"
        self.state = CapturingState()
        self.server = ThreadingHTTPServer(
            ("127.0.0.1", 0),
            make_handler(self.state, self.token, {"127.0.0.1", "localhost", "::1"}),
        )
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def _post(self, path: str, body: dict[str, object], token: str | None = None):
        request = urllib.request.Request(
            self.base + path,
            data=json.dumps(body).encode("utf-8"),
            method="POST",
            headers={
                "Content-Type": "application/json",
                "X-RR-Request-Token": token or self.token,
            },
        )
        return urllib.request.urlopen(request, timeout=2)

    def test_config_exposes_only_reference_app_choices(self) -> None:
        with urllib.request.urlopen(self.base + "/api/config", timeout=2) as response:
            value = json.load(response)
        self.assertEqual(value["request_token"], self.token)
        self.assertEqual(value["defaults"], {
            "family": "ipv4",
            "use_tls": False,
            "bandwidth": 1,
        })
        self.assertEqual(value["automation"]["interval_hours"], [1, 2, 4, 6, 12, 24])
        encoded = json.dumps(value).lower()
        for removed in ("node_link", "xray", "operator", "custom_ips"):
            self.assertNotIn(removed, encoded)

    def test_start_accepts_only_three_reference_parameters(self) -> None:
        with self._post("/api/start", {
            "family": "ipv6",
            "use_tls": False,
            "bandwidth": 20,
        }) as response:
            self.assertTrue(json.load(response)["ok"])
        self.assertEqual(self.state.submitted, ("ipv6", False, 20))

        with self.assertRaises(urllib.error.HTTPError) as raised:
            self._post("/api/start", {
                "family": "ipv4",
                "use_tls": True,
                "bandwidth": 1,
                "node_link": "vless://must-not-be-accepted",
            })
        self.assertEqual(raised.exception.code, 400)

    def test_post_requires_local_session_token(self) -> None:
        with self.assertRaises(urllib.error.HTTPError) as raised:
            self._post("/api/update", {}, token="wrong")
        self.assertEqual(raised.exception.code, 403)

    def test_automation_accepts_hour_choice_and_at_most_one_dns_target(self) -> None:
        dns = {
            "zone_id": "a" * 32,
            "record_name": "edge.example.com",
            "api_token": "secret-token",
        }
        with self._post("/api/automation/start", {
            "family": "ipv4",
            "use_tls": True,
            "bandwidth": 20,
            "interval_hours": 6,
            "dns_sync": dns,
            "dns_write_confirmed": True,
        }) as response:
            self.assertTrue(json.load(response)["ok"])
        assert self.state.automatic is not None
        self.assertEqual(self.state.automatic[:4], ("ipv4", True, 20, 6))
        self.assertEqual(self.state.automatic[4], dns)

    def test_automation_rejects_minutes_multiple_records_and_unconfirmed_dns(self) -> None:
        base = {
            "family": "ipv4",
            "use_tls": False,
            "bandwidth": 1,
            "interval_hours": 3,
            "dns_sync": None,
            "dns_write_confirmed": False,
        }
        with self.assertRaises(urllib.error.HTTPError) as raised:
            self._post("/api/automation/start", base)
        self.assertEqual(raised.exception.code, 400)

        invalid_dns = dict(base)
        invalid_dns["interval_hours"] = 1
        invalid_dns["dns_write_confirmed"] = True
        invalid_dns["dns_sync"] = {
            "zone_id": "a" * 32,
            "record_name": "edge.example.com",
            "api_token": "secret-token",
            "second_record": "must-not-be-accepted",
        }
        with self.assertRaises(urllib.error.HTTPError) as raised:
            self._post("/api/automation/start", invalid_dns)
        self.assertEqual(raised.exception.code, 400)

    def test_page_has_no_removed_controls(self) -> None:
        page = (ROOT / "web" / "index.html").read_text(encoding="utf-8").lower()
        for removed in ("node-link", "xray", "custom-ip", "operator"):
            self.assertNotIn(removed, page)
        for internal_menu in ("单 ip 测速", "清空缓存", "请选择菜单", "better-cloudflare-ip"):
            self.assertNotIn(internal_menu, page)
        self.assertIn("cloudflare dns", page)
        self.assertIn('value="24"', page)
        self.assertIn("每轮完成后自动解析 1 个 ip", page)
        self.assertIn("更新 ip 池", page)
        self.assertIn("signal-card", page)
        self.assertIn("workspace-grid", page)
        self.assertIn("measurement console", page)


class RuntimeStateTest(unittest.TestCase):
    def test_scan_publishes_exact_reference_result(self) -> None:
        state = RuntimeState()
        expected = ReferenceResult(
            ip="104.16.0.8",
            bandwidth=20,
            real_bandwidth=25,
            max_speed=3200,
            latency_ms=18,
            data_center="Hong Kong",
            elapsed=9,
        )
        with patch("cfopt.webapp.run_reference_scan", return_value=expected) as runner:
            ok, _message = state.start_scan(family="ipv4", use_tls=True, bandwidth=20)
            self.assertTrue(ok)
            assert state.worker is not None
            state.worker.join(timeout=2)
        snapshot = state.snapshot()
        self.assertEqual(snapshot["status"], "completed")
        self.assertEqual(snapshot["result"], expected.to_dict())
        self.assertEqual(runner.call_args.kwargs["task_count"], 50)
        self.assertNotIn("node", repr(runner.call_args).lower())

    def test_scheduler_runs_immediately_then_waits_for_selected_hours(self) -> None:
        state = RuntimeState()
        expected = ReferenceResult("104.16.0.8", 1, 2, 256, 20, "HKG", 3)
        with patch("cfopt.webapp.run_reference_scan", return_value=expected) as runner:
            ok, _message = state.start_automation(
                family="ipv4",
                use_tls=False,
                bandwidth=1,
                interval_hours=1,
                dns_sync=None,
            )
            self.assertTrue(ok)
            deadline = time.monotonic() + 2
            snapshot = state.snapshot()
            while snapshot["status"] != "completed" and time.monotonic() < deadline:
                time.sleep(0.01)
                snapshot = state.snapshot()
            self.assertEqual(snapshot["result"], expected.to_dict())
            self.assertEqual(snapshot["automation"]["runs_started"], 1)
            self.assertEqual(snapshot["automation"]["interval_hours"], 1)
            deadline = time.monotonic() + 1
            while snapshot["automation"]["next_run_at"] is None and time.monotonic() < deadline:
                time.sleep(0.01)
                snapshot = state.snapshot()
            self.assertIsNotNone(snapshot["automation"]["next_run_at"])
            stopped, _message = state.stop()
            self.assertTrue(stopped)
        if state.automation_worker is not None:
            state.automation_worker.join(timeout=1)
        self.assertEqual(runner.call_count, 1)
        self.assertFalse(state.snapshot()["automation"]["enabled"])

    def test_automatic_dns_writes_only_the_single_reference_result(self) -> None:
        expected = ReferenceResult("104.16.0.8", 1, 2, 256, 20, "HKG", 3)
        dns = {
            "api_token": "secret-token",
            "zone_id": "a" * 32,
            "record_name": "edge.example.com",
        }
        state = RuntimeState(
            status="completed",
            result=expected,
            automation_enabled=True,
            automation_generation=7,
            automation_config={"dns_sync": dns},
        )
        plan = DnsSyncPlan(
            zone_id="a" * 32,
            zone_name="example.com",
            record_name="edge.example.com",
            record_type="A",
            champion_ip=expected.ip,
            action="update",
            fingerprint="b" * 64,
            record_id="c" * 32,
            previous_content="104.16.0.7",
        )
        result = DnsSyncResult(
            action="updated",
            zone_id="a" * 32,
            zone_name="example.com",
            record_id="c" * 32,
            record_name="edge.example.com",
            record_type="A",
            content=expected.ip,
        )
        with patch("cfopt.webapp.CloudflareDnsClient") as client_type:
            client_type.return_value.inspect_sync.return_value = plan
            client_type.return_value.apply_sync.return_value = result
            state._sync_automatic_result(expected, 7)
        self.assertEqual(
            client_type.return_value.inspect_sync.call_args.kwargs["champion_ip"],
            expected.ip,
        )
        self.assertEqual(
            client_type.return_value.apply_sync.call_args.kwargs["champion_ip"],
            expected.ip,
        )
        self.assertTrue(client_type.return_value.apply_sync.call_args.kwargs["confirm_create"])
        self.assertNotIn("secret-token", repr(state.snapshot()))

    def test_dns_uses_only_current_reference_result_and_hides_token(self) -> None:
        state = RuntimeState(
            status="completed",
            result=ReferenceResult("104.16.0.8", 1, 2, 256, 20, "HKG", 3),
        )
        plan = DnsSyncPlan(
            zone_id="a" * 32,
            zone_name="example.com",
            record_name="edge.example.com",
            record_type="A",
            champion_ip="104.16.0.8",
            action="create",
            fingerprint="b" * 64,
        )
        result = DnsSyncResult(
            action="created",
            zone_id="a" * 32,
            zone_name="example.com",
            record_id="c" * 32,
            record_name="edge.example.com",
            record_type="A",
            content="104.16.0.8",
        )
        with patch("cfopt.webapp.CloudflareDnsClient") as client_type:
            client_type.return_value.inspect_sync.return_value = plan
            client_type.return_value.apply_sync.return_value = result
            public_plan = state.inspect_dns(
                api_token="secret-token",
                zone_id="a" * 32,
                record_name="edge.example.com",
            )
            self.assertNotIn("secret-token", repr(state.snapshot()))
            synced = state.apply_dns(str(public_plan["plan_id"]))
        self.assertEqual(synced, result.to_dict())
        self.assertEqual(
            client_type.return_value.inspect_sync.call_args.kwargs["champion_ip"],
            "104.16.0.8",
        )


if __name__ == "__main__":
    unittest.main()
