from __future__ import annotations

import csv
import io
import json
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from cfopt.cloudflare_dns import CloudflareDnsError, DnsSyncPlan, DnsSyncResult
from cfopt.models import MAX_BANDWIDTH, FamilyRunResult, IpMetric, OptimizerResult
from cfopt.node_template import parse_node_profile
from cfopt.webapp import RuntimeState, _apply_dns_sync, _csv_bytes, _result_champions, _traffic_upper_bound_mb, make_handler
from cfopt.xray_node import XrayRuntimeError


ROOT = Path(__file__).resolve().parents[1]
TEST_NODE_LINK = (
    "vless://12345678-abcd-abcd-abcd-123456789abc@104.18.0.1:8443"
    "?type=ws&security=tls&sni=argo.example.com&host=argo.example.com&path=%2Fvless%3Fed%3D2048"
)


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

    @staticmethod
    def _completed_result(ip: str = "104.16.0.1", family_name: str = "IPv4") -> OptimizerResult:
        metric = IpMetric(
            ip, family_name, round_floor_mbps=120.0, avg_complete_mbps=130.0,
            success_rate_pct=100.0, rounds_tested=3,
        )
        family = FamilyRunResult(family_name, [metric], [metric], candidate_count=1, compatible_count=1)
        return OptimizerResult(
            created_at="2026-01-01T00:00:00Z", mode="asia", operator="自动",
            requested_family="ipv6" if family_name == "IPv6" else "ipv4", ip_count=1,
            target_host="speed.cloudflare.com", source_kind="Cloudflare 官方 IP 池",
            families=[family], elapsed_seconds=1.0, purpose="direct", target_mbps=100,
            network_fingerprints={family_name: "test-network"},
        )

    def test_config_exposes_session_token_and_ip_limits(self) -> None:
        with urllib.request.urlopen(self.base + "/api/config", timeout=2) as response:
            body = json.load(response)
        self.assertEqual(body["version"], "0.1.0")
        self.assertEqual(body["request_token"], self.token)
        self.assertEqual(body["default_purpose"], "argo")
        self.assertEqual(body["default_node_port"], 443)
        self.assertEqual(body["target_mbps"]["default"], 100)
        self.assertGreater(body["max_custom_ips"], 0)
        self.assertEqual(set(body["modes"]), {"reference"})
        self.assertEqual(body["modes"]["reference"]["pre_concurrency"], 50)

    def test_web_traffic_bound_covers_two_samples_for_every_shortlisted_ip(self) -> None:
        expected = round(
            (
                100 * MAX_BANDWIDTH.pre_bytes
                + 2 * MAX_BANDWIDTH.micro_candidates * 64_000_000
            ) / 1_000_000.0,
            1,
        )
        self.assertEqual(_traffic_upper_bound_mb("max", "ipv4", 100), expected)
        self.assertEqual(_traffic_upper_bound_mb("max", "dual", 100), expected * 2)

    def test_dns_csv_does_not_emit_argo_node_parameters(self) -> None:
        family = FamilyRunResult(
            "IPv4", [IpMetric("104.16.0.1", "IPv4")], []
        )
        result = OptimizerResult(
            created_at="2026-01-01T00:00:00Z", mode="balanced", operator="自动",
            requested_family="ipv4", ip_count=1, target_host="speed.cloudflare.com",
            source_kind="当前 DNS", families=[family], elapsed_seconds=1.0, purpose="dns",
        )
        rows = list(csv.reader(io.StringIO(_csv_bytes(result).decode("utf-8-sig"))))
        header = rows[0]
        values = dict(zip(header, rows[1]))
        self.assertEqual(values["ip"], "104.16.0.1")
        for key in ("server", "port", "sni", "host", "ws_path"):
            self.assertEqual(values[key], "")

    def test_argo_csv_preserves_distinct_sni_and_ws_host(self) -> None:
        family = FamilyRunResult(
            "IPv4", [IpMetric("104.16.0.1", "IPv4", node_delay_ms=88.0)], []
        )
        result = OptimizerResult(
            created_at="2026-01-01T00:00:00Z", mode="reference", operator="自动",
            requested_family="ipv4", ip_count=1, target_host="tls.example.com",
            source_kind="在线维护 IP 池", families=[family], elapsed_seconds=1.0,
            purpose="argo", node_port=443, node_sni="tls.example.com",
            node_host="ws.example.com", ws_path="/argo",
        )
        rows = list(csv.reader(io.StringIO(_csv_bytes(result).decode("utf-8-sig"))))
        values = dict(zip(rows[0], rows[1]))
        self.assertEqual(values["sni"], "tls.example.com")
        self.assertEqual(values["host"], "ws.example.com")

    def test_runtime_state_rejects_missing_xray_before_starting_worker(self) -> None:
        state = RuntimeState()
        profile = parse_node_profile(TEST_NODE_LINK)
        with patch(
            "cfopt.webapp.validate_xray_runtime",
            side_effect=XrayRuntimeError("内置 Xray 核心无法启动"),
        ):
            ok, message = state.start({"_node_profile": profile})
        self.assertFalse(ok)
        self.assertIn("Xray", message)
        self.assertIsNone(state.worker)

    def test_cancelled_run_cannot_publish_winner_after_optimizer_returns(self) -> None:
        state = RuntimeState()
        completed = self._completed_result()

        def finish_after_cancel(**kwargs):
            kwargs["cancel_event"].set()
            return completed

        with patch("cfopt.webapp.run_optimizer", side_effect=finish_after_cancel):
            ok, _message = state.start({"mode": "reference", "family": "ipv4"})
            self.assertTrue(ok)
            assert state.worker is not None
            state.worker.join(timeout=2)
        snapshot = state.snapshot()
        self.assertEqual(snapshot["status"], "cancelled")
        self.assertTrue(snapshot["result"]["cancelled"])
        self.assertEqual(snapshot["result"]["families"], [])

    def test_direct_csv_emits_only_ip_as_node_server_and_target_status(self) -> None:
        family = FamilyRunResult(
            "IPv4", [IpMetric("104.16.0.1", "IPv4", round_floor_mbps=120.0)], []
        )
        result = OptimizerResult(
            created_at="2026-01-01T00:00:00Z", mode="balanced", operator="自动",
            requested_family="ipv4", ip_count=1, target_host="speed.cloudflare.com",
            source_kind="Cloudflare 官方 IP 池", families=[family], elapsed_seconds=1.0,
            purpose="direct", target_mbps=100,
        )
        rows = list(csv.reader(io.StringIO(_csv_bytes(result).decode("utf-8-sig"))))
        values = dict(zip(rows[0], rows[1]))
        self.assertEqual(values["ip"], "104.16.0.1")
        self.assertEqual(values["server"], "104.16.0.1")
        self.assertEqual(values["target_mbps"], "100")
        self.assertEqual(values["meets_target"], "yes")
        for key in ("port", "sni", "host", "ws_path"):
            self.assertEqual(values[key], "")

    def test_parse_ip_endpoint(self) -> None:
        with self._post("/api/ips/parse", {"text": "104.16.0.1\n2606:4700::1111", "filename": "ips.txt"}) as response:
            body = json.load(response)
        self.assertEqual(body["ips"], ["104.16.0.1", "2606:4700::1111"])

    def test_post_requires_session_token(self) -> None:
        with self.assertRaises(urllib.error.HTTPError) as raised:
            self._post("/api/ips/parse", {"text": "104.16.0.1"}, token="wrong")
        self.assertEqual(raised.exception.code, 403)

    def test_custom_start_passes_only_normalized_user_ips(self) -> None:
        with self._post("/api/start", {"mode": "reference", "family": "ipv4", "operator": "中国移动", "source": "custom", "ips": ["104.16.0.1", "104.16.0.1", "2606:4700::1111"], "target_mbps": 200, "confirmed": True}) as response:
            body = json.load(response)
        self.assertTrue(body["ok"])
        self.assertEqual(self.state.submitted_config["_ips"], ["104.16.0.1", "2606:4700::1111"])
        self.assertEqual(self.state.submitted_config["source"], "在线维护 IP 池 + 我的名单")
        self.assertEqual(self.state.submitted_config["purpose"], "direct")
        self.assertEqual(self.state.submitted_config["target_host"], "speed.cloudflare.com")
        self.assertEqual(self.state.submitted_config["target_mbps"], 200)
        self.assertGreater(self.state.submitted_config["traffic_upper_bound_mb"], 0)

    def test_argo_start_parses_full_node_but_keeps_credentials_private(self) -> None:
        payload = {
            "purpose": "argo", "mode": "reference", "family": "ipv4", "operator": "自动",
            "node_link": TEST_NODE_LINK,
            "source": "dns", "confirmed": True,
        }
        with self._post("/api/start", payload) as response:
            self.assertTrue(json.load(response)["ok"])
        self.assertEqual(self.state.submitted_config["target_host"], "argo.example.com")
        self.assertEqual(self.state.submitted_config["node_port"], 8443)
        self.assertEqual(self.state.submitted_config["ws_path"], "/vless?ed=2048")
        self.assertEqual(self.state.submitted_config["node_protocol"], "VLESS")
        self.assertNotIn("12345678", repr(self.state.submitted_config))

    def test_argo_start_rejects_missing_malformed_or_unsupported_node(self) -> None:
        base = {"purpose": "argo", "mode": "reference", "family": "ipv4", "source": "dns", "confirmed": True}
        for link in (
            "",
            "https://argo.example.com/path",
            "vless://bad-uuid@example.com:443?type=ws&security=tls&host=example.com",
            "vless://12345678-abcd-abcd-abcd-123456789abc@example.com:443?type=tcp&security=tls",
        ):
            with self.subTest(link=link), self.assertRaises(urllib.error.HTTPError) as raised:
                self._post("/api/start", {**base, "node_link": link})
            self.assertEqual(raised.exception.code, 400)

    def test_start_requires_explicit_traffic_confirmation(self) -> None:
        with self.assertRaises(urllib.error.HTTPError) as raised:
            self._post("/api/start", {"mode": "reference", "family": "ipv4", "target_host": "speed.cloudflare.com", "source": "dns"})
        self.assertEqual(raised.exception.code, 400)

    def test_direct_start_needs_no_domain_and_ignores_host_port_path(self) -> None:
        payload = {
            "mode": "reference", "family": "ipv4", "source": "dns", "confirmed": True,
            "target_host": "https://attacker.example/path", "node_port": 1234,
            "ws_path": "/ws%zz", "target_mbps": 100,
        }
        with self._post("/api/start", payload) as response:
            self.assertTrue(json.load(response)["ok"])
        self.assertEqual(self.state.submitted_config["purpose"], "direct")
        self.assertEqual(self.state.submitted_config["target_host"], "speed.cloudflare.com")
        self.assertEqual(self.state.submitted_config["node_port"], 443)
        self.assertEqual(self.state.submitted_config["ws_path"], "")

    def test_target_bandwidth_is_bounded(self) -> None:
        base = {"mode": "reference", "family": "ipv4", "source": "dns", "confirmed": True}
        for target in (0, 10001, True, "bad"):
            with self.subTest(target=target), self.assertRaises(urllib.error.HTTPError) as raised:
                self._post("/api/start", {**base, "target_mbps": target})
            self.assertEqual(raised.exception.code, 400)

    def test_legacy_modes_are_not_accepted_by_the_public_api(self) -> None:
        base = {"family": "ipv4", "source": "dns", "confirmed": True}
        for mode in ("balanced", "asia", "max"):
            with self.subTest(mode=mode), self.assertRaises(urllib.error.HTTPError) as raised:
                self._post("/api/start", {**base, "mode": mode})
            self.assertEqual(raised.exception.code, 400)

    def test_dns_sync_requires_current_champion_zone_and_preview(self) -> None:
        self.state.status = "completed"
        self.state.result = self._completed_result()
        base = {
            "record_name": "edge.example.com", "zone_id": "a" * 32,
            "api_token": "secret-token", "ip": "104.16.0.1", "family": "IPv4",
        }
        with patch("cfopt.webapp._network_matches_result", return_value=True):
            with self.assertRaises(urllib.error.HTTPError) as raised:
                self._post("/api/dns/apply", base)
        self.assertEqual(raised.exception.code, 400)

        with patch("cfopt.webapp._network_matches_result", return_value=True):
            with self.assertRaises(urllib.error.HTTPError) as raised:
                self._post("/api/dns/inspect", {**base, "zone_id": ""})
        self.assertEqual(raised.exception.code, 400)

        with (
            patch("cfopt.webapp._network_matches_result", return_value=True),
            patch("cfopt.webapp._inspect_dns_sync") as inspect_sync,
        ):
            with self.assertRaises(urllib.error.HTTPError) as raised:
                self._post("/api/dns/inspect", {**base, "ip": "8.8.8.8"})
            self.assertEqual(raised.exception.code, 409)
            inspect_sync.assert_not_called()

    def test_dns_inspect_rejects_network_change_and_unstable_winner(self) -> None:
        self.state.status = "completed"
        self.state.result = self._completed_result()
        base = {
            "record_name": "edge.example.com", "zone_id": "a" * 32,
            "api_token": "secret-token", "ip": "104.16.0.1", "family": "IPv4",
        }
        with (
            patch("cfopt.webapp._network_matches_result", return_value=False),
            patch("cfopt.webapp._inspect_dns_sync") as inspect_sync,
        ):
            with self.assertRaises(urllib.error.HTTPError) as raised:
                self._post("/api/dns/inspect", base)
            self.assertEqual(raised.exception.code, 409)
            inspect_sync.assert_not_called()

        self.state.result = self._completed_result()
        self.state.result.families[0].ranked[0].rounds_tested = 1
        with (
            patch("cfopt.webapp._network_matches_result", return_value=True),
            patch("cfopt.webapp._inspect_dns_sync") as inspect_sync,
        ):
            with self.assertRaises(urllib.error.HTTPError) as raised:
                self._post("/api/dns/inspect", base)
            self.assertEqual(raised.exception.code, 409)
            inspect_sync.assert_not_called()

    def test_dns_champion_combines_success_boundary_with_positive_floor(self) -> None:
        result = self._completed_result()
        metric = result.families[0].ranked[0]
        # The gates are checked independently here. In real aggregation any
        # failed Full round forces round_floor_mbps to zero (covered in core),
        # so a 2/3 outcome cannot pass this combined condition.
        metric.success_rate_pct = 66.0
        self.assertEqual(_result_champions(result), {"IPv4": "104.16.0.1"})
        metric.success_rate_pct = 65.9
        self.assertEqual(_result_champions(result), {})
        metric.success_rate_pct = 66.0
        metric.round_floor_mbps = 0
        self.assertEqual(_result_champions(result), {})
        metric.ip = "8.8.8.8"
        metric.round_floor_mbps = 100.0
        metric.rounds_tested = 2
        self.assertEqual(_result_champions(result), {"IPv4": "8.8.8.8"})
        metric.rounds_tested = 1
        self.assertEqual(_result_champions(result), {})

    def test_dns_inspect_then_apply_current_champion_without_token_leak(self) -> None:
        token = "secret-token-that-must-not-leak"
        self.state.status = "completed"
        self.state.result = self._completed_result()
        plan = DnsSyncPlan(
            zone_id="a" * 32, zone_name="", record_name="edge.example.com",
            record_type="A", champion_ip="104.16.0.1", action="update",
            fingerprint="c" * 64, record_id="b" * 32,
            previous_content="104.16.0.2", previous_ttl=300, previous_proxied=True,
        )
        changed = DnsSyncResult(
            action="updated", zone_id="a" * 32, zone_name="", record_id="b" * 32,
            record_name="edge.example.com", record_type="A", content="104.16.0.1",
        )
        with (
            patch("cfopt.webapp._network_matches_result", return_value=True),
            patch("cfopt.webapp._inspect_dns_sync", return_value=plan) as inspect_sync,
            patch("cfopt.webapp._apply_dns_plan", return_value=changed) as apply_plan,
        ):
            with self._post("/api/dns/inspect", {
                "record_name": "edge.example.com", "zone_id": "a" * 32,
                "api_token": token, "ip": "104.16.0.1", "family": "IPv4",
            }) as response:
                preview = json.load(response)
            apply_plan.assert_not_called()
            with self._post("/api/dns/apply", {
                "record_name": "edge.example.com", "zone_id": "a" * 32,
                "api_token": token, "ip": "104.16.0.1", "family": "IPv4",
                "fingerprint": plan.fingerprint, "dns_write_confirmed": True,
            }) as response:
                body = json.load(response)
        self.assertTrue(preview["ok"])
        self.assertEqual(preview["plan"]["previous_content"], "104.16.0.2")
        self.assertTrue(body["ok"])
        self.assertEqual(body["result"]["proxied"], False)
        inspected_config, inspected_ip = inspect_sync.call_args.args
        self.assertEqual(inspected_ip, "104.16.0.1")
        self.assertEqual(inspected_config["api_token"], token)
        submitted_config, submitted_ip, submitted_fingerprint = apply_plan.call_args.args
        self.assertEqual(submitted_ip, "104.16.0.1")
        self.assertEqual(submitted_fingerprint, plan.fingerprint)
        self.assertEqual(submitted_config["api_token"], token)
        public = json.dumps(self.state.snapshot(), ensure_ascii=False)
        self.assertNotIn(token, public)
        self.assertNotIn(token, json.dumps(preview, ensure_ascii=False))
        self.assertNotIn(token, json.dumps(body, ensure_ascii=False))

    def test_dns_apply_rejects_missing_or_stale_fingerprint(self) -> None:
        self.state.status = "completed"
        self.state.result = self._completed_result()
        base = {
            "record_name": "edge.example.com", "zone_id": "a" * 32,
            "api_token": "secret-token", "ip": "104.16.0.1", "family": "IPv4",
            "dns_write_confirmed": True,
        }
        with (
            patch("cfopt.webapp._network_matches_result", return_value=True),
            patch("cfopt.webapp._apply_dns_plan") as apply_plan,
        ):
            with self.assertRaises(urllib.error.HTTPError) as raised:
                self._post("/api/dns/apply", {**base, "fingerprint": "c" * 64})
            self.assertEqual(raised.exception.code, 409)
            apply_plan.assert_not_called()

    def test_dns_apply_rejects_result_change_after_preview(self) -> None:
        self.state.status = "completed"
        self.state.result = self._completed_result()
        plan = DnsSyncPlan(
            zone_id="a" * 32, zone_name="", record_name="edge.example.com",
            record_type="A", champion_ip="104.16.0.1", action="create",
            fingerprint="d" * 64,
        )
        base = {
            "record_name": "edge.example.com", "zone_id": "a" * 32,
            "api_token": "secret-token", "ip": "104.16.0.1", "family": "IPv4",
        }
        with (
            patch("cfopt.webapp._network_matches_result", return_value=True),
            patch("cfopt.webapp._inspect_dns_sync", return_value=plan),
        ):
            with self._post("/api/dns/inspect", base) as response:
                self.assertTrue(json.load(response)["ok"])
        self.state.result = self._completed_result("104.16.0.2")
        self.state.result.created_at = "2026-01-01T00:01:00Z"
        with (
            patch("cfopt.webapp._network_matches_result", return_value=True),
            patch("cfopt.webapp._apply_dns_plan") as apply_plan,
        ):
            with self.assertRaises(urllib.error.HTTPError) as raised:
                self._post("/api/dns/apply", {**base, "fingerprint": plan.fingerprint, "dns_write_confirmed": True})
            self.assertEqual(raised.exception.code, 409)
            apply_plan.assert_not_called()

    def test_automation_dns_config_is_confirmed_and_kept_out_of_public_config(self) -> None:
        token = "secret-token-that-must-not-leak"
        body = {
            "mode": "reference", "family": "ipv4", "operator": "自动", "source": "dns",
            "confirmed": True, "interval_minutes": 30, "dns_write_confirmed": True,
            "dns_sync": {
                "enabled": True, "record_name": "edge.example.com",
                "zone_id": "a" * 32, "api_token": token,
            },
        }
        with self._post("/api/automation/start", body) as response:
            self.assertTrue(json.load(response)["ok"])
        self.assertEqual(self.state.automation_config["_dns_sync"]["api_token"], token)
        public = self.state._public_config(self.state.automation_config)
        self.assertNotIn("_dns_sync", public)
        self.assertNotIn(token, json.dumps(public))

    def test_auth_failure_pauses_only_dns_automation(self) -> None:
        result = self._completed_result()
        secret = "secret-token-that-must-not-leak"
        dns_config = {
            "api_token": secret, "zone_id": "a" * 32, "record_name": "edge.example.com",
        }
        state = RuntimeState(
            automation_enabled=True,
            automation_generation=7,
            status="completed",
            result=result,
            automation_config={"_dns_sync": dns_config},
        )
        error = CloudflareDnsError(
            "Cloudflare API 鉴权失败；已请求暂停 DNS 自动写入",
            code="auth_failed", http_status=403, pause_dns_automation=True,
        )
        with (
            patch("cfopt.webapp._network_matches_result", return_value=True),
            patch("cfopt.webapp._apply_dns_sync", side_effect=error) as apply_sync,
        ):
            state._sync_automatic_champions(result, dns_config, generation=7)
            state._sync_automatic_champions(result, dns_config, generation=7)
        self.assertTrue(state.automation_enabled)
        self.assertTrue(state.dns_automation_paused)
        self.assertEqual(apply_sync.call_count, 1)
        self.assertNotIn(secret, "\n".join(state.logs))

    def test_stale_automation_generation_cannot_write_dns(self) -> None:
        result = self._completed_result()
        dns_config = {
            "api_token": "secret", "zone_id": "a" * 32, "record_name": "edge.example.com",
        }
        state = RuntimeState(
            automation_enabled=True,
            automation_generation=9,
            status="completed",
            result=result,
            automation_config={"_dns_sync": dns_config},
        )
        with patch("cfopt.webapp._apply_dns_sync") as apply_sync:
            state._sync_automatic_champions(result, dns_config, generation=8)
        apply_sync.assert_not_called()
        self.assertFalse(state.dns_write_in_progress)

    def test_family_specific_dns_conflict_does_not_skip_other_family(self) -> None:
        result = self._completed_result()
        dns_config = {
            "api_token": "secret", "zone_id": "a" * 32, "record_name": "edge.example.com",
        }
        state = RuntimeState(
            automation_enabled=True,
            automation_generation=3,
            status="completed",
            result=result,
            automation_config={"_dns_sync": dns_config},
        )
        ipv6_result = DnsSyncResult(
            action="updated", zone_id="a" * 32, zone_name="", record_id="b" * 32,
            record_name="edge.example.com", record_type="AAAA", content="2606:4700::1111",
        )
        family_error = CloudflareDnsError(
            "定时同步不会创建缺失记录", code="automatic_create_forbidden",
        )
        with (
            patch("cfopt.webapp._result_champions", return_value={
                "IPv4": "104.16.0.1", "IPv6": "2606:4700::1111",
            }),
            patch("cfopt.webapp._network_matches_result", return_value=True),
            patch("cfopt.webapp._apply_dns_sync", side_effect=[family_error, ipv6_result]) as apply_sync,
        ):
            state._sync_automatic_champions(result, dns_config, generation=3)
        self.assertEqual(apply_sync.call_count, 2)
        self.assertIn("AAAA edge.example.com", "\n".join(state.logs))

    def test_stop_during_ipv4_write_blocks_old_generation_before_ipv6(self) -> None:
        result = self._completed_result()
        dns_config = {
            "api_token": "secret", "zone_id": "a" * 32, "record_name": "edge.example.com",
        }
        state = RuntimeState(
            automation_enabled=True,
            automation_generation=4,
            status="completed",
            result=result,
            automation_config={"_dns_sync": dns_config},
        )
        old_stop_event = state.automation_stop_event
        ipv4_started = threading.Event()
        allow_ipv4_return = threading.Event()
        stop_finished = threading.Event()
        writes: list[str] = []

        def apply_sync(_config, ip):
            writes.append(ip)
            if ip == "104.16.0.1":
                ipv4_started.set()
                self.assertTrue(allow_ipv4_return.wait(timeout=2))
            return DnsSyncResult(
                action="updated", zone_id="a" * 32, zone_name="", record_id="b" * 32,
                record_name="edge.example.com",
                record_type="AAAA" if ":" in ip else "A", content=ip,
            )

        sync_thread = threading.Thread(
            target=state._sync_automatic_champions,
            args=(result, dns_config),
            kwargs={"generation": 4},
        )

        def stop_automation() -> None:
            self.assertTrue(state.stop_automation())
            stop_finished.set()

        with (
            patch("cfopt.webapp._result_champions", return_value={
                "IPv4": "104.16.0.1", "IPv6": "2606:4700::1111",
            }),
            patch("cfopt.webapp._network_matches_result", return_value=True),
            patch("cfopt.webapp._apply_dns_sync", side_effect=apply_sync),
        ):
            sync_thread.start()
            self.assertTrue(ipv4_started.wait(timeout=2))
            stop_thread = threading.Thread(target=stop_automation)
            stop_thread.start()
            self.assertTrue(old_stop_event.wait(timeout=2))
            self.assertFalse(stop_finished.is_set())
            allow_ipv4_return.set()
            sync_thread.join(timeout=2)
            stop_thread.join(timeout=2)

        self.assertFalse(sync_thread.is_alive())
        self.assertFalse(stop_thread.is_alive())
        self.assertTrue(stop_finished.is_set())
        self.assertEqual(writes, ["104.16.0.1"])

    def test_automatic_dns_never_creates_missing_record(self) -> None:
        config = {"api_token": "secret", "zone_id": "a" * 32, "record_name": "edge.example.com"}
        plan = DnsSyncPlan(
            zone_id="a" * 32, zone_name="", record_name="edge.example.com",
            record_type="A", champion_ip="104.16.0.1", action="create",
            fingerprint="e" * 64,
        )
        with (
            patch("cfopt.webapp._inspect_dns_sync", return_value=plan),
            patch("cfopt.webapp._apply_dns_plan") as apply_plan,
        ):
            with self.assertRaises(CloudflareDnsError) as raised:
                _apply_dns_sync(config, "104.16.0.1")
        self.assertEqual(raised.exception.code, "automatic_create_forbidden")
        apply_plan.assert_not_called()

    def test_automation_start_receives_bounded_interval(self) -> None:
        body = {
            "mode": "reference", "family": "dual", "operator": "自动", "target_host": "speed.cloudflare.com",
            "source": "dns", "confirmed": True, "interval_minutes": 30,
        }
        with self._post("/api/automation/start", body) as response:
            result = json.load(response)
        self.assertTrue(result["ok"])
        self.assertEqual(self.state.automation_interval, 30)
        self.assertTrue(self.state.automation_config["automation_enabled"])
        self.assertGreater(self.state.automation_config["traffic_upper_bound_mb"], 0)

    def test_network_fingerprint_is_runtime_only(self) -> None:
        self.state.status = "completed"
        self.state.result = self._completed_result()
        self.assertNotIn("network_fingerprints", self.state.result.to_dict())
        with urllib.request.urlopen(self.base + "/api/status", timeout=2) as response:
            status = json.load(response)
        with urllib.request.urlopen(self.base + "/api/export?format=json", timeout=2) as response:
            exported = json.load(response)
        self.assertNotIn("network_fingerprints", status["result"])
        self.assertNotIn("network_fingerprints", exported)
        self.assertNotIn("test-network", json.dumps(status))
        self.assertNotIn("test-network", json.dumps(exported))

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
        ok, _message = state.start_automation({"mode": "reference", "family": "ipv4"}, 5)
        self.assertTrue(ok)
        self.assertTrue(state.started.wait(timeout=1))
        stopped, _message = state.stop()
        self.assertTrue(stopped)
        if state.automation_worker:
            state.automation_worker.join(timeout=1)
        self.assertEqual(len(state.calls), 1)
        self.assertFalse(state.snapshot()["automation"]["enabled"])

    def test_stale_scheduler_generation_cannot_start_download(self) -> None:
        state = RuntimeState(
            automation_enabled=True,
            automation_generation=5,
            automation_config={"mode": "reference", "family": "ipv4"},
        )
        ok, message = state.start({
            "mode": "reference", "family": "ipv4", "_automation_generation": 4,
        }, scheduled=True)
        self.assertFalse(ok)
        self.assertIn("已停止", message)
        self.assertEqual(state.status, "idle")
        self.assertIsNone(state.worker)

    def test_ui_contract_requires_full_node_and_keeps_copy_ip_simple(self) -> None:
        html = (ROOT / "web" / "index.html").read_text(encoding="utf-8")
        script = (ROOT / "web" / "app.js").read_text(encoding="utf-8")
        self.assertIn('name="family" value="ipv4" checked', html)
        self.assertIn('name="mode" value="reference" checked', html)
        self.assertIn('name="useTls" value="true" checked', html)
        self.assertIn('id="nodeLink"', html)
        self.assertIn('V2rayNG 节点（必填）', html)
        self.assertIn('purpose: "argo"', script)
        self.assertIn('node_link: rawNodeLink', script)
        self.assertNotIn('argoValidationEnabled', script)
        self.assertIn("data-winner-ip", script)
        self.assertIn("解析到我的域名（DNS-only）", script)
        self.assertIn("revealDnsSettings(target)", script)
        self.assertIn('max: "最大带宽"', script)
        self.assertNotIn('entry.mode === "asia" ? "亚洲狩猎" : "均衡模式"', script)
        self.assertNotIn("复制 Argo 参数", script)
        self.assertNotIn("rr-edge-hunter-cf-api-token", script)


if __name__ == "__main__":
    unittest.main()
