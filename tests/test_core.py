from __future__ import annotations

import threading
import unittest
from unittest.mock import patch

from cfopt.models import ASIA_HUNT, BALANCED, MAX_BANDWIDTH, ProbeResult
from cfopt.pipeline import MAX_CANDIDATES_PER_FAMILY, _run_fast_speed_stage, build_snapshot, full_schedule, normalize_ws_path, run_optimizer
from cfopt.ranges import family_of, is_cloudflare_ip, sample_official_cloudflare_ips


def _probe(ip: str, bytes_target: int, *_args) -> ProbeResult:
    failed = ip.endswith(".1") and bytes_target > BALANCED.pre_bytes
    return ProbeResult(
        ok=not failed,
        target_ip=ip,
        actual_remote_address=ip,
        complete_mbps=0.0 if failed else (30.0 if ip.endswith(".2") else 20.0),
        payload_mbps=0.0 if failed else 35.0,
        ttfb_ms=15.0,
        colo="HKG" if ip.endswith(".1") else "NRT",
        loc="HK" if ip.endswith(".1") else "JP",
    )


class CoreRulesTest(unittest.TestCase):
    def test_cloudflare_ranges_and_family(self) -> None:
        self.assertTrue(is_cloudflare_ip("104.16.0.1"))
        self.assertTrue(is_cloudflare_ip("2606:4700::1111"))
        self.assertFalse(is_cloudflare_ip("1.1.1.1"))
        self.assertEqual(family_of("104.16.0.1"), "IPv4")
        self.assertEqual(family_of("2606:4700::1111"), "IPv6")

    def test_full_schedule_repeats_every_finalist(self) -> None:
        self.assertEqual(full_schedule(["104.16.0.1", "104.16.0.2"], 3), ["104.16.0.1"] * 3 + ["104.16.0.2"] * 3)

    def test_imported_ip_must_intersect_current_dns_assignment(self) -> None:
        with patch("cfopt.pipeline.network_fingerprint", return_value=("", "")):
            with self.assertRaisesRegex(ValueError, "没有交集"):
                run_optimizer(
                    purpose="dns",
                    ips=["104.16.0.2"],
                    resolved_ips=["104.16.0.1"],
                    family="ipv4",
                    probe_fn=_probe,
                    trace_fn=lambda *_: ("HKG", "HK"),
                )

    def test_failed_full_round_forces_ip_floor_zero(self) -> None:
        with patch("cfopt.pipeline.network_fingerprint", return_value=("", "")):
            result = run_optimizer(
                purpose="dns",
                ips=["104.16.0.1", "104.16.0.2"],
                resolved_ips=["104.16.0.1", "104.16.0.2"],
                family="ipv4",
                probe_fn=_probe,
                trace_fn=lambda *_: ("HKG", "HK"),
            )
        rows = result.families[0].ranked
        self.assertEqual(rows[0].ip, "104.16.0.2")
        self.assertEqual(next(row for row in rows if row.ip == "104.16.0.1").round_floor_mbps, 0.0)

    def test_asia_ranking_does_not_put_slow_hkg_before_fast_nrt(self) -> None:
        def stable(ip: str, _bytes: int, *_args) -> ProbeResult:
            return ProbeResult(ok=True, target_ip=ip, actual_remote_address=ip, complete_mbps=100.0 if ip.endswith(".2") else 10.0, payload_mbps=10.0, ttfb_ms=10.0)

        with patch("cfopt.pipeline.network_fingerprint", return_value=("", "")):
            result = run_optimizer(
                purpose="dns",
                mode="asia",
                ips=["104.16.0.1", "104.16.0.2"],
                resolved_ips=["104.16.0.1", "104.16.0.2"],
                family="ipv4",
                probe_fn=stable,
                trace_fn=lambda ip, *_: ("HKG", "HK") if ip.endswith(".1") else ("NRT", "JP"),
            )
        self.assertEqual(result.families[0].asia_ranked[0].ip, "104.16.0.2")

    def test_direct_mode_uses_fixed_cloudflare_host_without_argo_gate(self) -> None:
        resolved_hosts: list[str] = []

        def resolver(hostname: str) -> list[str]:
            resolved_hosts.append(hostname)
            return ["104.16.0.1"]

        def forbidden_compatibility(*_args, **_kwargs) -> ProbeResult:
            raise AssertionError("direct 模式不得调用 Argo 兼容门禁")

        with (
            patch("cfopt.pipeline.network_fingerprint", return_value=("", "")),
            patch("cfopt.pipeline.sample_official_cloudflare_ips", return_value=[]),
        ):
            result = run_optimizer(
                purpose="direct", target_host="", target_mbps=200,
                family="ipv4", resolver=resolver, probe_fn=_probe,
                trace_fn=lambda *_: ("HKG", "HK"), compatibility_fn=forbidden_compatibility,
            )
        self.assertEqual(resolved_hosts, ["speed.cloudflare.com"])
        self.assertEqual(result.target_host, "speed.cloudflare.com")
        self.assertEqual(result.measurement_host, "speed.cloudflare.com")
        self.assertEqual(result.measurement_port, 443)
        self.assertEqual(result.target_mbps, 200)
        self.assertEqual(result.families[0].ranked[0].ip, "104.16.0.1")

    def test_direct_pool_unions_dns_official_and_imported_cf_without_intersection(self) -> None:
        def samples(family: str) -> list[str]:
            return ["104.16.0.2"] if family == "IPv4" else []

        with (
            patch("cfopt.pipeline.network_fingerprint", return_value=("", "")),
            patch("cfopt.pipeline.sample_official_cloudflare_ips", side_effect=samples),
        ):
            result = run_optimizer(
                purpose="direct", ips=["104.16.0.3", "8.8.8.8"],
                resolved_ips=["104.16.0.1"], family="ipv4", probe_fn=_probe,
                trace_fn=lambda *_: ("HKG", "HK"),
            )
        rows = result.families[0].ranked
        self.assertEqual({row.ip for row in rows}, {"104.16.0.1", "104.16.0.2", "104.16.0.3"})
        self.assertEqual(result.rejected_ip_count, 1)
        self.assertIn("Cloudflare 官方 IP 池", result.source_kind)

    def test_direct_download_always_uses_speed_host_and_443(self) -> None:
        calls: list[tuple[str, int]] = []

        def download(ip: str, _bytes: int, *_args, hostname: str, port: int, **_kwargs) -> ProbeResult:
            calls.append((hostname, port))
            return ProbeResult(
                ok=True, target_ip=ip, actual_remote_address=ip,
                target_matches_remote=True, cert_verified=True,
                complete_mbps=120.0, payload_mbps=130.0, ttfb_ms=8.0,
            )

        with (
            patch("cfopt.pipeline.network_fingerprint", return_value=("", "")),
            patch("cfopt.pipeline.sample_official_cloudflare_ips", return_value=[]),
            patch("cfopt.pipeline.probe_download", side_effect=download),
            patch("cfopt.pipeline.probe_speed_window", side_effect=download),
        ):
            result = run_optimizer(
                purpose="direct", target_host="attacker.example", node_port=8443,
                resolved_ips=["104.16.0.1"], family="ipv4",
                trace_fn=lambda *_args, **_kwargs: ("HKG", "HK"),
            )
        self.assertTrue(calls)
        self.assertEqual(set(calls), {("speed.cloudflare.com", 443)})
        self.assertEqual(result.node_port, 443)

    def test_official_pool_sample_is_stable_bounded_and_spread(self) -> None:
        first = sample_official_cloudflare_ips("IPv4", 80)
        self.assertEqual(first, sample_official_cloudflare_ips("IPv4", 80))
        self.assertEqual(len(first), 80)
        self.assertEqual(len(set(first)), 80)
        self.assertTrue(all(is_cloudflare_ip(ip) and family_of(ip) == "IPv4" for ip in first))
        self.assertGreater(len({".".join(ip.split(".")[:2]) for ip in first}), 5)

    def test_argo_mode_unions_import_with_official_pool_without_dns_intersection(self) -> None:
        def compatible(ip: str, *_args) -> ProbeResult:
            allowed = ip in {"104.16.0.1", "104.16.0.2"}
            return ProbeResult(
                ok=allowed,
                target_ip=ip,
                actual_remote_address=ip,
                target_matches_remote=allowed,
                cert_verified=allowed,
            )

        with patch("cfopt.pipeline.network_fingerprint", return_value=("", "")):
            result = run_optimizer(
                purpose="argo",
                target_host="argo.example.com",
                ips=["104.16.0.2", "8.8.8.8"],
                resolved_ips=["104.16.0.1"],
                family="ipv4",
                probe_fn=_probe,
                trace_fn=lambda *_: ("HKG", "HK"),
                compatibility_fn=compatible,
                ws_path="/vless?ed=2048",
            )
        rows = result.families[0].ranked
        self.assertEqual({row.ip for row in rows}, {"104.16.0.1", "104.16.0.2"})
        by_ip = {row.ip: row for row in rows}
        self.assertIn("当前 DNS", by_ip["104.16.0.1"].source_tags)
        self.assertNotIn("我的 IP 名单（官方网段）", by_ip["104.16.0.1"].source_tags)
        self.assertIn("我的 IP 名单（官方网段）", by_ip["104.16.0.2"].source_tags)
        self.assertEqual(result.purpose, "argo")
        self.assertEqual(result.target_host, "argo.example.com")
        self.assertEqual(result.measurement_host, "speed.cloudflare.com")
        self.assertEqual(result.measurement_port, 443)
        self.assertEqual(result.ws_path, "/vless?ed=2048")
        self.assertGreaterEqual(result.rejected_ip_count, 1)

    def test_argo_measurement_stays_on_public_speed_endpoint_443(self) -> None:
        calls: list[tuple[str, int]] = []

        def download(ip: str, _bytes: int, *_args, hostname: str, port: int, **_kwargs) -> ProbeResult:
            calls.append((hostname, port))
            return ProbeResult(
                ok=True, target_ip=ip, actual_remote_address=ip,
                target_matches_remote=True, cert_verified=True,
                complete_mbps=10.0, payload_mbps=10.0, ttfb_ms=10.0,
            )

        def compatible(ip: str, *_args) -> ProbeResult:
            return ProbeResult(
                ok=True, target_ip=ip, actual_remote_address=ip,
                target_matches_remote=True, cert_verified=True,
            )

        with (
            patch("cfopt.pipeline.network_fingerprint", return_value=("", "")),
            patch("cfopt.pipeline.sample_official_cloudflare_ips", return_value=[]),
            patch("cfopt.pipeline.probe_download", side_effect=download),
            patch("cfopt.pipeline.probe_speed_window", side_effect=download),
        ):
            result = run_optimizer(
                purpose="argo", target_host="argo.example.com", node_port=8443,
                resolved_ips=["104.16.0.1"], family="ipv4",
                compatibility_fn=compatible,
                trace_fn=lambda *_args, **_kwargs: ("HKG", "HK"),
            )
        self.assertEqual(result.measurement_port, 443)
        self.assertTrue(calls)
        self.assertEqual(set(calls), {("speed.cloudflare.com", 443)})

    def test_argo_selected_port_is_used_only_by_compatibility_gate(self) -> None:
        gate_calls: list[tuple[str, int]] = []

        def compatibility(ip: str, *_args, hostname: str, port: int, **_kwargs) -> ProbeResult:
            gate_calls.append((hostname, port))
            return ProbeResult(
                ok=True, target_ip=ip, actual_remote_address=ip,
                target_matches_remote=True, cert_verified=True,
            )

        with (
            patch("cfopt.pipeline.network_fingerprint", return_value=("", "")),
            patch("cfopt.pipeline.sample_official_cloudflare_ips", return_value=[]),
            patch("cfopt.pipeline.probe_argo_compatibility", side_effect=compatibility),
        ):
            result = run_optimizer(
                purpose="argo", target_host="argo.example.com", node_port=2053,
                resolved_ips=["104.16.0.1"], family="ipv4", probe_fn=_probe,
                trace_fn=lambda *_args, **_kwargs: ("HKG", "HK"),
            )
        self.assertEqual(gate_calls, [("argo.example.com", 2053)])
        self.assertEqual(result.measurement_port, 443)

    def test_argo_domain_must_already_resolve_to_cloudflare(self) -> None:
        with self.assertRaisesRegex(ValueError, "未返回 Cloudflare"):
            run_optimizer(
                purpose="argo",
                target_host="argo.example.com",
                resolved_ips=["8.8.8.8"],
                family="ipv4",
            )

    def test_ws_path_is_relative_and_header_safe(self) -> None:
        self.assertEqual(normalize_ws_path("/ws?ed=2048"), "/ws?ed=2048")
        for value in ("https://example.com/ws", "//example.com/ws", "/ws#fragment", "/ws%zz", "/ws\r\nX: y"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                normalize_ws_path(value)

    def test_fast_mode_confirms_first_target_hit_and_stops(self) -> None:
        calls: list[str] = []

        def speed(ip: str, *_args) -> ProbeResult:
            calls.append(ip)
            return ProbeResult(
                ok=True,
                target_ip=ip,
                actual_remote_address=ip,
                target_matches_remote=True,
                cert_verified=True,
                complete_mbps=125.0,
                payload_mbps=130.0,
                ttfb_ms=8.0,
                bytes_downloaded=12_500_000,
            )

        output = _run_fast_speed_stage(
            ["104.16.0.1", "104.16.0.2"],
            BALANCED,
            100,
            threading.Event(),
            lambda *_: None,
            lambda *_: None,
            speed,
            "IPv4",
        )
        self.assertEqual(calls, ["104.16.0.1", "104.16.0.1"])
        self.assertEqual(len(output["104.16.0.1"]), 2)
        self.assertNotIn("104.16.0.2", output)

    def test_max_bandwidth_mode_tests_every_shortlisted_ip(self) -> None:
        calls: list[str] = []
        speeds = {"104.16.0.1": 80.0, "104.16.0.2": 220.0, "104.16.0.3": 150.0}

        def speed(ip: str, *_args) -> ProbeResult:
            calls.append(ip)
            value = speeds[ip]
            return ProbeResult(
                ok=True,
                target_ip=ip,
                actual_remote_address=ip,
                target_matches_remote=True,
                cert_verified=True,
                complete_mbps=value,
                payload_mbps=value,
                ttfb_ms=8.0,
                bytes_downloaded=8_000_000,
            )

        output = _run_fast_speed_stage(
            list(speeds),
            MAX_BANDWIDTH,
            100,
            threading.Event(),
            lambda *_: None,
            lambda *_: None,
            speed,
            "IPv4",
        )
        self.assertEqual(set(output), set(speeds))
        self.assertEqual(calls[:3], list(speeds))
        self.assertEqual(calls.count("104.16.0.2"), 2)
        self.assertTrue(all(len(samples) == 2 for samples in output.values()))

    def test_snapshot_filters_families_and_non_cf(self) -> None:
        snapshot = build_snapshot(["104.16.0.1", "2606:4700::1111", "1.1.1.1"], "IPv4", threading.Event(), lambda *_: None, lambda *_: None)
        self.assertEqual(snapshot.ips, ["104.16.0.1"])

    def test_snapshot_caps_each_family_before_real_probes(self) -> None:
        candidates = [f"104.16.0.{index}" for index in range(1, MAX_CANDIDATES_PER_FAMILY + 20)]
        snapshot = build_snapshot(candidates, "IPv4", threading.Event(), lambda *_: None, lambda *_: None)
        self.assertEqual(MAX_CANDIDATES_PER_FAMILY, 100)
        self.assertEqual(len(snapshot.ips), MAX_CANDIDATES_PER_FAMILY)
        self.assertEqual(snapshot.ips[0], "104.16.0.1")


if __name__ == "__main__":
    unittest.main()
