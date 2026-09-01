from __future__ import annotations

import threading
import unittest
from unittest.mock import patch

from cfopt.models import ASIA_HUNT, BALANCED, MAX_BANDWIDTH, IpMetric, ProbeResult, Snapshot
from cfopt.pipeline import (
    MAX_CANDIDATES_PER_FAMILY,
    NetworkChanged,
    OptimizerCancelled,
    RESTRICTED_PUBLIC_SOURCE,
    _run_fast_speed_stage,
    _run_parallel_rtt_rounds,
    _select_speed_candidates,
    build_snapshot,
    estimate_traffic_upper_bound_mb,
    full_schedule,
    normalize_ws_path,
    run_family,
    run_optimizer,
)
from cfopt.probe import speed_request_bytes
from cfopt.ranges import family_of, is_cloudflare_ip, sample_official_cloudflare_ips
from cfopt.ranking import rank, rank_asia, rank_maximum


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


def _rtt(ip: str, *_args, **_kwargs) -> ProbeResult:
    return ProbeResult(
        ok=True,
        target_ip=ip,
        actual_remote_address=ip,
        target_matches_remote=True,
        tcp_ms=8.0,
        ttfb_ms=8.0,
    )


def _speed_ok(ip: str, *_args, **_kwargs) -> ProbeResult:
    return ProbeResult(
        ok=True,
        target_ip=ip,
        actual_remote_address=ip,
        target_matches_remote=True,
        cert_verified=True,
        complete_mbps=120.0,
        payload_mbps=120.0,
        ttfb_ms=8.0,
        bytes_downloaded=15_000_000,
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

    def test_cancel_after_candidate_gate_cannot_publish_result(self) -> None:
        cancel = threading.Event()

        def gate(_ip: str) -> bool:
            cancel.set()
            return True

        with self.assertRaises(OptimizerCancelled):
            _run_fast_speed_stage(
                ["104.16.0.2"],
                BALANCED,
                100,
                cancel,
                lambda *_args: None,
                lambda _message: None,
                _speed_ok,
                "IPv4",
                candidate_gate=gate,
            )

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

    def test_failed_confirmation_is_not_exposed_as_copyable_result(self) -> None:
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
        self.assertEqual([row.ip for row in rows], ["104.16.0.2"])
        self.assertTrue(all(row.rounds_tested >= 2 for row in rows))

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
            return ["104.16.0.2"]

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
        self.assertEqual(result.families[0].ranked[0].ip, "104.16.0.2")

    def test_direct_pool_accepts_public_import_only_after_strict_retest(self) -> None:
        def samples(family: str, **_kwargs) -> list[str]:
            return ["104.16.0.2"] if family == "IPv4" else []

        rtt_calls: dict[str, int] = {}
        speed_calls: list[tuple[str, str, int]] = []

        def rtt(ip: str, *_args, **_kwargs) -> ProbeResult:
            rtt_calls[ip] = rtt_calls.get(ip, 0) + 1
            return _rtt(ip)

        def speed(ip: str, *_args, hostname: str, port: int, **_kwargs) -> ProbeResult:
            speed_calls.append((ip, hostname, port))
            value = 300.0 if ip == "8.8.8.8" else 10.0
            return ProbeResult(
                ok=True, target_ip=ip, actual_remote_address=ip,
                target_matches_remote=True, cert_verified=True, http_code=200,
                complete_mbps=value, payload_mbps=value, ttfb_ms=8.0,
                colo="HKG", bytes_downloaded=20_000_000,
            )

        with (
            patch("cfopt.pipeline.network_fingerprint", return_value=("", "")),
            patch("cfopt.pipeline.sample_official_cloudflare_ips", side_effect=samples),
            patch("cfopt.pipeline.probe_tcp_rtt", side_effect=rtt),
            patch("cfopt.pipeline.probe_speed_window", side_effect=speed),
        ):
            result = run_optimizer(
                purpose="direct", ips=["8.8.8.8", "10.0.0.1"], target_mbps=200,
                resolved_ips=["104.16.0.1"], family="ipv4",
            )
        rows = result.families[0].ranked
        self.assertIn("8.8.8.8", {row.ip for row in rows})
        external = next(row for row in rows if row.ip == "8.8.8.8")
        self.assertIn(RESTRICTED_PUBLIC_SOURCE, external.source_tags)
        self.assertEqual(rtt_calls["8.8.8.8"], 3)
        self.assertEqual([call for call in speed_calls if call[0] == "8.8.8.8"], [
            ("8.8.8.8", "speed.cloudflare.com", 443),
            ("8.8.8.8", "speed.cloudflare.com", 443),
        ])
        self.assertEqual(external.rounds_tested, 2)
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
                trace_fn=lambda *_args, **_kwargs: ("HKG", "HK"), rtt_probe_fn=_rtt,
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
                speed_probe_fn=_speed_ok,
                target_mbps=200,
                ws_path="/vless?ed=2048",
            )
        rows = result.families[0].ranked
        self.assertEqual({row.ip for row in rows}, {"104.16.0.1", "104.16.0.2"})
        by_ip = {row.ip: row for row in rows}
        self.assertIn("当前 DNS", by_ip["104.16.0.1"].source_tags)
        self.assertNotIn(RESTRICTED_PUBLIC_SOURCE, by_ip["104.16.0.1"].source_tags)
        self.assertIn(RESTRICTED_PUBLIC_SOURCE, by_ip["104.16.0.2"].source_tags)
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
                trace_fn=lambda *_args, **_kwargs: ("HKG", "HK"), rtt_probe_fn=_rtt,
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
                trace_fn=lambda *_args, **_kwargs: ("HKG", "HK"), speed_probe_fn=_speed_ok,
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

    def test_balanced_confirmation_failures_backfill_real_success_quota(self) -> None:
        calls: dict[str, int] = {}
        first_speeds = {
            "104.16.0.1": 150.0,
            "104.16.0.2": 90.0,
            "104.16.0.3": 80.0,
            "104.16.0.4": 70.0,
        }

        def speed(ip: str, *_args) -> ProbeResult:
            calls[ip] = calls.get(ip, 0) + 1
            failed_confirmation = calls[ip] == 2 and ip in {"104.16.0.1", "104.16.0.2"}
            value = first_speeds[ip]
            return ProbeResult(
                ok=not failed_confirmation,
                target_ip=ip,
                complete_mbps=0.0 if failed_confirmation else value,
                payload_mbps=0.0 if failed_confirmation else value,
            )

        output = _run_fast_speed_stage(
            list(first_speeds), BALANCED, 100, threading.Event(),
            lambda *_: None, lambda *_: None, speed, "IPv4",
        )
        confirmed = [ip for ip, samples in output.items() if len(samples) == 2 and all(item.ok for item in samples)]
        self.assertEqual(confirmed, ["104.16.0.3", "104.16.0.4"])
        self.assertEqual(calls, {ip: 2 for ip in first_speeds})

    def test_speed_stage_worst_case_progress_and_traffic_bound_cover_all_retests(self) -> None:
        ips = [f"104.16.0.{index}" for index in range(1, 11)]
        calls: dict[str, int] = {}
        progress: list[tuple[int, int]] = []

        def speed(ip: str, *_args) -> ProbeResult:
            calls[ip] = calls.get(ip, 0) + 1
            return ProbeResult(
                ok=calls[ip] == 1,
                target_ip=ip,
                complete_mbps=150.0 if calls[ip] == 1 else 0.0,
                payload_mbps=150.0 if calls[ip] == 1 else 0.0,
                bytes_downloaded=speed_request_bytes(100),
            )

        _run_fast_speed_stage(
            ips, BALANCED, 100, threading.Event(),
            lambda _stage, current, total, _detail: progress.append((current, total)),
            lambda *_: None, speed, "IPv4",
        )
        self.assertEqual(sum(calls.values()), len(ips) * 2)
        self.assertTrue(all(0 <= current <= total for current, total in progress))
        self.assertEqual(max(current for current, _total in progress), len(ips) * 2)
        snapshot = Snapshot("IPv4", ips)
        expected = (
            len(ips) * BALANCED.pre_bytes
            + len(ips) * 2 * speed_request_bytes(100)
        ) / 1_000_000.0
        self.assertEqual(estimate_traffic_upper_bound_mb(snapshot, BALANCED, 100), expected)

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

    def test_max_bandwidth_confirmation_failures_backfill_top_three(self) -> None:
        ips = [f"104.16.0.{index}" for index in range(1, 6)]
        first_speeds = {ip: 600.0 - index * 50.0 for index, ip in enumerate(ips)}
        calls: dict[str, int] = {}

        def speed(ip: str, *_args) -> ProbeResult:
            calls[ip] = calls.get(ip, 0) + 1
            failed = calls[ip] == 2 and ip in set(ips[:2])
            value = first_speeds[ip]
            return ProbeResult(
                ok=not failed,
                target_ip=ip,
                complete_mbps=0.0 if failed else value,
                payload_mbps=0.0 if failed else value,
            )

        output = _run_fast_speed_stage(
            ips, MAX_BANDWIDTH, 100, threading.Event(),
            lambda *_: None, lambda *_: None, speed, "IPv4",
        )
        confirmed = [ip for ip, samples in output.items() if len(samples) == 2 and all(item.ok for item in samples)]
        self.assertEqual(confirmed, ips[2:])
        self.assertEqual(calls, {ip: 2 for ip in ips})

    def test_maximum_final_ranking_exposes_only_twice_successful_candidates(self) -> None:
        ips = [f"104.16.0.{index}" for index in range(1, 6)]
        calls: dict[str, int] = {}

        def speed(ip: str, *_args, **_kwargs) -> ProbeResult:
            calls[ip] = calls.get(ip, 0) + 1
            failed = calls[ip] == 2 and ip in set(ips[:2])
            value = 600.0 - ips.index(ip) * 50.0
            return ProbeResult(
                ok=not failed, target_ip=ip, actual_remote_address=ip,
                target_matches_remote=True, cert_verified=True,
                complete_mbps=0.0 if failed else value,
                payload_mbps=0.0 if failed else value,
                ttfb_ms=8.0, colo="HKG",
            )

        with (
            patch("cfopt.pipeline.network_fingerprint", return_value=("", "")),
            patch("cfopt.pipeline.sample_official_cloudflare_ips", return_value=[]),
        ):
            result = run_optimizer(
                purpose="direct", mode="max", resolved_ips=ips, family="ipv4",
                rtt_probe_fn=_rtt, speed_probe_fn=speed,
            )

        rows = result.families[0].ranked
        self.assertEqual({row.ip for row in rows}, set(ips[2:]))
        self.assertTrue(all(row.rounds_tested == 2 and row.success_rate_pct == 100.0 for row in rows))

    def test_maximum_bandwidth_prefers_confirmed_average_speed(self) -> None:
        high_average = IpMetric(
            "104.16.0.20", "IPv4", min_complete_mbps=45.0,
            avg_complete_mbps=110.0, max_complete_mbps=125.0,
            success_rate_pct=100.0, round_floor_mbps=45.0, rounds_tested=2,
        )
        high_floor = IpMetric(
            "104.16.0.21", "IPv4", min_complete_mbps=70.0,
            avg_complete_mbps=80.0, max_complete_mbps=85.0,
            success_rate_pct=100.0, round_floor_mbps=70.0, rounds_tested=2,
        )
        one_lucky_sample = IpMetric(
            "104.16.0.22", "IPv4", min_complete_mbps=500.0,
            avg_complete_mbps=500.0, max_complete_mbps=500.0,
            success_rate_pct=100.0, round_floor_mbps=500.0, rounds_tested=1,
        )
        self.assertEqual(rank_maximum([high_floor, one_lucky_sample, high_average])[0].ip, high_average.ip)
        self.assertEqual(rank([high_average, high_floor])[0].ip, high_floor.ip)

    def test_asia_ranking_prefers_confirmed_over_single_sample_spike(self) -> None:
        stable = IpMetric(
            "104.16.0.30", "IPv4", min_complete_mbps=100.0,
            avg_complete_mbps=100.0, max_complete_mbps=100.0,
            success_rate_pct=100.0, round_floor_mbps=100.0, rounds_tested=2,
            edge_score=1,
        )
        lucky = IpMetric(
            "104.16.0.31", "IPv4", min_complete_mbps=500.0,
            avg_complete_mbps=500.0, max_complete_mbps=500.0,
            success_rate_pct=100.0, round_floor_mbps=500.0, rounds_tested=1,
            edge_score=5,
        )
        self.assertEqual(rank_asia([lucky, stable])[0].ip, stable.ip)

    def test_maximum_shortlist_keeps_fast_core_and_diverse_latency_tail(self) -> None:
        ranked = [f"104.16.{index // 256}.{index % 256}" for index in range(1, 101)]
        selected = _select_speed_candidates(ranked, 20, maximum=True)
        self.assertEqual(len(selected), 20)
        self.assertEqual(len(set(selected)), 20)
        self.assertTrue(set(ranked[:16]).issubset(selected))
        self.assertTrue(any(ranked.index(ip) >= 75 for ip in selected))
        preferred = ranked[-1]
        self.assertIn(preferred, _select_speed_candidates(ranked, 20, maximum=True, preferred=[preferred]))
        self.assertEqual(MAX_BANDWIDTH.micro_candidates, 20)

    def test_tcp_rtt_filter_requires_three_successful_rounds(self) -> None:
        ips = ["104.16.0.1", "104.16.0.2", "104.16.0.3"]
        calls: dict[str, int] = {}

        def rtt(ip: str, *_args) -> ProbeResult:
            calls[ip] = calls.get(ip, 0) + 1
            failed = ip.endswith(".2") and calls[ip] == 2
            return ProbeResult(ok=not failed, target_ip=ip, tcp_ms=10.0 + calls[ip])

        results = _run_parallel_rtt_rounds(
            ips, 3, 1.0, 50, "RTT", threading.Event(), lambda *_: None, rtt,
        )
        self.assertTrue(results[ips[0]].ok)
        self.assertFalse(results[ips[1]].ok)
        self.assertTrue(results[ips[2]].ok)
        self.assertEqual(calls, {ips[0]: 3, ips[1]: 2, ips[2]: 3})

    def test_network_change_after_throughput_discards_result_before_ranking(self) -> None:
        checks = 0
        speed_calls = 0

        def changed() -> bool:
            nonlocal checks
            checks += 1
            return checks >= 3

        def speed(ip: str, *_args, **_kwargs) -> ProbeResult:
            nonlocal speed_calls
            speed_calls += 1
            return ProbeResult(
                ok=True, target_ip=ip, actual_remote_address=ip,
                target_matches_remote=True, cert_verified=True,
                complete_mbps=150.0, payload_mbps=150.0,
            )

        with self.assertRaises(NetworkChanged):
            run_family(
                Snapshot("IPv4", ["104.16.0.1"]), BALANCED,
                threading.Event(), lambda *_: None, lambda *_: None,
                network_changed=changed, rtt_probe_fn=_rtt, speed_probe_fn=speed,
            )
        self.assertEqual(speed_calls, 2)
        self.assertEqual(checks, 3)

    def test_argo_gate_is_delayed_until_two_speed_samples_and_failure_backfills(self) -> None:
        speed_calls: list[str] = []
        gate_calls: list[str] = []

        def speed(ip: str, *_args) -> ProbeResult:
            speed_calls.append(ip)
            return ProbeResult(
                ok=True, target_ip=ip, actual_remote_address=ip,
                target_matches_remote=True, cert_verified=True,
                complete_mbps=150.0, payload_mbps=150.0, ttfb_ms=8.0,
            )

        def compatible(ip: str, *_args) -> ProbeResult:
            gate_calls.append(ip)
            allowed = not ip.endswith(".1")
            return ProbeResult(
                ok=allowed, target_ip=ip, actual_remote_address=ip,
                target_matches_remote=allowed, cert_verified=allowed,
            )

        with (
            patch("cfopt.pipeline.network_fingerprint", return_value=("", "")),
            patch("cfopt.pipeline.sample_official_cloudflare_ips", return_value=[]),
        ):
            result = run_optimizer(
                purpose="argo", target_host="argo.example.com",
                resolved_ips=["104.16.0.1"], ips=["104.16.0.2", "104.16.0.3"],
                family="ipv4", rtt_probe_fn=_rtt, speed_probe_fn=speed,
                compatibility_fn=compatible, target_mbps=100,
            )
        self.assertEqual(speed_calls, ["104.16.0.1", "104.16.0.1", "104.16.0.2", "104.16.0.2"])
        self.assertEqual(gate_calls, ["104.16.0.1", "104.16.0.2"])
        self.assertEqual([row.ip for row in result.families[0].ranked], ["104.16.0.2"])
        self.assertEqual(result.families[0].compatible_count, 1)
        self.assertEqual(result.rejected_ip_count, 1)

    def test_external_public_candidate_also_passes_argo_gate_before_output(self) -> None:
        events: list[tuple[str, str]] = []

        def speed(ip: str, *_args, **_kwargs) -> ProbeResult:
            events.append(("speed", ip))
            value = 300.0 if ip == "8.8.8.8" else 10.0
            return ProbeResult(
                ok=True, target_ip=ip, actual_remote_address=ip,
                target_matches_remote=True, cert_verified=True,
                complete_mbps=value, payload_mbps=value, ttfb_ms=8.0,
                colo="HKG",
            )

        def compatible(ip: str, *_args) -> ProbeResult:
            events.append(("argo", ip))
            return ProbeResult(
                ok=True, target_ip=ip, actual_remote_address=ip,
                target_matches_remote=True, cert_verified=True,
            )

        with (
            patch("cfopt.pipeline.network_fingerprint", return_value=("", "")),
            patch("cfopt.pipeline.sample_official_cloudflare_ips", return_value=[]),
        ):
            result = run_optimizer(
                purpose="argo", target_host="argo.example.com",
                resolved_ips=["104.16.0.1"], ips=["8.8.8.8"], family="ipv4",
                target_mbps=200, rtt_probe_fn=_rtt, speed_probe_fn=speed,
                compatibility_fn=compatible,
            )

        self.assertEqual([row.ip for row in result.families[0].ranked], ["8.8.8.8"])
        self.assertEqual(events.count(("speed", "8.8.8.8")), 2)
        self.assertEqual(events[-1], ("argo", "8.8.8.8"))

    def test_snapshot_accepts_public_unicast_but_filters_family_and_private(self) -> None:
        snapshot = build_snapshot(
            ["104.16.0.1", "2606:4700::1111", "8.8.8.8", "10.0.0.1"],
            "IPv4", threading.Event(), lambda *_: None, lambda *_: None,
        )
        self.assertEqual(snapshot.ips, ["104.16.0.1", "8.8.8.8"])

    def test_snapshot_caps_each_family_before_real_probes(self) -> None:
        candidates = [f"104.16.0.{index}" for index in range(1, MAX_CANDIDATES_PER_FAMILY + 20)]
        snapshot = build_snapshot(candidates, "IPv4", threading.Event(), lambda *_: None, lambda *_: None)
        self.assertEqual(MAX_CANDIDATES_PER_FAMILY, 100)
        self.assertEqual(len(snapshot.ips), MAX_CANDIDATES_PER_FAMILY)
        self.assertEqual(snapshot.ips[0], "104.16.0.1")

    def test_official_pool_rotates_with_seed_but_is_reproducible_and_bounded(self) -> None:
        first = sample_official_cloudflare_ips("IPv4", 100, seed="run-1")
        repeated = sample_official_cloudflare_ips("IPv4", 100, seed="run-1")
        rotated = sample_official_cloudflare_ips("IPv4", 100, seed="run-2")
        self.assertEqual(first, repeated)
        self.assertNotEqual(first, rotated)
        self.assertEqual(len(first), 100)
        self.assertEqual(len(set(first)), 100)
        self.assertTrue(all(is_cloudflare_ip(ip) and family_of(ip) == "IPv4" for ip in rotated))


if __name__ == "__main__":
    unittest.main()
