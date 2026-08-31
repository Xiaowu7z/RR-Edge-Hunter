from __future__ import annotations

import threading
import unittest
from unittest.mock import patch

from cfopt.models import ASIA_HUNT, BALANCED, ProbeResult
from cfopt.pipeline import MAX_CANDIDATES_PER_FAMILY, build_snapshot, full_schedule, run_optimizer
from cfopt.ranges import family_of, is_cloudflare_ip


def _probe(ip: str, bytes_target: int, *_args) -> ProbeResult:
    failed = ip.endswith(".1") and bytes_target == BALANCED.full_bytes
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
                    ips=["104.16.0.2"],
                    resolved_ips=["104.16.0.1"],
                    family="ipv4",
                    probe_fn=_probe,
                    trace_fn=lambda *_: ("HKG", "HK"),
                )

    def test_failed_full_round_forces_ip_floor_zero(self) -> None:
        with patch("cfopt.pipeline.network_fingerprint", return_value=("", "")):
            result = run_optimizer(
                ips=["104.16.0.1", "104.16.0.2"],
                resolved_ips=["104.16.0.1", "104.16.0.2"],
                family="ipv4",
                probe_fn=_probe,
                trace_fn=lambda *_: ("HKG", "HK"),
            )
        rows = result.families[0].ranked
        self.assertEqual(rows[0].ip, "104.16.0.2")
        self.assertEqual(next(row for row in rows if row.ip == "104.16.0.1").round_floor_mbps, 0.0)

    def test_asia_ranking_prefers_hkg_before_faster_nrt(self) -> None:
        def stable(ip: str, _bytes: int, *_args) -> ProbeResult:
            return ProbeResult(ok=True, target_ip=ip, actual_remote_address=ip, complete_mbps=100.0 if ip.endswith(".2") else 10.0, payload_mbps=10.0, ttfb_ms=10.0)

        with patch("cfopt.pipeline.network_fingerprint", return_value=("", "")):
            result = run_optimizer(
                mode="asia",
                ips=["104.16.0.1", "104.16.0.2"],
                resolved_ips=["104.16.0.1", "104.16.0.2"],
                family="ipv4",
                probe_fn=stable,
                trace_fn=lambda ip, *_: ("HKG", "HK") if ip.endswith(".1") else ("NRT", "JP"),
            )
        self.assertEqual(result.families[0].asia_ranked[0].ip, "104.16.0.1")

    def test_snapshot_filters_families_and_non_cf(self) -> None:
        snapshot = build_snapshot(["104.16.0.1", "2606:4700::1111", "1.1.1.1"], "IPv4", threading.Event(), lambda *_: None, lambda *_: None)
        self.assertEqual(snapshot.ips, ["104.16.0.1"])

    def test_snapshot_caps_each_family_before_real_probes(self) -> None:
        candidates = [f"104.16.0.{index}" for index in range(1, MAX_CANDIDATES_PER_FAMILY + 20)]
        snapshot = build_snapshot(candidates, "IPv4", threading.Event(), lambda *_: None, lambda *_: None)
        self.assertEqual(len(snapshot.ips), MAX_CANDIDATES_PER_FAMILY)
        self.assertEqual(snapshot.ips[0], "104.16.0.1")


if __name__ == "__main__":
    unittest.main()
