from __future__ import annotations

import random
import threading
import unittest
from unittest.mock import patch

from cfopt.reference_engine import (
    MaintainedData,
    RttResult,
    RoundCandidate,
    SpeedResult,
    _feed_lines,
    _parse_speed_target,
    build_round_candidates,
    run_reference_family,
)


class ReferenceEngineTest(unittest.TestCase):
    def test_feed_and_speed_target_are_bounded_and_normalized(self) -> None:
        self.assertEqual(
            _feed_lines("104.16.0.1/24\n104.16.0.0/24\n10.0.0.0/8\nbad", "IPv4"),
            ("104.16.0.0/24",),
        )
        self.assertEqual(
            _parse_speed_target("https://speed.cloudflare.com/__down?bytes=1000"),
            ("speed.cloudflare.com", "/__down?bytes=1000"),
        )
        with self.assertRaises(ValueError):
            _parse_speed_target("https://104.16.0.1/file")

    def test_round_has_reference_size_and_reserves_custom_literals(self) -> None:
        ranges = [f"104.{second}.0.0/16" for second in range(16, 116)]
        candidates = build_round_candidates(
            ranges,
            ["1.1.1.1", "2606:4700::1111", "192.168.1.1"],
            "IPv4",
            random.Random(7),
        )
        self.assertEqual(len(candidates), 100)
        self.assertIn(RoundCandidate("1.1.1.1", "我的 IP 名单"), candidates)
        self.assertEqual(len({item.ip for item in candidates}), 100)

    def test_first_target_hit_returns_and_failed_speed_moves_to_next(self) -> None:
        data = MaintainedData(
            ("104.16.0.0/24",),
            ("2606:4700::/48",),
            "speed.cloudflare.com",
            "/__down?bytes=100000000",
            {"HKG": "Hong Kong"},
            "test",
        )
        first = RoundCandidate("104.16.0.1", "维护 IP 池")
        second = RoundCandidate("104.16.0.2", "维护 IP 池")
        rtts = [RttResult(first, 10), RttResult(second, 20)]
        speeds = [
            SpeedResult(True, peak_kbps=6_400, tcp_ms=12, colo="HKG", bytes_downloaded=1_000_000),
            SpeedResult(True, peak_kbps=12_800, tcp_ms=14, colo="HKG", bytes_downloaded=2_000_000),
        ]
        with (
            patch("cfopt.reference_engine.build_round_candidates", return_value=[first, second]),
            patch("cfopt.reference_engine.run_rtt_round", return_value=rtts),
            patch("cfopt.reference_engine.probe_speed", side_effect=speeds) as speed,
        ):
            result = run_reference_family(
                family="IPv4",
                data=data,
                custom_ips=(),
                target_mbps=100,
                use_tls=True,
                cancel_event=threading.Event(),
                on_stage=lambda *_args: None,
                log=lambda _message: None,
                source_label="test",
            )
        self.assertEqual(speed.call_count, 2)
        self.assertEqual(result.ranked[0].ip, second.ip)
        self.assertEqual(result.ranked[0].peak_kbps, 12_800)
        self.assertEqual(result.ranked[0].data_center, "Hong Kong")
        self.assertEqual(result.ranked[0].rounds_tested, 1)


if __name__ == "__main__":
    unittest.main()
