from __future__ import annotations

import sys
import tempfile
import threading
import unittest
from pathlib import Path

from cfopt.reference_process import (
    ReferenceEngineCancelled,
    run_reference_scan,
    update_reference_data,
)


FAKE_SCAN = r"""
import pathlib
import sys

menu = sys.stdin.readline().strip()
bandwidth = sys.stdin.readline().strip()
tasks = sys.stdin.readline().strip()
pathlib.Path("received.txt").write_text("|".join((menu, bandwidth, tasks)), encoding="utf-8")
ip = "2606:4700::1111" if menu in {"3", "4"} else "104.16.0.8"
print("已加载 300 个数据中心位置信息")
print("已生成 100 个测试 IP，开始 RTT 测试...")
print("RTT 测试进度: 100/100")
print(ip + " 峰值速度 512 kB/s")
print()
print("优选 IP:", ip)
print("设置带宽:", bandwidth, "Mbps")
print("实测带宽: 4 Mbps")
print("峰值速度: 512 kB/s")
print("往返延迟: 28 毫秒")
print("数据中心: Hong Kong")
print("总计用时: 7 秒")
"""

FAKE_WAIT = r"""
import sys
import time

sys.stdin.readline()
sys.stdin.readline()
sys.stdin.readline()
print("已开始", flush=True)
time.sleep(30)
"""

FAKE_UPDATE = r"""
import pathlib
import sys

first = sys.stdin.readline().strip()
second = sys.stdin.readline().strip()
pathlib.Path("received.txt").write_text(first + "|" + second, encoding="utf-8")
print("正在重新下载数据...")
print("已加载 300 个数据中心位置信息")
"""


class ReferenceProcessTest(unittest.TestCase):
    def _script(self, root: Path, name: str, source: str) -> Path:
        path = root / name
        path.write_text(source, encoding="utf-8")
        return path

    def test_all_four_menu_mappings_and_summary_parser(self) -> None:
        cases = (
            ("ipv4", True, "1", "104.16.0.8"),
            ("ipv4", False, "2", "104.16.0.8"),
            ("ipv6", True, "3", "2606:4700::1111"),
            ("ipv6", False, "4", "2606:4700::1111"),
        )
        for family, use_tls, expected_menu, expected_ip in cases:
            with self.subTest(family=family, use_tls=use_tls), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                script = self._script(root, "fake_scan.py", FAKE_SCAN)
                captured: list[str] = []
                result = run_reference_scan(
                    family=family,
                    use_tls=use_tls,
                    bandwidth=20,
                    task_count=50,
                    cancel_event=threading.Event(),
                    on_line=captured.append,
                    command=[sys.executable, str(script)],
                    cache_dir=root,
                )
                self.assertEqual((root / "received.txt").read_text(encoding="utf-8"), f"{expected_menu}|20|50")
                self.assertEqual(result.ip, expected_ip)
                self.assertEqual(result.bandwidth, 20)
                self.assertEqual(result.real_bandwidth, 4)
                self.assertEqual(result.max_speed, 512)
                self.assertEqual(result.latency_ms, 28)
                self.assertEqual(result.data_center, "Hong Kong")
                self.assertEqual(result.elapsed, 7)
                self.assertTrue(any("RTT 测试进度" in line for line in captured))

    def test_cancel_terminates_reference_process(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            script = self._script(root, "fake_wait.py", FAKE_WAIT)
            cancel = threading.Event()
            cancel.set()
            with self.assertRaises(ReferenceEngineCancelled):
                run_reference_scan(
                    family="ipv4",
                    use_tls=True,
                    bandwidth=1,
                    cancel_event=cancel,
                    on_line=lambda _line: None,
                    command=[sys.executable, str(script)],
                    cache_dir=root,
                )

    def test_update_uses_original_menu_option_eight(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            script = self._script(root, "fake_update.py", FAKE_UPDATE)
            output: list[str] = []
            update_reference_data(
                cancel_event=threading.Event(),
                on_line=output.append,
                command=[sys.executable, str(script)],
                cache_dir=root,
            )
            self.assertEqual((root / "received.txt").read_text(encoding="utf-8"), "8|0")
            self.assertTrue(any("重新下载" in line for line in output))

    def test_rejects_non_reference_parameters(self) -> None:
        with self.assertRaises(ValueError):
            run_reference_scan(
                family="dual",
                use_tls=True,
                bandwidth=1,
                cancel_event=threading.Event(),
                on_line=lambda _line: None,
            )
        with self.assertRaises(ValueError):
            run_reference_scan(
                family="ipv4",
                use_tls=True,
                bandwidth=0,
                cancel_event=threading.Event(),
                on_line=lambda _line: None,
            )


if __name__ == "__main__":
    unittest.main()
