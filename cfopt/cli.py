from __future__ import annotations

import argparse
import csv
import json
import sys
import threading
from pathlib import Path

from .models import SPEED_HOST
from .pipeline import run_optimizer
from .webapp import serve


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="RR Edge Hunter 电脑端 Cloudflare IP 连通性优选工具")
    sub = parser.add_subparsers(dest="command")
    ui = sub.add_parser("ui", help="打开本地网页界面")
    ui.add_argument("--host", default="127.0.0.1")
    ui.add_argument("--port", type=int, default=0)
    ui.add_argument("--no-open", action="store_true", help="不自动打开浏览器")

    run = sub.add_parser("run", help="在命令行执行已分配 Cloudflare IP 的本机测量")
    run.add_argument("--mode", choices=("balanced", "asia"), default="balanced")
    run.add_argument("--family", choices=("ipv4", "ipv6", "dual"), default="dual")
    run.add_argument("--operator", default="自动", help="仅作为当前线路标签记录")
    run.add_argument("--target-host", default=SPEED_HOST, help="获授权的 Cloudflare 测试主机；只测其当前 DNS 分配地址")
    run.add_argument("--ips", type=Path, help="可选 IP 筛选名单；仅保留与当前 DNS 分配结果相交的地址")
    run.add_argument("--output", type=Path, default=Path("rr-edge-hunter-result.json"))
    run.add_argument("--csv", type=Path, help="额外导出 CSV")
    return parser


def _write_csv(path: Path, result: dict[str, object]) -> None:
    with path.open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(["family", "rank", "ip", "round_floor_mbps", "avg_mbps", "success_pct", "variation_pct", "pop", "loc", "rounds"])
        for family in result.get("families", []):
            if not isinstance(family, dict):
                continue
            rows = family.get("asia_ranked" if result.get("mode") == "asia" else "ranked", [])
            for index, row in enumerate(rows, 1):
                writer.writerow([
                    family.get("family", ""), index, row.get("ip", ""), row.get("round_floor_mbps", 0),
                    row.get("avg_complete_mbps", 0), row.get("success_rate_pct", 0), row.get("variation_pct", 0),
                    row.get("pop", ""), row.get("loc", ""), row.get("rounds_tested", 0),
                ])


def _run_command(args: argparse.Namespace) -> int:
    cancel_event = threading.Event()

    def stage(name: str, current: int, total: int, detail: str) -> None:
        progress = f" {current}/{total}" if total else ""
        suffix = f" · {detail}" if detail else ""
        print(f"\r[{name}{progress}]{suffix:<70}", end="", flush=True)

    def log(message: str) -> None:
        print(f"\n{message}")

    try:
        result = run_optimizer(
            mode=args.mode,
            family=args.family,
            operator=args.operator,
            target_host=args.target_host,
            ips_path=args.ips,
            source_kind="命令行 IP 名单" if args.ips else "当前 DNS",
            cancel_event=cancel_event,
            on_stage=stage,
            log=log,
        )
    except KeyboardInterrupt:
        cancel_event.set()
        print("\n已停止。")
        return 130
    except ValueError as exc:
        print(f"\n无法开始测量：{exc}", file=sys.stderr)
        return 2
    value = result.to_dict()
    args.output.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")
    if args.csv:
        _write_csv(args.csv, value)
    print(f"\n完成，JSON 已保存到：{args.output.resolve()}")
    if args.csv:
        print(f"CSV 已保存到：{args.csv.resolve()}")
    for family in result.families:
        rows = family.asia_ranked if result.mode == "asia" else family.ranked
        if rows:
            champion = rows[0]
            print(f"{family.family} 第一名：{champion.ip} · 复核底线 {champion.round_floor_mbps:.1f} Mbps · 平均 {champion.avg_complete_mbps:.1f} Mbps")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    if args.command in {None, "ui"}:
        serve(host=getattr(args, "host", "127.0.0.1"), port=getattr(args, "port", 0), open_browser=not getattr(args, "no_open", False))
        return 0
    if args.command == "run":
        return _run_command(args)
    parser.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
