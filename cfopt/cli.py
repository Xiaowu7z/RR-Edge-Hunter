from __future__ import annotations

import argparse
import json
import sys
import threading

from .reference_process import (
    ReferenceEngineCancelled,
    ReferenceEngineError,
    run_reference_scan,
    update_reference_data,
)
from .webapp import serve


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="RR Edge Hunter：调用 better-cloudflare-ip 原版程序优选 Cloudflare IP"
    )
    sub = parser.add_subparsers(dest="command")
    ui = sub.add_parser("ui", help="打开本机网页界面")
    ui.add_argument("--host", default="127.0.0.1")
    ui.add_argument("--port", type=int, default=0)
    ui.add_argument("--no-open", action="store_true", help="不自动打开浏览器")

    run = sub.add_parser("run", help="直接调用参考程序执行一次优选")
    run.add_argument("--family", choices=("ipv4", "ipv6"), default="ipv4")
    run.add_argument("--bandwidth", type=int, default=1, help="期望带宽，单位 Mbps")
    run.add_argument("--tls", action="store_true", help="使用参考程序的 TLS 443 模式")

    sub.add_parser("update", help="调用参考程序原版更新数据功能")
    return parser


def _run(args: argparse.Namespace) -> int:
    cancel = threading.Event()
    try:
        result = run_reference_scan(
            family=args.family,
            use_tls=args.tls,
            bandwidth=args.bandwidth,
            task_count=50,
            cancel_event=cancel,
            on_line=print,
        )
    except KeyboardInterrupt:
        cancel.set()
        print("\n已停止。", file=sys.stderr)
        return 130
    except (ValueError, ReferenceEngineError) as exc:
        print(f"优选失败：{exc}", file=sys.stderr)
        return 2
    print(json.dumps(result.to_dict(), ensure_ascii=False, indent=2))
    return 0


def _update() -> int:
    cancel = threading.Event()
    try:
        update_reference_data(cancel_event=cancel, on_line=print)
    except KeyboardInterrupt:
        cancel.set()
        print("\n已停止。", file=sys.stderr)
        return 130
    except ReferenceEngineError as exc:
        print(f"更新失败：{exc}", file=sys.stderr)
        return 2
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    if args.command in {None, "ui"}:
        serve(
            host=getattr(args, "host", "127.0.0.1"),
            port=getattr(args, "port", 0),
            open_browser=not getattr(args, "no_open", False),
        )
        return 0
    if args.command == "run":
        return _run(args)
    if args.command == "update":
        return _update()
    parser.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
