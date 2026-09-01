from __future__ import annotations

import argparse
import csv
import functools
import json
import sys
import threading
from pathlib import Path

from .models import SPEED_HOST
from .node_template import parse_node_profile
from .pipeline import run_optimizer
from .webapp import serve
from .xray_node import XrayNodeError, validate_xray_runtime, verify_node_candidate


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="RR Edge Hunter 电脑端 Cloudflare IP 连通性优选工具")
    sub = parser.add_subparsers(dest="command")
    ui = sub.add_parser("ui", help="打开本地网页界面")
    ui.add_argument("--host", default="127.0.0.1")
    ui.add_argument("--port", type=int, default=0)
    ui.add_argument("--no-open", action="store_true", help="不自动打开浏览器")

    run = sub.add_parser("run", help="在命令行执行完整节点 CF IP 优选或 DNS 体检")
    run.add_argument("--purpose", choices=("direct", "argo", "dns"), default="argo", help="argo=完整 Xray 节点门禁（默认）；direct=仅测速诊断；dns=当前 DNS 体检")
    run.add_argument("--mode", choices=("reference",), default="reference", help="固定为快速优选流程")
    run.add_argument("--family", choices=("ipv4", "ipv6", "dual"), default="ipv4")
    run.add_argument("--operator", default="自动", help="仅作为当前线路标签记录")
    run.add_argument("--target-host", default=SPEED_HOST, help="仅 Argo 高级复核或 DNS 体检使用；普通优选使用在线动态测速端点")
    run.add_argument("--node-port", type=int, default=443, help="仅用于 Argo 高级兼容复核；普通吞吐测速使用 TLS 443 或 --no-tls 的 80")
    run.add_argument("--ws-path", default="", help="可选 WebSocket 路径，例如 /vless")
    run.add_argument("--node-link-file", type=Path, help="Argo 模式必填：含单个 VMess/VLESS 分享链接的 UTF-8 文件，避免链接进入命令历史")
    run.add_argument("--target-mbps", type=int, default=100, help="达标参考带宽，默认 100 Mbps")
    run.add_argument("--no-tls", action="store_true", help="按参考程序的非 TLS 80 端口模式测速")
    run.add_argument("--ips", type=Path, help="可选公网 IP 名单；direct/Argo 模式作为受限候选并须经严格 CF 身份复测，DNS 模式用于交集筛选")
    run.add_argument("--output", type=Path, default=Path("rr-edge-hunter-result.json"))
    run.add_argument("--csv", type=Path, help="额外导出 CSV")
    return parser


def _write_csv(path: Path, result: dict[str, object]) -> None:
    argo = result.get("purpose") == "argo"
    node_output = result.get("purpose") in {"direct", "argo"}
    target_mbps = int(result.get("target_mbps", 100))
    node_sni = result.get("node_sni") or result.get("target_host", "")
    node_host = result.get("node_host") or node_sni
    with path.open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow([
            "family", "rank", "ip", "server", "target_mbps", "meets_target", "port", "sni", "host", "ws_path",
            "peak_kbps", "tcp_latency_ms", "scan_round", "data_center", "transport", "measurement_host", "measurement_port",
            "round_floor_mbps", "avg_mbps", "success_pct", "variation_pct", "v2rayng_delay_ms", "pop", "loc", "rounds",
        ])
        for family in result.get("families", []):
            if not isinstance(family, dict):
                continue
            rows = family.get("asia_ranked" if result.get("mode") == "asia" else "ranked", [])
            for index, row in enumerate(rows, 1):
                writer.writerow([
                    family.get("family", ""), index, row.get("ip", ""), row.get("ip", "") if node_output else "",
                    target_mbps, "yes" if float(row.get("round_floor_mbps", 0)) >= target_mbps else "no",
                    result.get("node_port", 443) if argo else "", node_sni if argo else "",
                    node_host if argo else "", result.get("ws_path", "") if argo else "",
                    row.get("peak_kbps", 0), row.get("latency_ms", 0), row.get("scan_round", 0), row.get("data_center", ""),
                    "TLS" if row.get("use_tls", result.get("use_tls", True)) else "plain HTTP",
                    result.get("measurement_host", ""), result.get("measurement_port", ""),
                    row.get("round_floor_mbps", 0),
                    row.get("avg_complete_mbps", 0), row.get("success_rate_pct", 0), row.get("variation_pct", 0),
                    row.get("node_delay_ms", 0),
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
        compatibility_fn = None
        profile = None
        target_host = args.target_host
        node_port = args.node_port
        ws_path = args.ws_path
        if args.purpose == "argo":
            if args.node_link_file is None:
                raise ValueError("Argo 模式必须提供 --node-link-file；文件中只放一个当前在 V2rayNG 能用的节点链接")
            try:
                if args.node_link_file.stat().st_size > 32 * 1024:
                    raise ValueError("节点链接文件不能超过 32 KiB")
                node_link = args.node_link_file.read_text(encoding="utf-8").strip()
            except OSError as exc:
                raise ValueError(f"无法读取节点链接文件：{exc}") from exc
            profile = parse_node_profile(node_link)
            target_host = profile.route.sni
            node_port = profile.route.port
            ws_path = profile.route.ws_path
            xray = validate_xray_runtime()
            compatibility_fn = functools.partial(
                verify_node_candidate,
                profile=profile,
                xray_executable=xray,
            )
        result = run_optimizer(
            mode=args.mode,
            family=args.family,
            operator=args.operator,
            target_host=target_host,
            ips_path=args.ips,
            source_kind="命令行 IP 名单" if args.ips else "当前 DNS",
            purpose=args.purpose,
            node_port=node_port,
            ws_path=ws_path,
            target_mbps=args.target_mbps,
            use_tls=not args.no_tls,
            cancel_event=cancel_event,
            on_stage=stage,
            log=log,
            compatibility_fn=compatibility_fn,
        )
    except KeyboardInterrupt:
        cancel_event.set()
        print("\n已停止。")
        return 130
    except (ValueError, XrayNodeError) as exc:
        print(f"\n无法开始测量：{exc}", file=sys.stderr)
        return 2
    if profile is not None:
        result.node_sni = profile.route.sni
        result.node_host = profile.route.host_header
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
            if result.mode == "reference":
                print(
                    f"{family.family} 达标 IP：{champion.ip} · "
                    f"完整一秒峰值 {champion.peak_kbps} kB/s "
                    f"({champion.avg_complete_mbps:.1f} Mbps) · TCP {champion.latency_ms} ms"
                )
            else:
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
