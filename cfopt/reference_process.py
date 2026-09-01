"""Thin process wrapper around the unmodified better-cloudflare-ip program."""

from __future__ import annotations

import os
import queue
import re
import shutil
import subprocess
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Sequence

from .resources import package_root


LineCallback = Callable[[str], None]
_END = object()
_MENU_PROMPT = "请选择菜单 (默认 0):"
_BANDWIDTH_PROMPT = "请设置期望的带宽大小 (默认最小 1，单位 Mbps):"
_TASK_COUNT_PROMPT = "请设置 RTT 测试进程数 (默认 50，最大 100):"
_PROMPTS = (_MENU_PROMPT, _BANDWIDTH_PROMPT, _TASK_COUNT_PROMPT)
_MENU_LINE = re.compile(r"^(?:-+|[0-8]\.\s*.+)$")


class ReferenceEngineError(RuntimeError):
    pass


class ReferenceEngineCancelled(ReferenceEngineError):
    pass


@dataclass(frozen=True)
class ReferenceResult:
    ip: str
    bandwidth: int
    real_bandwidth: int
    max_speed: int
    latency_ms: int
    data_center: str
    elapsed: int

    def to_dict(self) -> dict[str, object]:
        return {
            "ip": self.ip,
            "bandwidth": self.bandwidth,
            "realBandwidth": self.real_bandwidth,
            "maxSpeed": self.max_speed,
            "latencyMs": self.latency_ms,
            "dataCenter": self.data_center,
            "elapsed": self.elapsed,
        }


def reference_cache_dir() -> Path:
    if os.name == "nt":
        base = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local")
    else:
        base = Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache")
    path = base / "RR-Edge-Hunter" / "better-cloudflare-ip"
    path.mkdir(parents=True, exist_ok=True)
    return path


def resolve_engine_command() -> list[str]:
    root = package_root()
    names = (
        "better-cloudflare-ip.exe",
        "better-cloudflare-ip",
    )
    for name in names:
        executable = root / "reference-engine" / name
        if executable.is_file():
            return [str(executable)]

    source = root / "third_party" / "better-cloudflare-ip" / "main.go"
    go = shutil.which("go")
    if source.is_file() and go:
        return [go, "run", str(source)]
    raise ReferenceEngineError(
        "未找到优选引擎。正式便携版应包含 reference-engine/better-cloudflare-ip.exe；"
        "源码运行需要安装 Go。"
    )


def _start(
    command: Sequence[str] | None,
    cache_dir: Path | None,
) -> subprocess.Popen[str]:
    selected = list(command) if command is not None else resolve_engine_command()
    if not selected or any(not isinstance(item, str) or not item for item in selected):
        raise ReferenceEngineError("优选引擎启动命令无效")
    working = cache_dir or reference_cache_dir()
    working.mkdir(parents=True, exist_ok=True)
    kwargs: dict[str, object] = {}
    child_env = os.environ.copy()
    # Windows runners and some user locales default child Python processes to
    # a legacy code page.  The reference engine itself emits UTF-8, so keep the
    # entire subprocess boundary UTF-8 as well.  This does not alter the engine
    # or its parameters; it only makes its Chinese progress output decodable.
    child_env["PYTHONIOENCODING"] = "utf-8"
    child_env["PYTHONUTF8"] = "1"
    if os.name == "nt":
        kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW
    try:
        return subprocess.Popen(
            selected,
            cwd=working,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
            env=child_env,
            **kwargs,
        )
    except OSError as exc:
        raise ReferenceEngineError(f"优选引擎无法启动：{exc}") from exc


def _reader(process: subprocess.Popen[str], output: queue.Queue[object]) -> None:
    assert process.stdout is not None
    try:
        # The CLI prints its input prompts without a trailing newline.  Reading
        # one character at a time lets the wrapper answer each prompt only after
        # the engine has installed the matching Scanner.  Sending all answers at
        # once can leave the nested bandwidth Scanner blocked forever because
        # the menu Scanner buffered the remaining lines.
        while True:
            character = process.stdout.read(1)
            if character == "":
                break
            output.put(character)
    finally:
        output.put(_END)


def _stop(process: subprocess.Popen[str]) -> None:
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3)
    for stream in (process.stdin, process.stdout):
        if stream is not None and not stream.closed:
            stream.close()


def _send(process: subprocess.Popen[str], value: str) -> None:
    if process.stdin is None:
        raise ReferenceEngineError("优选引擎输入不可用")
    try:
        process.stdin.write(value)
        process.stdin.flush()
    except (BrokenPipeError, OSError) as exc:
        raise ReferenceEngineError("优选引擎在接收参数前已退出") from exc


def _number(line: str, label: str) -> int | None:
    match = re.search(rf"{re.escape(label)}\s*([0-9]+)", line)
    return int(match.group(1)) if match else None


def _public_line(value: str) -> str:
    """Hide the engine's interactive menu while retaining useful progress."""

    line = value.replace("\r", "")
    for prompt in _PROMPTS:
        line = line.replace(prompt, "")
    line = line.strip()
    if not line or _MENU_LINE.fullmatch(line):
        return ""
    if line.startswith("本地 ") and "不存在，正在下载" in line:
        return "正在准备 IP 池…"
    if re.fullmatch(r"已加载\s+\d+\s+个数据中心位置信息", line):
        return "IP 池已就绪"
    return line


def run_reference_scan(
    *,
    family: str,
    use_tls: bool,
    bandwidth: int,
    cancel_event: threading.Event,
    on_line: LineCallback,
    task_count: int = 50,
    command: Sequence[str] | None = None,
    cache_dir: Path | None = None,
) -> ReferenceResult:
    """Run options 1–4 of the original CLI and parse only its final summary."""

    if family not in {"ipv4", "ipv6"}:
        raise ValueError("IP 协议只能是 IPv4 或 IPv6")
    if isinstance(bandwidth, bool) or not isinstance(bandwidth, int) or bandwidth <= 0:
        raise ValueError("期望带宽必须是大于 0 的整数")
    if isinstance(task_count, bool) or not isinstance(task_count, int) or not 1 <= task_count <= 100:
        raise ValueError("RTT 进程数必须在 1–100 之间")

    menu = {
        ("ipv4", True): "1",
        ("ipv4", False): "2",
        ("ipv6", True): "3",
        ("ipv6", False): "4",
    }[(family, use_tls)]
    process = _start(command, cache_dir)
    output: queue.Queue[object] = queue.Queue()
    threading.Thread(target=_reader, args=(process, output), daemon=True).start()
    lines: list[str] = []
    values: dict[str, object] = {}
    line_buffer = ""
    prompt_window = ""
    input_phase = "menu"

    def accept(raw_line: str) -> bool:
        line = _public_line(raw_line)
        if not line:
            return False
        lines.append(line)
        del lines[:-30]
        on_line(line)

        match = re.search(r"优选 IP:\s*(\S+)", line)
        if match:
            values["ip"] = match.group(1)
        number = _number(line, "设置带宽:")
        if number is not None:
            values["bandwidth"] = number
        number = _number(line, "实测带宽:")
        if number is not None:
            values["real_bandwidth"] = number
        number = _number(line, "峰值速度:")
        if number is not None and "优选 IP:" not in line:
            values["max_speed"] = number
        number = _number(line, "往返延迟:")
        if number is not None:
            values["latency_ms"] = number
        match = re.search(r"数据中心:\s*(.*)$", line)
        if match:
            values["data_center"] = match.group(1).strip()
        number = _number(line, "总计用时:")
        if number is not None:
            values["elapsed"] = number
            return True
        return False

    try:
        completed = False
        while True:
            if cancel_event.is_set():
                _stop(process)
                raise ReferenceEngineCancelled("已停止")
            try:
                item = output.get(timeout=0.1)
            except queue.Empty:
                continue
            if item is _END:
                if line_buffer:
                    completed = accept(line_buffer) or completed
                break

            character = str(item)
            line_buffer += character
            prompt_window = (prompt_window + character)[-512:]
            if input_phase == "menu" and _MENU_PROMPT in prompt_window:
                _send(process, f"{menu}\n")
                input_phase = "bandwidth"
                prompt_window = ""
            elif input_phase == "bandwidth" and _BANDWIDTH_PROMPT in prompt_window:
                _send(process, f"{bandwidth}\n")
                input_phase = "tasks"
                prompt_window = ""
            elif input_phase == "tasks" and _TASK_COUNT_PROMPT in prompt_window:
                _send(process, f"{task_count}\n")
                input_phase = "running"
                prompt_window = ""

            while "\n" in line_buffer:
                raw_line, line_buffer = line_buffer.split("\n", 1)
                if accept(raw_line):
                    completed = True
                    break
            if completed:
                break

        ip = str(values.get("ip", "")).strip()
        if not ip:
            detail = "\n".join(lines[-8:])
            raise ReferenceEngineError(
                "本轮没有返回达标 IP" + (f"：\n{detail}" if detail else "")
            )
        result = ReferenceResult(
            ip=ip,
            bandwidth=int(values.get("bandwidth", bandwidth)),
            real_bandwidth=int(values.get("real_bandwidth", 0)),
            max_speed=int(values.get("max_speed", 0)),
            latency_ms=int(values.get("latency_ms", 0)),
            data_center=str(values.get("data_center", "")),
            elapsed=int(values.get("elapsed", 0)),
        )
        if process.poll() is None:
            try:
                _send(process, "0\n")
            except ReferenceEngineError:
                pass
        return result
    finally:
        _stop(process)


def update_reference_data(
    *,
    cancel_event: threading.Event,
    on_line: LineCallback,
    command: Sequence[str] | None = None,
    cache_dir: Path | None = None,
) -> None:
    """Run the original CLI's option 8, then exit."""

    process = _start(command, cache_dir)
    output: queue.Queue[object] = queue.Queue()
    threading.Thread(target=_reader, args=(process, output), daemon=True).start()
    lines: list[str] = []
    line_buffer = ""
    prompt_window = ""
    input_phase = "menu"
    try:
        while True:
            if cancel_event.is_set():
                _stop(process)
                raise ReferenceEngineCancelled("已停止")
            try:
                item = output.get(timeout=0.1)
            except queue.Empty:
                continue
            if item is _END:
                if line_buffer:
                    line = _public_line(line_buffer)
                    if line:
                        lines.append(line)
                        on_line(line)
                break

            character = str(item)
            line_buffer += character
            prompt_window = (prompt_window + character)[-512:]
            if input_phase == "menu" and _MENU_PROMPT in prompt_window:
                _send(process, "8\n")
                input_phase = "exit"
                prompt_window = ""
            elif input_phase == "exit" and _MENU_PROMPT in prompt_window:
                _send(process, "0\n")
                input_phase = "done"
                prompt_window = ""

            while "\n" in line_buffer:
                raw_line, line_buffer = line_buffer.split("\n", 1)
                line = _public_line(raw_line)
                if line:
                    lines.append(line)
                    del lines[:-30]
                    on_line(line)
        code = process.wait(timeout=3)
        if code != 0:
            raise ReferenceEngineError(
                f"IP 池更新失败（退出码 {code}）：" + "\n".join(lines[-8:])
            )
    finally:
        _stop(process)
