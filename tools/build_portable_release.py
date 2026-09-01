#!/usr/bin/env python3
"""Build a self-contained PyInstaller desktop bundle from committed source.

The release workflow runs this on a Windows runner to produce a portable ZIP
that contains ``CF-IP-Optimizer.exe`` and its private runtime directory.  No
locally installed Python is needed by an end user.  The builder reads a Git
archive of HEAD rather than the working tree, so stray local files and secrets
cannot become part of a release by accident.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile
import zipfile


ROOT = Path(__file__).resolve().parents[1]
APP_NAME = "CF-IP-Optimizer"
WINDOWS_TARGET = "Windows-x64"
LINUX_TARGET = "Linux-x64"
FIXED_ZIP_TIME = (1980, 1, 1, 0, 0, 0)


def _git(*args: str) -> bytes:
    try:
        return subprocess.run(
            ["git", "-C", str(ROOT), *args],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ).stdout
    except FileNotFoundError as exc:
        raise RuntimeError("便携版构建需要已安装 Git") from exc
    except subprocess.CalledProcessError as exc:
        detail = exc.stderr.decode("utf-8", "replace").strip()
        raise RuntimeError(f"无法读取已提交的发布源码：{detail or 'git 命令失败'}") from exc


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _valid_version(value: str) -> str:
    version = value.strip().lstrip("v")
    allowed = "0123456789.-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    if not version or any(char not in allowed for char in version):
        raise ValueError("版本号无效")
    return version


def _host_target() -> str:
    if sys.platform == "win32":
        return WINDOWS_TARGET
    if sys.platform.startswith("linux"):
        return LINUX_TARGET
    raise RuntimeError(f"当前平台暂不支持 PyInstaller 便携包：{platform.system() or sys.platform}")


def _safe_relative(name: str) -> PurePosixPath:
    relative = PurePosixPath(name)
    if relative.is_absolute() or ".." in relative.parts:
        raise RuntimeError(f"Git archive 中存在不安全路径：{name}")
    return relative


def _export_head(destination: Path) -> None:
    """Extract only ordinary tracked files from HEAD into a private staging tree."""

    archive_bytes = _git("archive", "--format=tar", "HEAD")
    with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:") as archive:
        for member in archive.getmembers():
            relative = _safe_relative(member.name)
            target = destination.joinpath(*relative.parts)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            if not member.isfile():
                raise RuntimeError(f"发布源码不允许包含非普通文件：{member.name}")
            target.parent.mkdir(parents=True, exist_ok=True)
            source = archive.extractfile(member)
            if source is None:
                raise RuntimeError(f"无法读取发布源码：{member.name}")
            with target.open("wb") as stream:
                shutil.copyfileobj(source, stream)
            target.chmod(member.mode & 0o777)


def _zip_info(name: PurePosixPath, executable: bool) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name.as_posix(), date_time=FIXED_ZIP_TIME)
    info.create_system = 3
    info.external_attr = ((0o100755 if executable else 0o100644) << 16)
    info.compress_type = zipfile.ZIP_DEFLATED
    return info


def _archive_directory(source: Path, root_name: str, destination: Path) -> None:
    with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as package:
        for path in sorted(source.rglob("*"), key=lambda item: item.relative_to(source).as_posix()):
            if not path.is_file():
                continue
            relative = PurePosixPath(root_name) / PurePosixPath(path.relative_to(source).as_posix())
            executable = path.suffix.lower() in {".exe", ".cmd", ".bat", ".sh"} or os.access(path, os.X_OK)
            package.writestr(_zip_info(relative, executable), path.read_bytes(), compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)


def _run_pyinstaller(source_root: Path, staging_root: Path) -> Path:
    version_file = source_root / "VERSION"
    web_dir = source_root / "web"
    entrypoint = source_root / "rr_optimizer.py"
    if not web_dir.is_dir() or not entrypoint.is_file():
        raise RuntimeError("发布源码缺少桌面入口或网页资源")
    command = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--clean",
        "--onedir",
        "--name",
        APP_NAME,
        "--distpath",
        str(staging_root / "dist"),
        "--workpath",
        str(staging_root / "work"),
        "--specpath",
        str(staging_root / "spec"),
        "--add-data",
        f"{web_dir}{os.pathsep}web",
        "--add-data",
        f"{version_file}{os.pathsep}.",
        str(entrypoint),
    ]
    try:
        subprocess.run(command, cwd=source_root, check=True)
    except FileNotFoundError as exc:
        raise RuntimeError("未找到 Python；无法运行 PyInstaller") from exc
    except subprocess.CalledProcessError as exc:
        raise RuntimeError("PyInstaller 未能生成便携程序") from exc
    bundle = staging_root / "dist" / APP_NAME
    executable = bundle / f"{APP_NAME}{'.exe' if sys.platform == 'win32' else ''}"
    if not executable.is_file():
        raise RuntimeError("PyInstaller 未生成应用程序入口")
    return bundle


def _write_user_guide(bundle: Path, target: str, version: str) -> None:
    executable = f"{APP_NAME}{'.exe' if target == WINDOWS_TARGET else ''}"
    guide = (
        "CF 优选IP（RR Edge Hunter）便携版\n"
        f"版本：{version}\n\n"
        "使用方法：\n"
        f"1. 保持本文件与 {executable} 及 _internal 文件夹在同一目录。\n"
        f"2. 双击 {executable}。\n"
        "3. 程序会自动在默认浏览器打开本机界面；测速记录只保存在本机。\n\n"
        "此版本已内置 Python 与 Xray 运行环境，无需安装。\n"
        "请不要单独移动或删除 _internal、xray 文件夹。\n"
    )
    (bundle / "使用说明.txt").write_text(guide, encoding="utf-8")


def _install_xray_runtime(bundle: Path, executable: Path, license_file: Path) -> str:
    if not executable.is_file() or executable.name.lower() != "xray.exe":
        raise RuntimeError("便携版缺少经过校验的 xray.exe")
    if not license_file.is_file():
        raise RuntimeError("便携版缺少 Xray-core LICENSE")
    runtime = bundle / "xray"
    runtime.mkdir(parents=True, exist_ok=True)
    shutil.copy2(executable, runtime / "xray.exe")
    shutil.copy2(license_file, runtime / "Xray-core-LICENSE.txt")
    return _sha256(runtime / "xray.exe")


def main() -> int:
    parser = argparse.ArgumentParser(description="Build a self-contained RR Edge Hunter portable desktop ZIP")
    parser.add_argument("--version", required=True, help="Release version with or without the v prefix")
    parser.add_argument("--target", choices=("auto", WINDOWS_TARGET, LINUX_TARGET), default="auto")
    parser.add_argument("--output-dir", type=Path, default=ROOT / "dist")
    parser.add_argument("--xray-exe", type=Path, help="Pinned official Xray Windows executable")
    parser.add_argument("--xray-license", type=Path, help="Xray-core license file from the same archive")
    args = parser.parse_args()

    try:
        version = _valid_version(args.version)
        host_target = _host_target()
    except (RuntimeError, ValueError) as exc:
        raise SystemExit(str(exc)) from exc
    target = host_target if args.target == "auto" else args.target
    if target != host_target:
        raise SystemExit(f"{target} 只能在对应平台构建；当前为 {host_target}")
    if target == WINDOWS_TARGET and (args.xray_exe is None or args.xray_license is None):
        raise SystemExit("Windows 便携版必须提供经过校验的 --xray-exe 与 --xray-license")
    try:
        import PyInstaller  # noqa: F401
    except ModuleNotFoundError as exc:
        raise SystemExit("缺少 PyInstaller；请先执行 python -m pip install pyinstaller") from exc

    args.output_dir.mkdir(parents=True, exist_ok=True)
    archive = args.output_dir / f"{APP_NAME}-{target}.zip"
    manifest = args.output_dir / f"{APP_NAME}-{target}.manifest.json"
    checksum = args.output_dir / f"{APP_NAME}-{target}.sha256"
    with tempfile.TemporaryDirectory(prefix="rr-edge-hunter-portable-") as temporary:
        staging_root = Path(temporary)
        source_root = staging_root / "source"
        source_root.mkdir()
        _export_head(source_root)
        (source_root / "VERSION").write_text(f"{version}\n", encoding="utf-8")
        bundle = _run_pyinstaller(source_root, staging_root)
        xray_sha256 = ""
        if target == WINDOWS_TARGET:
            xray_sha256 = _install_xray_runtime(bundle, args.xray_exe.resolve(), args.xray_license.resolve())
        _write_user_guide(bundle, target, version)
        _archive_directory(bundle, APP_NAME, archive)

    executable = f"{APP_NAME}{'.exe' if target == WINDOWS_TARGET else ''}"
    metadata = {
        "archive": archive.name,
        "entrypoint": f"{APP_NAME}/{executable}",
        "name": APP_NAME,
        "platform": target,
        "sha256": _sha256(archive),
        "source_revision": _git("rev-parse", "HEAD").decode("ascii").strip(),
        "version": version,
        "xray_sha256": xray_sha256,
        "xray_version": "v26.7.28" if xray_sha256 else "",
    }
    manifest.write_text(json.dumps(metadata, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    checksum.write_text(f"{metadata['sha256']}  {archive.name}\n", encoding="utf-8")
    print(archive)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
