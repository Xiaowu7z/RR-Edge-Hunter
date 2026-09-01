#!/usr/bin/env python3
from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path, PurePosixPath
import subprocess
import zipfile


ROOT = Path(__file__).resolve().parents[1]
FIXED_ZIP_TIME = (1980, 1, 1, 0, 0, 0)
ROOT_FILES = frozenset({
    "rr_optimizer.py",
    "start-windows.bat",
    "start-unix.sh",
    "README.md",
    "README_EN.md",
    "CHANGELOG.md",
    "NOTICE.md",
    "SECURITY.md",
    "THIRD_PARTY_NOTICES.md",
})
WEB_SUFFIXES = frozenset({".css", ".html", ".js"})


@dataclass(frozen=True)
class ArchiveMember:
    relative: PurePosixPath
    data: bytes
    executable: bool = False


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _git(*args: str) -> bytes:
    try:
        return subprocess.run(
            ["git", "-C", str(ROOT), *args],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ).stdout
    except FileNotFoundError as exc:
        raise RuntimeError("发布构建需要已安装 Git") from exc
    except subprocess.CalledProcessError as exc:
        detail = exc.stderr.decode("utf-8", "replace").strip()
        raise RuntimeError(f"无法读取已提交的发布源码：{detail or 'git 命令失败'}") from exc


def _is_allowed(relative: PurePosixPath) -> bool:
    """Return whether a tracked path is intentionally part of a desktop release.

    This deliberately does not include directories recursively. A future source
    type, generated artifact, key, or an accidentally tracked secret therefore
    cannot silently enter the ZIP without an explicit change here.
    """

    if relative.as_posix() in ROOT_FILES:
        return True
    if len(relative.parts) != 2:
        return relative.as_posix() == "third_party/better-cloudflare-ip/main.go"
    parent, filename = relative.parts
    if parent == "cfopt":
        return filename.endswith(".py")
    if parent == "web":
        return PurePosixPath(filename).suffix in WEB_SUFFIXES
    return False


def _tree_members() -> list[ArchiveMember]:
    """Read allowed regular files from HEAD, never from the working tree."""

    records = _git("ls-tree", "-r", "-z", "--full-tree", "HEAD").split(b"\0")
    members: list[ArchiveMember] = []
    present_root_files: set[str] = set()
    for record in records:
        if not record:
            continue
        header, raw_path = record.split(b"\t", 1)
        mode, object_type, object_id = header.decode("ascii").split()
        relative = PurePosixPath(raw_path.decode("utf-8"))
        if relative.is_absolute() or ".." in relative.parts or not _is_allowed(relative):
            continue
        if object_type != "blob" or mode not in {"100644", "100755"}:
            raise RuntimeError(f"发布文件必须是普通文件：{relative}")
        members.append(ArchiveMember(relative, _git("cat-file", "blob", object_id), mode == "100755"))
        if relative.as_posix() in ROOT_FILES:
            present_root_files.add(relative.as_posix())

    missing = sorted(ROOT_FILES - present_root_files)
    if missing:
        raise FileNotFoundError(f"发布文件缺失：{', '.join(missing)}")
    if not members:
        raise RuntimeError("未找到可发布的已提交源码")
    return sorted(members, key=lambda item: item.relative.as_posix())


def archive_members(version: str) -> list[ArchiveMember]:
    members = _tree_members()
    members.append(ArchiveMember(PurePosixPath("VERSION"), f"{version}\n".encode("utf-8")))
    return sorted(members, key=lambda item: item.relative.as_posix())


def _zip_info(path: PurePosixPath, executable: bool) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(path.as_posix(), date_time=FIXED_ZIP_TIME)
    info.create_system = 3
    info.external_attr = ((0o100755 if executable else 0o100644) << 16)
    info.compress_type = zipfile.ZIP_DEFLATED
    return info


def main() -> int:
    parser = argparse.ArgumentParser(description="Build a reproducible RR Edge Hunter desktop ZIP")
    parser.add_argument("--version", required=True, help="Release version without the v prefix")
    parser.add_argument("--output-dir", type=Path, default=ROOT / "dist")
    args = parser.parse_args()
    version = args.version.strip().lstrip("v")
    if not version or any(char not in "0123456789.-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ" for char in version):
        raise SystemExit("版本号无效")
    args.output_dir.mkdir(parents=True, exist_ok=True)
    basename = f"RR-Edge-Hunter-Desktop-{version}"
    archive = args.output_dir / f"{basename}.zip"
    manifest = args.output_dir / f"{basename}.manifest.json"
    checksum = args.output_dir / f"{basename}.sha256"
    members = archive_members(version)
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as package:
        for member in members:
            package.writestr(
                _zip_info(PurePosixPath(basename) / member.relative, member.executable),
                member.data,
                compress_type=zipfile.ZIP_DEFLATED,
                compresslevel=9,
            )
    metadata = {
        "archive": archive.name,
        "files": [member.relative.as_posix() for member in members],
        "name": basename,
        "runtime_version_file": "VERSION",
        "sha256": sha256(archive),
        "source_revision": _git("rev-parse", "HEAD").decode("ascii").strip(),
        "version": version,
    }
    manifest.write_text(json.dumps(metadata, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    checksum.write_text(f"{metadata['sha256']}  {archive.name}\n", encoding="utf-8")
    print(archive)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
