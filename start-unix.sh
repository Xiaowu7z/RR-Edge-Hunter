#!/usr/bin/env sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$SCRIPT_DIR"

for python_bin in python3 python; do
  if command -v "$python_bin" >/dev/null 2>&1 && "$python_bin" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)' >/dev/null 2>&1; then
    if ! command -v go >/dev/null 2>&1; then
      echo "[RR Edge Hunter] 源码运行需要 Go 1.22 或更高版本；正式便携版已内置参考程序。" >&2
      exit 1
    fi
    exec "$python_bin" rr_optimizer.py ui "$@"
  fi
done

echo "[RR Edge Hunter] 需要 Python 3.11 或更高版本。请安装或升级 Python 后重试。" >&2
exit 1
