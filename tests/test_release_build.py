from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from pathlib import PurePosixPath

from tools.build_portable_release import _install_reference_engine
from tools.build_release import _is_allowed


ROOT = Path(__file__).resolve().parents[1]
BUILD = ROOT / "tools" / "build_release.py"
ZIP_TIME = (1980, 1, 1, 0, 0, 0)


class ReleaseBuildTest(unittest.TestCase):
    def _build(self, output_dir: Path, version: str) -> Path:
        subprocess.run(
            [sys.executable, str(BUILD), "--version", version, "--output-dir", str(output_dir)],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
        return output_dir / f"RR-Edge-Hunter-Desktop-{version}.zip"

    def test_release_is_reproducible_and_excludes_untracked_files(self) -> None:
        version = "9.8.7"
        untracked_secret = ROOT / "web" / ".release-build-test-secret.pem"
        untracked_secret.write_text("must not ship\n", encoding="utf-8")
        try:
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                first = self._build(root / "one", version)
                second = self._build(root / "two", version)
                self.assertEqual(first.read_bytes(), second.read_bytes())

                with zipfile.ZipFile(first) as package:
                    names = package.namelist()
                    self.assertEqual(names, sorted(names))
                    self.assertNotIn(f"RR-Edge-Hunter-Desktop-{version}/web/{untracked_secret.name}", names)
                    self.assertEqual(package.read(f"RR-Edge-Hunter-Desktop-{version}/VERSION"), b"9.8.7\n")
                    self.assertTrue(all(info.date_time == ZIP_TIME for info in package.infolist()))
        finally:
            untracked_secret.unlink(missing_ok=True)

    def test_source_package_allows_only_the_pinned_reference_file(self) -> None:
        self.assertTrue(_is_allowed(PurePosixPath("third_party/better-cloudflare-ip/main.go")))
        self.assertFalse(_is_allowed(PurePosixPath("third_party/better-cloudflare-ip/modified.go")))
        self.assertFalse(_is_allowed(PurePosixPath("runtime/better-cloudflare-ip.exe")))

    def test_portable_engine_is_installed_under_pyinstaller_resources(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle = root / "bundle"
            (bundle / "_internal").mkdir(parents=True)
            engine = root / "better-cloudflare-ip.exe"
            engine.write_bytes(b"reference-engine-test")
            digest = _install_reference_engine(bundle, engine)
            installed = bundle / "_internal" / "reference-engine" / engine.name
            self.assertEqual(installed.read_bytes(), engine.read_bytes())
            self.assertEqual(len(digest), 64)


if __name__ == "__main__":
    unittest.main()
