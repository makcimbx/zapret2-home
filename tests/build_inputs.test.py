#!/usr/bin/env python3
"""Source-only checks for the build's runtime trust boundary; never compile/install."""
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


class BuildInputs(unittest.TestCase):
    def test_missing_and_tampered_runtime_fail_before_build(self):
        with tempfile.TemporaryDirectory(prefix='z2-input-test-') as directory:
            root = pathlib.Path(directory)
            shutil.copy2(ROOT / 'build.py', root / 'build.py')
            shutil.copy2(ROOT / 'runtime-pins.json', root / 'runtime-pins.json')
            ctl = root / 'files/usr/libexec/zapret2-home-ctl'
            ctl.parent.mkdir(parents=True)
            ctl.write_text("package_version '0.4.5'\n")
            result = subprocess.run([sys.executable, root / 'build.py'], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('Missing runtime asset: nfqws2', result.stderr)
            asset = root / 'files/usr/lib/zapret2-home/nfqws2'
            asset.parent.mkdir(parents=True)
            asset.write_bytes(b'not a trusted runtime')
            # Python -O must not bypass the integrity check.
            result = subprocess.run([sys.executable, '-O', root / 'build.py'], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('Runtime pin mismatch: nfqws2', result.stderr)
            self.assertFalse((root / 'dist').exists())

    def test_tracked_lua_matches_runtime_pins(self):
        pins = json.loads((ROOT / 'runtime-pins.json').read_text())
        import hashlib
        for name, digest in pins.items():
            if name.startswith('lua/'):
                with self.subTest(name=name):
                    self.assertEqual(hashlib.sha256((ROOT / 'files/usr/lib/zapret2-home' / name).read_bytes()).hexdigest(), digest)


if __name__ == '__main__':
    unittest.main()
