#!/usr/bin/env python3
"""Pinned curl: real HTTP/3 and certificate failures, loopback-only private namespace."""
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
from local_env import HTTP3_CURL, HTTP3_PYTHON as PYTHON


class PrivateHttp3Client(unittest.TestCase):
    def test_pinned_binary_features_and_real_quic_tls_validation(self):
        client = HTTP3_CURL
        self.assertEqual(hashlib.sha256(client.read_bytes()).hexdigest(),
                         '45893c2080d3f54d2428853494b9796bdc88c8d959701a7eb48c01c9b10a84e2')
        version = subprocess.check_output([str(client), '-q', '--version'], text=True)
        self.assertIn('HTTP3', version)
        with tempfile.TemporaryDirectory(prefix='z2-http3-client-', dir=tempfile.gettempdir()) as tmp:
            work = pathlib.Path(tmp)
            work.chmod(0o755)
            shutil.copyfile(client, work / 'curl')
            (work / 'curl').chmod(0o755)
            # UID32771 is private to this loopback fixture, not the shared diagnostic UID1.
            result = subprocess.run(['unshare', '--net', '/bin/sh', '-c',
                'ip link set lo up; exec "$1" "$2"', 'http3-fixture', str(PYTHON),
                str(ROOT / 'tests/http3_peer_fixture.py')], cwd=work, capture_output=True, text=True, timeout=40)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            evidence = json.loads(result.stdout)
            self.assertTrue(evidence['passed'])
            self.assertEqual([r['returncode'] for r in evidence['results']], [0, 60, 60])
            self.assertIn('HTTP_VERSION=3 CODE=200 SSL_VERIFY=0', evidence['results'][0]['stdout'])
            self.assertTrue(all(r['uid'] == 32771 for r in evidence['results']))


if __name__ == '__main__':
    unittest.main()
