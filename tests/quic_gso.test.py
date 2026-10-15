#!/usr/bin/env python3
"""Real patched NFQUEUE + HTTP/3, confined to a disposable loopback netns."""
import hashlib
import json
import os
import pathlib
import shutil
import signal
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
from local_env import HTTP3_PYTHON as PYTHON, HTTP3_CURL as CLIENT, NFQWS2_GSO_NATIVE as ENGINE
LIB = ROOT / 'files/usr/lib/zapret2-home'


class PrivateQuicGso(unittest.TestCase):
    def test_real_patched_nfqueue_http3_and_tls_controls(self):
        for path, expected in [
            (CLIENT, '45893c2080d3f54d2428853494b9796bdc88c8d959701a7eb48c01c9b10a84e2'),
            (ENGINE, '622c1782236c2630a1c279f9c6bd0b983aced35db8034dff037a6ac5bc1c0114'),
            (LIB / 'lua/zapret-lib.lua', 'b67a470f23b00a8d6e732c4e5135a39b224511e0b71809d5f4616adf62674980'),
            (LIB / 'lua/zapret-antidpi.lua', '31c9dd75b0bd55e98e5306293f2be81e9d2ecadcbbf9157394ff37dcff7dc85a'),
            (LIB / 'fake/quic-google.bin', 'f4589c57749f956bb30538197a521d7005f8b0a8723b4707e72405e51ddac50a'),
        ]:
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), expected, str(path))
        self.assertIn('HTTP3', subprocess.check_output([str(CLIENT), '-q', '--version'], text=True))
        with tempfile.TemporaryDirectory(prefix='z2-quic-gso-', dir=tempfile.gettempdir()) as tmp:
            work = pathlib.Path(tmp)
            work.chmod(0o755)
            shutil.copyfile(CLIENT, work / 'curl')
            (work / 'curl').chmod(0o755)
            proc = subprocess.Popen([
                'unshare', '--net', str(PYTHON), '-B',
                str(ROOT / 'tests/quic_gso_peer_fixture.py'), os.readlink('/proc/self/ns/net'),
            ], cwd=work, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
            try:
                stdout, stderr = proc.communicate(timeout=45)
            finally:
                if proc.poll() is None:
                    os.killpg(proc.pid, signal.SIGTERM)
                    try:
                        proc.communicate(timeout=8)
                    except subprocess.TimeoutExpired:
                        os.killpg(proc.pid, signal.SIGKILL)
                        proc.communicate()
            self.assertEqual(proc.returncode, 0, stdout + stderr)
            evidence = json.loads(stdout)
            self.assertTrue(evidence['passed'])
            self.assertEqual([r['returncode'] for r in evidence['results']], [0, 60, 60])
            self.assertTrue(all(r['uid'] == 32771 for r in evidence['results']))
            self.assertEqual(evidence['results'][0]['body_sha256'],
                             'ab3f3ade1cde6bd819243505c387b2154d8585a0c8be3b6afc1afe4e49d7a49b')
            self.assertGreater(evidence['callback_count'], 0)
            self.assertGreaterEqual(evidence['fake_packets_captured'], 6)
            self.assertGreater(evidence['fake_log_count'], 0)
            self.assertEqual(evidence['queue_drops'], [0, 0])
            self.assertTrue(evidence['engine_reaped'])
            print(json.dumps(evidence, indent=2))


if __name__ == '__main__':
    unittest.main()
