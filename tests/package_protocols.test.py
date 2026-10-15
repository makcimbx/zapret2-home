#!/usr/bin/env python3
"""Verify actual 0.4.5 archive contents/modes/ELF and all recorded hashes locally."""
import hashlib
import io
import json
import pathlib
import struct
import subprocess
import tarfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


class PackagedProtocols(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        digest, name = (ROOT / 'dist/package.sha256').read_text().split()
        assert name == 'zapret2-home_0.4.5_aarch64_cortex-a53.ipk'
        cls.package = ROOT / 'dist' / name
        assert hashlib.sha256(cls.package.read_bytes()).hexdigest() == digest
        with tarfile.open(cls.package, 'r:gz') as outer:
            control = outer.extractfile('./control.tar.gz').read()
            data = outer.extractfile('./data.tar.gz').read()
        cls.archive = tarfile.open(fileobj=io.BytesIO(data), mode='r:gz')
        with tarfile.open(fileobj=io.BytesIO(control), mode='r:gz') as archive:
            cls.control = archive.extractfile('./control').read().decode()

    @classmethod
    def tearDownClass(cls):
        cls.archive.close()

    def body(self, name):
        return self.archive.extractfile('./' + name).read()

    def test_all_packaged_files_match_recorded_and_current_source(self):
        manifest = json.loads((ROOT / 'dist/files-manifest.json').read_text())
        modes = json.loads((ROOT / 'dist/file-modes.json').read_text())
        names = {member.name.removeprefix('./') for member in self.archive.getmembers() if member.isfile()}
        self.assertEqual(set(manifest), names)
        self.assertEqual(set(modes), names)
        for name, digest in manifest.items():
            with self.subTest(name=name):
                self.assertEqual(hashlib.sha256(self.body(name)).hexdigest(), digest)
                self.assertEqual(hashlib.sha256((ROOT / 'files' / name).read_bytes()).hexdigest(), digest)
                self.assertEqual(format(self.archive.getmember('./' + name).mode, 'o'), modes[name])

    def test_new_payloads_are_in_runtime_integrity_manifest(self):
        records = {}
        for line in self.body('usr/lib/zapret2-home/SHA256SUMS').decode().splitlines():
            digest, name = line.split()
            records[name] = digest
        for name in ('protocols.uc', 'protocol-catalog.json', 'stun-probe', 'curl-http3', 'nfqws2-quic', 'fake/quic-google.bin', 'fake/discord-ip-discovery-without-port.bin', 'fake/stun.bin'):
            self.assertIn(name, records)
            self.assertEqual(hashlib.sha256(self.body('usr/lib/zapret2-home/' + name)).hexdigest(), records[name])
        self.assertEqual(records['fake/quic-google.bin'], 'f4589c57749f956bb30538197a521d7005f8b0a8723b4707e72405e51ddac50a')
        self.assertEqual(records['curl-http3'], 'a5b0f6cde4b0e0d6be09bd92ee24fc63f8a3cb20810bc3dc531ee33f0a2d8ae9')
        self.assertEqual(records['fake/discord-ip-discovery-without-port.bin'], '3f63c3a0cc63b90a6a8c50ffc61a32cc7d1f1b60457a96b90719256744df0e96')
        self.assertEqual(records['fake/stun.bin'], '9cd5469309780ca56c0bd97266524a48c7ee529d02c3179cfecb20b260a59641')

    def test_native_helpers_are_executable_static_aarch64(self):
        for name in ('nfqws2', 'nfqws2-quic', 'stun-probe', 'curl-http3'):
            path = 'usr/lib/zapret2-home/' + name
            self.assertEqual(self.archive.getmember('./' + path).mode, 0o755)
            elf = self.body(path)
            self.assertEqual(elf[:6], b'\x7fELF\x02\x01')
            self.assertEqual(struct.unpack_from('<H', elf, 18)[0], 183)
            headers = subprocess.check_output(['readelf', '-l', str(ROOT / 'files' / path)], text=True)
            self.assertNotIn('INTERP', headers)

    def test_quic_diagnostic_engine_is_pinned_and_main_engine_unchanged(self):
        private = 'usr/lib/zapret2-home/nfqws2-quic'
        self.assertEqual(hashlib.sha256(self.body(private)).hexdigest(), '5a40e3e823082a5788c7bc7d4e78ed9d2d5c6edb37f4580e300700694adac23b')
        self.assertEqual(hashlib.sha256(self.body('usr/lib/zapret2-home/nfqws2')).hexdigest(), '8788877cd4b3140357dd10524832ca508d47055efae072bc426b887bfea253a7')
        provenance = json.loads(self.body('usr/share/zapret2-home/quic-diagnostic-engine.json'))
        self.assertEqual(provenance['sha256'], hashlib.sha256(self.body(private)).hexdigest())
        self.assertFalse(provenance['main_engine_replaced'])
        self.assertEqual(provenance['extra_argument'], '--reasm-disable=quic_initial')
        patch = self.body('usr/share/licenses/zapret2-home/quic-diagnostics/nfqa-gso.patch')
        self.assertEqual(provenance['patch_sha256'], hashlib.sha256(patch).hexdigest())
        self.assertIn(b'NFQA_CFG_F_FAIL_OPEN | NFQA_CFG_F_GSO', patch)
        for name in ('nfqws2-MIT', 'LuaJIT-COPYRIGHT', 'libmnl-COPYING', 'libnetfilter_queue-COPYING', 'libnfnetlink-COPYING', 'zlib-LICENSE', 'LGPL-2.1', 'SOURCE-NOTICE.txt'):
            self.assertGreater(len(self.body('usr/share/licenses/zapret2-home/quic-diagnostics/' + name)), 100)

    def test_fresh_install_defaults_keep_new_protocols_off(self):
        config = self.body('etc/config/zapret2_home').decode()
        self.assertIn("option tcp_enabled '1'", config)
        self.assertIn("option quic_enabled '0'", config)
        self.assertIn("option udp_enabled '0'", config)
        self.assertIn('Version: 0.4.5\n', self.control)
        self.assertNotIn('python', self.control.lower())

    def test_private_http3_client_preserves_system_curl_and_ships_notices(self):
        names = {member.name.removeprefix('./') for member in self.archive.getmembers() if member.isfile()}
        self.assertNotIn('usr/bin/curl', names)
        self.assertNotIn('usr/lib/libcurl.so', names)
        provenance = json.loads(self.body('usr/share/zapret2-home/http3-client.json'))
        self.assertEqual(provenance['sha256'], hashlib.sha256(self.body('usr/lib/zapret2-home/curl-http3')).hexdigest())
        self.assertEqual(provenance['ca_bundle'], '/etc/ssl/certs/ca-certificates.crt')
        for name in ('curl', 'openssl', 'ngtcp2', 'nghttp3', 'LGPL-3.0', 'musl-COPYRIGHT', 'GCC-RUNTIME-EXCEPTION', 'SOURCE-NOTICE.txt'):
            self.assertGreater(len(self.body('usr/share/licenses/zapret2-home/http3/' + name)), 100)


if __name__ == '__main__':
    unittest.main()
