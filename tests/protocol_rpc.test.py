#!/usr/bin/env python3
"""Real shell RPC dispatch/ACL contract; relocated helpers are explicit I/O doubles.
No router, ubus authentication claim, service changes or network access.
"""
import json
import os
import pathlib
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
RPC = ROOT / 'files/usr/libexec/rpcd/zapret2_home'
ACL = ROOT / 'files/usr/share/rpcd/acl.d/luci-app-zapret2-home.json'


class ProtocolRpc(unittest.TestCase):
    def test_advertised_signatures_match_contract(self):
        result = subprocess.run(['sh', str(RPC), 'list'], check=True, capture_output=True, text=True)
        methods = json.loads(result.stdout)
        self.assertEqual(methods['protocols_catalog'], {})
        self.assertEqual(methods['protocols_status'], {})
        self.assertEqual(methods['protocols_test'], {'protocol': 'str', 'profiles': 'str', 'targets': 'str', 'repeat': 1})
        self.assertEqual(methods['protocols_apply'], {'protocol': 'str', 'enabled': False, 'profile': 'str'})
        self.assertEqual(methods['profiles_apply'], {'profile': 'str'})
        self.assertEqual(set(methods['configure']), {'clients', 'destinations', 'autostart', 'client_mode', 'lists', 'auto_update'})

    def test_acl_is_narrow_and_complete(self):
        acl = json.loads(ACL.read_text())['luci-app-zapret2-home']
        read = set(acl['read']['ubus']['zapret2_home'])
        write = set(acl['write']['ubus']['zapret2_home'])
        advertised = json.loads(subprocess.check_output(['sh', str(RPC), 'list']))
        self.assertEqual(read & write, set())
        self.assertEqual(read | write, set(advertised))
        self.assertTrue({'protocols_catalog', 'protocols_status'} <= read)
        self.assertTrue({'protocols_test', 'protocols_apply'} <= write)
        self.assertNotIn('file', acl['read'])
        self.assertNotIn('file', acl['write'])
        self.assertNotIn('uci', acl['write'])

    def test_fixed_routes_forward_original_payload_unchanged(self):
        routes = {
            'protocols_catalog': ('profiles', 'protocols-catalog'),
            'protocols_status': ('profiles', 'protocols-status'),
            'protocols_test': ('profiles', 'protocols-test'),
            'protocols_apply': ('ctl', 'protocols-apply'),
            'profiles_catalog': ('profiles', 'catalog'),
            'profiles_status': ('profiles', 'status'),
            'profiles_test': ('profiles', 'test'),
            'profiles_apply': ('ctl', 'profiles-apply'),
        }
        with tempfile.TemporaryDirectory(prefix='z2-rpc-', dir=tempfile.gettempdir()) as name:
            directory = pathlib.Path(name)
            source = RPC.read_text()
            helper = '#!/usr/bin/env python3\nimport json,pathlib,sys\nprint(json.dumps({"helper":pathlib.Path(sys.argv[0]).name,"args":sys.argv[1:],"payload":sys.stdin.read()}))\n'
            for kind in ('ctl', 'profiles'):
                path = directory / kind
                path.write_text(helper)
                path.chmod(0o755)
                source = source.replace('/usr/libexec/zapret2-home-' + kind, str(path))
            staged = directory / 'rpc'
            staged.write_text(source)
            payload = json.dumps({'protocol': 'quic', 'enabled': True, 'profile': 'quic_google', 'ubus_rpc_session': 'a' * 32, 'unknown': "$(touch never); ' \""}) + '\n'
            for method, (kind, command) in routes.items():
                with self.subTest(method=method):
                    response = subprocess.run(['sh', str(staged), 'call', method], input=payload, capture_output=True, text=True, check=True)
                    value = json.loads(response.stdout)
                    self.assertEqual(value, {'helper': kind, 'args': [command], 'payload': payload})
            response = subprocess.run(['sh', str(staged), 'call', 'protocols_test;echo BAD'], input=payload, capture_output=True, text=True, check=True)
            self.assertEqual(json.loads(response.stdout)['ok'], False)


if __name__ == '__main__':
    unittest.main()
