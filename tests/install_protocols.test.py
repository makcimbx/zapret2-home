#!/usr/bin/env python3
"""Native ucode verification of installer branch preservation, no router calls."""
import copy
import os
import json
import pathlib
import re
import shlex
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import install

from local_env import UCODE, MODULES


class ProtocolUpgrade(unittest.TestCase):
    def test_ssh_transport_preserves_short_binary_and_script_inputs(self):
        for command, data, target, expected in [
            ('printf short', None, 'printf short', None),
            ('dd of=/private/package.ipk', b'\x00\xff\n', 'dd of=/private/package.ipk', b'\x00\xff\n'),
            ('set -eu\n' + '# protected script\n' * 2000, None, 'sh -s', ('set -eu\n' + '# protected script\n' * 2000).encode()),
            ('printf binary\n', b'abc', 'printf binary\n', b'abc')]:
            with self.subTest(command=target), patch.object(install.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, b'ok', b'')) as call:
                self.assertEqual(install.run(command, data, timeout=17), 'ok')
                call.assert_called_once_with(install.SSH+[target], input=expected, capture_output=True, timeout=17)
        with patch.object(install.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1, b'', b'failure')):
            with self.assertRaisesRegex(RuntimeError, 'failure'):
                install.run('set -eu\nfalse')

    @classmethod
    def setUpClass(cls):
        script = install.upgrade_script({}, True, '/private/package.ipk', 'a' * 64, '0.3.0')
        matches = re.findall(r'let defaults=.*?exit\(1\); \}', script)
        assert len(matches) == 2, matches
        assert matches[0] == matches[1]
        cls.expression = matches[0]

    def accepts(self, before, after):
        source = 'let a=json(ARGV[0]),b=json(ARGV[1]); ' + self.expression
        return subprocess.run([str(UCODE), '-e', source, json.dumps(before), json.dumps(after)], capture_output=True, text=True).returncode == 0

    def test_legacy_defaults_preserved(self):
        before = {'profile_id': 'alt1'}
        after = {'profile_id': 'alt1', 'protocols': {'tcp': {'enabled': True, 'profile': 'alt1'}, 'quic': {'enabled': False, 'profile': 'quic_google'}, 'udp': {'enabled': False, 'profile': 'udp_fake2'}}}
        self.assertTrue(self.accepts(before, after))
        after['protocols']['quic']['enabled'] = True
        self.assertFalse(self.accepts(before, after))

    def test_each_enabled_and_profile_field_is_preserved(self):
        before = {'profile_id': 'stock', 'protocols': {'tcp': {'enabled': False, 'profile': 'stock'}, 'quic': {'enabled': True, 'profile': 'quic_zero'}, 'udp': {'enabled': True, 'profile': 'udp_fake6'}}}
        self.assertTrue(self.accepts(before, copy.deepcopy(before)))
        for group in ('tcp', 'quic', 'udp'):
            for field in ('enabled', 'profile'):
                with self.subTest(group=group, field=field):
                    after = copy.deepcopy(before)
                    after['protocols'][group][field] = not after['protocols'][group][field] if field == 'enabled' else 'changed'
                    self.assertFalse(self.accepts(before, after))

    def test_new_status_requires_all_groups_and_real_types(self):
        before = {'profile_id': 'alt1'}
        good = {'profile_id': 'alt1', 'protocols': {'tcp': {'enabled': True, 'profile': 'alt1'}, 'quic': {'enabled': False, 'profile': 'quic_google'}, 'udp': {'enabled': False, 'profile': 'udp_fake2'}}}
        self.assertFalse(self.accepts(before, {'profile_id': 'alt1'}))
        for group in ('tcp', 'quic', 'udp'):
            with self.subTest(group=group, field='missing'):
                after = copy.deepcopy(good)
                del after['protocols'][group]
                self.assertFalse(self.accepts(before, after))
            for field, value in (('enabled', 0), ('enabled', 'false'), ('profile', None)):
                with self.subTest(group=group, field=field, value=value):
                    after = copy.deepcopy(good)
                    after['protocols'][group][field] = value
                    self.assertFalse(self.accepts(before, after))

    def test_missing_nondefault_saved_branch_fails(self):
        before = {'profile_id': 'alt1', 'protocols': {'tcp': {'enabled': True, 'profile': 'alt1'}, 'quic': {'enabled': True, 'profile': 'quic_zero'}, 'udp': {'enabled': False, 'profile': 'udp_fake2'}}}
        self.assertFalse(self.accepts(before, {'profile_id': 'alt1'}))


    def test_file_modes_checked_before_restore_and_finish(self):
        with tempfile.TemporaryDirectory(prefix='z2-modes-', dir=tempfile.gettempdir()) as name:
            binary = pathlib.Path(name) / 'helper'
            binary.write_text('fixture')
            key = str(binary).lstrip('/')
            script = install.upgrade_script({key: 'a' * 64}, True, '/private/package.ipk', 'b' * 64, '0.3.0', modes={key: '755'})
            check = next(line for line in script.splitlines() if line.startswith(install.MODE_CHECK+' '))
            self.assertLess(script.index(check), script.index('restore-begin'))
            self.assertLess(script.index(check), script.index('finish'))
            check = check.replace('ucode -e', shlex.quote(str(UCODE))+' -L '+shlex.quote(str(MODULES))+' -e', 1)
            env = dict(os.environ, PATH=name)
            binary.chmod(0o755)
            self.assertEqual(subprocess.run(['/bin/sh', '-c', check], env=env).returncode, 0)
            binary.chmod(0o644)
            self.assertNotEqual(subprocess.run(['/bin/sh', '-c', check], env=env).returncode, 0)
            binary.chmod(0o4755)
            self.assertNotEqual(subprocess.run(['/bin/sh', '-c', check], env=env).returncode, 0)
            binary.unlink()
            self.assertNotEqual(subprocess.run(['/bin/sh', '-c', check], env=env).returncode, 0)
        for modes in ({}, {'x': '755;false'}, {'x': 755}):
            with self.subTest(modes=modes), self.assertRaises(ValueError):
                install.upgrade_script({'x': 'a' * 64}, True, '/private/package.ipk', 'b' * 64, '0.3.0', modes=modes)


if __name__ == '__main__':
    unittest.main()
