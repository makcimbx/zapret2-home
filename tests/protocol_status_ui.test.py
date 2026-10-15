#!/usr/bin/env python3
"""Real saved router history -> native ucode -> unchanged browser status validator."""
import copy
import json
import os
import pathlib
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
from local_env import UCODE, MODULES as MODULE
VIEW = ROOT / 'files/www/luci-static/resources/view/services/zapret2home.js'
VALIDATE = r"""
const fs = require('node:fs'), vm = require('node:vm');
const source = fs.readFileSync(process.argv[1], 'utf8');
const context = { _: x => x, requireOK: reply => { if (reply.ok !== true) throw Error('RPC error'); } };
vm.createContext(context);
vm.runInContext(source.slice(source.indexOf('var profileIds ='), source.indexOf('function savedProtocol')), context);
context.checkedProfilesStatus(JSON.parse(fs.readFileSync(0, 'utf8')));
"""


class HistoryUI(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='z2-history-ui-', dir=tempfile.gettempdir())
        self.addCleanup(self.tmp.cleanup)
        self.base = pathlib.Path(self.tmp.name)
        self.run = self.base / 'profiles'
        self.run.mkdir()
        source = (ROOT / 'files/usr/lib/zapret2-home/profiles.uc').read_text()
        source = source.replace("const RUN = '/var/run/zapret2-home/profiles';", f"const RUN = '{self.run}';")
        source = source.replace("const MAIN = '/var/run/zapret2-home';", f"const MAIN = '{self.base}';")
        source = source.replace("const CATALOG = '/usr/lib/zapret2-home/profile-catalog.json';", f"const CATALOG = '{ROOT / 'files/usr/lib/zapret2-home/profile-catalog.json'}';")
        self.uc = self.base / 'profiles.uc'
        self.uc.write_text(source)
        self.legacy = json.loads((ROOT / 'tests/fixtures/protocols-status-legacy-router.json').read_text())

    def response(self, saved, command='protocols-status'):
        path = self.run / 'result'
        path.write_text(json.dumps(saved))
        original = path.read_bytes()
        output = subprocess.check_output([UCODE, '-L', MODULE, str(self.uc), command], timeout=10)
        self.assertEqual(path.read_bytes(), original, 'Status reads must not rewrite stored evidence')
        return json.loads(output)

    def check_ui(self, reply, accepted=True):
        result = subprocess.run(['node', '-e', VALIDATE, str(VIEW)], input=json.dumps(reply), text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode == 0, accepted, result.stderr)

    def test_sanitized_legacy_history_is_consumable_without_mutating_input(self):
        self.assertNotIn('protocol', self.legacy)
        self.assertEqual(len(self.legacy['results']), 30)
        reply = self.response(self.legacy)
        self.check_ui(reply)
        self.assertNotIn('plan', reply['data'], 'Do not invent an acknowledged plan')
        for before, after in zip(self.legacy['results'], reply['data']['results']):
            self.assertEqual(after, dict(before, protocol='tcp'))
        broken = copy.deepcopy(reply)
        for row in broken['data']['results']:
            del row['protocol']
        self.check_ui(broken, accepted=False)
        self.check_ui(self.response(self.legacy, 'status'))

    def test_legacy_plan_is_tagged_only_when_present(self):
        saved = dict(self.legacy, plan=dict(profiles=['alt1'], targets=['gitlab'], repeat=1))
        reply = self.response(saved)
        self.assertEqual(reply['data']['plan'], dict(saved['plan'], protocol='tcp'))
        self.check_ui(reply)

    def test_actual_generated_plans_survive_pending_running_and_completed_status(self):
        control = self.base / 'control.lock'
        control.mkdir()
        (control / 'pid').write_text(str(os.getpid()))
        def native(*args):
            return subprocess.check_output([UCODE, '-L', MODULE, str(self.uc), *map(str, args)], timeout=10)
        for protocol, profiles, targets in [('tcp', 'alt1 stock', 'gitlab unitask'), ('quic', 'quic_google quic_zero', 'youtube_h3'), ('udp', 'udp_fake2 udp_fake6', 'stun_google')]:
            with self.subTest(protocol=protocol):
                job = native('acquire', os.getpid(), protocol).decode().strip()
                native('plan', job, protocol, profiles, targets, 2)
                for state in ['pending', 'running', 'results']:
                    native('state', job, state)
                    stored = (self.run / 'result').read_bytes()
                    self.assertEqual(json.loads(stored)['plan']['profiles'], profiles)
                    self.assertEqual(json.loads(stored)['plan']['targets'], targets)
                    for command in ['protocols-status', 'status']:
                        reply = json.loads(native(command))
                        if command == 'protocols-status' or protocol == 'tcp':
                            self.check_ui(reply)
                            self.assertEqual(reply['data']['plan'], dict(protocol=protocol, profiles=profiles.split(), targets=targets.split(), repeat=2))
                        else:
                            self.assertEqual(reply['data']['results'], [])
                            self.assertNotIn('plan', reply['data'])
                    self.assertEqual((self.run / 'result').read_bytes(), stored)
                native('release', job, os.getpid())
                self.check_ui(json.loads(native('protocols-status')))
                import shutil
                shutil.rmtree(self.run / job)

    def test_plan_conversion_preserves_invalid_values_for_frontend_rejection(self):
        base = dict(self.legacy, protocol='tcp', results=[])
        for profiles, targets in [('alt1 alt1', 'gitlab'), ('untrusted', 'gitlab'), ('', 'gitlab'), ('alt1', 'untrusted'), ('alt1', 'gitlab gitlab')]:
            saved = dict(base, plan=dict(protocol='tcp', profiles=profiles, targets=targets, repeat=1))
            self.check_ui(self.response(saved), accepted=False)

    def test_modern_or_conflicting_missing_tags_and_unknown_ids_remain_rejected(self):
        modern = dict(self.legacy, protocol='tcp', results=[dict(self.legacy['results'][0], protocol='tcp')])
        self.check_ui(self.response(modern))
        self.check_ui(self.response(dict(self.legacy, protocol='tcp')), accepted=False)
        for change in [dict(protocol='udp'), dict(profile='quic_google'), dict(target='stun_google')]:
            saved = copy.deepcopy(self.legacy)
            saved['results'][0].update(change)
            reply = self.response(saved)
            self.check_ui(reply, accepted=False)
            for key, value in change.items():
                self.assertEqual(reply['data']['results'][0][key], value)


if __name__ == '__main__':
    unittest.main()
