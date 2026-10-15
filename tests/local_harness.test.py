#!/usr/bin/env python3
"""Portable path resolution and gate failure reporting; no router access."""
import ast
import contextlib
import hashlib
import io
import json
import os
import pathlib
import re
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

from local_env import executable

ROOT = pathlib.Path(__file__).resolve().parents[1]


class LocalHarness(unittest.TestCase):
    def test_path_defaults_and_environment_override(self):
        with tempfile.TemporaryDirectory() as tmp:
            binary = pathlib.Path(tmp) / 'fixture-command'
            binary.write_text('#!/bin/sh\nexit 0\n')
            binary.chmod(0o755)
            with patch.dict(os.environ, {'PATH': tmp}, clear=True):
                self.assertEqual(executable('FIXTURE_COMMAND', binary.name), binary)
                self.assertEqual(executable('FIXTURE_COMMAND', 'missing'), pathlib.Path('missing').absolute())
            with patch.dict(os.environ, {'FIXTURE_COMMAND': str(binary)}):
                self.assertEqual(executable('FIXTURE_COMMAND', 'missing'), binary)

    def test_gate_records_execution_errors_and_timeouts(self):
        tree = ast.parse((ROOT / 'tests/backend_release_local.py').read_text())
        run = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'run')
        with tempfile.TemporaryDirectory() as tmp:
            namespace = dict(globals(), ROOT=pathlib.Path(tmp), OUT=pathlib.Path(tmp))
            exec(compile(ast.Module(body=[run], type_ignores=[]), str(ROOT / 'tests/backend_release_local.py'), 'exec'), namespace)
            for error, code in [(FileNotFoundError('fixture missing'), 127),
                                (subprocess.TimeoutExpired(['fixture'], 540), 124)]:
                with self.subTest(error=type(error).__name__), patch.object(subprocess, 'run', side_effect=error), contextlib.redirect_stdout(io.StringIO()):
                    name, result = namespace['run'](('fixture', ['fixture']))
                    self.assertEqual(name, 'fixture')
                    self.assertEqual(result['exit_code'], code)
                    self.assertIsNone(result['passed'])
                    self.assertEqual(result['error'], str(error))
                    self.assertIn('HARNESS ERROR:', (pathlib.Path(tmp) / result['log']).read_text())
                    self.assertEqual(json.loads(json.dumps(result)), result)


if __name__ == '__main__':
    unittest.main(verbosity=2)
