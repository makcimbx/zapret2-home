#!/usr/bin/env python3
"""Run relocated, otherwise exact ctl + real ucode/jshn/ash in a local sandbox.
Only UCI, own init service, nft and list-cache I/O are explicit fault doubles.
The engine is a real private compiled process checked through /proc/PID/exe.
No router, host nft, sysctl, network requests or installed UCI are accessed.
"""
import json
import os
import pathlib
import shlex
import signal
import subprocess
import tempfile
import time
import unittest

from local_env import BUSYBOX
ROOT = pathlib.Path(__file__).resolve().parents[1]
from local_env import SCRATCH, UCODE, MODULES, JSHN, JSHN_SH

MOCK = r'''#!/usr/bin/env python3
import json, os, pathlib, shlex, subprocess, sys, time
root = pathlib.Path(os.environ['MOCK_ROOT']); run = root/'run'
kind = pathlib.Path(sys.argv[0]).name; args = sys.argv[1:]
with (root/'events').open('a') as out: out.write(json.dumps([kind]+args)+'\n')
def fault(name):
 p = root/name
 if not p.exists(): return False
 if p.read_text() == 'once': p.unlink()
 return True
def cfg():
 data = {}; section = ''
 for line in (root/'config/zapret2_home').read_text().splitlines():
  words = shlex.split(line, comments=True)
  if not words: continue
  if words[0] == 'config': section = words[2]; data[section] = {'_type': words[1]}
  elif words[0] == 'option': data[section][words[1]] = words[2]
 return data
def uci_export(data): return json.dumps(data, sort_keys=True)
def clear(name): (run/name).unlink(missing_ok=True)
def enabled(): return (root/'enabled').exists()
if kind == 'uci':
 if args[0] == '-q': args.pop(0)
 action = args[0]
 if action == 'get':
  parts = args[1].split('.'); value = cfg().get(parts[1], {}).get(parts[2]);
  if value is None: sys.exit(1)
  print(value)
 elif action == 'changes':
  if (root/'pending').exists(): print('zapret2_home.main.clients=dirty')
 elif action == 'export': print(uci_export(cfg()))
 elif action == 'set':
  p = root/'delta'; data = json.loads(p.read_text()) if p.exists() else cfg()
  key, value = args[1].split('=', 1); _, sec, opt = key.split('.'); data[sec][opt] = value
  p.write_text(json.dumps(data))
 elif action == 'commit':
  data = json.loads((root/'delta').read_text())
  (root/'config/zapret2_home').write_text(''.join('config '+shlex.quote(v['_type'])+' '+shlex.quote(k)+'\n'+''.join(' option '+shlex.quote(a)+' '+shlex.quote(b)+'\n' for a,b in v.items() if a != '_type') for k,v in data.items()))
  (root/'delta').unlink()
  if fault('wrong-commit'):
   p=root/'config/zapret2_home'; p.write_text(p.read_text().replace('option profile fake','option profile stock'))
  if fault('wrong-protocol-commit'):
   p=root/'config/zapret2_home'; p.write_text(p.read_text().replace('option udp_enabled 1','option udp_enabled 0'))
  if fault('fail-commit'): sys.exit(1)
 elif action == 'revert':
  if fault('fail-revert'): sys.exit(1)
  (root/'delta').unlink(missing_ok=True)
 else: sys.exit(2)
 sys.exit(0)
if kind == 'nft':
 if args[0] == 'list': sys.exit(0 if (run/'table').exists() else 1)
 if args[0] == 'delete':
  if fault('fail-delete'): sys.exit(1)
  clear('table'); sys.exit(0)
 if args[0] == '-c': sys.exit(1 if fault('fail-nft-check') else 0)
 if args[0] == '-f':
  if fault('fail-apply'): sys.exit(1)
  (run/'table').touch(); sys.exit(0)
 sys.exit(2)
if kind == 'lists':
 if args[0] == 'ensure-idle': sys.exit(1 if (root/'list-busy').exists() else 0)
 if args[0] in ('ensure', 'elements'): sys.exit(1 if fault('fail-cache') else 0)
 if args[0] == 'update':
  (root/'list-busy').touch(); sys.exit(0)
 if args[0] == 'catalog': print('[]')
 if args[0] == 'status': print('{}')
 sys.exit(0)
if kind == 'cp':
 if '.restore.' in args[-1] and fault('fail-restore'): sys.exit(1)
 sys.exit(subprocess.call(['/bin/cp']+args))
if kind == 'svc':
 action = args[0]
 if action == 'enabled': sys.exit(0 if enabled() else 1)
 if action in ('enable','disable'):
  if action == 'enable': (root/'enabled').touch()
  else: (root/'enabled').unlink(missing_ok=True)
  sys.exit(1 if fault('fail-autostart') else 0)
 if action == 'stop':
  if fault('fail-stop'): sys.exit(1)
  clear('requested'); (run/'stopping').touch()
  pid = int((run/'engine.pid').read_text()) if (run/'engine.pid').exists() else 0
  if pid:
   try: os.kill(pid, 15)
   except ProcessLookupError: pass
  sys.exit(subprocess.call([str(root/'ctl'), 'quiesce'], stdout=subprocess.DEVNULL))
 if action == 'start':
  if subprocess.call([str(root/'ctl'), 'request'], stdout=subprocess.DEVNULL): sys.exit(1)
  if fault('fail-start'): sys.exit(1)
  if subprocess.call([str(root/'ctl'), 'prepare'], stdout=subprocess.DEVNULL): sys.exit(1)
  if (root/'start-pause').exists():
   (root/'start-paused').touch()
   while (root/'start-pause').exists(): time.sleep(.02)
  if (root/'no-engine').exists(): sys.exit(0)
  profile = cfg()['main'].get('profile','alt1')
  if (root/'wrong-argv').exists(): profile='alt1'
  main=cfg()['main']
  branches=[main.get('tcp_enabled','1'),profile,main.get('quic_enabled','0'),main.get('quic_profile','quic_google'),main.get('udp_enabled','0'),main.get('udp_profile','udp_fake2')]
  p = subprocess.Popen([str(root/'engine'),'213','main','run',*branches], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
  (root/'engine-pids').open('a').write(str(p.pid)+'\n')
  (run/'engine.pid').write_text(str(p.pid)+'\n')
  if (root/'wrong-owner').exists():
   (run/'table').touch(); (run/'owner').write_text('zapret2-home:999999\n'); sys.exit(0)
  sys.exit(subprocess.call([str(root/'ctl'), 'apply', str(p.pid)], stdout=subprocess.DEVNULL))
 sys.exit(2)
if kind == 'ubus': print('{"l3_device":"wan-test"}'); sys.exit(0)
if kind == 'jsonfilter': print('wan-test'); sys.exit(0)
sys.exit(2)
'''

class ActiveConfigure(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  SCRATCH.mkdir(parents=True, exist_ok=True)
  cls.shared = tempfile.TemporaryDirectory(prefix='z2-active-engine-', dir=SCRATCH)
  c = pathlib.Path(cls.shared.name)/'engine.c'
  c.write_text('#include <unistd.h>\n#include <stdlib.h>\n#include <string.h>\n#include <stdio.h>\n#include <signal.h>\nchar *q;void stop(int s){if(q)unlink(q);_exit(0);}int main(int n,char **a){if(n>1 && !strcmp(a[1],"--dry-run"))return access(getenv("ENGINE_FAULT"),F_OK)==0;q=getenv("ENGINE_QUEUE");signal(SIGTERM,stop);if(q){FILE*f=fopen(q,"w");fputs("213 0 0\\n",f);fclose(f);}for(;;)pause();}\n')
  cls.engine = c.with_suffix('')
  subprocess.run(['cc', str(c), '-o', str(cls.engine)], check=True, capture_output=True)
 @classmethod
 def tearDownClass(cls): cls.shared.cleanup()
 def setUp(self):
  self.tmp = tempfile.TemporaryDirectory(prefix='z2-active-config-', dir=SCRATCH)
  self.d = pathlib.Path(self.tmp.name)
  for name in ('bin','run','lib','config'): (self.d/name).mkdir()
  self.run = self.d/'run'; self.config = self.d/'config/zapret2_home'
  self.original = b"# Preserve comments, unknown options and sections\nconfig service 'main'\n option clients ''\n option destinations ''\n option client_mode 'all'\n option lists 'flowseal cloudflare hetzner cloudfront ovh digitalocean'\n option auto_update '1'\n option custom 'keep exact bytes'\n\nconfig spare 'extra'\n option value 'unchanged'\n"
  self.config.write_bytes(self.original); self.config.chmod(0o600)
  (self.d/'enabled').touch()
  for name in ('uci','nft','lists','svc','cp','ubus','jsonfilter'):
   p = self.d/'bin'/name; p.write_text(MOCK); p.chmod(0o755)
  (self.d/'bin/jshn').symlink_to(JSHN)
  (self.d/'lib/validate.uc').write_text((ROOT/'files/usr/lib/zapret2-home/validate.uc').read_text().replace('/usr/lib/zapret2-home',str(self.d/'lib')))
  (self.d/'lib/lock.uc').write_text((ROOT/'files/usr/lib/zapret2-home/lock.uc').read_text().replace("const RUN='/var/run/zapret2-home';",f"const RUN='{self.run}';"))
  for name in ('protocols.uc','protocol-catalog.json','profile-catalog.json'):
   (self.d/'lib'/name).write_text((ROOT/'files/usr/lib/zapret2-home'/name).read_text().replace('/usr/lib/zapret2-home',str(self.d/'lib')))
  (self.d/'lib/status-lists.uc').write_bytes((ROOT/'files/usr/lib/zapret2-home/status-lists.uc').read_bytes())
  for name in ('nfqws2','nfqws2-quic'):
   (self.d/'lib'/name).write_bytes(self.engine.read_bytes()); (self.d/'lib'/name).chmod(0o755)
  sums = subprocess.check_output(['sha256sum','nfqws2','nfqws2-quic'], cwd=self.d/'lib')
  (self.d/'lib/SHA256SUMS').write_bytes(sums)
  (self.d/'acct').write_text('1\n'); (self.d/'queue').write_text('')
  raw = (ROOT/'files/usr/libexec/zapret2-home-ctl').read_text()
  # Fixed relocation only; no shell-function replacements or reimplementation.
  paths = {
   '/usr/share/libubox/jshn.sh':str(JSHN_SH), '/usr/libexec/zapret2-home-ctl':str(self.d/'ctl'),
   '/usr/libexec/zapret2-home-engine':str(self.d/'engine'), '/usr/libexec/zapret2-home-worker':str(self.d/'worker'),
   '/usr/libexec/zapret2-home-lists':str(self.d/'bin/lists'), '/etc/init.d/zapret2-home':str(self.d/'bin/svc'),
   '/usr/lib/zapret2-home':str(self.d/'lib'), '/var/run/zapret2-home':str(self.run),
   '/etc/config/zapret2_home':str(self.config), '/etc/config/.zapret2_home.restore.':str(self.d/'config/.zapret2_home.restore.'),
   '/proc/sys/net/netfilter/nf_conntrack_acct':str(self.d/'acct'), '/proc/net/netfilter/nfnetlink_queue':str(self.d/'queue'),
  }
  for old,new in paths.items(): raw = raw.replace(old,new)
  raw = raw.replace('#!/bin/sh', '#!'+BUSYBOX+' ash', 1)
  raw = raw.replace('PATH=/usr/sbin:/usr/bin:/sbin:/bin', 'PATH='+str(self.d/'bin')+':/usr/sbin:/usr/bin:/sbin:/bin')
  # BusyBox resolves applets before PATH, so explicit executables are mandatory.
  raw = raw.replace('ucode ', shlex.quote(str(UCODE))+' -L '+shlex.quote(str(MODULES))+' ')
  raw = raw.replace('cp -p ', shlex.quote(str(self.d/'bin/cp'))+' -p ').replace('cp "$CFG_JOB/result" ',shlex.quote(str(self.d/'bin/cp'))+' "$CFG_JOB/result" ')
  (self.d/'ctl').write_text(raw); (self.d/'ctl').chmod(0o755)
  engine = (ROOT/'files/usr/libexec/zapret2-home-engine').read_text()
  engine = engine.replace('/usr/lib/zapret2-home',str(self.d/'lib')).replace('#!/bin/sh','#!'+BUSYBOX+' ash',1)
  engine = engine.replace('ucode ',shlex.quote(str(UCODE))+' -L '+shlex.quote(str(MODULES))+' ')
  (self.d/'engine').write_text(engine); (self.d/'engine').chmod(0o755)
  self.env = dict(os.environ, MOCK_ROOT=str(self.d), ENGINE_FAULT=str(self.d/'fail-engine'), ENGINE_QUEUE=str(self.d/'queue'), PATH=str(self.d/'bin')+':'+os.environ['PATH'])
  self.request = dict(clients='192.168.1.20/32',destinations='65.108.59.85/32',autostart=False,client_mode='selected',lists='',auto_update=False)
 def tearDown(self):
  # Terminal publication precedes final result-copy/unlock; wait before deleting the sandbox.
  for marker in self.run.glob('configure-job.*/pid'):
   pid=marker.read_text().strip(); deadline=time.monotonic()+5
   while time.monotonic()<deadline:
    path=pathlib.Path('/proc/'+pid+'/stat')
    if not path.exists(): break
    try: raw=path.read_text()
    except FileNotFoundError: break
    if raw[raw.rindex(') ')+2:].split()[0]=='Z': break
    time.sleep(.02)
  if (self.d/'engine-pids').exists():
   for pid in (self.d/'engine-pids').read_text().splitlines():
    try: os.kill(int(pid),signal.SIGKILL)
    except ProcessLookupError: pass
  self.tmp.cleanup()
 def call(self, command, request=None, timeout=55):
  return subprocess.run([str(self.d/'ctl'),command],input=json.dumps(request if request is not None else self.request),text=True,capture_output=True,env=self.env,timeout=timeout)
 def configure(self, request=None, command='configure'):
  p = self.call(command,request); self.assertTrue(p.stdout.strip(),p.stderr)
  x = json.loads(p.stdout)
  if x.get('pending'):
   # Public configure is RPC-bounded; the exact detached controller publishes
   # terminal success/failure separately while holding the same control lock.
   self.assertTrue(x['ok']); result=self.run/('configure-job.'+x['job_id'])/'result'
   deadline=time.monotonic()+55
   while not result.exists() and time.monotonic()<deadline: time.sleep(.05)
   self.assertTrue(result.exists(),'detached transaction did not publish a result')
   p.stdout=result.read_text(); x=json.loads(p.stdout); p.returncode=0 if x['ok'] else 1
  return p,x
 def active(self):
  p = subprocess.run([str(self.d/'bin/svc'),'start'],env=self.env,capture_output=True,text=True,timeout=10)
  self.assertEqual(p.returncode,0,p.stdout+p.stderr)
  return (self.run/'engine.pid').read_text()
 def fault(self,name,once=False): (self.d/name).write_text('once' if once else 'always')
 def events(self): return [json.loads(x) for x in (self.d/'events').read_text().splitlines()]
 def assert_restored(self,active=True):
  self.assertEqual(self.config.read_bytes(),self.original)
  self.assertEqual(self.config.stat().st_mode & 0o777,0o600)
  self.assertTrue((self.d/'enabled').exists())
  self.assertEqual((self.run/'requested').exists(),active)
  self.assertEqual((self.run/'table').exists(),active)
  self.assertEqual(self.call('running').returncode,0 if active else 1)
  if active: self.assertFalse((self.run/'stopping').exists())
 def test_active_save_restarts_and_confirms_real_new_process(self):
  old=self.active(); p,x=self.configure(); self.assertEqual(p.returncode,0,p.stdout+p.stderr); self.assertTrue(x['ok'])
  self.assertNotEqual((self.run/'engine.pid').read_text(),old)
  self.assertEqual(self.call('running').returncode,0); self.assertTrue((self.run/'table').exists()); self.assertFalse((self.d/'enabled').exists())
  self.assertFalse((self.run/'stopping').exists()); self.assertTrue((self.run/'requested').exists())
  self.assertIn(b'keep exact bytes',self.config.read_bytes()); self.assertIn(b'unchanged',self.config.read_bytes())
 def test_noop_active_save_preserves_live_scope(self):
  old=self.active(); before=len(self.events()); request=dict(clients='',destinations='',autostart=True,client_mode='all',lists='flowseal cloudflare hetzner cloudfront ovh digitalocean',auto_update=True)
  p,x=self.configure(request); self.assertEqual(p.returncode,0,p.stdout+p.stderr); self.assertTrue(x['ok']); self.assertTrue(x['unchanged']); self.assertEqual(self.call('running').returncode,0)
  self.assertEqual((self.run/'engine.pid').read_text(),old); self.assertEqual(self.config.read_bytes(),self.original)
  self.assertFalse(any(e[:2] in (['svc','stop'],['svc','start'],['uci','commit']) for e in self.events()[before:]))
  self.assertTrue((self.d/'enabled').exists()); self.assertIn(b'flowseal cloudflare hetzner cloudfront ovh digitalocean',self.config.read_bytes())
 def test_noop_with_running_source_job_does_not_cancel_engine(self):
  old=self.active(); self.fault('list-busy'); before=len(self.events()); request=dict(clients='',destinations='',autostart=True,client_mode='all',lists='flowseal cloudflare hetzner cloudfront ovh digitalocean',auto_update=True)
  p,x=self.configure(request); self.assertEqual(p.returncode,0,p.stdout+p.stderr); self.assertTrue(x['unchanged']); self.assertEqual((self.run/'engine.pid').read_text(),old); self.assertEqual(self.config.read_bytes(),self.original); self.assertTrue((self.d/'list-busy').exists()); self.assertFalse(any(e[:2] in (['svc','stop'],['svc','start'],['uci','commit']) for e in self.events()[before:]))
 def test_inactive_save_never_starts_engine(self):
  (self.run/'stopping').touch(); p,x=self.configure(); self.assertEqual(p.returncode,0,p.stdout+p.stderr); self.assertTrue(x['ok'])
  self.assertEqual(self.call('running').returncode,1); self.assertTrue((self.run/'stopping').exists()); self.assertFalse((self.run/'requested').exists())
  self.assertFalse(any(e[:2]==['svc','start'] for e in self.events()))
 def test_invalid_request_rejected_before_stop(self):
  self.active(); before=len(self.events()); request=dict(self.request,clients='invalid'); p,x=self.configure(request)
  self.assertNotEqual(p.returncode,0); self.assertFalse(x['ok']); self.assert_restored()
  self.assertFalse(any(e[:2]==['svc','stop'] for e in self.events()[before:]))
 def test_transport_metadata_accepted_not_saved(self):
  self.active(); p,x=self.configure(dict(self.request,ubus_rpc_session='a'*32)); self.assertEqual(p.returncode,0,p.stdout+p.stderr); self.assertTrue(x['ok']); self.assertNotIn(b'ubus_rpc_session',self.config.read_bytes())
 def test_pending_wan_rejected_intent_preserved(self):
  (self.run/'requested').touch(); p,x=self.configure(); self.assertNotEqual(p.returncode,0); self.assertFalse(x['ok']); self.assertTrue((self.run/'requested').exists()); self.assertEqual(self.config.read_bytes(),self.original)
 def test_list_job_busy_rejected_before_stop(self):
  self.active(); self.fault('list-busy'); before=len(self.events()); p,x=self.configure(); self.assertNotEqual(p.returncode,0); self.assertFalse(x['ok']); self.assert_restored(); self.assertFalse(any(e[:2]==['svc','stop'] for e in self.events()[before:]))
 def test_autostart_failure_rolls_back_entire_config_and_runtime(self):
  self.active(); self.fault('fail-autostart',True); p,x=self.configure(); self.assertNotEqual(p.returncode,0); self.assertFalse(x['ok']); self.assertTrue(x['rolled_back']); self.assert_restored()
 def test_inactive_autostart_failure_restores_stopped_flags(self):
  (self.run/'stopping').touch(); self.fault('fail-autostart',True); p,x=self.configure(); self.assertNotEqual(p.returncode,0); self.assertTrue(x['rolled_back']); self.assert_restored(False); self.assertTrue((self.run/'stopping').exists())
 def test_commit_failure_after_write_restores_bytes_and_running(self):
  self.active(); self.fault('fail-commit',True); p,x=self.configure(); self.assertNotEqual(p.returncode,0); self.assertTrue(x['rolled_back']); self.assert_restored()
 def test_start_failure_restores_previous_running_state(self):
  self.active(); self.fault('fail-start',True); p,x=self.configure(); self.assertNotEqual(p.returncode,0); self.assertTrue(x['rolled_back']); self.assert_restored()
 def test_failed_recovery_start_is_not_rolled_back(self):
  self.active(); self.fault('fail-start'); p,x=self.configure(); self.assertNotEqual(p.returncode,0); self.assertFalse(x['rolled_back']); self.assertEqual(self.config.read_bytes(),self.original); self.assertFalse((self.run/'requested').exists()); self.assertTrue((self.run/'stopping').exists())
 def test_restore_write_failure_is_not_rolled_back(self):
  self.active(); self.fault('fail-start',True); self.fault('fail-restore'); p,x=self.configure(); self.assertNotEqual(p.returncode,0); self.assertFalse(x['rolled_back']); self.assertFalse((self.run/'requested').exists()); self.assertTrue((self.run/'stopping').exists()); self.assertEqual(self.call('running').returncode,1)
 def test_service_stop_failure_aborts_without_config_mutation(self):
  self.active(); self.fault('fail-stop'); p,x=self.configure(); self.assertNotEqual(p.returncode,0); self.assertFalse(x['ok']); self.assertEqual(self.config.read_bytes(),self.original); self.assertTrue((self.d/'enabled').exists())
  self.assertFalse(x['rolled_back']); self.assertTrue(x['running']); self.assertTrue(x['table_present']); self.assertTrue(x['requested']); self.assertFalse(x['stopping'])
 def test_rule_removal_failure_retains_owner_no_config_mutation(self):
  self.active(); self.fault('fail-delete'); p,x=self.configure(); self.assertNotEqual(p.returncode,0); self.assertFalse(x['rolled_back']); self.assertEqual(self.config.read_bytes(),self.original); self.assertTrue((self.run/'owner').exists()); self.assertTrue((self.run/'table').exists()); self.assertFalse((self.run/'requested').exists()); self.assertTrue((self.run/'stopping').exists())
  self.assertFalse(x['running']); self.assertTrue(x['table_present']); self.assertFalse(x['requested']); self.assertTrue(x['stopping'])
 def test_candidate_cache_preflight_failure_restores(self):
  self.active(); self.fault('fail-cache',True); p,x=self.configure(); self.assertNotEqual(p.returncode,0); self.assertTrue(x['rolled_back']); self.assert_restored()
 def test_candidate_nft_preflight_failure_restores(self):
  self.active(); self.fault('fail-nft-check',True); p,x=self.configure(); self.assertNotEqual(p.returncode,0); self.assertTrue(x['rolled_back']); self.assert_restored()
 def test_candidate_engine_preflight_failure_never_stops_runtime(self):
  old=self.active(); self.fault('fail-engine'); before=len(self.events()); p,x=self.configure(); self.assertNotEqual(p.returncode,0); self.assertFalse(x['rolled_back']); self.assert_restored(); self.assertEqual((self.run/'engine.pid').read_text(),old); self.assertFalse(any(e[:2]==['svc','stop'] for e in self.events()[before:]))
 def test_unconfirmed_start_cannot_return_success(self):
  self.active(); self.fault('no-engine'); p,x=self.configure(); self.assertNotEqual(p.returncode,0); self.assertFalse(x['ok']); self.assertFalse(x['rolled_back']); self.assertEqual(self.config.read_bytes(),self.original); self.assertFalse((self.run/'requested').exists())
 def test_recovery_autostart_failure_is_not_rolled_back(self):
  self.active(); self.fault('fail-autostart'); p,x=self.configure(); self.assertNotEqual(p.returncode,0); self.assertFalse(x['rolled_back']); self.assertEqual(self.config.read_bytes(),self.original); self.assertFalse((self.run/'requested').exists()); self.assertTrue((self.run/'stopping').exists())
 def test_wrong_generation_owner_never_confirms_success(self):
  self.active(); self.fault('wrong-owner'); p,x=self.configure(); self.assertNotEqual(p.returncode,0); self.assertFalse(x['ok']); self.assertFalse(x['rolled_back']); self.assertEqual(self.config.read_bytes(),self.original)
 def test_pending_uci_changes_rejected_before_stop(self):
  self.active(); self.fault('pending'); before=len(self.events()); p,x=self.configure(); self.assertNotEqual(p.returncode,0); self.assertFalse(x['ok']); self.assert_restored(); self.assertTrue((self.d/'pending').exists()); self.assertFalse(any(e[:2]==['svc','stop'] for e in self.events()[before:]))
 def test_invalid_saved_config_is_not_overwritten(self):
  self.active(); self.config.write_bytes(self.original.replace(b"option client_mode 'all'",b"option client_mode 'invalid'")); previous=self.config.read_bytes(); before=len(self.events()); p,x=self.configure(); self.assertNotEqual(p.returncode,0); self.assertFalse(x['ok']); self.assertEqual(self.config.read_bytes(),previous); self.assertFalse(any(e[:2]==['svc','stop'] for e in self.events()[before:]))
 def test_invalid_transport_metadata_rejected_before_stop(self):
  self.active(); before=len(self.events()); p,x=self.configure(dict(self.request,ubus_rpc_session='bad')); self.assertNotEqual(p.returncode,0); self.assertFalse(x['ok']); self.assert_restored(); self.assertFalse(any(e[:2]==['svc','stop'] for e in self.events()[before:]))
 def test_inactive_failure_without_stopping_marker_restores_absence(self):
  self.fault('fail-autostart',True); p,x=self.configure(); self.assertNotEqual(p.returncode,0); self.assertTrue(x['rolled_back']); self.assert_restored(False); self.assertFalse((self.run/'stopping').exists())
 def wait_result(self, job_id, timeout=55):
  result=self.run/('configure-job.'+job_id)/'result'; deadline=time.monotonic()+timeout
  while not result.exists() and time.monotonic()<deadline: time.sleep(.05)
  self.assertTrue(result.exists(),'detached transaction did not publish a result')
  return json.loads(result.read_text())
 def test_live_au_toggle_restarts_without_changing_eligibility(self):
  old=self.active(); request=dict(clients='',destinations='',autostart=True,client_mode='all',lists='flowseal cloudflare hetzner cloudfront ovh digitalocean',auto_update=False)
  p,x=self.configure(request); self.assertEqual(p.returncode,0,p.stdout+p.stderr); self.assertNotEqual((self.run/'engine.pid').read_text(),old)
  first=(self.run/'engine.pid').read_text(); p,x=self.configure(dict(request,auto_update=True)); self.assertEqual(p.returncode,0,p.stdout+p.stderr); self.assertNotEqual((self.run/'engine.pid').read_text(),first)
  status=json.loads(self.call('status').stdout); self.assertEqual(status['client_mode'],'all'); self.assertEqual(status['lists'],request['lists']); self.assertEqual(status['clients'],''); self.assertEqual(status['destinations'],''); self.assertTrue(status['running']); self.assertTrue(status['autostart']); self.assertTrue(status['auto_update']); self.assertEqual(status['configure_result']['job_id'],x['job_id'])
 def test_rpc_bounded_pending_and_term_restores_old_runtime(self):
  self.active(); self.fault('start-pause'); started=time.monotonic(); p=self.call('configure',timeout=25); elapsed=time.monotonic()-started; x=json.loads(p.stdout)
  self.assertLess(elapsed,25); self.assertTrue(x['pending']); self.assertTrue(x['ok']); self.assertTrue((self.d/'start-paused').exists())
  s=json.loads(self.call('status').stdout); self.assertTrue(s['configure_pending']); self.assertFalse(s['configure_recovery_required']); self.assertEqual(s['configure_job_id'],x['job_id'])
  pid=int((self.run/('configure-job.'+x['job_id'])/'pid').read_text()); os.kill(pid,signal.SIGTERM); (self.d/'start-pause').unlink()
  result=self.wait_result(x['job_id']); self.assertFalse(result['ok']); self.assertTrue(result['rolled_back']); self.assert_restored()
  s=json.loads(self.call('status').stdout); self.assertFalse(s['configure_pending']); self.assertFalse(s['configure_recovery_required']); self.assertEqual(s['configure_result'],result)
 def test_sigkill_rpc_caller_does_not_cancel_transaction(self):
  self.active(); self.fault('start-pause'); p=subprocess.Popen([str(self.d/'ctl'),'configure'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,env=self.env)
  p.stdin.write(json.dumps(self.request)); p.stdin.close(); p.stdin=None; deadline=time.monotonic()+12
  while not (self.d/'start-paused').exists() and time.monotonic()<deadline: time.sleep(.02)
  self.assertTrue((self.d/'start-paused').exists()); job=(self.run/'configure.job').read_text().strip(); p.kill(); p.communicate(timeout=5)
  self.assertTrue(json.loads(self.call('status').stdout)['configure_pending']); (self.d/'start-pause').unlink(); result=self.wait_result(job)
  self.assertTrue(result['ok']); self.assertEqual(self.call('running').returncode,0); self.assertFalse((self.run/'stopping').exists()); self.assertTrue((self.run/'table').exists()); self.assertFalse((self.d/'enabled').exists())
 def test_sigkill_job_reports_recovery_required_without_false_result(self):
  self.active(); self.fault('start-pause'); p=self.call('configure',timeout=25); x=json.loads(p.stdout); self.assertTrue(x['pending']); pid=int((self.run/('configure-job.'+x['job_id'])/'pid').read_text())
  os.kill(pid,signal.SIGKILL); (self.d/'start-pause').unlink(); deadline=time.monotonic()+5
  while time.monotonic()<deadline:
   s=json.loads(self.call('status').stdout)
   if s['configure_recovery_required']: break
   time.sleep(.05)
  self.assertTrue(s['configure_recovery_required']); self.assertFalse(s['configure_pending']); self.assertFalse(s['configure_result']['ok']); self.assertFalse(s['configure_result']['rolled_back'])
  backups=[p for p in self.run.glob('configure.[0-9]*') if p.is_dir()]; self.assertEqual(len(backups),1); self.assertEqual((backups[0]/'config').read_bytes(),self.original)
  p=self.call('configure'); self.assertNotEqual(p.returncode,0); self.assertFalse(json.loads(p.stdout)['ok'])
 def test_update_launch_serialized_during_restart(self):
  self.active(); self.fault('start-pause')
  p=subprocess.Popen([str(self.d/'ctl'),'configure'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,env=self.env)
  p.stdin.write(json.dumps(self.request)); p.stdin.close(); p.stdin=None
  for _ in range(200):
   if (self.d/'start-paused').exists(): break
   time.sleep(.02)
  self.assertTrue((self.d/'start-paused').exists())
  update=subprocess.Popen([str(self.d/'ctl'),'update_lists'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,env=self.env)
  time.sleep(.2); self.assertIsNone(update.poll()); self.assertFalse((self.d/'list-busy').exists())
  (self.d/'start-pause').unlink(); out,err=p.communicate(timeout=20); self.assertEqual(p.returncode,0,out+err)
  out,err=update.communicate(timeout=15); self.assertEqual(update.returncode,0,out+err); self.assertTrue((self.d/'list-busy').exists())

 def apply_protocol(self, protocol, enabled, profile, **metadata):
  return self.configure(dict(protocol=protocol,enabled=enabled,profile=profile,**metadata),command='protocols-apply')
 def test_protocol_active_apply_preserves_branches_and_scope(self):
  old=self.active(); p,x=self.apply_protocol('quic',True,'quic_zero'); self.assertEqual(p.returncode,0,p.stdout+p.stderr); self.assertNotEqual((self.run/'engine.pid').read_text(),old)
  p,x=self.apply_protocol('udp',True,'udp_fake6'); self.assertEqual(p.returncode,0,p.stdout+p.stderr)
  s=json.loads(self.call('status').stdout); self.assertEqual(s['protocols'],dict(tcp=dict(enabled=True,profile='alt1'),quic=dict(enabled=True,profile='quic_zero'),udp=dict(enabled=True,profile='udp_fake6'))); self.assertEqual(s['client_mode'],'all'); self.assertTrue(s['autostart']); self.assertTrue(s['auto_update'])
  pid=(self.run/'engine.pid').read_text().strip(); args=pathlib.Path('/proc/'+pid+'/cmdline').read_bytes().split(b'\0')[:-1]; self.assertEqual(args.count(b'--new'),2)
 def test_protocol_all_off_rejected_and_inactive_stays_inactive(self):
  p,x=self.apply_protocol('tcp',False,'alt1'); self.assertNotEqual(p.returncode,0); self.assertIn('Stop',x['error']); self.assertEqual(self.config.read_bytes(),self.original)
  p,x=self.apply_protocol('quic',True,'quic_google',ubus_rpc_session='a'*32); self.assertEqual(p.returncode,0,p.stdout+p.stderr)
  p,x=self.apply_protocol('tcp',False,'stock'); self.assertEqual(p.returncode,0,p.stdout+p.stderr); self.assertEqual(self.call('running').returncode,1); self.assertFalse((self.run/'requested').exists()); self.assertNotIn(b'ubus_rpc_session',self.config.read_bytes())
  s=json.loads(self.call('status').stdout); self.assertFalse(s['protocols']['tcp']['enabled']); self.assertEqual(s['profile_id'],'stock')
 def test_protocol_invalid_boundary_no_side_effect(self):
  for request in ({'protocol':'tcp','enabled':True,'profile':'quic_google'},{'protocol':'udp','enabled':'1','profile':'udp_fake2'},{'protocol':'quic','enabled':True,'profile':'quic_zero','clients':''},{'protocol':'udp','enabled':True,'profile':'udp_fake2','ubus_rpc_session':'a'*32+'\0bad'},{'protocol':'bad','enabled':True,'profile':'alt1'}):
   p=self.call('protocols-apply',request); self.assertNotEqual(p.returncode,0); self.assertFalse(json.loads(p.stdout)['ok']); self.assertEqual(self.config.read_bytes(),self.original)
 def test_legacy_configure_and_profile_preserve_all_protocol_choices(self):
  for group,profile in [('quic','quic_zero'),('udp','udp_fake6')]:
   p,x=self.apply_protocol(group,True,profile); self.assertEqual(p.returncode,0,p.stdout+p.stderr)
  p,x=self.apply_protocol('tcp',False,'stock'); self.assertEqual(p.returncode,0,p.stdout+p.stderr)
  self.active(); p,x=self.configure(); self.assertEqual(p.returncode,0,p.stdout+p.stderr)
  p,x=self.apply_profile('fake'); self.assertEqual(p.returncode,0,p.stdout+p.stderr)
  s=json.loads(self.call('status').stdout); self.assertEqual(s['protocols'],dict(tcp=dict(enabled=False,profile='fake'),quic=dict(enabled=True,profile='quic_zero'),udp=dict(enabled=True,profile='udp_fake6')))
 def test_protocol_commit_readback_restores_exact_full_config(self):
  self.active();self.fault('wrong-protocol-commit');p,x=self.apply_protocol('udp',True,'udp_fake6');self.assertNotEqual(p.returncode,0);self.assertTrue(x['rolled_back']);self.assert_restored()
 def test_protocol_detached_caller_death_preserves_requested_branch(self):
  self.active();self.fault('start-pause')
  p=subprocess.Popen([str(self.d/'ctl'),'protocols-apply'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,env=self.env)
  p.stdin.write(json.dumps(dict(protocol='udp',enabled=True,profile='udp_fake6')));p.stdin.close();p.stdin=None;deadline=time.monotonic()+12
  while not (self.d/'start-paused').exists() and time.monotonic()<deadline:time.sleep(.02)
  self.assertTrue((self.d/'start-paused').exists());job=(self.run/'configure.job').read_text().strip();p.kill();p.communicate(timeout=5)
  self.assertTrue(json.loads(self.call('status').stdout)['configure_pending']);(self.d/'start-pause').unlink();self.assertTrue(self.wait_result(job)['ok'])
  status=json.loads(self.call('status').stdout);self.assertTrue(status['running']);self.assertTrue(status['autostart']);self.assertEqual(status['protocols']['udp'],dict(enabled=True,profile='udp_fake6'));self.assertEqual(status['client_mode'],'all')
 def test_protocol_detached_term_restores_all_choices(self):
  self.active();self.fault('start-pause');p=self.call('protocols-apply',dict(protocol='quic',enabled=True,profile='quic_zero'),timeout=25);x=json.loads(p.stdout);self.assertTrue(x['pending']);job=x['job_id']
  os.kill(int((self.run/('configure-job.'+job)/'pid').read_text()),signal.SIGTERM);(self.d/'start-pause').unlink();result=self.wait_result(job);self.assertFalse(result['ok']);self.assertTrue(result['rolled_back']);self.assert_restored()
 def test_protocol_failure_restores_all_config_exactly(self):
  p,x=self.apply_protocol('udp',True,'udp_fake6'); self.assertEqual(p.returncode,0,p.stdout+p.stderr); self.original=self.config.read_bytes(); self.active(); self.fault('fail-start',True)
  p,x=self.apply_protocol('quic',True,'quic_google'); self.assertNotEqual(p.returncode,0); self.assertTrue(x['rolled_back']); self.assert_restored()
 def test_protocol_rules_all_nonempty_combinations_are_scoped(self):
  for tcp,quic,udp in [(1,0,0),(0,1,0),(0,0,1),(1,1,0),(1,0,1),(0,1,1),(1,1,1)]:
   with self.subTest(tcp=tcp,quic=quic,udp=udp):
    self.config.write_bytes(self.original.replace(b" option custom",f" option tcp_enabled '{tcp}'\n option quic_enabled '{quic}'\n option udp_enabled '{udp}'\n option custom".encode()))
    p=self.call('prepare'); self.assertEqual(p.returncode,0,p.stdout+p.stderr); rules=(self.run/'rules.nft').read_text()
    self.assertEqual('tcp dport 443' in rules,bool(tcp));self.assertEqual('udp dport 443' in rules,bool(quic));self.assertEqual('udp dport { 19294-19344, 50000-50100 }' in rules,bool(udp));self.assertNotIn('udp sport',rules)
    self.assertEqual(rules.count('ct original packets <= 20'),tcp+quic+udp);self.assertEqual(rules.count('0x40000000 != 0'),tcp+quic+udp)
    for line in rules.splitlines():
     if 'queue num' in line and 'dport' in line:self.assertIn('iifname "br-lan" oifname "wan-test" ip saddr @clients ip daddr @destinations',line);self.assertIn('queue num 213 bypass',line)
     if 'udp dport' in line and 'queue num' in line:self.assertIn('ct direction original',line)
    for token in ('ip daddr @excluded return','meta mark & 0x00100000 != 0 return','ct status dnat return','198.18.0.0/15','192.0.2.1/32','ip daddr != @excluded'):self.assertIn(token,rules)
 def test_protocol_apply_writes_only_requested_branch(self):
  p,x=self.apply_protocol('quic',True,'quic_zero');self.assertEqual(p.returncode,0,p.stdout+p.stderr)
  writes=[e[2].split('=')[0] for e in self.events() if e[:2]==['uci','set']]
  self.assertEqual(writes,['zapret2_home.main.quic_enabled','zapret2_home.main.quic_profile'])
 def test_protocol_rejects_updater_diagnostics_and_recovery_even_noop(self):
  self.fault('list-busy');p,x=self.apply_protocol('udp',False,'udp_fake2');self.assertNotEqual(p.returncode,0);(self.d/'list-busy').unlink()
  diag=self.run/'profiles';diag.mkdir();(diag/'owner').write_text('{"job":"busy"}');p,x=self.apply_protocol('udp',False,'udp_fake2');self.assertNotEqual(p.returncode,0);(diag/'owner').unlink()
  (self.run/'configure.job').write_text('123');(self.run/'configure-job.123').mkdir();p,x=self.apply_protocol('udp',False,'udp_fake2');self.assertNotEqual(p.returncode,0);self.assertEqual(self.config.read_bytes(),self.original)
 def test_protocol_saved_invalid_boolean_or_dormant_profile_is_not_overwritten(self):
  for option,value in [('tcp_enabled','true'),('udp_profile','alt1'),('quic_enabled',''),('quic_profile','bad')]:
   self.config.write_bytes(self.original.replace(b' option custom',f" option {option} '{value}'\n option custom".encode()));before=self.config.read_bytes()
   p,x=self.apply_protocol('tcp',True,'stock');self.assertNotEqual(p.returncode,0);self.assertEqual(self.config.read_bytes(),before)
 def test_protocol_legacy_defaults_noop_byte_identical(self):
  old=self.active(); p,x=self.apply_protocol('udp',False,'udp_fake2'); self.assertEqual(p.returncode,0,p.stdout+p.stderr); self.assertTrue(x['unchanged']); self.assertEqual(self.config.read_bytes(),self.original); self.assertEqual((self.run/'engine.pid').read_text(),old)
 def apply_profile(self, profile, **metadata):
  return self.configure(dict(profile=profile,**metadata),command='profiles-apply')
 def test_profile_apply_active_preserves_scope_autostart_and_changes_exact_argv(self):
  old=self.active(); p,x=self.apply_profile('fake_disorder'); self.assertEqual(p.returncode,0,p.stdout+p.stderr)
  s=json.loads(self.call('status').stdout); self.assertEqual(s['profile_id'],'fake_disorder'); self.assertIn('multidisorder_legacy',s['profile']); self.assertTrue(s['running']); self.assertTrue(s['autostart']); self.assertTrue(s['auto_update'])
  self.assertEqual(s['client_mode'],'all'); self.assertEqual(s['lists'],'flowseal cloudflare hetzner cloudfront ovh digitalocean'); self.assertEqual(s['clients'],''); self.assertEqual(s['destinations'],'')
  pid=(self.run/'engine.pid').read_text().strip(); self.assertNotEqual(pid,old.strip())
  args=pathlib.Path('/proc/'+pid+'/cmdline').read_bytes().split(b'\0')[:-1]
  expected=json.loads((self.d/'lib/profile-catalog.json').read_text())[-1]['args']
  self.assertEqual([a.decode() for a in args if a.startswith(b'--lua-desync=')],expected); self.assertIn(b'--in-range=x',args); self.assertIn(b'--qnum=213',args)
 def test_inactive_apply_checks_saved_profile_readback(self):
  self.fault('wrong-commit',True); p,x=self.apply_profile('fake'); self.assertNotEqual(p.returncode,0,p.stdout+p.stderr); self.assertTrue(x['rolled_back']); self.assert_restored(False)
 def test_profile_apply_inactive_stays_inactive(self):
  p,x=self.apply_profile('overlap'); self.assertEqual(p.returncode,0,p.stdout+p.stderr); self.assertFalse((self.run/'requested').exists()); self.assertEqual(self.call('running').returncode,1); self.assertTrue((self.d/'enabled').exists()); self.assertEqual(json.loads(self.call('status').stdout)['profile_id'],'overlap')
 def test_profile_apply_same_legacy_alt1_is_noop(self):
  old=self.active(); before=len(self.events()); p,x=self.apply_profile('alt1'); self.assertEqual(p.returncode,0,p.stdout+p.stderr); self.assertTrue(x['unchanged']); self.assertEqual((self.run/'engine.pid').read_text(),old); self.assertEqual(self.config.read_bytes(),self.original); self.assertFalse(any(e[:2] in (['svc','stop'],['svc','start'],['uci','commit']) for e in self.events()[before:]))
 def test_legacy_configure_preserves_previously_selected_profile(self):
  p,x=self.apply_profile('stock'); self.assertEqual(p.returncode,0,p.stdout+p.stderr); self.active(); p,x=self.configure(); self.assertEqual(p.returncode,0,p.stdout+p.stderr); self.assertEqual(json.loads(self.call('status').stdout)['profile_id'],'stock')
 def test_explicit_configure_profile_is_validated_and_applied(self):
  self.active(); p,x=self.configure(dict(self.request,profile='fake_split')); self.assertEqual(p.returncode,0,p.stdout+p.stderr); self.assertEqual(json.loads(self.call('status').stdout)['profile_id'],'fake_split')
 def test_profile_apply_invalid_id_fields_and_metadata_are_side_effect_free(self):
  old=self.active(); before=len(self.events())
  for request in ({'profile':'stock; touch /bad'},{'profile':'stock\0bad'},{'profile':'seqovl'},{'profile':None},{'profile':['stock']},{'profile':'fake','clients':'192.168.1.20'},{'profile':'fake','ubus_rpc_session':None},{'profile':'fake','ubus_rpc_session':'a'*32+'\0bad'},{}):
   with self.subTest(request=request):
    p=self.call('profiles-apply',request); self.assertNotEqual(p.returncode,0,p.stdout+p.stderr); self.assertFalse(json.loads(p.stdout)['ok'])
  self.assertEqual((self.run/'engine.pid').read_text(),old); self.assert_restored(); self.assertFalse(any(e[:2]==['svc','stop'] for e in self.events()[before:]))
 def test_profile_apply_transport_token_not_persisted(self):
  p,x=self.apply_profile('fake',ubus_rpc_session='a'*32); self.assertEqual(p.returncode,0,p.stdout+p.stderr); self.assertNotIn(b'ubus_rpc_session',self.config.read_bytes())
 def test_profile_apply_preflight_before_stop(self):
  old=self.active(); self.fault('fail-engine'); before=len(self.events()); p,x=self.apply_profile('stock'); self.assertNotEqual(p.returncode,0); self.assertEqual((self.run/'engine.pid').read_text(),old); self.assert_restored(); self.assertFalse(any(e[:2]==['svc','stop'] for e in self.events()[before:]))
 def test_profile_apply_failed_start_restores_exact_legacy_config(self):
  self.active(); self.fault('fail-start',True); p,x=self.apply_profile('stock'); self.assertNotEqual(p.returncode,0); self.assertTrue(x['rolled_back']); self.assert_restored(); self.assertEqual(json.loads(self.call('status').stdout)['profile_id'],'alt1')
 def test_profile_apply_failure_restores_previously_selected_profile_bytes(self):
  p,x=self.apply_profile('stock'); self.assertEqual(p.returncode,0,p.stdout+p.stderr); self.original=self.config.read_bytes(); self.active(); self.fault('fail-start',True)
  p,x=self.apply_profile('fake_split'); self.assertNotEqual(p.returncode,0); self.assertTrue(x['rolled_back']); self.assert_restored(); self.assertEqual(json.loads(self.call('status').stdout)['profile_id'],'stock')
 def test_profile_apply_actual_wrong_argv_rolls_back(self):
  self.active(); self.fault('wrong-argv'); p,x=self.apply_profile('fake'); self.assertNotEqual(p.returncode,0); self.assertFalse(x['ok']); self.assertTrue(x['rolled_back']); self.assert_restored()
 def test_profile_recovery_failure_blocks_subsequent_apply(self):
  self.active(); self.fault('fail-start'); p,x=self.apply_profile('stock'); self.assertFalse(x['rolled_back']); self.assertTrue(x['recovery_required']); self.assertTrue(json.loads(self.call('status').stdout)['configure_recovery_required']); self.assertTrue(list(self.run.glob('configure.[0-9]*')))
  p,x=self.apply_profile('fake'); self.assertNotEqual(p.returncode,0); self.assertEqual(self.config.read_bytes(),self.original)
 def test_profile_apply_even_noop_rejects_updater(self):
  old=self.active(); self.fault('list-busy'); p,x=self.apply_profile('alt1'); self.assertNotEqual(p.returncode,0); self.assertEqual((self.run/'engine.pid').read_text(),old); self.assert_restored()
 def test_profile_apply_rejects_guarded_owner_pending_cleanup_and_unknown(self):
  old=self.active(); diag=self.run/'profiles'; diag.mkdir(); before=len(self.events())
  for name,value in [('owner',{'job':'lost.owner'}),('result',{'state':'running'}),('result',{'state':'pending'}),('result',{'state':'cleanup'}),('result',{'state':'unknown'}),('owner',{'bad':'owner'})]:
   with self.subTest(name=name,value=value):
    (diag/name).write_text(json.dumps(value)); p,x=self.apply_profile('stock'); self.assertNotEqual(p.returncode,0,p.stdout+p.stderr); (diag/name).unlink()
  (diag/'result').write_text('broken JSON'); p,x=self.apply_profile('stock'); self.assertNotEqual(p.returncode,0); (diag/'result').unlink()
  self.assertEqual((self.run/'engine.pid').read_text(),old); self.assert_restored(); self.assertFalse(any(e[:2]==['svc','stop'] for e in self.events()[before:]))
 def test_profile_apply_rejects_finishing_live_identity(self):
  diag=self.run/'profiles'; diag.mkdir(); pid=str(os.getpid()); raw=pathlib.Path('/proc/'+pid+'/stat').read_text(); ticks=raw[raw.rindex(') ')+2:].split()[19]
  (diag/'finishing').write_text(json.dumps(dict(pid=pid,ticks=ticks))); p,x=self.apply_profile('stock'); self.assertNotEqual(p.returncode,0); self.assertEqual(self.config.read_bytes(),self.original)
 def test_profile_apply_accepts_completed_diagnostic_with_dead_finisher(self):
  diag=self.run/'profiles'; diag.mkdir(); (diag/'result').write_text(json.dumps({'state':'results','results':[]})); (diag/'finishing').write_text(json.dumps(dict(pid='99999999',ticks='1')))
  p,x=self.apply_profile('stock'); self.assertEqual(p.returncode,0,p.stdout+p.stderr)
 def test_diag_owner_published_under_same_control_lock_wins_apply_race(self):
  old=self.active(); diag=self.run/'profiles'; diag.mkdir(); actor=self.d/'acquire'
  source=(self.d/'ctl').read_text().split('case "$1" in\n status)')[0]
  actor.write_text(source+"\nlock_op control || exit 1\nprintf '%s\\n' '{\"job\":\"acquired\"}' >\"$RUN/profiles/owner\"\ntouch \"$RUN/acquired\"\nsleep 1\n"); actor.chmod(0o755)
  launch=subprocess.Popen([str(actor)],env=self.env,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
  deadline=time.monotonic()+5
  while not (self.run/'acquired').exists() and time.monotonic()<deadline: time.sleep(.02)
  self.assertTrue((self.run/'acquired').exists()); p,x=self.apply_profile('stock'); out,err=launch.communicate(timeout=5); self.assertEqual(launch.returncode,0,out+err); self.assertNotEqual(p.returncode,0); self.assertEqual((self.run/'engine.pid').read_text(),old); self.assert_restored()

 def test_real_source_worker_execs_all_saved_protocols_and_reaps_owned_engine(self):
  for group,profile in [('quic','quic_google'),('udp','udp_fake6')]:
   p,x=self.apply_protocol(group,True,profile);self.assertEqual(p.returncode,0,p.stdout+p.stderr)
  self.test_real_source_worker_execs_saved_profile_and_reaps_owned_engine()
 def test_real_source_worker_execs_saved_profile_and_reaps_owned_engine(self):
  p,x=self.apply_profile('fake_split'); self.assertEqual(p.returncode,0,p.stdout+p.stderr)
  worker=(ROOT/'files/usr/libexec/zapret2-home-worker').read_text()
  for old,new in {'/usr/libexec/zapret2-home-worker':str(self.d/'worker'),'/usr/libexec/zapret2-home-engine':str(self.d/'engine'),'/usr/libexec/zapret2-home-ctl':str(self.d/'ctl'),'/usr/libexec/zapret2-home-list-timer':'/bin/true','/usr/lib/zapret2-home':str(self.d/'lib'),'/var/run/zapret2-home':str(self.run),'/proc/net/netfilter/nfnetlink_queue':str(self.d/'queue')}.items(): worker=worker.replace(old,new)
  worker=worker.replace('#!/bin/sh','#!'+BUSYBOX+' ash',1).replace('ucode ',shlex.quote(str(UCODE))+' -L '+shlex.quote(str(MODULES))+' ').replace('logger -t zapret2-home',':')
  (self.d/'worker').write_text(worker); (self.d/'worker').chmod(0o755); (self.run/'requested').touch()
  process=subprocess.Popen([str(self.d/'worker')],env=self.env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
  try:
   deadline=time.monotonic()+8
   while not (self.run/'owner').exists() and time.monotonic()<deadline: time.sleep(.02)
   self.assertTrue((self.run/'owner').exists()); pid=(self.run/'engine.pid').read_text().strip()
   self.assertEqual(os.readlink('/proc/'+pid+'/exe'),str(self.d/'lib/nfqws2'))
   argv=pathlib.Path('/proc/'+pid+'/cmdline').read_bytes().split(b'\0')[:-1]; expected=json.loads((self.d/'lib/profile-catalog.json').read_text())[4]['args']
   self.assertEqual([a.decode() for a in argv if a.startswith(b'--lua-desync=')][:len(expected)],expected); self.assertEqual(self.call('running').returncode,0)
   status=json.loads(self.call('status').stdout)['protocols'];self.assertEqual(b'--filter-udp=443' in argv,status['quic']['enabled']);self.assertEqual(b'--filter-udp=19294-19344,50000-50100' in argv,status['udp']['enabled']);self.assertEqual(argv.count(b'--new'),int(status['quic']['enabled'])+int(status['udp']['enabled']));self.assertEqual(argv.count(b'--qnum=213'),1)
  finally:
   process.terminate(); out,err=process.communicate(timeout=8)
  self.assertEqual(process.returncode,0,out+err); self.assertFalse((self.run/'engine.pid').exists()); self.assertFalse((self.run/'owner').exists()); self.assertFalse((self.run/'worker.pid').exists()); self.assertFalse((self.run/'table').exists())
 def test_deployed_alt1_without_explicit_in_range_is_migrated_safely(self):
  helper=self.d/'lib/protocols.uc'; original=helper.read_text(); helper.write_text(original.replace("'--in-range=x',",'',1)); old=self.active(); helper.write_text(original)
  p,x=self.apply_profile('stock'); self.assertEqual(p.returncode,0,p.stdout+p.stderr); self.assertNotEqual((self.run/'engine.pid').read_text(),old); self.assertEqual(json.loads(self.call('status').stdout)['profile_id'],'stock')
 def test_engine_launcher_six_profiles_both_queues_exact_exec_identity(self):
  for profile in json.loads((self.d/'lib/profile-catalog.json').read_text()):
   for queue in ('213','214'):
    with self.subTest(profile=profile['id'],queue=queue):
     p=subprocess.run([str(self.d/'engine'),queue,profile['id'],'dry-run'],env=self.env,capture_output=True); self.assertEqual(p.returncode,0,p.stderr)
     p=subprocess.Popen([str(self.d/'engine'),queue,profile['id'],'run'],env=self.env,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
     try:
      deadline=time.monotonic()+3
      while os.readlink('/proc/'+str(p.pid)+'/exe')!=str(self.d/'lib/nfqws2') and time.monotonic()<deadline: time.sleep(.01)
      self.assertEqual(os.readlink('/proc/'+str(p.pid)+'/exe'),str(self.d/'lib/nfqws2'))
      argv=pathlib.Path('/proc/'+str(p.pid)+'/cmdline').read_bytes().split(b'\0')[:-1]
      prefix=[str(self.d/'lib/nfqws2'),'--qnum='+queue]+['--lua-init=@'+str(self.d/'lib/lua'/name) for name in ('zapret-lib.lua','zapret-antidpi.lua','hostfakesplit-alt1.lua')]+['--filter-tcp=443','--filter-l7=tls','--in-range=x','--out-range=-n20' if profile['id']=='fake_split' else '--out-range=-n6','--payload=tls_client_hello']
      self.assertEqual([a.decode() for a in argv],prefix+profile['args'])
      if queue=='213':
       matched=subprocess.run([str(UCODE),'-L',str(MODULES),str(self.d/'lib/protocols.uc'),'main-match',str(p.pid),'strict','1',profile['id'],'0','quic_google','0','udp_fake2'],env=self.env,capture_output=True);self.assertEqual(matched.returncode,0,matched.stderr)
     finally: p.terminate(); p.communicate(timeout=3)
 def test_engine_launcher_protocol_interface_matches_shared_argv(self):
  for group,profile in [('quic','quic_google'),('quic','quic_zero'),('udp','udp_fake2'),('udp','udp_fake6')]:
   for queue in ('213','214'):
    with self.subTest(group=group,profile=profile,queue=queue):
     p=subprocess.run([str(self.d/'engine'),queue,profile,'dry-run',group],env=self.env,capture_output=True);self.assertEqual(p.returncode,0,p.stderr)
     p=subprocess.Popen([str(self.d/'engine'),queue,profile,'run',group],env=self.env,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
     try:
      diagnostic_quic=group=='quic' and queue=='214'
      executable=str(self.d/'lib'/('nfqws2-quic' if diagnostic_quic else 'nfqws2'))
      deadline=time.monotonic()+3
      while os.readlink('/proc/'+str(p.pid)+'/exe')!=executable and time.monotonic()<deadline:time.sleep(.01)
      self.assertEqual(os.readlink('/proc/'+str(p.pid)+'/exe'),executable)
      actual=pathlib.Path('/proc/'+str(p.pid)+'/cmdline').read_bytes().split(b'\0')[:-1]
      self.assertEqual(actual[0].decode(),executable)
      self.assertEqual(b'--reasm-disable=quic_initial' in actual,diagnostic_quic)
      expected=subprocess.run([str(UCODE),'-L',str(MODULES),str(self.d/'lib/protocols.uc'),'argv',queue,profile,'run',group],env=self.env,capture_output=True,check=True).stdout.splitlines()
      self.assertEqual(actual,expected);self.assertNotIn(b'--filter-tcp=443',actual);self.assertEqual(sum(a.startswith(b'--qnum=') for a in actual),1)
     finally:p.terminate();p.communicate(timeout=3)
 def test_engine_launcher_rejects_injection_and_unsupported_modes(self):
  for args in [('215','alt1','run'),('213;exit 0','alt1','run'),('213','fake;exit 0','run'),('213','alt1','--dry-run'),('213','seqovl','run'),('213','alt1','run','extra')]:
   with self.subTest(args=args):
    p=subprocess.run([str(self.d/'engine'),*args],env=self.env,capture_output=True); self.assertNotEqual(p.returncode,0)
  catalog=self.d/'lib/profile-catalog.json'; data=json.loads(catalog.read_text()); data[0]['args']=['--lua-desync=fake;touch /bad']; catalog.write_text(json.dumps(data)); p=subprocess.run([str(self.d/'engine'),'213','alt1','run'],env=self.env,capture_output=True); self.assertNotEqual(p.returncode,0)

if __name__=='__main__': unittest.main(verbosity=2)
