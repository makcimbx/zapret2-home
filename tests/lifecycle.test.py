#!/usr/bin/env python3
"""Fault/race regressions on the exact shell functions with explicit nft test double."""
import unittest,pathlib,tempfile,subprocess,os,time,shlex
ROOT=pathlib.Path(__file__).resolve().parents[1]
from local_env import SCRATCH, CMD
class Lifecycle(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(prefix='z2-lifecycle-',dir=SCRATCH);self.d=pathlib.Path(self.tmp.name);self.b=self.d/'bin';self.b.mkdir();self.run=self.d/'run';self.run.mkdir()
  nft=self.b/'nft';nft.write_text('''#!/usr/bin/env python3
import sys,os,pathlib,time
p=pathlib.Path(os.environ['MOCK_RUN']);a=sys.argv[1:]
if a[:1]==['list']:sys.exit(0 if (p/'table').exists() else 1)
if a[:1]==['delete']:
 if (p/'fail-delete').exists():sys.exit(1)
 (p/'table').unlink(missing_ok=True);sys.exit(0)
if a[:1]==['-c']:sys.exit(0)
if a[:1]==['-f']:
 (p/'applying').touch()
 while (p/'pause').exists():time.sleep(.03)
 (p/'table').touch();sys.exit(0)
sys.exit(2)
''');nft.chmod(0o755)
  source=(ROOT/'files/usr/libexec/zapret2-home-ctl').read_text().split('case "$1" in\n status)')[0]
  lib=self.d/'lib';lib.mkdir();(lib/'lock.uc').write_text((ROOT/'files/usr/lib/zapret2-home/lock.uc').read_text().replace("const RUN='/var/run/zapret2-home';",f"const RUN='{self.run}';"))
  ucode=self.b/'ucode';ucode.write_text('#!/bin/sh\nexec '+shlex.join(CMD)+' "$@"\n');ucode.chmod(0o755)
  source=source.replace('LIB=/usr/lib/zapret2-home','LIB='+str(lib)).replace('/usr/libexec/zapret2-home-lists ensure-idle','true').replace('. /usr/share/libubox/jshn.sh','').replace('RUN=/var/run/zapret2-home','RUN='+shlex.quote(str(self.run))).replace('export PATH','PATH='+shlex.quote(str(self.b))+':$PATH; export PATH')
  self.source=source+'\nis_running() { P=100; return 0; }\nmake_rules() { printf "table\n" >"$RUN/rules.nft"; }\nerr() { printf "ERROR:%s\\n" "$1"; return 1; }\nok() { printf "OK\\n"; }\n'
  self.env=dict(os.environ,MOCK_RUN=str(self.run))
 def tearDown(self):self.tmp.cleanup()
 def spawn(self,body):return subprocess.Popen(['sh','-c',self.source+'\n'+body],env=self.env,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
 def execute(self,body):
  p=self.spawn(body);o,e=p.communicate(timeout=20);return p.returncode,o.decode(),e.decode()
 def test_apply_remove_are_serialized(self):
  (self.run/'requested').touch();(self.run/'pause').touch();a=self.spawn('apply')
  for _ in range(100):
   if (self.run/'applying').exists():break
   time.sleep(.03)
  self.assertTrue((self.run/'applying').exists());r=self.spawn('remove');time.sleep(.15)
  self.assertIsNone(r.poll());(self.run/'pause').unlink()
  a.communicate(timeout=15);r.communicate(timeout=15)
  self.assertEqual((a.returncode,r.returncode),(0,0));self.assertFalse((self.run/'table').exists());self.assertFalse((self.run/'owner').exists())
 def test_delete_failure_preserves_owner_and_failure(self):
  (self.run/'table').touch();(self.run/'owner').write_text('zapret2-home:100\n');(self.run/'fail-delete').touch()
  self.assertNotEqual(self.execute('remove')[0],0);self.assertTrue((self.run/'owner').exists());self.assertTrue((self.run/'table').exists())
  (self.run/'fail-delete').unlink();self.assertEqual(self.execute('remove')[0],0);self.assertFalse((self.run/'table').exists());self.assertFalse((self.run/'owner').exists())
 def test_late_worker_cannot_remove_new_generation(self):
  (self.run/'table').touch();(self.run/'owner').write_text('zapret2-home:101\n')
  self.assertEqual(self.execute('remove 100')[0],0);self.assertTrue((self.run/'table').exists());self.assertTrue((self.run/'owner').exists())
 def test_stopping_gate_prevents_apply(self):
  (self.run/'requested').touch();(self.run/'stopping').touch()
  self.assertNotEqual(self.execute('apply')[0],0);self.assertFalse((self.run/'table').exists())
 def test_enable_failure_is_not_success(self):
  svc=self.b/'svc';svc.write_text('#!/bin/sh\nexit 1\n');svc.chmod(0o755)
  body='SVC='+shlex.quote(str(svc))+"\nset_autostart 1\n"
  rc,out,err=self.execute(body);self.assertNotEqual(rc,0);self.assertNotIn('OK',out)
 def test_deferred_wan_start_and_manual_stop_intent(self):
  ctl=self.b/'ctl';init=self.b/'init'
  raw=(ROOT/'files/usr/libexec/zapret2-home-ctl').read_text()
  dispatch='case "$1" in\n status)'+raw.split('case "$1" in\n status)',1)[1]
  override='\nSVC='+shlex.quote(str(init))+'\nis_running() { return 1; }\nworker_alive() { return 1; }\nwan() { test -f "$RUN/wan-up"; }\nprepare() { return 0; }\n'
  ctl.write_text((self.source+override+dispatch).replace('/usr/libexec/zapret2-home-ctl',str(ctl)));ctl.chmod(0o755)
  s=(ROOT/'files/etc/init.d/zapret2-home').read_text().split('\n',1)[1].replace('/usr/libexec/zapret2-home-ctl',str(ctl)).replace('ucode /usr/lib/zapret2-home/lock.uc',str(self.b/'ucode')+' '+str(self.d/'lib/lock.uc')).replace('/var/run/zapret2-home',str(self.run))
  init.write_text('#!/bin/sh\nRUN='+shlex.quote(str(self.run))+'\n'+s+'\nlogger() { :; }\nprocd_open_instance() { :; }\nprocd_set_param() { :; }\nprocd_close_instance() { touch "$RUN/registered"; }\nstart() { start_service; }\nstop() { stop_service; }\ncase "$1" in start) start;; stop) stop;; esac\n');init.chmod(0o755)
  def call(p,arg):return subprocess.run([str(p),arg],env=self.env,capture_output=True,timeout=15)
  self.assertEqual(call(init,'start').returncode,0);self.assertTrue((self.run/'requested').exists());self.assertFalse((self.run/'registered').exists())
  (self.run/'wan-up').touch();self.assertEqual(call(ctl,'reconcile').returncode,0);self.assertTrue((self.run/'registered').exists())
  (self.run/'registered').unlink();self.assertEqual(call(init,'stop').returncode,0);self.assertFalse((self.run/'requested').exists())
  self.assertEqual(call(ctl,'reconcile').returncode,0);self.assertFalse((self.run/'registered').exists())
if __name__=='__main__':unittest.main(verbosity=2)
