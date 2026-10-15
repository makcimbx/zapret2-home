#!/usr/bin/env python3
"""Pinned legacy hook/admission counterexamples, local sandbox only.
These tests explain a BLOCKED migration, not a maintenance bootstrap guarantee.
"""
import ast,hashlib,io,json,os,pathlib,shlex,subprocess,tarfile,tempfile,unittest
from local_env import BUSYBOX
ROOT=pathlib.Path(__file__).resolve().parents[1]
OLD=pathlib.Path(os.environ.get('LEGACY_IPK', str(ROOT/'dist/zapret2-home_0.2.4_aarch64_cortex-a53.ipk')))
PIN='e32eef16eae42ff5673293b25facd0208f5b4ce14cd69bf81dc9f9b53b462db1'
from local_env import SCRATCH, CMD
def archive_files():
 assert hashlib.sha256(OLD.read_bytes()).hexdigest()==PIN,'Unknown legacy IPK: no fallback'
 result={}
 with tarfile.open(OLD) as outer:
  for part in ('control','data'):
   member=next(m for m in outer.getmembers() if m.name.endswith(part+'.tar.gz'))
   with tarfile.open(fileobj=io.BytesIO(outer.extractfile(member).read())) as inner:
    result[part]={m.name.removeprefix('./'):inner.extractfile(m).read() for m in inner.getmembers() if m.isfile()}
 return result
class LegacyBoundary(unittest.TestCase):
 def setUp(self):
  self.archive=archive_files();self.tmp=tempfile.TemporaryDirectory(prefix='z2-legacy-',dir=SCRATCH);self.d=pathlib.Path(self.tmp.name);self.run=self.d/'run';self.run.mkdir();self.external=self.d/'EXTERNAL-recovery';self.external.mkdir();self.bin=self.d/'bin';self.bin.mkdir()
  self.env=dict(os.environ,PATH=str(self.bin)+':'+os.environ['PATH'],MOCK_ROOT=str(self.d))
  self.write(self.bin/'svc','#!/bin/sh\nprintf "%s\\n" "$1" >>"$MOCK_ROOT/service-actions"\n')
  self.write(self.bin/'profiles','#!/bin/sh\ncat "$MOCK_ROOT/profile-status"\n')
  self.write(self.bin/'jsonfilter','#!/usr/bin/env python3\nimport json,sys\nprint(str(json.load(sys.stdin)["data"]["running"]).lower())\n')
  (self.d/'profile-status').write_text('{"data":{"running":false}}')
  for name in ('prerm','postrm','postinst'):self.write(self.d/name,self.relocate(self.archive['control'][name].decode()))
 def tearDown(self):self.tmp.cleanup()
 def write(self,path,text):path.write_text(text);path.chmod(0o755)
 def relocate(self,text):return text.replace('/usr/libexec/zapret2-home-profiles',str(self.bin/'profiles')).replace('/etc/init.d/zapret2-home',str(self.bin/'svc')).replace('/var/run/zapret2-home',str(self.run)).replace('/tmp/luci-',str(self.d/'luci-'))
 def hook(self,name):return subprocess.run([BUSYBOX,'ash',str(self.d/name),'upgrade'],env=self.env,text=True,capture_output=True,timeout=5)
 def test_pinned_old_prerm_refuses_live_diagnostic_before_service_stop(self):
  (self.d/'profile-status').write_text('{"data":{"running":true}}');self.assertNotEqual(self.hook('prerm').returncode,0);self.assertFalse((self.d/'service-actions').exists())
 def test_exact_old_hooks_destroy_runtime_but_external_recovery_survives(self):
  samples={'configure.123/config':b'opaque exact UCI bytes\n','profiles/result':b'{"state":"results"}\n','lifecycle.json':b'new-protocol gate is ignored by old hooks\n'}
  for name,data in samples.items():
   p=self.run/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(data)
   p=self.external/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(data)
  (self.external/'old.ipk').write_bytes(OLD.read_bytes());(self.external/'lists.snapshot').write_bytes(b'EXPLICIT list cache fixture\n');(self.external/'intent.json').write_text('{"running":false,"autostart":true}')
  for name in ('prerm','postrm','postinst'):self.assertEqual(self.hook(name).returncode,0,name)
  self.assertFalse(self.run.exists());self.assertEqual((self.d/'service-actions').read_text(),'stop\nenabled\n')
  for name,data in samples.items():self.assertEqual((self.external/name).read_bytes(),data)
  self.assertEqual(hashlib.sha256((self.external/'old.ipk').read_bytes()).hexdigest(),PIN)
 def test_exact_new_postrm_retains_guard_freeze_and_backups(self):
  tree=ast.parse((ROOT/'build.py').read_text());control=next(n.value for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='control' for t in n.targets));hooks={ast.literal_eval(k):ast.literal_eval(v) for k,v in zip(control.keys,control.values) if ast.literal_eval(k)=='postrm'}
  self.write(self.d/'postrm',self.relocate(hooks['postrm']));names=('admission.guard','lifecycle.json','configure.123/config')
  for name in names:p=self.run/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text('retained')
  self.assertEqual(self.hook('postrm').returncode,0)
  for name in names:self.assertEqual((self.run/name).read_text(),'retained')
 def test_exact_old_list_admission_ignores_actual_new_lifecycle_freeze(self):
  lock=self.d/'lock.uc';lock.write_text((ROOT/'files/usr/lib/zapret2-home/lock.uc').read_text().replace('/var/run/zapret2-home',str(self.run)))
  p=subprocess.run(CMD+[str(lock),'freeze','',str(os.getpid())],capture_output=True,text=True,timeout=5);self.assertEqual(p.returncode,0,p.stderr)
  source=self.archive['data']['usr/libexec/zapret2-home-lists'].decode();function=source[source.index('lock_state() {'):source.index('reap_stale()')]
  script='LOCK='+shlex.quote(str(self.run/'list-update.lock'))+'\n'+function.replace('ucode ',shlex.join(CMD)+' ')+'\nlock_state acquire\n'
  p=subprocess.run([BUSYBOX,'ash','-c',script],env=self.env,capture_output=True,text=True,timeout=5);self.assertEqual(p.returncode,0,p.stderr)
  self.assertTrue((self.run/'list-update.lock/pid').exists());self.assertTrue((self.run/'lifecycle.json').exists())
if __name__=='__main__':unittest.main(verbosity=2)
