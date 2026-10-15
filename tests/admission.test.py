#!/usr/bin/env python3
"""Deterministic real fs.file.lock interprocess tests; no router or network access.
Only paths are relocated; pause probes add a second real flock rendezvous.
"""
import ast,fcntl,importlib.util,json,os,pathlib,select,shlex,signal,subprocess,tempfile,time,unittest
from local_env import BUSYBOX
ROOT=pathlib.Path(__file__).resolve().parents[1]
from local_env import SCRATCH, CMD
spec=importlib.util.spec_from_file_location('installer',ROOT/'install.py');installer=importlib.util.module_from_spec(spec);spec.loader.exec_module(installer)
class Admission(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(prefix='z2-admission-',dir=SCRATCH);self.d=pathlib.Path(self.tmp.name);self.run=self.d/'run';self.run.mkdir();self.procs=[]
  self.source=(ROOT/'files/usr/lib/zapret2-home/lock.uc').read_text().replace("const RUN='/var/run/zapret2-home';",f"const RUN='{self.run}';")
  self.lock=self.d/'lock.uc';self.lock.write_text(self.source)
 def tearDown(self):
  for p in self.procs:
   if p.poll() is None:os.killpg(p.pid,signal.SIGKILL)
   p.communicate(timeout=5)
  self.tmp.cleanup()
 def call(self,mode,name='',me=None,parent='',token=None,parent_ticks=''):
  env=dict(os.environ)
  if token is not None:env['Z2_LIFECYCLE_TOKEN']=token
  return subprocess.run(CMD+[str(self.lock),mode,name,str(me or os.getpid()),str(parent),str(parent_ticks)],capture_output=True,text=True,env=env,timeout=5)
 def actor(self,body,lock=None):
  prefix='u() { '+shlex.join(CMD+[str(lock or self.lock)])+' "$@"; }\n'
  body=body.replace('$U','u')
  # Keep the owner alive until the test closes its pipe.
  p=subprocess.Popen(['/bin/sh','-c',prefix+body+'\nread -r END\n'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,start_new_session=True);self.procs.append(p);return p
 def line(self,p):
  self.assertTrue(select.select([p.stdout],[],[],5)[0], 'Actor did not acknowledge');return p.stdout.readline().strip()
 def finish_actor(self,p):p.communicate('\n',timeout=5)
 def pause_source(self,needle):
  paused=self.d/'paused.uc';signal=self.d/'snapshot';barrier=self.d/'barrier'
  paused.write_text(self.source.replace(needle,needle+f'\nwritefile("{signal}","ready"); let b=open("{barrier}","a"); if(!b.lock("x")) exit(1);',1))
  fd=barrier.open('a');self.addCleanup(fd.close);fcntl.flock(fd,fcntl.LOCK_EX);return paused,signal,fd
 def waitfile(self,path):
  end=time.monotonic()+5
  while not path.exists() and time.monotonic()<end:time.sleep(.005)
  self.assertTrue(path.exists())
 def test_stale_snapshot_cannot_delete_new_owner_all_three_locks(self):
  for name in ('control','rules','list-update'):
   with self.subTest(name=name):
    path=self.run/(name+'.lock');path.mkdir();(path/'pid').write_text('99999999\n');(path/'ticks').write_text('1\n')
    paused,signal,fd=self.pause_source('let live=current && (!ticks || ticks==current.ticks);')
    a=self.actor(f'$U acquire {name} "$$"; echo A:$?:$$',paused);self.waitfile(signal)
    b=self.actor(f'echo TRY; $U acquire {name} "$$"; echo B:$?:$$');self.assertEqual(self.line(b),'TRY')
    # Once it opened the same inode it cannot cross the held admission guard.
    self.assertFalse(select.select([b.stdout],[],[],.1)[0]);fcntl.flock(fd,fcntl.LOCK_UN);fd.close()
    aa=self.line(a);bb=self.line(b);self.assertTrue(aa.startswith('A:0:'));self.assertTrue(bb.startswith('B:1:'))
    owner=aa.split(':')[2];self.assertEqual((path/'pid').read_text().strip(),owner)
    self.finish_actor(a);self.finish_actor(b);self.assertEqual(self.call('reap',name).returncode,0);signal.unlink()
 def test_late_handoff_and_release_cannot_overwrite_replacement(self):
  for name in ('control','rules','list-update'):
   with self.subTest(name=name):
    a=self.actor(f'$U acquire {name} "$$"; echo $$');old=self.line(a);self.finish_actor(a)
    b=self.actor(f'$U acquire {name} "$$"; echo $$');new=self.line(b)
    self.assertNotEqual(self.call('handoff',name,parent=old).returncode,0)
    self.assertEqual(self.call('release',name,me=old).returncode,1) # dead actor is never an owner
    self.assertEqual((self.run/(name+'.lock')/'pid').read_text().strip(),new)
    self.assertEqual(self.call('release',name).returncode,0);self.assertTrue((self.run/(name+'.lock')).exists())
    self.finish_actor(b);self.assertEqual(self.call('reap',name).returncode,0)
 def test_parent_release_after_handoff_cannot_remove_child(self):
  self.assertEqual(self.call('acquire','control').returncode,0)
  ticks=(self.run/'control.lock/ticks').read_text().strip()
  child=self.actor(f'$U handoff control "$$" {os.getpid()} {ticks}; echo $?')
  self.assertEqual(self.line(child),'0');self.assertEqual(self.call('release','control').returncode,0)
  self.assertEqual((self.run/'control.lock/pid').read_text().strip(),str(child.pid));self.finish_actor(child)
 def test_reused_parent_pid_with_new_ticks_cannot_be_stolen_by_late_child(self):
  # Explicit MOCK /proc stat reads: deterministic PID reuse, no host PID churn.
  proc=self.d/'mock-proc';proc.mkdir()
  for pid,ticks in ((9001,'22'),(9002,'33')):
   (proc/str(pid)).mkdir();fields=['S','1']+['0']*17+[ticks]
   (proc/str(pid)/'stat').write_text(str(pid)+' (MOCK identity) '+' '.join(fields))
  mock_caller="{pid:'mock-helper',ticks:'1',ppid:me}"
  self.lock.write_text(self.source.replace("readfile('/proc/'+pid+'/stat')",f"readfile('{proc}/'+pid+'/stat')").replace("let caller=ident(readlink('/proc/self'));", "let caller="+mock_caller+"; // MOCK caller for deterministic /proc generations").replace("let guarded_caller=ident(readlink('/proc/self'));", "let guarded_caller="+mock_caller+"; // SAME explicit caller mock, not a real ancestry test"))
  for name in ('control','rules','list-update'):
   path=self.run/(name+'.lock');path.mkdir();(path/'pid').write_text('9001\n');(path/'ticks').write_text('22\n')
   for expected in ('','11'):
    self.assertNotEqual(self.call('handoff',name,me=9002,parent=9001,parent_ticks=expected).returncode,0)
    self.assertEqual((path/'pid').read_text(),'9001\n');self.assertEqual((path/'ticks').read_text(),'22\n')
   self.assertEqual(self.call('handoff',name,me=9002,parent=9001,parent_ticks='22').returncode,0)
   self.assertEqual((path/'pid').read_text(),'9002\n')
 def test_orphan_waiting_helper_cannot_release_reused_parent_generation(self):
  # Real process ancestry and flock; ONLY parent PID reuse/stat is mocked.
  owner_file=self.d/'owner'; owner_stat=self.d/'owner-stat'; ready=self.d/'caller-ready'; go=self.d/'go'; helper_file=self.d/'helper'
  source=self.source.replace("let raw=readfile('/proc/'+pid+'/stat')",f"let raw=readfile(pid==trim(readfile('{owner_file}') || '') ? '{owner_stat}' : '/proc/'+pid+'/stat')")
  source=source.replace("let guard=open(RUN+'/admission.guard','a');",f"writefile('{ready}',sprintf('%J',caller)); let guard=open(RUN+'/admission.guard','a');")
  self.lock.write_text(source)
  actor=self.d/'parent.py'
  actor.write_text('import os,pathlib,subprocess,time\nd=pathlib.Path('+repr(str(self.d))+')\n(d/"owner").write_text(str(os.getpid()))\nwhile not (d/"go").exists():time.sleep(.005)\np=subprocess.Popen('+repr(CMD+[str(self.lock),'release','control'])+'+[str(os.getpid())],stdout=(d/"out").open("w"),stderr=(d/"err").open("w"))\n(d/"helper").write_text(str(p.pid))\np.wait()\n')
  with (self.run/'admission.guard').open('a') as guard:
   fcntl.flock(guard,fcntl.LOCK_EX)
   parent=subprocess.Popen(['python3',str(actor)],start_new_session=True);self.procs.append(parent)
   self.waitfile(owner_file);owner=owner_file.read_text()
   fields=['S','1']+['0']*17+['11'];owner_stat.write_text(owner+' (MOCK reused parent) '+' '.join(fields))
   path=self.run/'control.lock';path.mkdir();(path/'pid').write_text(owner+'\n');(path/'ticks').write_text('11\n')
   go.touch();self.waitfile(ready);self.waitfile(helper_file);helper=helper_file.read_text()
   parent.kill();parent.wait(timeout=5)
   fields[-1]='22';owner_stat.write_text(owner+' (MOCK reused parent) '+' '.join(fields));(path/'ticks').write_text('22\n')
   self.assertNotEqual(pathlib.Path('/proc/'+helper+'/stat').read_text().rsplit(') ',1)[1].split()[1],owner)
   fcntl.flock(guard,fcntl.LOCK_UN)
  end=time.monotonic()+5
  while time.monotonic()<end:
   proc=pathlib.Path('/proc/'+helper+'/stat')
   if not proc.exists() or proc.read_text().rsplit(') ',1)[1].split()[0]=='Z':break
   time.sleep(.005)
  else:
   os.kill(int(helper),signal.SIGKILL)
   self.fail('Orphan helper did not terminate')
  self.assertTrue(path.exists(),'Old orphan helper deleted the replacement owner')
  self.assertEqual((path/'pid').read_text(),owner+'\n');self.assertEqual((path/'ticks').read_text(),'22\n')
  self.assertIn('identity changed while waiting',(self.d/'err').read_text())
 def test_leaked_token_unrelated_caller_and_owner_generation_are_rejected(self):
  owner=self.actor('$U freeze "" "$$"');token=self.line(owner)
  for mode,name in (('acquire','rules'),('restore-begin',''),('restore-context',''),('shutdown',''),('finish','')):
   self.assertNotEqual(self.call(mode,name,token=token).returncode,0)
  for mode in ('finish','restore-begin','restore-context','worker-acquire'):
   self.assertNotEqual(self.call(mode,me=owner.pid,token=token).returncode,0,'Forged live owner PID')
  self.assertTrue((self.run/'lifecycle.json').exists());self.finish_actor(owner)
  # Same PID but wrong generation cannot authenticate even the original token.
  gate=json.loads((self.run/'lifecycle.json').read_text());gate['owner']={'pid':str(os.getpid()),'ticks':'1'}
  (self.run/'lifecycle.json').write_text(json.dumps(gate))
  for mode in ('restore-begin','restore-context','shutdown','finish'):
   self.assertNotEqual(self.call(mode,token=token).returncode,0)
  self.assertTrue((self.run/'lifecycle.json').exists())
 def test_freeze_rejects_all_owned_directories(self):
  for name in ('control','rules','list-update','shutdown','service'):
   self.assertEqual(self.call('acquire',name).returncode,0);self.assertNotEqual(self.call('freeze').returncode,0)
   self.assertFalse((self.run/'lifecycle.json').exists());self.assertEqual(self.call('release',name).returncode,0)
 def test_freeze_rejects_configure_pending_recovery_and_backups(self):
  (self.run/'configure.job').write_text('123');job=self.run/'configure-job.123';job.mkdir()
  for result in (None,{'ok':False,'rolled_back':False},{'ok':False,'rolled_back':True,'recovery_required':True}):
   if result is not None:(job/'result').write_text(json.dumps(result))
   self.assertNotEqual(self.call('freeze').returncode,0)
  (job/'result').write_text('{"ok":true}');backup=self.run/'configure.123';backup.mkdir();(backup/'config').write_text('RETAIN')
  self.assertNotEqual(self.call('freeze').returncode,0);self.assertEqual((backup/'config').read_text(),'RETAIN')
  (backup/'config').unlink();backup.rmdir();token=self.call('freeze').stdout.strip();self.assertTrue(token);self.assertEqual(self.call('finish',token=token).returncode,0)
 def test_freeze_rejects_diagnostic_owner_finishing_and_invalid_state(self):
  d=self.run/'profiles';d.mkdir()
  (d/'owner').write_text('{"pid":"99999999","job":"stale"}');self.assertNotEqual(self.call('freeze').returncode,0);(d/'owner').unlink()
  ticks=pathlib.Path('/proc/self/stat').read_text().rsplit(') ',1)[1].split()[19]
  (d/'finishing').write_text(json.dumps({'pid':str(os.getpid()),'ticks':ticks}));self.assertNotEqual(self.call('freeze').returncode,0);(d/'finishing').unlink()
  (d/'finishing').write_text('{}');self.assertNotEqual(self.call('freeze').returncode,0);(d/'finishing').unlink()
  for text in ('{','{"state":"running"}'):
   (d/'result').write_text(text);self.assertNotEqual(self.call('freeze').returncode,0)
 def test_freeze_blocks_new_control_rules_list_and_handoff_until_correct_finish(self):
  p=self.call('freeze');self.assertEqual(p.returncode,0,p.stderr);token=p.stdout.strip()
  for name in ('control','rules','list-update'):self.assertNotEqual(self.call('acquire',name).returncode,0)
  self.assertNotEqual(self.call('finish',token='wrong').returncode,0)
  child=self.actor('$U finish "" "$$"; echo $?');self.assertEqual(self.line(child),'1');self.finish_actor(child)
  # Only fixed shutdown rules get the authenticated inherited transaction token.
  self.assertEqual(self.call('acquire','rules',token=token).returncode,0);self.assertEqual(self.call('release','rules').returncode,0)
  self.assertEqual(self.call('finish',token=token).returncode,0);self.assertFalse((self.run/'lifecycle.json').exists());self.assertEqual(self.call('acquire','control').returncode,0)
 def test_admission_and_freeze_are_one_atomic_domain(self):
  paused,signal,fd=self.pause_source('let live=current && (!ticks || ticks==current.ticks);')
  actor=self.actor('$U acquire control "$$"; echo $?',paused);self.waitfile(signal)
  freeze=self.actor('echo TRY; $U freeze "" "$$"; echo F:$?');self.assertEqual(self.line(freeze),'TRY');self.assertFalse(select.select([freeze.stdout],[],[],.1)[0])
  fcntl.flock(fd,fcntl.LOCK_UN);fd.close();self.assertEqual(self.line(actor),'0');self.assertEqual(self.line(freeze),'F:1');self.assertFalse((self.run/'lifecycle.json').exists());self.finish_actor(actor);self.finish_actor(freeze)
 def test_dead_owner_recovery_requires_token_and_revalidates_idle(self):
  actor=self.actor('$U freeze "" "$$"');token=self.line(actor)
  self.assertNotEqual(self.call('recover',token=token).returncode,0)
  self.finish_actor(actor);self.assertNotEqual(self.call('finish',token=token).returncode,0)
  self.assertNotEqual(self.call('recover',token='wrong').returncode,0)
  backup=self.run/'configure.999';backup.mkdir()
  self.assertNotEqual(self.call('recover',token=token).returncode,0);backup.rmdir()
  recovered=self.call('recover',token=token);self.assertEqual(recovered.returncode,0,recovered.stderr)
  self.assertNotEqual(recovered.stdout.strip(),token);self.assertEqual(self.call('finish',token=recovered.stdout.strip()).returncode,0)
  bad=json.dumps({'token':recovered.stdout.strip(),'owner':{},'kind':'installer'});(self.run/'lifecycle.json').write_text(bad)
  for mode in ('recover','finish','acquire'):
   self.assertNotEqual(self.call(mode,token=recovered.stdout.strip()).returncode,0);self.assertEqual((self.run/'lifecycle.json').read_text(),bad)
 def test_frozen_actual_worker_cannot_reap_or_spawn(self):
  (self.run/'requested').touch();(self.run/'worker.lock').mkdir();(self.run/'worker.pid').write_text('99999999\n')
  token=self.call('freeze').stdout.strip();self.assertTrue(token)
  worker=(ROOT/'files/usr/libexec/zapret2-home-worker').read_text().replace('RUN=/var/run/zapret2-home','RUN='+str(self.run)).replace('LIB=/usr/lib/zapret2-home','LIB='+str(self.d)).replace('ucode ',shlex.join(CMD)+' ')
  path=self.d/'worker';path.write_text(worker)
  p=subprocess.run([BUSYBOX,'ash',str(path)],capture_output=True,text=True,timeout=5)
  self.assertNotEqual(p.returncode,0);self.assertEqual((self.run/'worker.pid').read_text(),'99999999\n');self.assertTrue((self.run/'worker.lock').exists());self.assertFalse((self.run/'engine.pid').exists())
  self.assertEqual(self.call('finish',token=token).returncode,0)
 def test_actual_ctl_rejects_mutators_during_freeze_without_service_or_uci_writes(self):
  spec=importlib.util.spec_from_file_location('active_fixture',ROOT/'tests/active_config.test.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
  cls=module.ActiveConfigure;cls.setUpClass();fixture=cls('test_noop_active_save_preserves_live_scope');fixture.setUp()
  try:
   lock=fixture.d/'lib/lock.uc';p=subprocess.run(CMD+[str(lock),'freeze','',str(os.getpid())],capture_output=True,text=True,check=True);token=p.stdout.strip()
   for command,payload in [('configure',fixture.request),('profiles-apply',{'profile':'stock'}),('control',{'action':'start'}),('update_lists',{})]:
    p=fixture.call(command,payload);self.assertNotEqual(p.returncode,0,p.stdout+p.stderr);self.assertFalse(json.loads(p.stdout)['ok']);self.assertIn('Package lifecycle frozen',p.stderr)
   self.assertEqual(fixture.config.read_bytes(),fixture.original);self.assertFalse((fixture.run/'configure.job').exists())
   events=[json.loads(line) for line in (fixture.d/'events').read_text().splitlines()]
   self.assertTrue(all(event[:2] in (['svc','enabled'],['nft','list']) for event in events),events)
   subprocess.run(CMD+[str(lock),'finish','',str(os.getpid())],env=dict(os.environ,Z2_LIFECYCLE_TOKEN=token),capture_output=True,check=True)
  finally:fixture.tearDown();cls.tearDownClass()
 def test_legacy_installer_fails_before_staging_stop_or_opkg(self):
  calls=[];old=installer.run
  def blocked(command,*args,**kw):
   calls.append(command)
   command=command.replace('/usr/lib/zapret2-home/lock.uc',str(self.lock)).replace('/usr/libexec/zapret2-home-',str(self.d/'legacy-')).replace('/usr/lib/opkg/info/zapret2-home.',str(self.d/'legacy-hook-')).replace('ucode ',shlex.join(CMD)+' ')
   result=subprocess.run([BUSYBOX,'ash','-c',command],capture_output=True,text=True,timeout=5)
   if result.returncode:raise RuntimeError(result.stderr)
   return result.stdout
  installer.run=blocked
  try:
   with self.assertRaisesRegex(RuntimeError,'legacy'):installer.install(upgrade=True,live=True)
   self.lock.rename(self.d/'helper-offline')
   with self.assertRaisesRegex(RuntimeError,'legacy'):installer.install(upgrade=True,live=True)
  finally:installer.run=old
  self.assertFalse((self.run/'admission.guard').exists(),'Legacy refusal must precede staged helper invocation')
  self.assertEqual(len(calls),2)
  for command in calls:self.assertIn('test -f /usr/lib/zapret2-home/lock.uc',command);self.assertNotIn(' stop',command);self.assertNotIn('dd of=',command)
 def test_exact_hooks_and_installer_transaction_preserve_freeze_on_failure(self):
  tree=ast.parse((ROOT/'build.py').read_text());control=next(n.value for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='control' for t in n.targets))
  hooks={ast.literal_eval(k):ast.literal_eval(v) for k,v in zip(control.keys,control.values) if ast.literal_eval(k) in ('postinst','prerm','postrm')}
  bin=self.d/'bin';bin.mkdir();cfg=self.d/'config';cfg.write_text('EXACT USER CONFIG\n');events=self.d/'events'
  package=self.d/'package.ipk';package.write_text('PRIVATE PACKAGE');digest=__import__('hashlib').sha256(package.read_bytes()).hexdigest()
  def write(p,text):p.write_text(text);p.chmod(0o755)
  write(bin/'ucode','#!/bin/sh\nexec '+shlex.join(CMD)+' "$@"\n')
  for name,text in hooks.items():
   text=text.replace('/usr/lib/zapret2-home/lock.uc',str(self.lock)).replace('/var/run/zapret2-home',str(self.run)).replace('/etc/init.d/zapret2-home',str(bin/'svc')).replace('/tmp/luci-',str(self.d/'luci-'))
   write(self.d/name,text)
  write(bin/'svc','#!/bin/sh\nprintf "%s\\n" "$1" >>'+shlex.quote(str(events))+'\nexit 0\n')
  write(bin/'nft','#!/bin/sh\nexit 1\n');write(bin/'ctl','#!/bin/sh\nexit 1\n');write(bin/'rpcd','#!/bin/sh\nexit 0\n');write(bin/'uci','#!/bin/sh\nexit 0\n')
  write(bin/'ubus','#!/bin/sh\nprintf \'%s\\n\' \'{"running":false,"table_present":false,"autostart":true,"integrity_ok":true,"package_version":"0.2.5","profile_id":"alt1","protocols":{"tcp":{"enabled":true,"profile":"alt1"},"quic":{"enabled":false,"profile":"quic_google"},"udp":{"enabled":false,"profile":"udp_fake2"}}}\'\n')
  # Explicit executable opkg double: real parent identity, exact real hooks.
  c=self.d/'opkg.c';c.write_text('#include <stdlib.h>\nint main(void){return system(getenv("HOOKS"))==0?0:1;}\n');subprocess.run(['gcc','-o',str(bin/'opkg'),str(c)],check=True)
  env=dict(os.environ,PATH=str(bin)+':'+os.environ['PATH'])
  script=installer.upgrade_script({},True,str(package),digest,'0.2.5').replace(installer.PRODUCTION,'printf stable').replace('/usr/lib/zapret2-home/lock.uc',str(self.lock)).replace('/var/run/zapret2-home',str(self.run)).replace('/etc/config/zapret2_home',str(cfg)).replace('/etc/init.d/zapret2-home',str(bin/'svc')).replace('/usr/libexec/zapret2-home-ctl',str(bin/'ctl')).replace('/etc/init.d/rpcd',str(bin/'rpcd'))
  # Empty manifest would make sha256sum reject input; use the actual sandbox cfg.
  script=script.replace("printf '%s' '\n'", "printf '%s' "+shlex.quote(subprocess.check_output(['sha256sum',str(cfg)],text=True)))
  (self.run/'keep-backup').mkdir();(self.run/'keep-backup/config').write_text('KEEP')
  env['HOOKS']=shlex.quote(str(self.d/'prerm'))+' upgrade && '+shlex.quote(str(self.d/'postrm'))+' upgrade && '+shlex.quote(str(self.d/'postinst'))+' configure'
  p=subprocess.run(['/bin/sh','-c',script],env=env,capture_output=True,text=True,timeout=15)
  self.assertEqual(p.returncode,0,p.stdout+p.stderr);self.assertFalse((self.run/'lifecycle.json').exists());self.assertEqual(json.loads(p.stdout)['status']['integrity_ok'],True);self.assertEqual((self.run/'keep-backup/config').read_text(),'KEEP')
  backup=self.run/'configure.789';backup.mkdir();(backup/'config').write_text('REAL CONFIG BACKUP')
  subprocess.run([str(self.d/'postrm'),'upgrade'],env=env,capture_output=True,check=True)
  self.assertEqual((backup/'config').read_text(),'REAL CONFIG BACKUP');(backup/'config').unlink();backup.rmdir()
  env['HOOKS']=shlex.quote(str(self.d/'prerm'))+' upgrade; exit 1'
  p=subprocess.run(['/bin/sh','-c',script],env=env,capture_output=True,text=True,timeout=15)
  self.assertNotEqual(p.returncode,0);self.assertTrue((self.run/'lifecycle.json').exists());self.assertTrue((self.run/'lifecycle-recovery.uc').exists());self.assertEqual((self.run/'keep-backup/config').read_text(),'KEEP')
if __name__=='__main__':unittest.main(verbosity=2)
