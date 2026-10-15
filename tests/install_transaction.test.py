#!/usr/bin/env python3
"""Local exact installer/hooks/init/ctl/worker integration. No router access.
procd is an explicitly compiled parent/exec double, not a shell-function worker.
Only its fixed PID/exe constants and filesystem paths are relocated in lock.uc.
UCI/nft/engine I/O doubles come from active_config; actual /proc identities apply.
"""
import ast,hashlib,importlib.util,json,os,pathlib,shlex,signal,subprocess,time,unittest,threading,concurrent.futures
from local_env import BUSYBOX
ROOT=pathlib.Path(__file__).resolve().parents[1]
VERSION=next(ast.literal_eval(n.value) for n in ast.parse((ROOT/'build.py').read_text()).body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='VER' for t in n.targets))
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
active=load('active_fixture',ROOT/'tests/active_config.test.py');installer=load('installer',ROOT/'install.py')
CMD=[str(active.UCODE),'-L',str(active.MODULES)]
PROCD=r'''#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
int main(int n,char **a){signal(SIGCHLD,SIG_IGN);char token[128];FILE *f=fopen(a[1],"r+");if(!f)return 1;while(fgets(token,sizeof(token),f)){token[strcspn(token,"\n")]=0;pid_t p=fork();if(p==0){if(*token)setenv("Z2_LIFECYCLE_TOKEN",token,1);else unsetenv("Z2_LIFECYCLE_TOKEN");execl(a[2],a[2],NULL);_exit(127);}FILE *o=fopen(a[3],"a");fprintf(o,"%d\n",p);fclose(o);}return 0;}
'''
class InstallTransaction(unittest.TestCase):
 @classmethod
 def setUpClass(cls):active.ActiveConfigure.setUpClass()
 @classmethod
 def tearDownClass(cls):active.ActiveConfigure.tearDownClass()
 def write(self,path,text):path.write_text(text);path.chmod(0o755)
 def setUp(self):
  self.f=active.ActiveConfigure('test_inactive_save_never_starts_engine');self.f.setUp();self.d=self.f.d;self.run=self.f.run;self.env=self.f.env;self.procs=[]
  self.package=self.d/'package.ipk';self.package.write_text('EXPLICIT MOCK PACKAGE');self.digest=hashlib.sha256(self.package.read_bytes()).hexdigest()
  self.production=self.d/'production';self.production.write_text('VPN/firewall/pid unchanged\n');self.cache=self.d/'cache';self.cache.write_text('EXACT LIST SNAPSHOT\n')
  paths={'/usr/libexec/zapret2-home-ctl':str(self.d/'ctl'),'/usr/libexec/zapret2-home-worker':str(self.d/'worker'),'/usr/libexec/zapret2-home-engine':str(self.d/'engine'),'/usr/libexec/zapret2-home-list-timer':str(self.d/'timer'),'/usr/libexec/zapret2-home-lists':str(self.d/'bin/lists'),'/usr/lib/zapret2-home':str(self.d/'lib'),'/var/run/zapret2-home':str(self.run),'/etc/config/zapret2_home':str(self.f.config),'/etc/init.d/zapret2-home':str(self.d/'bin/svc'),'/etc/init.d/rpcd':str(self.d/'bin/rpcd'),'/usr/share/libubox/jshn.sh':str(active.JSHN_SH),'/proc/net/netfilter/nfnetlink_queue':str(self.d/'queue')}
  self.paths=paths
  def relocate(text):
   for old,new in paths.items():text=text.replace(old,new)
   return text.replace('#!/bin/sh','#!'+BUSYBOX+' ash',1).replace('PATH=/usr/sbin:/usr/bin:/sbin:/bin','PATH='+str(self.d/'bin')+':/usr/sbin:/usr/bin:/sbin:/bin').replace('ucode ',shlex.join(CMD)+' ')
  self.relocate=relocate
  for name,source in [('worker','files/usr/libexec/zapret2-home-worker'),('timer','files/usr/libexec/zapret2-home-list-timer')]:self.write(self.d/name,relocate((ROOT/source).read_text()))
  self.write(self.d/'bin/ucode','#!/bin/sh\nexec '+shlex.join(CMD)+' "$@"\n')
  fifo=self.d/'procd.fifo';os.mkfifo(fifo)
  c=self.d/'procd.c';c.write_text(PROCD);subprocess.run(['cc',str(c),'-o',str(self.d/'procd')],check=True,capture_output=True)
  self.procd=subprocess.Popen([str(self.d/'procd'),str(fifo),str(self.d/'worker'),str(self.d/'worker-pids')],env=self.env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True)
  lock=self.d/'lib/lock.uc';lock.write_text(lock.read_text().replace("self.ppid!='1'",f"self.ppid!='{self.procd.pid}'").replace("!='/sbin/procd'",f"!='{self.d}/procd'").replace("'/usr/libexec/zapret2-home-worker'",repr(str(self.d/'worker'))))
  init='#!'+BUSYBOX+' ash\n'+relocate((ROOT/'files/etc/init.d/zapret2-home').read_text()).split('\n',1)[1]
  wrapper='''
procd_open_instance() { RESTORE_TOKEN=''; }
procd_set_param() { [ "$1" != env ] || RESTORE_TOKEN=${2#Z2_LIFECYCLE_TOKEN=}; }
procd_close_instance() { printf '%s\n' "$RESTORE_TOKEN" >"$MOCK_ROOT/procd.fifo"; }
case "$1" in
 enabled) test -f "$MOCK_ROOT/enabled";;
 enable) touch "$MOCK_ROOT/enabled";;
 disable) rm -f "$MOCK_ROOT/enabled";;
 start) [ ! -f "$MOCK_ROOT/fail-start" ] && start_service;;
 stop) [ ! -f "$MOCK_ROOT/fail-stop" ] && stop_service; touch "$MOCK_ROOT/procd-kill-called";;
 restart) stop_service && start_service;;
 *) exit 1;;
esac
'''
  self.write(self.d/'bin/svc',init+wrapper)
  self.write(self.d/'bin/rpcd','#!/bin/sh\n[ ! -f "$MOCK_ROOT/fail-reload" ]\n')
  # Third status is final readback; rendezvous is outside all application code.
  self.write(self.d/'bin/ubus',r'''#!/usr/bin/env python3
import json,os,pathlib,subprocess,time
r=pathlib.Path(os.environ['MOCK_ROOT'])
if os.sys.argv[1:3]!=['call','zapret2_home']:print('{"l3_device":"wan-test"}');raise SystemExit(0)
p=r/'status-count';n=int(p.read_text())+1 if p.exists() else 1;p.write_text(str(n))
if n>=2 and (r/'rpc-status-unavailable').exists():raise SystemExit(1)
if n in (2,3) and (r/'rpc-status-delayed').exists():raise SystemExit(1)
if n==3:
 (r/'final-paused').touch()
 while (r/'pause-final').exists():time.sleep(.01)
v=json.loads(subprocess.check_output([str(r/'ctl'),'status']))
if n==3 and (r/'fail-readback').exists():v['profile_id']='WRONG'
print(json.dumps(v))
''')
  tree=ast.parse((ROOT/'build.py').read_text());control=next(n.value for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='control' for t in n.targets))
  for k,v in zip(control.keys,control.values):
   name=ast.literal_eval(k)
   if name in ('prerm','postrm','postinst'):self.write(self.d/name,relocate(ast.literal_eval(v)).replace('/tmp/luci-',str(self.d/'luci-')))
  c=self.d/'opkg.c';c.write_text('#include <stdlib.h>\nint main(void){return system(getenv("HOOKS"))==0?0:1;}\n');subprocess.run(['cc',str(c),'-o',str(self.d/'bin/opkg')],check=True,capture_output=True)
  self.env['HOOKS']='touch '+shlex.quote(str(self.d/'opkg-entered'))+'; '+shlex.quote(str(self.d/'prerm'))+' upgrade && '+shlex.quote(str(self.d/'postrm'))+' upgrade && '+shlex.quote(str(self.d/'postinst'))+' configure'
 def tearDown(self):
  for p in self.procs:
   if p.poll() is None:os.killpg(p.pid,signal.SIGKILL)
   p.communicate(timeout=5)
  os.killpg(self.procd.pid,signal.SIGKILL);self.procd.wait(timeout=5)
  # Waitable compiled procd reaps normally; final hard cleanup is sandbox only.
  if (self.run/'engine.pid').exists():
   try:os.kill(int((self.run/'engine.pid').read_text()),signal.SIGKILL)
   except ProcessLookupError:pass
  self.f.tearDown()
 def active(self):
  p=subprocess.run([str(self.d/'ctl'),'control'],input='start',env=self.env,text=True,capture_output=True,timeout=20);self.assertEqual(p.returncode,0,p.stdout+p.stderr)
 def script(self):
  manifest={str(self.d/'lib/lock.uc').lstrip('/'):hashlib.sha256((self.d/'lib/lock.uc').read_bytes()).hexdigest()}
  text=installer.upgrade_script(manifest,True,str(self.package),self.digest,VERSION).replace(installer.PRODUCTION,'cat '+shlex.quote(str(self.production)))
  return self.relocate(text)
 def start(self):
  p=subprocess.Popen([BUSYBOX,'ash','-c',self.script()],env=self.env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,start_new_session=True);self.procs.append(p);return p
 def result(self,p,success=True):
  out,err=p.communicate(timeout=35)
  if success:self.assertEqual(p.returncode,0,out+err);return json.loads(out)
  self.assertNotEqual(p.returncode,0,out+err);self.assertTrue((self.run/'lifecycle.json').exists(),err);self.assertTrue((self.run/'lifecycle-recovery.uc').exists());return err
 def waitfile(self,path):
  deadline=time.monotonic()+10
  while not path.exists() and time.monotonic()<deadline:time.sleep(.01)
  self.assertTrue(path.exists(),str(path))
 def lockcall(self,mode,token,me=None,name=''):
  return subprocess.run(CMD+[str(self.d/'lib/lock.uc'),mode,name,str(me or os.getpid())],env=dict(self.env,Z2_LIFECYCLE_TOKEN=token),capture_output=True,text=True,timeout=5)
 def test_direct_quiesce_holds_shutdown_lease_until_mutation_finishes(self):
  ctl=self.d/'ctl';ctl.write_text(ctl.read_text().replace('quiesce_locked() {','quiesce_locked() {\n touch "$MOCK_ROOT/quiesce-paused"\n while [ -f "$MOCK_ROOT/pause-quiesce" ]; do sleep .01; done',1))
  (self.d/'pause-quiesce').touch()
  p=subprocess.Popen([str(ctl),'quiesce'],env=self.env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,start_new_session=True);self.procs.append(p);self.waitfile(self.d/'quiesce-paused')
  self.assertTrue((self.run/'shutdown.lock').is_dir());blocked=self.lockcall('freeze','');self.assertNotEqual(blocked.returncode,0);self.assertFalse((self.run/'lifecycle.json').exists())
  (self.d/'pause-quiesce').unlink();out,err=p.communicate(timeout=10);self.assertEqual(p.returncode,0,out+err);self.assertFalse((self.run/'shutdown.lock').exists())
  freeze=self.lockcall('freeze','');self.assertEqual(freeze.returncode,0,freeze.stderr);self.assertEqual(self.lockcall('finish',freeze.stdout.strip()).returncode,0)
 def test_inflight_init_stop_keeps_lease_through_post_callback_procd_kill(self):
  # Explicit rc.common post-callback double: unconditional kill even on return.
  svc=self.d/'bin/svc';svc.write_text(svc.read_text().replace('touch "$MOCK_ROOT/procd-kill-called"','touch "$MOCK_ROOT/init-paused"; while [ -f "$MOCK_ROOT/pause-init" ]; do sleep .01; done; touch "$MOCK_ROOT/procd-kill-called"'))
  (self.d/'pause-init').touch();p=subprocess.Popen([str(svc),'stop'],env=self.env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,start_new_session=True);self.procs.append(p);self.waitfile(self.d/'init-paused')
  self.assertFalse((self.run/'shutdown.lock').exists());self.assertTrue((self.run/'service.lock').exists());self.assertNotEqual(self.lockcall('freeze','').returncode,0)
  (self.d/'pause-init').unlink();out,err=p.communicate(timeout=10);self.assertEqual(p.returncode,0,out+err);self.assertTrue((self.d/'procd-kill-called').exists());self.assertFalse((self.run/'service.lock').exists())
  frozen=self.lockcall('freeze','');self.assertEqual(frozen.returncode,0,frozen.stderr);self.assertEqual(self.lockcall('finish',frozen.stdout.strip()).returncode,0)
 def test_restore_uses_actual_procd_parent_saved_profile_scope_and_readback(self):
  # Nondefault profile/full scope/lists/AU/autostart survive byte-for-byte.
  self.f.config.write_bytes(self.f.original+b"\nconfig unused 'other'\n option opaque 'preserve'\n")
  self.f.config.write_text(self.f.config.read_text().replace(" option clients ''"," option profile 'fake'\n option clients '192.168.1.20/32'").replace(" option client_mode 'all'"," option client_mode 'selected'"))
  original=self.f.config.read_bytes();self.active();old=(self.run/'engine.pid').read_text();x=self.result(self.start())
  self.assertEqual(x['initial']['profile_id'],'fake');self.assertEqual(x['status']['profile_id'],'fake');self.assertTrue(x['status']['running']);self.assertTrue(x['status']['table_present']);self.assertTrue(x['status']['auto_update'])
  self.assertEqual(self.f.config.read_bytes(),original);self.assertEqual(self.cache.read_text(),'EXACT LIST SNAPSHOT\n');self.assertNotEqual((self.run/'engine.pid').read_text(),old)
  worker=(self.run/'worker.pid').read_text().strip();stat=pathlib.Path('/proc/'+worker+'/stat').read_text().rsplit(') ',1)[1].split();self.assertEqual(stat[1],str(self.procd.pid));self.assertFalse((self.run/'lifecycle.json').exists())
 def test_stopped_intent_both_marker_states_never_launches_procd(self):
  for stopping in (False,True):
   with self.subTest(stopping=stopping):
    (self.d/'enabled').unlink(missing_ok=True)
    if stopping:(self.run/'stopping').touch()
    else:(self.run/'stopping').unlink(missing_ok=True)
    (self.d/'status-count').unlink(missing_ok=True);x=self.result(self.start());self.assertFalse(x['status']['running']);self.assertFalse(x['status']['autostart']);self.assertFalse((self.run/'requested').exists());self.assertEqual((self.run/'stopping').exists(),stopping);self.assertFalse((self.d/'worker-pids').exists());self.assertEqual(self.f.config.read_bytes(),self.f.original)
 def test_restore_freeze_blocks_clients_competing_installer_and_unrelated_token_holder(self):
  self.active();(self.d/'pause-final').touch();p=self.start();self.waitfile(self.d/'final-paused');gate=json.loads((self.run/'lifecycle.json').read_text());self.assertIn('worker',gate)
  before=self.f.config.read_bytes();engine=(self.run/'engine.pid').read_text()
  for command,payload in [('configure',self.f.request),('profiles-apply',{'profile':'stock'}),('control','stop'),('control','disable'),('update_lists',{}),('quiesce',{}),('request',{})]:
   denied=subprocess.run([str(self.d/'ctl'),command],input=payload if command=='control' else json.dumps(payload),env=self.env,text=True,capture_output=True,timeout=10);self.assertNotEqual(denied.returncode,0,denied.stdout+denied.stderr)
  (self.d/'procd-kill-called').unlink(missing_ok=True)
  for action in ('start','stop','restart'):
   denied=subprocess.run([str(self.d/'bin/svc'),action],env=self.env,text=True,capture_output=True,timeout=5);self.assertNotEqual(denied.returncode,0,denied.stdout+denied.stderr)
  self.assertFalse((self.d/'procd-kill-called').exists(),'Denied init stop must exit before generic procd kill')
  self.assertNotEqual(self.lockcall('acquire',gate['token'],name='rules').returncode,0)
  q=self.start();out,err=q.communicate(timeout=5);self.assertNotEqual(q.returncode,0);self.assertIn('Lifecycle frozen',err)
  self.assertEqual(self.f.config.read_bytes(),before);self.assertEqual((self.run/'engine.pid').read_text(),engine);self.assertTrue((self.run/'requested').exists());self.assertFalse((self.run/'stopping').exists());self.assertEqual(json.loads((self.run/'lifecycle.json').read_text())['owner'],gate['owner'])
  (self.d/'pause-final').unlink();self.result(p);self.assertFalse((self.run/'lifecycle.json').exists())
 def test_failed_restore_retains_gate_and_recovery_without_general_admission(self):
  self.active();(self.d/'fail-start').touch();self.result(self.start(),False)
  self.assertEqual(self.f.config.read_bytes(),self.f.original);self.assertTrue((self.run/'lifecycle-config').exists());self.assertFalse((self.run/'requested').exists());self.assertTrue((self.run/'stopping').exists())
  self.assertNotEqual(self.f.call('control',{'action':'start'}).returncode,0)
 def test_final_readback_fault_retains_freeze_after_running_restore(self):
  self.active();(self.d/'fail-readback').touch();self.result(self.start(),False);self.assertTrue((self.run/'table').exists());self.assertTrue((self.run/'requested').exists());self.assertEqual(self.f.config.read_bytes(),self.f.original)
 def test_reload_fault_keeps_recovery(self):
  (self.d/'fail-reload').touch();self.result(self.start(),False)
 def test_uci_read_error_rejects_before_stop_and_opkg(self):
  self.active();engine=(self.run/'engine.pid').read_bytes();uci=self.d/'bin/uci'
  original=uci.read_bytes();real=self.d/'bin/uci.real';real.write_bytes(original);real.chmod(0o755)
  self.write(uci,'#!'+BUSYBOX+' ash\n[ "$1" != -q ] || shift\n[ "$1" != changes ] || exit 7\nexec "'+str(real)+'" "$@"\n')
  self.result(self.start(),False);self.assertFalse((self.d/'opkg-entered').exists());self.assertEqual((self.run/'engine.pid').read_bytes(),engine);self.assertTrue((self.run/'table').exists())
 def test_delayed_rpc_registration_is_polled_before_restore(self):
  self.active();(self.d/'rpc-status-delayed').touch();x=self.result(self.start());self.assertTrue(x['status']['running']);self.assertGreaterEqual(int((self.d/'status-count').read_text()),5)
 def test_rpc_registration_timeout_retains_gate_before_restore(self):
  (self.d/'rpc-status-unavailable').touch();self.result(self.start(),False);self.assertFalse((self.run/'requested').exists());self.assertFalse((self.d/'worker-pids').exists())
 def test_hash_rechecked_inside_freeze_before_opkg(self):
  self.package.write_text('TAMPERED AFTER UPLOAD');err=self.result(self.start(),False);self.assertIn('FAILED',err);self.assertFalse((self.d/'opkg-entered').exists())
 def test_production_integrity_fault_at_final_readback_retains_gate(self):
  self.active();(self.d/'pause-final').touch();p=self.start();self.waitfile(self.d/'final-paused');self.production.write_text('EXPLICIT MOCK interference\n');(self.d/'pause-final').unlink();self.result(p,False)
 def test_package_hooks_cannot_change_saved_autostart_in_either_direction(self):
  hooks=self.env['HOOKS']
  for expected in (True,False):
   enabled=self.d/'enabled'
   if expected:enabled.touch()
   elif enabled.exists():enabled.unlink()
   self.active()
   # Model the native opkg reinstall disable and the opposite fresh-hook enable.
   mutation=('rm -f ' if expected else 'touch ')+shlex.quote(str(enabled))
   self.env['HOOKS']=hooks+' && '+mutation
   result=self.result(self.start())
   self.assertEqual(result['status']['autostart'],expected)
   self.assertTrue(result['status']['running'])
   self.assertFalse((self.run/'lifecycle.json').exists())
  self.assertNotIn('--force-reinstall',self.script())
 def test_owner_generation_mismatch_during_restore_retains_gate(self):
  self.active();(self.d/'pause-final').touch();p=self.start();self.waitfile(self.d/'final-paused');gate=json.loads((self.run/'lifecycle.json').read_text());gate['owner']['ticks']='1';(self.run/'lifecycle.json').write_text(json.dumps(gate));(self.d/'pause-final').unlink();self.result(p,False)
 def test_two_actual_local_install_clients_have_private_stages_and_only_own_cleanup(self):
  # Explicit SSH/filesystem relocation double; mktemp/dd/hash/transactions are real.
  client=self.d/'client';(client/'dist').mkdir(parents=True);remote=self.d/'remote-tmp';remote.mkdir()
  package_name=f'zapret2-home_{VERSION}_fixture.ipk';(client/'dist'/package_name).write_bytes(self.package.read_bytes());(client/'dist/package.sha256').write_text(self.digest+'  '+package_name+'\n')
  (client/'dist/files-manifest.json').write_text(json.dumps({str(self.d/'lib/lock.uc').lstrip('/'):hashlib.sha256((self.d/'lib/lock.uc').read_bytes()).hexdigest()}))
  (client/'dist/file-modes.json').write_text(json.dumps({str(self.d/'lib/lock.uc').lstrip('/'):format((self.d/'lib/lock.uc').stat().st_mode&0o777,'o')}))
  status=self.d/'opkg-status';status.write_text(f'Package: zapret2-home\nVersion: {VERSION}\n')
  barrier=threading.Barrier(2);stages=[];cleanups=[];original=(installer.ROOT,installer.run,installer.require_gate)
  def local(command,inp=None,timeout=240):
   if command=='opkg status zapret2-home':command='cat '+shlex.quote(str(status))
   if command.startswith('umask 077; dd of='):barrier.wait(timeout=10)
   if command.startswith('rm -f '):cleanups.append(command)
   command=self.relocate(command.replace(installer.PRODUCTION,'cat '+shlex.quote(str(self.production)))).replace('/tmp/hermes-z2-install.',str(remote/'hermes-z2-install.'))
   p=subprocess.run([BUSYBOX,'ash','-c',command],input=inp,env=self.env,capture_output=True,timeout=timeout)
   if p.returncode:raise RuntimeError(p.stdout.decode()+p.stderr.decode())
   out=p.stdout.decode()
   if command.startswith('umask 077; mktemp'):
    stages.append(pathlib.Path(out.strip()));out=out.replace(str(remote)+'/','/tmp/')
   return out
  def attempt():
   try:return ('success',installer.install(upgrade=True,live=True))
   except RuntimeError as error:return ('failed',str(error))
  try:
   installer.ROOT=client;installer.run=local;installer.require_gate=lambda: self.assertEqual(self.lockcall('abi','').stdout.strip(),'1')
   with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:results=list(pool.map(lambda _:attempt(),range(2)))
  finally:installer.ROOT,installer.run,installer.require_gate=original
  self.assertEqual(sorted(x[0] for x in results),['failed','success'],results);self.assertEqual(len(stages),2);self.assertNotEqual(stages[0],stages[1]);self.assertEqual(len(cleanups),1)
  retained=[p for p in stages if p.exists()];self.assertEqual(len(retained),1);self.assertEqual((retained[0]/'package.ipk').read_bytes(),self.package.read_bytes());self.assertIn('/tmp/'+retained[0].name+'/package.ipk',next(x[1] for x in results if x[0]=='failed'));self.assertFalse((self.run/'lifecycle.json').exists())
 def test_grant_is_one_use_and_correct_procd_replay_cannot_reap_restored_worker(self):
  self.active();(self.d/'pause-final').touch();p=self.start();self.waitfile(self.d/'final-paused');gate=json.loads((self.run/'lifecycle.json').read_text());marker=(self.run/'worker.pid').read_bytes();engine=(self.run/'engine.pid').read_bytes()
  with (self.d/'procd.fifo').open('w') as fifo:fifo.write(gate['token']+'\n')
  deadline=time.monotonic()+3
  while len((self.d/'worker-pids').read_text().splitlines())<3 and time.monotonic()<deadline:time.sleep(.01)
  replay=(self.d/'worker-pids').read_text().splitlines()[-1];deadline=time.monotonic()+3
  while pathlib.Path('/proc/'+replay).exists() and time.monotonic()<deadline:time.sleep(.01)
  self.assertFalse(pathlib.Path('/proc/'+replay).exists());self.assertEqual((self.run/'worker.pid').read_bytes(),marker);self.assertEqual((self.run/'engine.pid').read_bytes(),engine);self.assertEqual(json.loads((self.run/'lifecycle.json').read_text())['worker'],gate['worker']);(self.d/'pause-final').unlink();self.result(p)
 def test_wrong_procd_parent_or_missing_grant_cannot_register_worker(self):
  # Freeze/arm owned by this test process, token intentionally given to wrong parent.
  freeze=self.lockcall('freeze','');self.assertEqual(freeze.returncode,0,freeze.stderr);token=freeze.stdout.strip();self.assertEqual(self.lockcall('restore-begin',token).returncode,0);(self.run/'requested').touch()
  p=subprocess.run([str(self.d/'worker')],env=dict(self.env,Z2_LIFECYCLE_TOKEN=token),capture_output=True,text=True,timeout=5);self.assertNotEqual(p.returncode,0);self.assertIn('Not lifecycle procd worker',p.stderr);self.assertFalse((self.run/'worker.pid').exists())
  with (self.d/'procd.fifo').open('w') as fifo:fifo.write('\n')
  self.waitfile(self.d/'worker-pids');time.sleep(.1);self.assertFalse((self.run/'worker.pid').exists());self.assertNotIn('worker',json.loads((self.run/'lifecycle.json').read_text()))
if __name__=='__main__':unittest.main(verbosity=2)
