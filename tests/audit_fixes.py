#!/usr/bin/env python3
"""Exact worker/package-hook fault probes. Engine/controller/files are sandboxed."""
import ast,json,os,pathlib,shlex,signal,subprocess,tempfile,time
from local_env import BUSYBOX
ROOT=pathlib.Path(__file__).resolve().parents[1]
from local_env import SCRATCH, CMD
results=[]
def write(p,s):p.write_text(s);p.chmod(0o755)
def check(name,condition):
 assert condition,name
 results.append(name);print('PASS',name,flush=True)
def waitfile(p,condition=lambda s: bool(s)):
 for _ in range(200):
  if p.exists() and condition(p.read_text().strip()):return p.read_text().strip()
  time.sleep(.02)
 raise AssertionError('Timed out: '+str(p))
with tempfile.TemporaryDirectory(prefix='z2-crash-fixture-',dir=SCRATCH) as t:
 d=pathlib.Path(t);run=d/'run';run.mkdir();lib=d/'lib';lib.mkdir();bin=d/'bin';bin.mkdir()
 (run/'requested').touch();(d/'queue').write_text('213 fixture\n')
 write(bin/'ucode','#!/bin/sh\nexec '+shlex.join(CMD)+' "$@"\n')
 c=d/'engine.c';c.write_text('#include <unistd.h>\nint main(void){for(;;) pause();}\n')
 subprocess.run(['gcc','-o',str(lib/'nfqws2'),str(c)],check=True)
 write(d/'ctl','#!/bin/sh\nexit 0\n');write(d/'timer','#!/bin/sh\nexit 0\n')
 write(bin/'uci','#!/bin/sh\nexit 1\n') # Explicit absent-profile UCI fixture.
 (lib/'profile-catalog.json').write_bytes((ROOT/'files/usr/lib/zapret2-home/profile-catalog.json').read_bytes())
 (lib/'protocol-catalog.json').write_bytes((ROOT/'files/usr/lib/zapret2-home/protocol-catalog.json').read_bytes())
 (lib/'protocols.uc').write_text((ROOT/'files/usr/lib/zapret2-home/protocols.uc').read_text().replace('/usr/lib/zapret2-home',str(lib)))
 (lib/'lock.uc').write_text((ROOT/'files/usr/lib/zapret2-home/lock.uc').read_text().replace('/var/run/zapret2-home',str(run)).replace('/usr/libexec/zapret2-home-worker',str(d/'worker')))
 launcher=(ROOT/'files/usr/libexec/zapret2-home-engine').read_text().replace('LIB=/usr/lib/zapret2-home','LIB='+str(lib)).replace('#!/bin/sh','#!'+BUSYBOX+' ash',1)
 write(d/'launcher',launcher)
 s=(ROOT/'files/usr/libexec/zapret2-home-worker').read_text().replace('#!/bin/sh','#!'+BUSYBOX+' ash',1).replace('/usr/libexec/zapret2-home-engine',str(d/'launcher')).replace('LIB=/usr/lib/zapret2-home','LIB='+str(lib)).replace('RUN=/var/run/zapret2-home','RUN='+str(run)).replace('/usr/libexec/zapret2-home-worker',str(d/'worker')).replace('/usr/libexec/zapret2-home-ctl',str(d/'ctl')).replace('/usr/libexec/zapret2-home-list-timer',str(d/'timer')).replace('/proc/net/netfilter/nfnetlink_queue',str(d/'queue'))
 write(d/'worker',s);env=dict(os.environ,PATH=str(bin)+':'+os.environ['PATH']);procs=[];engines=[]
 try:
  first=subprocess.Popen([str(d/'worker')],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE);procs.append(first)
  old=int(waitfile(run/'engine.pid'));engines.append(old)
  duplicate=subprocess.run([str(d/'worker')],env=env,capture_output=True,timeout=5)
  check('a verified live owner blocks a second worker',duplicate.returncode==1 and int((run/'engine.pid').read_text())==old)
  first.kill();first.wait(timeout=5)
  check('SIGKILL leaves the actual stale lock and engine',(run/'worker.lock').exists() and pathlib.Path('/proc/'+str(old)).exists())
  second=subprocess.Popen([str(d/'worker')],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE);procs.append(second)
  new=int(waitfile(run/'engine.pid',lambda x: x.isdigit() and int(x)!=old));engines.append(new)
  check('direct procd-style respawn reclaims stale ownership',second.poll() is None and int((run/'worker.pid').read_text())==second.pid)
  oldexe=pathlib.Path('/proc/'+str(old)+'/exe')
  check('only the old owned engine is terminated',not oldexe.exists() and pathlib.Path('/proc/'+str(new)+'/exe').resolve()==lib/'nfqws2')
  second.terminate();second.wait(timeout=8)
  check('normal cleanup removes only its generation',not (run/'worker.pid').exists() and not (run/'engine.pid').exists() and not (run/'worker.lock').exists())
 finally:
  for p in procs:
   if p.poll() is None:p.kill();p.wait()
  for pid in engines:
   try:os.kill(pid,signal.SIGTERM)
   except ProcessLookupError:pass
module=ast.parse((ROOT/'build.py').read_text());control=next(n.value for n in module.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='control' for t in n.targets))
hooks={ast.literal_eval(k):ast.literal_eval(v) for k,v in zip(control.keys,control.values) if ast.literal_eval(k) in ('postinst','prerm')}
with tempfile.TemporaryDirectory(prefix='z2-hooks-fixture-',dir=SCRATCH) as t:
 d=pathlib.Path(t);state=d/'enabled';svc=d/'svc';run=d/'run';run.mkdir();lock=d/'lock.uc'
 lock.write_text((ROOT/'files/usr/lib/zapret2-home/lock.uc').read_text().replace("const RUN='/var/run/zapret2-home';",f"const RUN='{run}';"))
 bin=d/'bin';bin.mkdir();write(bin/'ucode','#!/bin/sh\nexec '+shlex.join(CMD)+' "$@"\n');env=dict(os.environ,PATH=str(bin)+':'+os.environ['PATH'])
 def opkg(body):subprocess.run(['opkg','-c',body+'; RC=$?; exit "$RC"'],executable='/bin/sh',check=True,env=env)
 write(svc,'#!/bin/sh\ncase "$1" in enabled) test "$(cat '+shlex.quote(str(state))+')" = 1;; disable) printf 0 >'+shlex.quote(str(state))+';; stop) exit 0;; esac\n')
 for name,text in hooks.items():write(d/name,text.replace('/usr/lib/zapret2-home/lock.uc',str(lock)).replace('/var/run/zapret2-home',str(run)).replace('/etc/init.d/zapret2-home',str(svc)).replace('/tmp/luci-indexcache',str(d/'index')).replace('/tmp/luci-modulecache',str(d/'modules')))
 state.write_text('1');opkg(shlex.quote(str(d/'prerm'))+' upgrade && '+shlex.quote(str(d/'postinst'))+' configure')
 check('upgrade hooks retain enabled autostart',state.read_text()=='1')
 state.write_text('0');opkg(shlex.quote(str(d/'postinst'))+' configure')
 check('a fresh disabled install remains disabled',state.read_text()=='0')
 state.write_text('1');opkg(shlex.quote(str(d/'prerm'))+' remove')
 check('removal still disables autostart',state.read_text()=='0')
 deps=(ROOT/'build.py').read_text();check('curl and TLS trust are direct dependencies','kmod-nfnetlink-queue, curl, ca-bundle' in deps)
(ROOT/'dist'/'audit-fixes-results.json').write_text(json.dumps({'passed':len(results),'tests':results,'scope':'local exact source; worker engine, controller and package hooks sandboxed'},indent=2))
print('AUDIT_FIXES_PASS',len(results))
