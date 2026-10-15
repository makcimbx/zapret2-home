#!/usr/bin/env python3
"""Sandbox backend/timer faults with real ucode + native libubox jshn.
Network/UCI/controller are EXPLICIT MOCKS; no production cache or router writes.
Paths alone are remapped in the tested shell source; no test hooks in package.
"""
import argparse, json, os, pathlib, shlex, shutil, signal, subprocess, tempfile, time
from local_env import UCODE, MODULES, JSHN, JSHN_SH
from local_env import BUSYBOX
ROOT = pathlib.Path(__file__).resolve().parents[1]
p = argparse.ArgumentParser()
p.add_argument('--ucode', default=str(UCODE))
p.add_argument('--module-dir', default=str(MODULES))
p.add_argument('--jshn', default=str(JSHN))
p.add_argument('--jshn-sh', default=str(JSHN_SH))
p.add_argument('--results', type=pathlib.Path)
a = p.parse_args()
scratch = pathlib.Path(tempfile.gettempdir())
scratch.mkdir(parents=True, exist_ok=True)
tmp = pathlib.Path(tempfile.mkdtemp(prefix='z2-lists-tests-', dir=scratch))
bin = tmp / 'bin'; bin.mkdir()
run = tmp / 'run'; run.mkdir()
lib=tmp/'lib';lib.mkdir()
for p in (ROOT/'files/usr/lib/zapret2-home').glob('*.uc'): (lib/p.name).write_bytes(p.read_bytes())
(lib/'lock.uc').write_text((lib/'lock.uc').read_text().replace("const RUN='/var/run/zapret2-home';",f"const RUN='{run}';"))
cache = tmp / 'cache'; cfg = tmp / 'fixture.json'; ctl = bin / 'ctl'
helper = bin / 'lists'; timer = bin / 'timer'; worker = bin / 'worker'
results = []
processes = []

def write(path, content):
    path.write_text(content); path.chmod(0o755)

def settings(**kw):
    v = json.loads(cfg.read_text()) if cfg.exists() else {'lists': '', 'auto_update': '0', 'running': False,
         'reconcile_fail': False, 'delay': 0, 'bodies': {'flowseal':'65.108.59.85\n10.0.0.0/8\n', 'cloudflare':'1.1.1.0/24\n'}}
    v.update(kw); cfg.write_text(json.dumps(v)); return v

mock = '''#!/usr/bin/python3
import json, os, pathlib, sys, time
cfg=pathlib.Path(os.environ['Z2_FIXTURE']); v=json.loads(cfg.read_text())
args=sys.argv[1:]; name=pathlib.Path(sys.argv[0]).name
if name=='uci':
 key=args[-1].rsplit('.',1)[-1]
 if key not in v: sys.exit(1)
 print(v[key]); sys.exit(0)
if name=='ctl':
 if args[0]=='running': sys.exit(0 if v['running'] else 1)
 if args[0] in ['reconcile-running','update_lists']:
  with open(os.environ['Z2_CALLS'],'a') as f: f.write(args[0]+'\\n')
  if args[0]=='update_lists': sys.exit(0)
  if v.get('reconcile_fail')=='once':
   v['reconcile_fail']=False; cfg.write_text(json.dumps(v)); sys.exit(1)
  sys.exit(1 if v.get('reconcile_fail') else 0)
 sys.exit(2)
if name=='curl':
 assert args[0]=='-q' and '--proxy' in args and '--proto' in args and '=https' in args
 assert '--max-time' in args and args[args.index('--max-time')+1]=='60'
 assert '--limit-rate' in args and args[args.index('--limit-rate')+1]=='256K'
 assert '-k' not in args and '--insecure' not in args and '-L' not in args
 url=args[-1]; assert url.startswith('https://raw.githubusercontent.com/')
 id='flowseal' if 'Flowseal/' in url else url.rsplit('/',1)[-1].removesuffix('.lst')
 time.sleep(v.get('delay',0))
 if v.get('mutate'):
  new=json.loads(cfg.read_text()); new['lists']=v['mutate']; new.pop('mutate',None); cfg.write_text(json.dumps(new))
 if v.get('fail')==id: sys.exit(28)
 body=v['bodies'].get(id,'8.8.8.0/24\\n')
 if v.get('oversize'): body='x'*3000000
 pathlib.Path(args[args.index('--output')+1]).write_text(body)
 sys.exit(0)
sys.exit(2)
'''
for name in ['uci', 'curl', 'ctl']: write(bin/name, mock)
write(bin/'ucode', '#!/bin/sh\nexec '+shlex.quote(a.ucode)+' -L '+shlex.quote(a.module_dir)+' "$@"\n')
(bin/'jshn').symlink_to(pathlib.Path(a.jshn).resolve())
write(worker, '#!/bin/sh\ntrap "exit 0" TERM INT\nwhile :; do sleep 1; done\n')

def source(path):
    s = path.read_text().replace('#!/bin/sh', '#!'+BUSYBOX+' ash', 1)
    pairs = {
      'PATH=/usr/sbin:/usr/bin:/sbin:/bin': f'PATH={bin}:/usr/sbin:/usr/bin:/sbin:/bin',
      'LIB=/usr/lib/zapret2-home': f'LIB={lib}',
      'RUN=/var/run/zapret2-home': f'RUN={run}',
      'CACHE=/etc/zapret2-home/lists': f'CACHE={cache}',
      'SELF=/usr/libexec/zapret2-home-lists': f'SELF={helper}',
      'CTL=/usr/libexec/zapret2-home-ctl': f'CTL={ctl}',
      'LISTS=/usr/libexec/zapret2-home-lists': f'LISTS={helper}',
      'WORKER=/usr/libexec/zapret2-home-worker': f'WORKER={worker}',
      'CATALOG=/usr/share/zapret2-home/lists.json': f'CATALOG={ROOT}/files/usr/share/zapret2-home/lists.json',
      '. /usr/share/libubox/jshn.sh': '. '+shlex.quote(str(pathlib.Path(a.jshn_sh).resolve())),
    }
    for old,new in pairs.items(): s=s.replace(old,new)
    return s
original = source(ROOT/'files/usr/libexec/zapret2-home-lists')
write(helper, original); write(timer, source(ROOT/'files/usr/libexec/zapret2-home-list-timer'))
env = dict(os.environ, Z2_FIXTURE=str(cfg), Z2_CALLS=str(tmp/'calls'),
           LD_LIBRARY_PATH=os.pathsep.join(filter(None, [str(pathlib.Path(a.jshn).resolve().parent), os.environ.get('LD_LIBRARY_PATH')])))

def command(*args, good=None):
    r = subprocess.run([str(helper), *args], env=env, capture_output=True, timeout=20)
    if good is not None: assert (r.returncode==0)==good, (args, r.returncode, r.stdout, r.stderr)
    return r

def check(name, condition=True):
    assert condition, name
    results.append({'name':name,'passed':True})

def snapshot():
    if not cache.exists(): return {}
    out = {}
    for f in sorted(cache.rglob('*')):
        if f.is_symlink(): out[str(f.relative_to(cache))]=('link',os.readlink(f),f.lstat().st_mtime_ns)
        elif f.is_file(): out[str(f.relative_to(cache))]=(f.read_bytes().hex(),f.stat().st_ino,f.stat().st_mtime_ns)
    return out

def idle():
    for i in range(100):
        if command('ensure-idle').returncode==0: return
        time.sleep(.1)
    raise AssertionError('updater did not finish')

def start_timer():
    w=subprocess.Popen([str(worker)], env=env, start_new_session=True); processes.append(w)
    (run/'worker.pid').write_text(str(w.pid)+'\n'); (run/'requested').touch()
    t=subprocess.Popen([str(timer),str(w.pid)], env=env, stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    processes.append(t); time.sleep(.4)
    return w,t

def stop_timer(w,t):
    # Snapshot direct children: cleanup must reap the long sleep, not leave it.
    children=[]
    try: children=pathlib.Path(f'/proc/{t.pid}/task/{t.pid}/children').read_text().split()
    except FileNotFoundError: pass
    t.terminate(); t.communicate(timeout=5)
    for pid in children: assert not pathlib.Path('/proc/'+pid).exists(), ('orphan timer child',pid)
    os.killpg(w.pid,signal.SIGTERM); w.wait(timeout=5)

try:
    settings()
    gate=subprocess.run([str(bin/'ucode'),str(lib/'lock.uc'),'freeze','',str(os.getpid())],env=env,capture_output=True,text=True,check=True).stdout.strip()
    command('update',good=False)
    assert (run/'lifecycle.json').exists() and not (run/'list-update.lock').exists() and not (cache/'current').exists()
    subprocess.run([str(bin/'ucode'),str(lib/'lock.uc'),'finish','',str(os.getpid())],env=dict(env,Z2_LIFECYCLE_TOKEN=gate),capture_output=True,check=True)
    check('catalog six fixed sources', len(json.loads(command('catalog',good=True).stdout))==6)
    command('ensure',good=True); check('absent UCI selection defaults empty')
    check('empty elements is truly empty',command('elements',good=True).stdout==b'')
    check('status contract initially idle',json.loads(command('status',good=True).stdout)['update_running'] is False)
    settings(lists='unknown'); command('ensure',good=False); command('update',good=False)
    check('unknown ID cannot download or launch',not cache.exists())
    settings(lists='flowseal cloudflare flowseal')
    command('ensure',good=False); check('missing cache does not auto-download',not cache.exists())
    command('update-run',good=True)
    check('coherent selected snapshot created',cache.joinpath('current/flowseal.list').exists() and cache.joinpath('current/cloudflare.list').exists())
    check('persistent cache root-only 0700',(cache.stat().st_mode & 0o777)==0o700)
    command('ensure',good=True)
    check('safe newline union',command('elements',good=True).stdout==b'1.1.1.0/24\n65.108.59.85/32\n')
    s=json.loads(command('status',good=True).stdout)
    check('source count/discard metadata',s['list_state']['flowseal']['source_count']==2 and s['list_state']['flowseal']['discarded']==1)
    before=snapshot(); command('update-run',good=True)
    check('unchanged SHA causes ZERO persistent file/symlink writes',snapshot()==before)
    settings(running=True, bodies={'flowseal':'65.108.59.86\n','cloudflare':'1.1.1.0/24\n'})
    inode=(cache/'current/cloudflare.list').stat().st_ino
    command('update-run',good=True)
    check('running daemon reconcile-runningd, no engine start',(tmp/'calls').read_text().splitlines()==['reconcile-running'])
    check('unchanged source hardlinked without rewrite',(cache/'current/cloudflare.list').stat().st_ino==inode)
    before=snapshot()
    settings(fail='cloudflare',bodies={'flowseal':'65.108.59.87\n','cloudflare':'1.1.1.0/24\n'})
    command('update-run',good=False)
    check('MOCK second-source network failure preserves entire snapshot',snapshot()==before)
    settings(fail=None,bodies={'flowseal':'65.108.59.87\n','cloudflare':'<html>503</html>\n'})
    command('update-run',good=False); check('MOCK parse failure preserves entire snapshot',snapshot()==before)
    settings(bodies={'flowseal':'65.108.59.87\n','cloudflare':''})
    command('update-run',good=False); check('MOCK empty source preserves entire snapshot',snapshot()==before)
    settings(bodies={'flowseal':'65.108.59.87\n','cloudflare':'1.1.1.0/24\n'},reconcile_fail='once')
    command('update-run',good=False)
    # Rollback atomically restores the old target; replacing the symlink itself
    # necessarily changes its mtime. All payload bytes/inodes remain unchanged.
    restored=snapshot(); expected=dict(before)
    expected['current']=('link',before['current'][1],restored['current'][2])
    check('MOCK nft reconcile-running failure rolls cache back',restored==expected)
    before=restored
    settings(reconcile_fail=False,mutate='hetzner')
    command('update-run',good=False); check('concurrent UCI selection change aborts commit',snapshot()==before)
    settings(lists='flowseal cloudflare',oversize=True)
    command('update-run',good=False); check('MOCK chunked oversized file blocked by actual rlimit',snapshot()==before)
    settings(oversize=False,running=False)
    calls=(tmp/'calls').read_text(); command('update-run',good=True)
    check('stopped daemon is NEVER reconcile-runningd or started',(tmp/'calls').read_text()==calls)
    (run/'list-update.lock').mkdir(); (run/'list-update.lock/pid').write_text('999999999\n')
    command('ensure-idle',good=True); check('stale PID lock reclaimed',not (run/'list-update.lock').exists())
    (run/'list-update.lock').mkdir(); (run/'list-update.lock/pid').write_text(str(os.getpid())+'\n')
    command('ensure-idle',good=False); command('update',good=False)
    check('live owner blocks configure and parallel updater',json.loads(command('status',good=True).stdout)['update_running'] is True)
    shutil.rmtree(run/'list-update.lock')
    settings(delay=2)
    r=command('update',good=True); check('async real handshake accepted',json.loads(r.stdout)=={'ok':True,'pending':True})
    command('ensure-idle',good=False); command('update',good=False); idle()
    check('async lock cleared on EXIT',not (run/'list-update.lock').exists())
    settings(delay=10)
    before=snapshot()
    interrupted=subprocess.Popen([str(helper),'update-run'],env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    processes.append(interrupted)
    downloader=None
    for i in range(100):
        children=pathlib.Path(f'/proc/{interrupted.pid}/task/{interrupted.pid}/children').read_text().split()
        for pid in children:
            try:
                if str(bin/'curl').encode() in pathlib.Path('/proc/'+pid+'/cmdline').read_bytes(): downloader=pid
            except FileNotFoundError: pass
        if downloader: break
        time.sleep(.02)
    assert downloader, 'download child not found'
    interrupted.terminate(); interrupted.communicate(timeout=5)
    check('TERM reaps actual downloader before releasing lock',not pathlib.Path('/proc/'+downloader).exists() and not (run/'list-update.lock').exists())
    check('interrupted update retains complete working cache',snapshot()==before)
    settings(delay=2)
    # Force only feature discovery branch; the BusyBox executable itself is real.
    write(bin/'start-stop-daemon','#!/bin/sh\nexec '+shlex.quote(BUSYBOX)+' start-stop-daemon "$@"\n')
    write(helper,original.replace('if command -v nohup >/dev/null 2>&1; then','if false; then'))
    r=command('update',good=True); check('actual BusyBox detached fallback + handshake',json.loads(r.stdout)['pending'] is True)
    idle(); write(helper,original)
    # A detached child that never executes cannot claim pending:true.
    write(bin/'start-stop-daemon','#!/bin/sh\nexit 0\n')
    write(helper,original.replace('if command -v nohup >/dev/null 2>&1; then','if false; then').replace('start-stop-daemon -S -b -x',str(bin/'start-stop-daemon')+' -S -b -x'))
    command('update',good=False); check('MOCK missing child never gives UI false success',not (run/'list-update.lock').exists())
    write(helper,original); settings(delay=0)
    # Cache corruption is caught before any nft elements reach stdout.
    f=cache/'current/flowseal.list'; old=f.read_bytes(); f.write_text('65.108.59.85\n}; flush ruleset\n')
    command('ensure',good=False); r=command('elements',good=False)
    check('corrupt cache rejected with no partial stdout',not r.stdout)
    f.write_bytes(old)
    (tmp/'calls').write_text('')
    settings(auto_update='0',running=True)
    w,t=start_timer(); check('timer auto_update=false performs no job',not (tmp/'calls').read_text())
    stop_timer(w,t); check('timer TERM reaps all sleeping children')
    settings(auto_update='1')
    w,t=start_timer(); check('fresh selected caches do not redownload at worker startup',not (tmp/'calls').read_text())
    stop_timer(w,t)
    for id in ['flowseal','cloudflare']:
        (run/('list-checked.'+id)).write_text('1\n')
    w,t=start_timer(); check('stale selected caches invoke controller update_lists',(tmp/'calls').read_text().splitlines()==['update_lists'])
    stop_timer(w,t)
    settings(lists='')
    (tmp/'calls').write_text(''); w,t=start_timer()
    check('empty selection never triggers timer downloads',not (tmp/'calls').read_text()); stop_timer(w,t)
    # TERM at the exact cache/live-rule handoff must roll BOTH resources back.
    settings(lists='flowseal cloudflare',running=False,delay=0,bodies={'flowseal':'65.108.59.90\n','cloudflare':'1.1.1.0/24\n'})
    command('update-run',good=True)
    old=(cache/'current/flowseal.list').read_text()
    model=tmp/'active-rules'; model.write_text(old)
    boundary='''#!/usr/bin/python3
import json, os, pathlib, sys
v=json.loads(pathlib.Path(os.environ['Z2_FIXTURE']).read_text())
if sys.argv[1]=='running': sys.exit(0 if v['running'] else 1)
if sys.argv[1]=='reconcile-running':
 root=pathlib.Path(os.environ['Z2_CALLS']).parent
 (root/'active-rules').write_text((root/'cache/current/flowseal.list').read_text())
 once=root/'signalled-once'
 if not once.exists():
  once.touch(); os.kill(os.getppid(),15)
 sys.exit(0)
sys.exit(2)
'''
    write(ctl,boundary)
    settings(running=True,bodies={'flowseal':'65.108.59.91\n','cloudflare':'1.1.1.0/24\n'})
    command('update-run',good=False)
    check('TERM after successful nft apply restores cache AND live-rule model',(cache/'current/flowseal.list').read_text()==old and model.read_text()==old)
    check('interrupted rule rollback is reported without false success','previous cache and live rules restored' in json.loads(command('status',good=True).stdout)['update_error'])
    write(ctl,mock)
    settings(reconcile_fail=True,bodies={'flowseal':'65.108.59.92\n','cloudflare':'1.1.1.0/24\n'})
    command('update-run',good=False)
    check('unconfirmed live rollback is CRITICAL and preserves recovery evidence','CRITICAL' in json.loads(command('status',good=True).stdout)['update_error'] and (cache/'current/flowseal.list').read_text()==old and len(list(cache.glob('snapshot.*')))>=2)
    print(f'backend/timer: {len(results)}/{len(results)} sandbox tests passed (network/UCI/nft MOCKED; ucode/jshn/BusyBox real)')
    if a.results: a.results.write_text(json.dumps({'tests':results,'network':'mocked','ucode':a.ucode,'jshn':a.jshn},indent=2)+'\n')
finally:
    for proc in processes:
        if proc.poll() is None:
            try: os.killpg(proc.pid,signal.SIGTERM) if proc.args[0]==str(worker) else proc.terminate()
            except ProcessLookupError: pass
            try: proc.wait(timeout=3)
            except subprocess.TimeoutExpired: proc.kill()
    try:
        if (run/'list-update.lock/pid').exists():
            pid=int((run/'list-update.lock/pid').read_text()); os.kill(pid,signal.SIGTERM)
    except (ProcessLookupError,ValueError): pass
    shutil.rmtree(tmp)
