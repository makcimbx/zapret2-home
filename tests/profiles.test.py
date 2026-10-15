#!/usr/bin/env python3
"""Real BusyBox ash/ucode/start-stop-daemon + real namespace nft syntax.
ONLY network, nfqws2 and installed nft STATE are explicit mocks. No router access.
The mocked body never claims a production hash match. Runs as root for real UID 1.
"""
import argparse, hashlib, json, os, pathlib, re, shlex, shutil, signal, subprocess, tempfile, time
from local_env import UCODE, MODULES, JSHN, JSHN_SH
from local_env import BUSYBOX
ROOT = pathlib.Path(__file__).resolve().parents[1]
p = argparse.ArgumentParser()
p.add_argument('--ucode', default=str(UCODE))
p.add_argument('--module-dir', default=str(MODULES))
p.add_argument('--nft-out', type=pathlib.Path)
p.add_argument('--keep', action='store_true')
p.add_argument('--safety-only', action='store_true', help='run registration/probe fault regressions only')
a = p.parse_args()
assert os.geteuid() == 0, 'real UID isolation fixture needs root'
scratch = pathlib.Path(tempfile.gettempdir())
scratch.mkdir(parents=True, exist_ok=True)
tmp = pathlib.Path(tempfile.mkdtemp(prefix='z2-profiles-', dir=scratch)); tmp.chmod(0o711)
bin = tmp/'bin'; bin.mkdir(); lib = tmp/'lib'; lib.mkdir(); run = tmp/'run'; run.mkdir()
main = tmp/'main'; main.mkdir(mode=0o700); control = main/'control.lock'
shared_catalog = lib/'profile-catalog.json'; launcher = bin/'engine'
profile_ids = ['alt1','stock','overlap','fake','fake_split','fake_disorder']
shared_catalog.write_bytes((ROOT/'files/usr/lib/zapret2-home/profile-catalog.json').read_bytes())
(lib/'protocols.uc').write_text((ROOT/'files/usr/lib/zapret2-home/protocols.uc').read_text().replace("const LIB='/usr/lib/zapret2-home';",f"const LIB='{lib}';"))
(lib/'protocol-catalog.json').write_bytes((ROOT/'files/usr/lib/zapret2-home/protocol-catalog.json').read_bytes())
(lib/'lock.uc').write_text((ROOT/'files/usr/lib/zapret2-home/lock.uc').read_text().replace("const RUN='/var/run/zapret2-home';",f"const RUN='{main}';"))
proc = tmp/'proc'; (proc/'net/netfilter').mkdir(parents=True)
queue = proc/'net/netfilter/nfnetlink_queue'; queue.write_text('')
for name in ['tcp','tcp6','udp','udp6']: (proc/'net'/name).write_text('')
(proc/'loadavg').write_text('0.10 0.10 0.10 1/1 1\n')
(proc/'stat').write_text('cpu 1 2 3 4 5 6 7 8 9 10\n'+''.join(f'cpu{i} 1 2 3 4 5 6 7 8 9 10\n' for i in range(4)))
cfg = tmp/'fixture.json'; table = tmp/'table.json'; calls = tmp/'calls'
helper = bin/'profiles'; uc = lib/'profiles.uc'; checks=[]; children=[]

def write(path, content):
    path.write_text(content); path.chmod(0o755)

def settings(**kw):
    v={'delay':.1, 'exit':0, 'route':'192.0.2.2', 'tls':'0', 'http':'200'}
    v.update(kw); cfg.write_text(json.dumps(v)); cfg.chmod(0o644)

mock = r'''#!/usr/bin/python3
import json, os, pathlib, re, signal, sys, time
name=pathlib.Path(sys.argv[0]).name
v=json.loads(pathlib.Path('/proc/self/fd/5' if name=='4' else os.environ['PROFILE_FIXTURE']).read_text())
args=sys.argv[1:]; name='curl' if name=='4' else name
queue=pathlib.Path(os.environ['PROFILE_QUEUE']); table=pathlib.Path(os.environ['PROFILE_TABLE'])
if name=='nft':
 with open(os.environ['PROFILE_CALLS'],'a') as f: f.write('nft '+repr(args)+'\n')
 if args==['-t','list','ruleset']:
  print(v.get('ruleset','table inet main { }')); sys.exit(0)
 if args[:2]==['-c','-f']: sys.exit(1 if v.get('syntax_fail') else 0)
 if args[:1]==['-f']:
  if v.get('apply_fail'): sys.exit(1)
  rules=pathlib.Path(args[1]).read_text(); comment=re.search(r'comment "([^"]+)"',rules)[1]
  table.write_text(json.dumps({'nftables':[{'table':{'family':'inet','name':'zapret2_home_profiles','comment':comment}}]})); sys.exit(0)
 if args[:3]==['-j','list','tables']:
  mode=v.get('probe_before' if table.exists() else 'probe_after')
  if mode=='exit': sys.exit(1)
  if mode is not None: print(mode); sys.exit(0)
  print(table.read_text() if table.exists() else '{"nftables":[]}'); sys.exit(0)
 if args[:3]==['-j','list','table']:
  assert args[3:]==['inet','zapret2_home_profiles']
  if not table.exists(): sys.exit(1)
  print(table.read_text()); sys.exit(0)
 if args[:2]==['delete','table']:
  assert args==['delete','table','inet','zapret2_home_profiles']
  if v.get('delete_fail'): sys.exit(1)
  table.unlink(missing_ok=True); sys.exit(0)
 raise AssertionError(args)
if name=='capcurl':
 print(v.get('features','Features: alt-svc HTTP2 SSL'))
 sys.exit(0)
if name=='stun-probe':
 assert os.getuid()==1 and len(args)==1 and 12600<=int(args[0])<=12659
 time.sleep(v.get('delay',.1))
 print(json.dumps(dict(binding_success=v.get('binding',True),remote_ip='74.125.250.129',remote_port=19302,local_ip=v['route'],local_port=int(args[0]),mapped_ip=v.get('mapped','192.0.2.2'),mapped_port=int(args[0]),time_total=.1,ignored_transactions=1)))
 sys.exit(v['exit'])
if name in ('nfqws2','nfqws2-quic'):
 assert '--qnum=214' in args
 protocol='quic' if '--filter-udp=443' in args else ('udp' if '--filter-udp=19294-19344,50000-50100' in args else 'tcp')
 assert name==('nfqws2-quic' if protocol=='quic' else 'nfqws2')
 assert [x for x in args if x.startswith('--reasm-')]==(['--reasm-disable=quic_initial'] if protocol=='quic' else [])
 assert {'tcp':'--filter-l7=tls','quic':'--filter-l7=quic','udp':'--filter-l7=discord,stun'}[protocol] in args
 strategies=[x for x in args if x.startswith('--lua-desync=')]
 catalog=json.loads(pathlib.Path(os.environ['PROFILE_CATALOG']).read_text())
 expected_range='--out-range=-n6'
 if protocol=='tcp':
  matched=[p for p in catalog if p['args']==strategies]; assert len(matched)==1
  if matched[0]['id']=='fake_split': expected_range='--out-range=-n20'
 else:
  expected_count=2 if protocol=='udp' and '--payload=discord_ip_discovery' in args else 1
  assert len(strategies)==expected_count and all(s.startswith('--lua-desync=fake:blob=') for s in strategies)
 assert '--in-range=x' in args and [x for x in args if x.startswith('--out-range=')]==[expected_range]
 with open(os.environ['PROFILE_CALLS'],'a') as f: f.write(json.dumps({'engine_pid':os.getpid(),'engine_path':sys.argv[0],'args':args})+'\n')
 if '--dry-run' in args: sys.exit(1 if v.get('engine_fail') else 0)
 def stop(*unused):
  queue.write_text(''); sys.exit(0)
 signal.signal(signal.SIGTERM,stop)
 queue.write_text('214 123 0 2 65535 0 0 0 1\n')
 while True: time.sleep(.05)
if name=='curl':
 assert os.getuid()==1, 'real start-stop-daemon must switch uid'
 assert args[0]=='-q' and '--proxy' in args and '--proto' in args and '=https' in args
 assert args[args.index('--cacert')+1]=='/etc/ssl/certs/ca-certificates.crt'
 assert args[args.index('--limit-rate')+1]=='64K'
 assert args[args.index('--max-time')+1]=='20'
 assert args[args.index('--connect-timeout')+1]=='5'
 assert args[args.index('--max-filesize')+1]=='2097152'
 assert args[args.index('--user-agent')+1]=='Mozilla/5.0'
 assert ('--http2' in args)!=('--http3-only' in args) and '--insecure' not in args and '-k' not in args and '-L' not in args
 pin=args[args.index('--resolve')+1]; host,unused,ip=pin.split(':')
 assert (host,ip) in [('gitlab.hotreload.net','65.108.59.85'),('download.openupm.com','107.175.71.2'),('app.tavily.com','52.85.154.99'),('i.ytimg.com','142.251.14.119'),('i.ytimg.com','142.251.1.119'),('discord.com','162.159.136.232')]
 assert ('--http3-only' in args)==(ip=='142.251.1.119')
 assert (os.path.basename(sys.executable)=='curl-http3')==('--http3-only' in args), 'capability and QUIC transfer must use the private client; TCP keeps the system client'
 assert args[-1].startswith('https://'+host+'/')
 time.sleep(v.get('delay',.1))
 body=b'EXPLICIT MOCK NETWORK BODY\n'
 if v.get('oversize'): body=b'x'*3000000
 if v.get('early_tls'): body=b''
 # Actual FD reopen works despite root-only protected parent directories.
 with open(args[args.index('--output')+1],'wb') as f: f.write(body)
 metrics={'http_code':v['http'],'size_download':str(len(body)), 'remote_ip':ip,'local_ip':v['route'],'local_port':args[args.index('--local-port')+1], 'time_total':'0.5','time_connect':v.get('connect','0.1'),'time_appconnect':v.get('appconnect','0.3'),'ssl_verify_result':v['tls'],'http_version':'3' if '--http3-only' in args else '2'}
 if v.get('early_tls'): metrics.update(http_code=0,remote_ip='',local_ip='',local_port=-1,time_appconnect=0,http_version='0')
 print(json.dumps(metrics))
 sys.exit(v['exit'])
raise AssertionError(name)
'''
write(bin/'nft',mock); write(bin/'curl',mock); write(lib/'nfqws2',mock); write(lib/'nfqws2-quic',mock)
write(bin/'capcurl',mock); write(lib/'stun-probe',mock.replace("args=sys.argv[1:]; name='curl' if name=='4' else name", "args=sys.argv[1:]; name='stun-probe'"))
(lib/'curl-http3').symlink_to('/usr/bin/python3')  # Separate executable path; HTTP3 networking remains an explicit double.
# Actual packaged launcher/catalog; only nfqws2 is an explicit process double.
write(launcher,(ROOT/'files/usr/libexec/zapret2-home-engine').read_text().replace('LIB=/usr/lib/zapret2-home',f'LIB={lib}').replace('#!/bin/sh','#!'+BUSYBOX+' ash',1))
def manifest():
    (lib/'SHA256SUMS').write_text(''.join(hashlib.sha256(path.read_bytes()).hexdigest()+'  '+str(path)+'\n' for path in [lib/'nfqws2',lib/'nfqws2-quic',shared_catalog,launcher,lib/'protocols.uc',lib/'protocol-catalog.json',lib/'stun-probe']))
manifest()
write(bin/'ucode',f'''#!/usr/bin/python3
import json, os, pathlib, sys, time
v=json.loads(pathlib.Path({str(cfg)!r}).read_text())
args=sys.argv[1:]
if len(args)>4 and args[1]=='remember' and v.get('reap_before_remember')==args[3]: time.sleep(.15)
if len(args)>4 and args[1]=='remember' and v.get('remember_fail')==args[3]:
    base=pathlib.Path({str(run)!r})/args[2]
    counter=base/('remember-count-'+args[3])
    count=int(counter.read_text())+1 if counter.exists() else 1
    counter.write_text(str(count))
    if count==v.get('remember_nth',1):
        time.sleep(.15)  # Let the real waitable process exec, not just its launch shell.
        pid=int(args[4])
        raw=pathlib.Path(f'/proc/{{pid}}/stat').read_text().rsplit(') ',1)[1].split()
        with open({str(tmp/'remember-faults')!r},'a') as f: f.write(json.dumps(dict(pid=pid,ticks=raw[19],name=args[3]))+'\\n')
        if v.get('stale_pid'): (base/args[3]).write_text(json.dumps(dict(pid=str(v['stale_pid']),ticks='0')))
        if v.get('deny_kill'): pathlib.Path({str(tmp/'deny-kill')!r}).write_text(str(pid))
        if v.get('native_ident_fail'):
            pathlib.Path({str(tmp/'identity-fault')!r}).write_text(str(pid))
        else: sys.exit(1)
os.execv({a.ucode!r},[{a.ucode!r},'-L',{a.module_dir!r},*args])
''')
# Explicit executable paths: BusyBox standalone applets can bypass PATH injection.
write(bin/'ssd','#!/bin/sh\nexec '+shlex.quote(BUSYBOX)+' start-stop-daemon "$@"\n')
shell=(ROOT/'files/usr/libexec/zapret2-home-profiles').read_text()
shell=shell.replace('"$LIB/curl-http3" --version',f'{bin}/capcurl --version')
# Keep the private executable's own path without traversing root-only scratch parents as UID1.
shell=shell.replace('HTTP_CLIENT="$LIB/curl-http3"','HTTP_CLIENT=/proc/self/fd/6/curl-http3')
shell=shell.replace('#!/bin/sh','#!'+BUSYBOX+' ash',1)
for old,new in {
 'PATH=/usr/sbin:/usr/bin:/sbin:/bin':f'PATH={bin}:/usr/sbin:/usr/bin:/sbin:/bin',
 'LIB=/usr/lib/zapret2-home':f'LIB={lib}', 'RUN=/var/run/zapret2-home/profiles':f'RUN={run}',
 'SELF=/usr/libexec/zapret2-home-profiles':f'SELF={helper}', 'PROC=/proc':f'PROC={proc}',
 'LAUNCHER=/usr/libexec/zapret2-home-engine':f'LAUNCHER={launcher}', 'CONTROL=/var/run/zapret2-home/control.lock':f'CONTROL={control}',
 'start-stop-daemon -S':f'{bin}/ssd -S', '/usr/bin/curl':'/usr/bin/python3',

 '-c 1 -- \\':'-c 1 -- /proc/self/fd/4 \\',
 '3>"$BASE/body" &':f'3>"$BASE/body" 4<{bin}/curl 5<{cfg} 6<"$LIB" &',
 '-x "$LIB/stun-probe" -c 1 -- "$PORT") >"$BASE/metrics" 2>"$BASE/curl.log" &':f'-x /usr/bin/python3 -c 1 -- /proc/self/fd/4 "$PORT") >"$BASE/metrics" 2>"$BASE/curl.log" 4<"$LIB/stun-probe" 5<{cfg} &',
 'nft -':f'{bin}/nft -', 'nft list':f'{bin}/nft list', 'nft delete':f'{bin}/nft delete',
}.items(): shell=shell.replace(old,new)
shell=shell.replace('else run_test "$PARENT";',f'else exec 2>{tmp}/trace; set -x; run_test "$PARENT";')
shell=shell.replace('cleanup() {',f'cleanup() {{\n [ -n "$BASE" ] && cp "$BASE/curl.log" {tmp}/last-curl.log 2>/dev/null\n [ -n "$BASE" ] && cp "$BASE/engine.log" {tmp}/last-engine.log 2>/dev/null')
# Select the worker-side health path deterministically for one fault regression.
shell=shell.replace('health_check() {',f'health_check() {{\n [ "$1" != watchdog ] || [ ! -f {tmp}/worker-health-only ] || return 0')
# Signal-denial fault applies only to the newly spawned failed-registration PID.
shell=shell.replace('remember_child() {',f'''kill() {{
 if [ -f {tmp}/deny-kill ]; then
  read -r DENIED <{tmp}/deny-kill
  [ "$2" != "$DENIED" ] || return 1
 fi
 command kill "$@"
}}
remember_child() {{''')
write(helper,shell)
uc_source=(ROOT/'files/usr/lib/zapret2-home/profiles.uc').read_text()
uc_source=uc_source.replace('function ident(pid, parent) {', 'function ident(pid, parent) {\n if (ARGV[0]==\'remember\' && trim(readfile('+repr(str(tmp/'identity-fault'))+') || \'\')==\'\'+pid) return null;')
uc_source=uc_source.replace("const RUN = '/var/run/zapret2-home/profiles';",f"const RUN = '{run}';")
uc_source=uc_source.replace("const MAIN = '/var/run/zapret2-home';",f"const MAIN = '{main}';")
uc_source=uc_source.replace("const CATALOG = '/usr/lib/zapret2-home/profile-catalog.json';",f"const CATALOG = '{shared_catalog}';")
# Relocate only health metadata; identity and UID discovery keep real /proc.
uc_source=uc_source.replace("open(PROC+'/'+name,'r')",f"open('{proc}/'+name,'r')")
uc_source=uc_source.replace("PROC+'/net/",repr(str(proc/'net')+'/')[:-1])
write(uc,uc_source)
env=dict(os.environ,PROFILE_FIXTURE=str(cfg),PROFILE_QUEUE=str(queue),PROFILE_TABLE=str(table),PROFILE_CALLS=str(calls),PROFILE_CATALOG=str(shared_catalog),PROFILE_ENGINE=str(lib/'nfqws2'))

def command(cmd, payload=None, good=None):
    r=subprocess.run([str(helper),cmd],input=payload,capture_output=True,env=env,timeout=12)
    if good is not None: assert (r.returncode==0)==good, (cmd,r.returncode,r.stdout,r.stderr)
    return r

def u(*args):
    return subprocess.run([str(bin/'ucode'),str(uc),*map(str,args)],env=env,capture_output=True,timeout=5)

def check(name, yes=True):
    assert yes, name; checks.append(name); print('PASS',name,flush=True)

def data(cmd='status'): return json.loads(command(cmd,good=True).stdout)['data']
def pending(payload=None):
    r=command('test',json.dumps(payload or {'profiles':'alt1','targets':'tavily','repeat':1}).encode(),good=True)
    x=json.loads(r.stdout); assert x['pending'] is True; return x['job_id']
def terminal(cmd='status'):
    for unused in range(600):
        x=data(cmd)
        if not x['running']:
            if x.get('state')=='error' and not x.get('results'): print('TERMINAL_ERROR',json.dumps(x),flush=True)
            return x
        time.sleep(.1)
    raise AssertionError(('not terminal',data(),tmp))
def await_marker(job, name):
    for unused in range(100):
        path=run/job/name
        if path.exists(): return json.loads(path.read_text())
        time.sleep(.05)
    raise AssertionError(('missing marker',name,tmp))
def live(pid):
    try: return pathlib.Path(f'/proc/{pid}/stat').read_text().rsplit(') ',1)[1].split()[0]!='Z'
    except FileNotFoundError: return False

def clean():
    assert not (run/'owner').exists() and not table.exists() and queue.read_text()==''
    assert not [x for x in run.iterdir() if x.is_dir()]

def retained():
    for unused in range(150):
        result=data('protocols-status')
        owner=json.loads((run/'owner').read_text()) if (run/'owner').exists() else {}
        wdpath=run/owner.get('job','missing')/'watchdog'
        watch=json.loads(wdpath.read_text()) if wdpath.exists() else {}
        if 'Cleanup failed' in result.get('error','') and not live(int(owner.get('pid',0))) and not live(int(watch.get('pid',0))):
            return result
        time.sleep(.1)
    raise AssertionError(('cleanup not retained/quiescent',result,tmp))

def recover_fixture():
    # Fixture-only recovery after the real worker/watchdog have both stopped.
    owner=json.loads((run/'owner').read_text())
    assert not live(int(owner['pid']))
    wdpath=run/owner['job']/'watchdog'
    assert not wdpath.exists() or not live(int(json.loads(wdpath.read_text())['pid']))
    table.unlink(missing_ok=True); (run/'owner').unlink()
    for path in run.iterdir():
        if path.is_dir(): shutil.rmtree(path)
    clean()

def safety_regressions():
    payload={'profiles':'alt1','targets':'tavily','repeat':1}
    faultlog=tmp/'remember-faults'
    unrelated=subprocess.Popen(['/usr/bin/sleep','120']); children.append(unrelated)
    for name,nth,protocol,native in [('engine',2,'tcp',False),('curl',1,'tcp',False),('curl',1,'udp',False),('watchdog',1,'tcp',False),('engine',2,'tcp',True),('curl',1,'tcp',True),('curl',1,'udp',True)]:
        calls.write_text(''); faultlog.unlink(missing_ok=True)
        settings(delay=8,remember_fail=name,remember_nth=nth,stale_pid=unrelated.pid,native_ident_fail=native)
        request=payload if protocol=='tcp' else dict(protocol='udp',profiles='udp_fake2',targets='stun_google',repeat=1)
        response=command('test' if protocol=='tcp' else 'protocols-test',json.dumps(request).encode())
        assert response.returncode==0 or name=='watchdog',(name,response.stdout,response.stderr)
        result=terminal('protocols-status'); clean()
        faults=[json.loads(line) for line in faultlog.read_text().splitlines()]
        assert len(faults)==1 and result['state']=='error' and unrelated.poll() is None
        assert not pathlib.Path('/proc/'+str(faults[0]['pid'])).exists(),faults
        check(f'failed {"native identity in" if native else "exit from"} remember {name} #{nth} / {protocol}: exact own child stopped and reaped, stale PID untouched, normal cleanup')
    unrelated.terminate(); unrelated.wait(timeout=5)
    for name,protocol,exit_code in [('engine','tcp',0),('curl','tcp',0),('curl','tcp',7),('curl','tcp',28),('curl','udp',7)]:
        settings(delay=0,reap_before_remember=name,exit=exit_code)
        if protocol=='tcp': pending()
        else: command('protocols-test',json.dumps(dict(protocol='udp',profiles='udp_fake2',targets='stun_google',repeat=1)).encode(),good=True)
        result=terminal('protocols-status'); clean()
        assert result['state']=='results' and len(result['results'])==1,result
        row=result['results'][0]
        check(f'fast completed {name} / {protocol} preserves exact exit {exit_code}',row['exit']==exit_code and (exit_code==0 or not row['full_match']))
    for protocol,target,profile in [('tcp','tavily','alt1'),('quic','youtube_h3','quic_google')]:
        settings(early_tls=True,exit=35,features='Features: HTTP2 HTTP3 SSL')
        command('protocols-test',json.dumps(dict(protocol=protocol,profiles=profile,targets=target,repeat=2)).encode(),good=True)
        result=terminal('protocols-status'); clean()
        check(f'{protocol} worker completes both failed TLS attempts without socket metadata; no false route abort or success',result['state']=='results' and len(result['results'])==2 and all(r['exit']==35 and not r['full_match'] and not r['route_verified'] for r in result['results']))
    calls.write_text(''); faultlog.unlink()
    settings(remember_fail='engine',remember_nth=2,deny_kill=True)
    command('test',json.dumps(payload).encode(),good=True)
    result=retained(); fault=json.loads(faultlog.read_text())
    assert result['running'] and table.exists() and live(fault['pid'])
    assert (run/result['job_id']/'engine-unregistered').exists()
    command('test',json.dumps(payload).encode(),good=False)
    check('unconfirmed own-child termination retains owner/table/recovery intent and blocks admission')
    assert u('identity',fault['pid']).stdout.decode().strip()==fault['ticks']
    os.kill(fault['pid'],signal.SIGTERM)
    for unused in range(100):
        if not live(fault['pid']): break
        time.sleep(.05)
    assert not live(fault['pid'])
    (tmp/'deny-kill').unlink(); recover_fixture()
    for phase in ['before','after']:
        for mode in ['exit','', '{', '[]', '{}', '{"nftables":null}', ' '*131073]:
            calls.write_text(''); settings(**{'probe_'+phase:mode})
            command('test',json.dumps(payload).encode(),good=True)
            result=retained()
            assert result['running'] and table.exists()==(phase=='before'),(phase,mode,result)
            command('test',json.dumps(payload).encode(),good=False)
            recover_fixture()
        check(f'nft {phase}-delete exit/empty/malformed/nonobject/missing-array/invalid-array/oversize errors retain cleanup lock')
    calls.write_text(''); settings(apply_fail=True)
    pending(); result=terminal(); clean()
    check('valid nft table absence remains successful cleanup after failed apply',result['state']=='error')
    calls.write_text(''); settings()

try:
    settings()
    subprocess.run([BUSYBOX,'ash','-n',str(helper)],check=True)
    safety_regressions()
    if a.safety_only:
        print(json.dumps({'passed':len(checks),'suite':'safety-only','ucode':'REAL','shell':'REAL BusyBox ash','network':'EXPLICIT MOCK','engine':'EXPLICIT MOCK','nft_state':'EXPLICIT MOCK','sandbox':str(tmp)}))
        raise SystemExit(0)
    # Preserve the original idle-status fixture after the independent fault suite.
    (run/'result').unlink(missing_ok=True)
    preflight_dir=run/'preflight-fixture'; preflight_dir.mkdir()
    def preflight_rules(text, allowed, error='Diagnostic port scope conflict'):
        (preflight_dir/'ruleset').write_text(text)
        result=u('preflight',preflight_dir.name)
        assert (result.returncode==0)==allowed, (text,result.stdout,result.stderr)
        if not allowed: assert json.loads(result.stdout)['error']==error, result.stdout
    for text in ['udp dport { 19000-20000, 50000-65535 } counter packets 969 bytes 69113', 'counter packets 12611 bytes 12659', 'ip6 daddr 2001:db8:12611::1 counter', 'meta mark set 12611', 'comment "tcp sport 12611 queue to 214"', 'tcp sport 12500-12599 tcp dport { 443, 12660-12700 } counter packets 12611 bytes 12659', 'th dport 7070 @nh,128,32 0xc0a8010d accept']:
        preflight_rules(text,True)
    check('unrelated UDP range / counters / IPv6 / mark / comments are not TCP port conflicts')
    for text in ['tcp sport 12600', 'tcp dport 12659', 'tcp sport 12599-12660', 'tcp dport { 443, 12599-12600 }', 'th sport 12611', 'th dport { 443, 12659-12700 }', 'tcp sport 443 tcp dport 12611', 'tcp dport @ports', 'th sport != 443', 'tcp sport & 255 == 80', 'tcp sport set 443', 'tcp sport . ip daddr { 443 . 192.0.2.1 }', 'tcp dport 443 vmap { 443 : accept }']:
        preflight_rules(text,False)
    check('TCP / th singleton, range, set, second predicate and unknown expressions fail closed')
    for text in ['queue num 213 bypass', 'queue flags bypass to 213', 'queue flags bypass,fanout to 212-213', 'queue to 215', 'queue flags bypass to 213 comment "main"']:
        preflight_rules(text,True)
    for text in ['queue num 214 bypass', 'queue num 213-215 fanout bypass', 'queue flags bypass to 214', 'queue flags bypass,fanout to 213-215', 'queue to 214', 'queue to numgen inc mod 4 offset 213', 'queue', 'queue flags bypass to @queues']:
        preflight_rules(text,False,'Diagnostic queue scope conflict')
    check('both queue rendering families allow 213 and reject 214 / overlaps / unknowns')
    native_cases=[('udp dport { 19000-20000, 50000-65535 } counter packets 12611 bytes 12659\ntcp dport 443 queue num 213 bypass',True,None), ('tcp sport 12611 counter',False,'Diagnostic port scope conflict'), ('tcp dport { 443, 12599-12600 } counter',False,'Diagnostic port scope conflict'), ('th dport 12659 counter',False,'Diagnostic port scope conflict'), ('tcp dport 443 queue num 214 bypass',False,'Diagnostic queue scope conflict'), ('tcp dport 443 queue num 213-215 fanout,bypass',False,'Diagnostic queue scope conflict')]
    renderings=[]; native_fixture=tmp/'preflight-native.nft'
    for body,allowed,error in native_cases:
        native_fixture.write_text('table inet probe {\n chain test {\n'+body+'\n }\n}\n')
        rendered=subprocess.run(['unshare','-Urn',BUSYBOX,'ash','-c','/usr/sbin/nft -f "$1" && /usr/sbin/nft -t list ruleset','ash',str(native_fixture)],capture_output=True,text=True,check=True)
        preflight_rules(rendered.stdout,allowed,error)
        renderings.append({'input':body,'native_terse':rendered.stdout,'allowed':allowed})
    (tmp/'preflight-native-renderings.json').write_text(json.dumps(renderings,indent=2)+'\n')
    check('REAL private namespace native nft UDP/counter/queue213 allow and TCP/th/queue214 range deny')
    live_fixture=ROOT/'dist/nft-preflight-live.txt'
    if live_fixture.exists():
        preflight_rules(live_fixture.read_text(),True)
        check('actual router terse nft capture passes isolated preflight without rewriting rules')
    (preflight_dir/'ruleset').unlink(); preflight_dir.rmdir()
    subprocess.run([BUSYBOX,'ash','-n',str(helper)],check=True)
    catalog=json.loads(command('catalog',good=True).stdout)['catalog']
    check('real ucode shared catalog fixed 6 profiles / 5 targets', [p['id'] for p in catalog['profiles']]==profile_ids and len(catalog['targets'])==5 and catalog['apply_supported'])
    check('public diagnostic budgets 60 rows / 1350 seconds / 128KiB state',catalog['limits']['max_rows']==60 and catalog['limits']['max_seconds']==1350 and catalog['limits']['max_state_bytes']==131072)
    command('apply',b'{\"profile\":\"stock\"}',good=False)
    check('no apply operation in diagnostic helper')
    check('initial combined status idle',data()['state']=='idle')
    for cmd in ['status','catalog']:
        command(cmd,b'{"ubus_rpc_session":"'+b'0'*32+b'"}',good=True)
        command(cmd,b'{"cmd":"id"}',good=False)
        command(cmd,b'{"ubus_rpc_session":null}',good=False)
        command(cmd,json.dumps({'ubus_rpc_session':'a'*32+'\x00bad'}).encode(),good=False)
    check('catalog/status transport metadata validation')
    for raw in [b'{}',b'[]',b'{', b'{"profiles":"alt1","targets":"tavily","repeat":true}',b'{"profiles":"alt1","targets":"tavily","repeat":3}',b'{"profiles":"alt1;touch /x","targets":"tavily","repeat":1}',b'{"profiles":"alt1","targets":"https://evil","repeat":1}',b'{"profiles":"alt1","targets":"tavily","repeat":1,"cmd":"id"}',b'{"profiles":"alt1","targets":"tavily","repeat":1,"ubus_rpc_session":null}',b'{"profiles":"alt1","targets":"tavily","repeat":1,"ubus_rpc_session":"bad"}',b'{}\0{"cmd":"id"}',b' '*4097]:
        command('test',raw,good=False)
    check('real bounded strict parser rejects types / extras / command / URL / NUL / oversized input',not (run/'owner').exists())
    # The directory guard is the main helper's lock, not a second flock domain.
    payload=b'{"profiles":"alt1","targets":"tavily","repeat":1}'
    command('test',json.dumps({'profiles':'alt1','targets':'tavily','repeat':1,'ubus_rpc_session':'a'*32+'\x00bad'}).encode(),good=False)
    gate=subprocess.run([str(bin/'ucode'),str(lib/'lock.uc'),'freeze','',str(os.getpid())],env=env,capture_output=True,text=True,check=True).stdout.strip()
    command('test',payload,good=False)
    assert (main/'lifecycle.json').exists() and not control.exists() and not (run/'owner').exists()
    subprocess.run([str(bin/'ucode'),str(lib/'lock.uc'),'finish','',str(os.getpid())],env=dict(env,Z2_LIFECYCLE_TOKEN=gate),capture_output=True,check=True)
    control.mkdir(); (control/'pid').write_text(str(os.getpid()))
    command('test',payload,good=False)
    check('launch refuses held main control guard without removing another owner', (control/'pid').read_text()==str(os.getpid()) and not (run/'owner').exists())
    (control/'pid').unlink(); command('test',payload,good=False)
    check('stale main control directory fails closed and remains for main recovery',control.exists() and not (run/'owner').exists())
    control.rmdir()
    check('direct acquire requires main guard',u('acquire',os.getpid()).returncode!=0 and not (run/'owner').exists())
    configjob=main/'configure-job.123'; configjob.mkdir(); marker=main/'configure.job'
    for token,result in [('bad',None),('123',None),('123',{'ok':False}),('123',{'ok':False,'rolled_back':False}),('123',{'ok':'true'})]:
        marker.write_text(token)
        if result is None: (configjob/'result').unlink(missing_ok=True)
        else: (configjob/'result').write_text(json.dumps(result))
        command('test',payload,good=False)
        assert not control.exists() and not (run/'owner').exists()
    check('pending configure / dead configure / uncertain rollback reject launch under main guard')
    marker.write_text('123'); (configjob/'result').write_text(json.dumps({'ok':False,'rolled_back':True}))
    settings(); pending(); completed=terminal(); clean()
    check('confirmed rollback permits diagnostics and releases only its main guard',completed['state']=='results' and not control.exists())
    marker.unlink(); shutil.rmtree(configjob)
    # A live finishing watcher must block even after owner release.
    ticks=u('identity',os.getpid()).stdout.decode().strip()
    (run/'finishing').write_text(json.dumps({'pid':str(os.getpid()),'ticks':ticks}))
    command('test',payload,good=False)
    check('live finishing watcher blocks relaunch and main guard is released',not control.exists() and not (run/'owner').exists())
    (run/'finishing').write_text(json.dumps({'pid':str(os.getpid()),'ticks':'0'}))
    calls.write_text('')
    compiled=tmp/'profiles.ucb'
    native=subprocess.run([str(bin/'ucode'),'-c','-o',str(compiled),str(uc)],env=env,capture_output=True)
    run_native=subprocess.run([str(bin/'ucode'),str(compiled),'catalog'],env=env,capture_output=True) if native.returncode==0 else native
    check('native ucode compilation and bytecode catalog execution',native.returncode==0 and run_native.returncode==0 and json.loads(run_native.stdout)['catalog']==catalog)
    rules=u('rules','123.456').stdout
    assert b'meta skuid 1 ip daddr @targets tcp sport 12600-12659' in rules
    assert b'queue num 214 bypass' in rules and b'hook forward' not in rules and b'queue num 213' not in rules
    check('nft destinations exactly all five trusted target IPs', b'elements = { '+', '.join(t['ip'] for t in catalog['targets']).encode()+b' }' in rules)
    syntax=tmp/'generated.nft'; syntax.write_bytes(rules)
    real=subprocess.run(['unshare','-Urn','/usr/sbin/nft','-c','-f',str(syntax)],capture_output=True)
    check('REAL nft -c in private user/net namespace',real.returncode==0 or False)
    ns=subprocess.run(['unshare','-Urn',BUSYBOX,'ash','-c','/usr/sbin/nft -f "$1" && ! /usr/sbin/nft -f "$1" 2>/dev/null && /usr/sbin/nft -j list table inet zapret2_home_profiles','ash',str(syntax)],capture_output=True)
    check('REAL namespace nft exclusive create refuses existing table',ns.returncode==0 and b'z2profiles:123.456' in ns.stdout)
    if a.nft_out: a.nft_out.parent.mkdir(parents=True,exist_ok=True); a.nft_out.write_bytes(rules)
    job=pending({'profiles':' '.join(reversed(profile_ids))+' alt1','targets':'discord youtube tavily unitask gitlab','repeat':2,'ubus_rpc_session':'0'*32})
    result=terminal(); clean()
    if result['state']!='results' or len(result['results'])!=60: print('batch result:',result,flush=True)
    check('real detached BusyBox handshake, deduped 6x5x2 batch and cleanup',result['state']=='results' and len(result['results'])==60)
    launched=[json.loads(line) for line in calls.read_text().splitlines() if line.startswith('{')]
    engines=[x for x in launched if 'engine_pid' in x]
    expected=json.loads(shared_catalog.read_text())
    check('actual shared queue214 launcher dry-run/run for all six',len(engines)==12 and [[v for v in x['args'] if v.startswith('--lua-desync=')] for x in engines]==[p['args'] for p in expected for mode in ['dry-run','run']] and [('--dry-run' in x['args']) for x in engines]==[True,False]*6)
    exec_probe=subprocess.Popen([str(launcher),'214','alt1','dry-run'],env=dict(env,PATH=str(bin)+':'+env['PATH']),stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    probe_output=exec_probe.communicate(timeout=5)
    assert probe_output==(b'',b'') and exec_probe.returncode==0, probe_output
    assert json.loads(calls.read_text().splitlines()[-1])['engine_pid']==exec_probe.pid, 'Actual shared launcher must exec, not spawn a different engine PID'
    check('mock network cannot claim full pinned hash proof',all(not x['full_match'] and x['route_verified'] and x['tls_verified'] for x in result['results']))
    check('reserved unique source ports', [x['source_port'] for x in result['results']]==list(range(12600,12660)))
    check('root-only bounded result and runtime',run.stat().st_mode&0o777==0o700 and (run/'result').stat().st_mode&0o777==0o600 and (run/'result').stat().st_size<131072)
    settings(); (lib/'SHA256SUMS').write_text('0'*64+'  nfqws2\n'); pending(); result=terminal(); clean()
    check('runtime integrity mismatch refuses isolated engine and rules',result['state']=='error' and not result['results'])
    manifest()
    for path in [shared_catalog,launcher]:
        original=path.read_bytes(); path.write_bytes(original+b'\n')
        settings(); pending(); rejected=terminal(); clean(); path.write_bytes(original)
        assert rejected['state']=='error' and not rejected['results']
    check('integrity preflight also checks actual shared catalog / launcher')
    settings(route='192.0.2.1'); pending(); result=terminal(); clean()
    check('mock responding wrong WAN tuple aborts batch',result['state']=='error' and result['results'][0]['failure']=='route')
    settings(tls='60'); pending(); result=terminal(); clean()
    check('mock TLS verification failure is not full match',not result['results'][0]['tls_verified'])
    settings(exit=28,connect='0',appconnect='0'); pending(); result=terminal(); clean()
    check('connection/setup timeout does not blame SYN or profile',result['results'][0]['failure']=='connect_or_setup')
    for kw in [{'syntax_fail':True},{'apply_fail':True},{'engine_fail':True},{'ruleset':'table inet other { queue num 214 bypass; }'}]:
        settings(**kw); pending(); result=terminal(); clean(); assert result['state']=='error'
    check('mock syntax/apply/engine/scope failures exact cleanup')
    for scope in ['queue num 213-215 bypass', 'queue num numgen inc mod 4 offset 213']:
        settings(ruleset=scope); pending(); failed=terminal(); clean(); assert failed['state']=='error' and not failed['results']
    check('queue range containing 214 / dynamic queue fail closed')
    for scope in ['ct mark 0x005A1724','ct mark 5904164','tcp sport 12659','tcp dport 12599-12660','tcp sport { 12590-12610, 12700 }','table inet zapret2_home_profiles {}']:
        settings(ruleset=scope); pending(); failed=terminal(); clean(); assert failed['state']=='error' and not failed['results'],scope
    check('all ctmark encodings / upper port / intersecting ranges / existing table fail closed')
    settings(ruleset='queue num 213 bypass\nqueue num 215 fanout bypass\ntcp sport 12500-12599\ntcp dport 12660-12700'); pending(); accepted=terminal(); clean()
    check('main queue213 and disjoint queue/port ranges remain permitted',accepted['state']=='results')
    settings(); queue.write_text('214 12 0 2 65535 0 0 0 1\n'); pending(); result=terminal(); queue.write_text(''); clean()
    check('explicit occupied queue fixture refuses test',result['state']=='error')
    (proc/'net/tcp').write_text('0: 0100007F:3138 00000000:0000 0A\n'); pending(); result=terminal(); (proc/'net/tcp').write_text(''); clean()
    check('explicit occupied source port fixture refuses test',result['state']=='error')
    (proc/'net/tcp6').write_text('0: 00000000000000000000000000000001:3173 00000000000000000000000000000000:0000 0A\n'); pending(); result=terminal(); (proc/'net/tcp6').write_text(''); clean()
    check('upper reserved port12659 in tcp6 refuses test',result['state']=='error')
    settings(oversize=True,delay=.5); pending(); result=terminal(); clean()
    check('real BusyBox file-size ceiling with explicit oversized mock body',result['results'][0]['bytes']<=2097152 and not result['results'][0]['full_match'])
    # Real UID 1 conflict, not a fake process listing.
    settings(); busy=subprocess.Popen([BUSYBOX,'start-stop-daemon','-S','-x','/usr/bin/sleep','-c','1','--','5']); children.append(busy)
    time.sleep(.1); pending(); result=terminal(); busy.terminate(); busy.wait(timeout=5); clean()
    check('real conflicting UID 1 process refuses test',result['state']=='error' and not result['results'])
    settings(delay=8); job=pending(); marker=await_marker(job,'curl')
    command('test',b'{"profiles":"stock","targets":"gitlab","repeat":1}',good=False)
    owner=json.loads((run/'owner').read_text()); watch=await_marker(job,'watchdog'); sleep=await_marker(job,'watchdog-sleep'); engine=await_marker(job,'engine')
    os.kill(int(owner['pid']),signal.SIGTERM); result=terminal(); clean()
    check('real worker TERM reaps curl/engine/watchdog/sleep before release',result['state']=='error' and all(not live(int(x['pid'])) for x in [marker,watch,sleep,engine]))
    settings(delay=8); job=pending(); marker=await_marker(job,'curl'); owner=json.loads((run/'owner').read_text()); engine=await_marker(job,'engine')
    os.kill(int(owner['pid']),signal.SIGKILL); result=terminal(); clean()
    check('real worker SIGKILL watchdog exact cleanup, last results preserved',result['state']=='error' and not live(int(marker['pid'])) and not live(int(engine['pid'])) and (run/'result').exists())
    # Shared metadata is not a prerequisite for watchdog identity and cleanup.
    settings(delay=8); job=pending(); marker=await_marker(job,'curl'); owner=json.loads((run/'owner').read_text()); engine=await_marker(job,'engine')
    saved=shared_catalog.read_bytes(); shared_catalog.write_text('{'); os.kill(int(owner['pid']),signal.SIGKILL)
    for unused in range(200):
        if not (run/'owner').exists(): break
        time.sleep(.05)
    shared_catalog.write_bytes(saved); result=terminal(); clean()
    check('SIGKILL watchdog cleanup survives damaged shared catalog',result['state']=='error' and not live(int(marker['pid'])) and not live(int(engine['pid'])))
    calls.write_text('')  # Fixture audit already asserted; child file-size ceiling applies to append too.
    for value in ['1.01','4.00']:
        (proc/'loadavg').write_text(f'{value} 0 0 1/1 1\n'); settings(delay=2); pending(); result=terminal(); clean()
        check(f'four-online-CPU worker permits load {value}, including preflight and watchdog',result['state']=='results' and len(result['results'])==1)
    (proc/'loadavg').write_text('0.1 0 0 1/1 1\n')
    for path,raw,message in [
        (proc/'loadavg','4.01 0 0 1/1 1\n','Превышен лимит нагрузки на процессор'),
        (queue,'214 123 65 2 65535 0 0 0 1\n','Очередь 214 переполнена или теряет пакеты'),
        (queue,'214 123 0 2 65535 1 0 0 1\n','Очередь 214 переполнена или теряет пакеты'),
        (queue,'214 123 0 2 65535 0 1 0 1\n','Очередь 214 переполнена или теряет пакеты'),
        (proc/'stat','cpu0 invalid\n','Не удалось безопасно проверить нагрузку и очередь')]:
        settings(delay=8); job=pending(); marker=await_marker(job,'curl'); engine=await_marker(job,'engine'); watch=await_marker(job,'watchdog')
        owner=json.loads((run/'owner').read_text()); original=path.read_text(); path.write_text(raw)
        result=terminal(); clean()
        if path!=queue: path.write_text(original)
        check(f'watchdog distinct reason and exact cleanup: {raw.strip()}',result['state']=='error' and result['error']==message and all(not live(int(x['pid'])) for x in [owner,marker,engine,watch]))
        snapshot=result['guard_failure']; assert snapshot['source']=='watchdog'
        if path==proc/'loadavg':
            assert snapshot['exit_code']==2 and snapshot['details']['load_1m']==4.01 and snapshot['details']['online_cpus']==4 and snapshot['details']['load_limit']==4
        elif path==queue:
            fields=raw.split(); assert snapshot['exit_code']==3 and snapshot['details']['queue']==214
            assert [snapshot['details'][key] for key in ['pending','drops','user_drops']]==[int(fields[i]) for i in [2,5,6]]
        else: assert snapshot['exit_code']==1 and 'CPU' in snapshot['details']['error']
        assert json.loads((run/'result').read_text())['guard_failure']==snapshot
    (tmp/'worker-health-only').touch(); (proc/'loadavg').write_text('4.01 0 0 1/1 1\n')
    settings(); pending(); result=terminal(); clean()
    assert result['error']=='Превышен лимит нагрузки на процессор'
    assert result['guard_failure']['source']=='worker' and result['guard_failure']['details']['load_1m']==4.01
    assert json.loads((run/'result').read_text())['guard_failure']==result['guard_failure']
    (tmp/'worker-health-only').unlink(); (proc/'loadavg').write_text('0.1 0 0 1/1 1\n')
    check('worker-side health abort retains exact resource snapshot after cleanup')
    settings(delay=8); job=pending(); marker=await_marker(job,'curl'); engine=await_marker(job,'engine'); watch=await_marker(job,'watchdog')
    own=json.loads((run/'owner').read_text()); own['started']=float(pathlib.Path('/proc/uptime').read_text().split()[0])-1351; (run/'owner').write_text(json.dumps(own)); result=terminal(); clean()
    check('watchdog distinct real monotonic deadline and exact cleanup',result['state']=='error' and result['error']=='Истёк лимит времени диагностики (1350 с)' and all(not live(int(x['pid'])) for x in [own,marker,engine,watch]))
    # PID reuse guard: same live pid but deliberately wrong start time must never be signalled.
    settings(); control.mkdir(); (control/'pid').write_text(str(os.getpid()))
    acquired=u('acquire',os.getpid()); assert acquired.returncode==0, acquired.stderr
    me=acquired.stdout.decode().strip(); (control/'pid').unlink(); control.rmdir(); child=subprocess.Popen(['/usr/bin/sleep','10']); children.append(child)
    u('remember',me,'engine',child.pid); ident=json.loads((run/me/'engine').read_text()); ident['ticks']='0'; (run/me/'engine').write_text(json.dumps(ident))
    check('PID identity mismatch refuses child PID',u('child-pid',me,'engine').returncode!=0 and child.poll() is None)
    check('foreign PID cannot release generation owner',u('release',me,child.pid).returncode!=0 and (run/'owner').exists())
    # Synthetic successful metrics exercise hash/length/TLS/tuple conjunction, not real network evidence.
    u('state',me,'running',''); target=catalog['targets'][2]
    metrics={'http_code':'200','local_ip':'192.0.2.2','remote_ip':target['ip'],'local_port':'12600','time_connect':'0.1','time_appconnect':'0.3','ssl_verify_result':'0'}
    (run/me/'metrics').write_text(json.dumps(metrics)); r=u('row',me,'alt1','tavily',1,0,target['sha256'],target['bytes'],12600)
    check('explicit synthetic expected tuple/hash/bytes conjunction',r.returncode==0 and data()['results'][0]['full_match'])
    # Every target is a full-resource check, never video / voice proof.
    for index,target in enumerate(catalog['targets'][3:],1):
        metrics.update(remote_ip=target['ip'],local_port=str(12600+index))
        (run/me/'metrics').write_text(json.dumps(metrics)); r=u('row',me,'fake_split',target['id'],1,0,target['sha256'],target['bytes'],12600+index)
        assert r.returncode==0 and data()['results'][-1]['full_match']
    check('synthetic exact YouTube and Discord resource conjunction',len(data()['results'])==3)
    target=catalog['targets'][4]; nextport=12603
    for arguments in [('unknown','discord',2,0,target['sha256'],target['bytes'],nextport),('fake','unknown',2,0,target['sha256'],target['bytes'],nextport),('fake','discord',3,0,target['sha256'],target['bytes'],nextport),('fake','discord',2,0,'bad',target['bytes'],nextport),('fake','discord',2,0,target['sha256'],2097153,nextport),('fake','discord',2,0,target['sha256'],target['bytes'],12660),('fake_split','discord',1,0,target['sha256'],target['bytes'],nextport)]:
        assert u('row',me,*arguments).returncode!=0 and len(data()['results'])==3
    check('row trust boundary rejects unknown IDs / repeat / digest / size / port / duplicate')
    for delta in [{'http_code':'206'},{'time_appconnect':'0'},{'ssl_verify_result':'1'},{'remote_ip':'192.0.2.1'},{'local_ip':'192.0.2.1'},{'local_port':'12604'}]:
        u('state',me,'running',''); original=json.loads((run/'result').read_text()); original['results']=[]; (run/'result').write_text(json.dumps(original))
        testmetrics=dict(metrics,remote_ip=target['ip'],local_port='12600')
        testmetrics.update(delta); (run/me/'metrics').write_text(json.dumps(testmetrics))
        u('row',me,'fake','discord',2,0,target['sha256'],target['bytes'],12600)
        assert not data()['results'][0]['full_match']
    check('exact HTTP200 / TLS handshake / verification / remoteIP / WANIP / sourceport required')
    original=(run/'result').read_bytes(); (run/'result').write_bytes(b' '*131073)
    command('status',good=False); (run/'result').write_bytes(original)
    check('status rejects oversized persisted state before JSON read')
    original=json.loads((run/'result').read_text()); original['results']=[dict(original['results'][0],source_port=p,expected_source_port=p) for p in range(12600,12660)]; (run/'result').write_text(json.dumps(original))
    check('61st row exceeds fixed port and row budget',u('row',me,'stock','discord',1,0,target['sha256'],target['bytes'],12660).returncode!=0 and len(data()['results'])==60)
    child.terminate(); child.wait(timeout=5); u('release',me,os.getpid()); shutil.rmtree(run/me)
    udp={'protocol':'udp','profiles':'udp_fake6 udp_fake2','targets':'stun_google','repeat':2}
    quic={'protocol':'quic','profiles':'quic_zero quic_google','targets':'youtube_h3','repeat':1}
    def protocol_pending(payload):
        ack=json.loads(command('protocols-test',json.dumps(payload).encode(),good=True).stdout)
        assert ack['pending'] is True
        return ack['job_id']
    settings()
    for cmd in ['protocols-catalog','protocols-status']:
        command(cmd,b'{"unknown":true}',good=False)
        command(cmd,b'{"ubus_rpc_session":null}',good=False)
    groups=json.loads(command('protocols-catalog',b'{}',good=True).stdout)['catalog']['groups']
    check('new shell catalog uses runtime groups and exact curl Features capability',len(groups)==3 and not groups[1]['test_supported'] and groups[2]['test_supported'])
    before=calls.read_bytes(); persisted=(run/'result').read_bytes(); scope=set(run.iterdir())
    for features in ['Features: HTTP2 SSL','curl HTTP3 fake version\nFeatures: HTTP2 SSL','Features: HTTP3fake HTTP2 SSL']:
        settings(features=features)
        denied=command('protocols-test',json.dumps(quic).encode(),good=False)
        assert 'HTTP3' in json.loads(denied.stdout)['error']
    check('QUIC rejects before mutation without exact Features HTTP3 and no fallback',calls.read_bytes()==before and (run/'result').read_bytes()==persisted and set(run.iterdir())==scope and not control.exists())
    calls.write_text(''); settings(features='Features: HTTP2 HTTP3 SSL'); protocol_pending(quic); result=terminal('protocols-status'); clean()
    check('real shared worker QUIC four-arg launch and UID1 --http3-only (mock network)',result['state']=='results' and result['plan']==dict(quic,profiles=['quic_google','quic_zero'],targets=['youtube_h3']) and len(result['results'])==2 and all(r['protocol']=='quic' and r['http_version']=='3' and not r['full_match'] for r in result['results']))
    engines=[json.loads(line) for line in calls.read_text().splitlines() if line.startswith('{')]
    check('QUIC worker selects private engine and exact Initial reassembly disable in dry-run/run',len(engines)==4 and all(x['engine_path']==str(lib/'nfqws2-quic') and [v for v in x['args'] if v.startswith('--reasm-')]==['--reasm-disable=quic_initial'] for x in engines) and [('--dry-run' in x['args']) for x in engines]==[True,False]*2)
    settings(); protocol_pending(udp); result=terminal('protocols-status'); clean()
    check('real shared worker UDP fixed tuple/UID1 and four-arg engine (synthetic STUN)',result['state']=='results' and result['plan']==dict(udp,profiles=['udp_fake2','udp_fake6'],targets=['stun_google']) and len(result['results'])==4 and all(r['protocol']=='udp' and r['binding_success'] and r['full_match'] and r['route_verified'] for r in result['results']))
    check('legacy completed UDP status reveals no unsupported IDs',data()['results']==[] and data()['state']=='idle' and not data()['running'])
    settings(mapped='192.0.2.1'); protocol_pending(udp); result=terminal('protocols-status'); clean()
    check('mapped WAN mismatch aborts UDP batch without false success',result['state']=='error' and len(result['results'])==1 and not result['results'][0]['full_match'])
    for scope in ['udp sport 12659','th dport 12600']:
        settings(ruleset=scope); protocol_pending(udp); result=terminal('protocols-status'); clean()
        assert result['state']=='error' and not result['results']
    (proc/'net/udp6').write_text('0: 00000000000000000000000000000001:3173 00000000000000000000000000000000:0000 07\n')
    settings(); protocol_pending(udp); result=terminal('protocols-status'); (proc/'net/udp6').write_text(''); clean()
    check('UDP reserved port rule and udp6 socket conflicts fail closed',result['state']=='error')
    for sig in [signal.SIGTERM,signal.SIGKILL]:
        settings(delay=8); job=protocol_pending(udp); marker=await_marker(job,'curl'); engine=await_marker(job,'engine')
        legacy=data(); assert legacy['running'] and legacy['results']==[] and 'plan' not in legacy
        command('test',b'{"profiles":"stock","targets":"gitlab","repeat":1}',good=False)
        command('protocols-test',json.dumps(udp).encode(),good=False)
        owner=json.loads((run/'owner').read_text()); os.kill(int(owner['pid']),sig)
        result=terminal('protocols-status'); clean()
        assert result['state']=='error' and not live(int(marker['pid'])) and not live(int(engine['pid']))
    check('UDP owner blocks legacy/new callers; real TERM/KILL recovery reaps all shared children')
    settings(delete_fail=True); pending(); result=None
    for unused in range(100):
        result=data()
        if 'Cleanup failed' in result.get('error',''): break
        time.sleep(.1)
    check('mock nft deletion failure retains scope lock, blocks next test',result['state']=='error' and result['running'] and table.exists())
    command('test',b'{"profiles":"alt1","targets":"tavily","repeat":1}',good=False)
    # Wait for the exact failed generation to stop before fixture-only recovery.
    own=json.loads((run/'owner').read_text()); watch=run/own['job']/'watchdog'
    for unused in range(100):
        wd=json.loads(watch.read_text()) if watch.exists() else {}
        if not live(int(own['pid'])) and (not wd or not live(int(wd['pid']))): break
        time.sleep(.1)
    assert not live(int(own['pid'])) and not live(int(wd['pid']))
    # Explicit fixture recovery, not a claimed production recovery API.
    table.unlink(); (run/'owner').unlink();
    for x in run.iterdir():
        if x.is_dir(): shutil.rmtree(x)
    print(json.dumps({'passed':len(checks),'network':'EXPLICIT MOCK','engine':'EXPLICIT MOCK','nft_state':'EXPLICIT MOCK','nft_syntax':'REAL namespace nft -c','ucode':'REAL','shell':'REAL BusyBox ash','sandbox':str(tmp)},ensure_ascii=False))
finally:
    for child in children:
        if child.poll() is None: child.terminate(); child.wait(timeout=5)
    # On failure, stop only fixture argv processes, including detached workers.
    if (run/'owner').exists():
        try: os.kill(int(json.loads((run/'owner').read_text())['pid']),signal.SIGTERM)
        except (ProcessLookupError,ValueError): pass
        time.sleep(2)
    if not a.keep and not (run/'owner').exists(): shutil.rmtree(tmp)
    elif tmp.exists(): print('retained sandbox:',tmp)
