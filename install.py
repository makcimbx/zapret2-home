#!/usr/bin/env python3
"""Own-package installer. One live owner freezes stop/replace/restore/readback.
Legacy controllers/hooks have no atomic gate: refuse before staging or stopping.
"""
import pathlib,subprocess,json,hashlib,sys,shlex,re
ROOT=pathlib.Path(__file__).resolve().parent
SSH=['ssh','-o','BatchMode=yes','-o','ConnectTimeout=7','root@192.168.1.1']
PRODUCTION='sha256sum /etc/config/podkop /etc/sing-box/config.json /etc/config/firewall; pidof sing-box'
MODE_CHECK='ucode -e '+shlex.quote('import { stat } from "fs"; let s=stat(ARGV[0]); if(!s || s.type!="file" || s.mode!=int(ARGV[1],8)) exit(1);')
def run(s,inp=None,timeout=240):
 # Dropbear can reject large exec requests; keep the protected script on stdin.
 script=inp is None and '\n' in s
 p=subprocess.run(SSH+(['sh -s'] if script else [s]),input=s.encode() if script else inp,capture_output=True,timeout=timeout)
 if p.returncode:raise RuntimeError(s+'\n'+p.stdout.decode(errors='replace')+p.stderr.decode(errors='replace'))
 return p.stdout.decode()
def snap():return run(PRODUCTION)
def require_gate():
 # No staged overwrite of legacy code, no check-then-upgrade fallback.
 run("test -f /usr/lib/zapret2-home/lock.uc || { printf '%s\\n' 'BLOCKED: legacy package has no admission gate; independently verified offline transition required' >&2; exit 1; }; for f in /usr/libexec/zapret2-home-ctl /usr/libexec/zapret2-home-profiles /usr/libexec/zapret2-home-lists /usr/libexec/zapret2-home-worker /usr/lib/opkg/info/zapret2-home.prerm /usr/lib/opkg/info/zapret2-home.postrm; do grep -qx '# Admission-ABI: 1' \"$f\" || { printf '%s\\n' 'BLOCKED: legacy/mixed package lacks atomic admission; independently verified offline transition required' >&2; exit 1; }; done; test \"$(ucode /usr/lib/zapret2-home/lock.uc abi '' \"$$\")\" = 1")
def upgrade_script(manifest,live,package_path,package_hash,package_version,production_before=None,modes=None):
 hashes='\n'.join(h+'  /'+f for f,h in manifest.items() if f!='etc/config/zapret2_home')+'\n'
 if modes is not None:
  if set(modes)!=set(manifest) or any(not isinstance(m,str) or not re.fullmatch(r'[0-7]{3,4}',m) for m in modes.values()):raise ValueError('Invalid file mode manifest')
 mode_checks=''.join(MODE_CHECK+' '+shlex.quote('/'+f)+' '+shlex.quote(m)+'\n' for f,m in (modes or {}).items() if f!='etc/config/zapret2_home')
 # Old releases omitted protocol branches; normalize only their documented defaults.
 protocols_check='''let defaults={tcp:{enabled:true,profile:a.profile_id || "alt1"},quic:{enabled:false,profile:"quic_google"},udp:{enabled:false,profile:"udp_fake2"}}; for(let name in ["tcp","quic","udp"]) { let p=a.protocols?.[name] ?? defaults[name], q=b.protocols?.[name]; if(type(q)!="object" || type(q.enabled)!="bool" || type(q.profile)!="string" || q.enabled!=p.enabled || q.profile!=p.profile) exit(1); }'''
 # All acceptance checks precede finish; errors retain the gate and recovery data.
 return '''set -eu
umask 077
LOCK=/usr/lib/zapret2-home/lock.uc
RUN=/var/run/zapret2-home
Z2_LIFECYCLE_TOKEN=$(ucode "$LOCK" freeze '' "$$") || exit 1
export Z2_LIFECYCLE_TOKEN
cp "$LOCK" "$RUN/lifecycle-recovery.uc"
cp -p /etc/config/zapret2_home "$RUN/lifecycle-config"
PRODUCTION_BEFORE=$('''+PRODUCTION+''')
'''+('test "$PRODUCTION_BEFORE" = '+shlex.quote(production_before.rstrip('\n'))+'\n' if production_before is not None else '')+'''ubus call zapret2_home status '{}' >"$RUN/lifecycle-before.json"
REQUESTED=0; [ ! -f "$RUN/requested" ] || REQUESTED=1
STOPPING=0; [ ! -f "$RUN/stopping" ] || STOPPING=1
ucode -e 'import { readfile } from "fs"; let s=json(readfile(ARGV[0])); if(!s.integrity_ok || s.running!=s.table_present || (s.running ? (ARGV[2]!="1" || ARGV[3]!="0") : ARGV[2]!="0") || (ARGV[1]!="1" && s.running)) exit(1);' "$RUN/lifecycle-before.json" '''+('1' if live else '0')+''' "$REQUESTED" "$STOPPING"
CHANGES=$(uci -q changes zapret2_home) || exit $?
test -z "$CHANGES"
/etc/init.d/zapret2-home stop
if /usr/libexec/zapret2-home-ctl running; then exit 1; fi
if nft list table inet zapret2_home >/dev/null 2>&1; then exit 1; fi
printf '%s\\n' '''+shlex.quote(package_hash+'  '+package_path)+''' | sha256sum -c - >&2
opkg install '''+shlex.quote(package_path)+''' >&2
/etc/init.d/rpcd reload
printf '%s' '''+shlex.quote(hashes)+''' | sha256sum -c - >&2
'''+mode_checks+'''
cmp -s "$RUN/lifecycle-config" /etc/config/zapret2_home
AUTOSTART=$(ucode -e 'import {readfile} from "fs"; print(json(readfile(ARGV[0])).autostart ? "enable" : "disable");' "$RUN/lifecycle-before.json")
/etc/init.d/zapret2-home "$AUTOSTART"
i=0
until ubus call zapret2_home status '{}' >"$RUN/lifecycle-stopped.json"; do
 i=$((i+1)); [ "$i" -lt 10 ] || exit 1; sleep 1
done
ucode -e 'import { readfile } from "fs"; let a=json(readfile(ARGV[0])), b=json(readfile(ARGV[1])); for(let k in ["clients","destinations","client_mode","lists","auto_update","profile_id","autostart"]) if(b[k]!=a[k]) exit(1); '''+protocols_check+''' if(b.running || b.table_present || !b.integrity_ok) exit(1);' "$RUN/lifecycle-before.json" "$RUN/lifecycle-stopped.json"
ucode "$LOCK" restore-begin '' "$$"
if [ "$REQUESTED" = 1 ]; then
 /etc/init.d/zapret2-home start >&2
 /usr/libexec/zapret2-home-ctl lifecycle-check >&2
else
 if [ "$STOPPING" = 1 ]; then touch "$RUN/stopping"; else rm -f "$RUN/stopping"; fi
fi
ubus call zapret2_home status '{}' >"$RUN/lifecycle-after.json"
cmp -s "$RUN/lifecycle-config" /etc/config/zapret2_home
test "$PRODUCTION_BEFORE" = "$('''+PRODUCTION+''')"
REQUESTED_AFTER=0; [ ! -f "$RUN/requested" ] || REQUESTED_AFTER=1
STOPPING_AFTER=0; [ ! -f "$RUN/stopping" ] || STOPPING_AFTER=1
test "$REQUESTED" = "$REQUESTED_AFTER"; test "$STOPPING" = "$STOPPING_AFTER"
ucode -e 'import { readfile } from "fs"; let a=json(readfile(ARGV[0])), b=json(readfile(ARGV[1])); for(let k in ["clients","destinations","client_mode","lists","auto_update","profile_id","autostart","running","table_present"]) if(b[k]!=a[k]) exit(1); '''+protocols_check+''' if(!b.integrity_ok || b.package_version!=ARGV[2]) exit(1); print(sprintf("%J\\n",{initial:a,status:b}));' "$RUN/lifecycle-before.json" "$RUN/lifecycle-after.json" '''+shlex.quote(package_version)+''' >"$RUN/lifecycle-result.json"
ucode "$LOCK" finish '' "$$"
cat "$RUN/lifecycle-result.json"
'''
def install(upgrade=False,live=False):
 if live and not upgrade:raise ValueError('live requires upgrade')
 if upgrade:
  require_gate()  # Must precede staging, stop, config writes or opkg.
  assert 'Package: zapret2-home' in run('opkg status zapret2-home')
 else:
  assert run('test ! -e /usr/lib/zapret2-home && test ! -e /etc/config/zapret2_home && test ! -e /etc/init.d/zapret2-home')==''
 before=snap();(ROOT/'dist/production-before.txt').write_text(before)
 package_hash,package_name=(ROOT/'dist/package.sha256').read_text().strip().split()
 assert pathlib.Path(package_name).name==package_name,'Invalid package basename'
 b=(ROOT/'dist'/package_name).read_bytes();assert hashlib.sha256(b).hexdigest()==package_hash,'Built package digest mismatch'
 manifest=json.loads((ROOT/'dist/files-manifest.json').read_text())
 modes=json.loads((ROOT/'dist/file-modes.json').read_text())
 if set(modes)!=set(manifest) or any(not isinstance(m,str) or not re.fullmatch(r'[0-7]{3,4}',m) for m in modes.values()):raise ValueError('Invalid file mode manifest')
 stage=run('umask 077; mktemp -d /tmp/hermes-z2-install.XXXXXXXXXX').strip()
 if not re.fullmatch(r'/tmp/hermes-z2-install\.[A-Za-z0-9]{10}',stage):raise RuntimeError('Invalid private stage: '+stage)
 package_path=stage+'/package.ipk';q=shlex.quote(package_path)
 try:
  run('umask 077; dd of='+q+' 2>/dev/null',b)
  assert run('sha256sum '+q).split()[0]==package_hash
  if upgrade:
   result=json.loads(run(upgrade_script(manifest,live,package_path,package_hash,package_name.split('_')[1],before,modes)))
   initial,status=result['initial'],result['status']
  else:
   print(run("printf '%s\\n' "+shlex.quote(package_hash+'  '+package_path)+' | sha256sum -c - >&2 && opkg install '+q))
   print(run('/etc/init.d/rpcd reload; ubus -v list zapret2_home'))
   initial=None
   for f,h in manifest.items():
    assert run('sha256sum '+shlex.quote('/'+f)).split()[0]==h,(f,h)
    run(MODE_CHECK+' '+shlex.quote('/'+f)+' '+shlex.quote(modes[f]))
   status=json.loads(run("ubus call zapret2_home status '{}'"))
   assert status['package_version']==package_name.split('_')[1] and not status['running'] and not status['table_present'] and status['integrity_ok'],status
  if not upgrade:assert before==snap(),'Production VPN state changed'
  (ROOT/'dist/install-verification.json').write_text(json.dumps({'initial':initial,'status':status,'production_before':before,'production_after':snap(),'installed_files':len(manifest)},ensure_ascii=False,indent=2))
 except Exception as error:
  raise RuntimeError('Installation failed; private recovery package retained at '+package_path) from error
 else:
  run('rm -f '+q+'; rmdir '+shlex.quote(stage))
 return initial,status
if __name__=='__main__':print(json.dumps(install('--upgrade' in sys.argv),ensure_ascii=False))
