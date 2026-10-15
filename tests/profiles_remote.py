#!/usr/bin/env python3
"""Authorized isolated backend staging/live test; preserve main service and VPN."""
import pathlib,subprocess,json,hashlib,shlex,time
ROOT=pathlib.Path(__file__).resolve().parents[1]; OUT=ROOT/'dist';OUT.mkdir(exist_ok=True)
SSH=['ssh','-o','BatchMode=yes','-o','ConnectTimeout=7','root@192.168.1.1']
CMD='/usr/libexec/zapret2-home-profiles'
KEYS=('running','table_present','autostart','client_mode','clients','destinations','lists','auto_update')
def remote(cmd,data=None,timeout=30):
 p=subprocess.run(SSH+[cmd],input=data,capture_output=True,timeout=timeout)
 if p.returncode:raise RuntimeError(p.stdout.decode()+p.stderr.decode())
 return p.stdout.decode()
def status():return json.loads(remote("ubus call zapret2_home status '{}'"))
def profile(op,payload={}):return json.loads(remote('printf %s '+shlex.quote(json.dumps(payload))+' | '+CMD+' '+op))
def production():return remote('sha256sum /etc/config/podkop /etc/sing-box/config.json /etc/config/firewall; pidof sing-box')
before=production(); initial=status(); assert initial['running'] and initial['integrity_ok']
evidence={'initial':initial,'production_before':before,'checks':[]}
try:
 # New files only; package integration follows independently verified execution.
 for rel,mode in [('usr/libexec/zapret2-home-profiles','755'),('usr/lib/zapret2-home/profiles.uc','644')]:
  b=(ROOT/'files'/rel).read_bytes(); digest=hashlib.sha256(b).hexdigest()
  remote('dd of=/'+rel+' 2>/dev/null',b)
  remote('chmod '+mode+' /'+rel)
  got=remote('sha256sum /'+rel).split()[0];assert got==digest
  evidence['checks'].append({'file':rel,'sha256':got})
 evidence['catalog']=profile('catalog')
 assert len(evidence['catalog']['catalog']['profiles'])==2
 # Target parser/nft syntax, no rule activation at this stage.
 remote("ucode /usr/lib/zapret2-home/profiles.uc rules 123.456 >/tmp/hermes-z2-profiles-check.nft; nft -c -f /tmp/hermes-z2-profiles-check.nft; R=$?; rm -f /tmp/hermes-z2-profiles-check.nft; exit $R")
 launch=profile('test',{'profiles':'alt1 stock','targets':'gitlab unitask tavily','repeat':1});evidence['launch']=launch
 assert launch.get('ok') and launch.get('pending'),launch
 for _ in range(250):
  s=profile('status');evidence['diagnostics']=s
  (OUT/'profiles-live-partial.json').write_text(json.dumps(evidence,ensure_ascii=False,indent=2))
  if not s['data']['running']:break
  time.sleep(1)
 else:raise RuntimeError('Diagnostic did not finish; inspect retained exact generation, never blanket-kill')
 d=s['data'];print(json.dumps(d,ensure_ascii=False,indent=2))
 assert d['state']=='results' and not d.get('error'),d
 rows=d['results'];assert len(rows)==6,rows
 assert all(r['full_match'] for r in rows if r['profile']=='alt1'),rows
 assert all(r['route_verified'] for r in rows if r['status']),rows
 evidence['cleanup']=remote('if nft list table inet zapret2_home_profiles >/dev/null 2>&1; then exit 1; fi; cat /proc/net/netfilter/nfnetlink_queue; cat /proc/loadavg')
 assert not any(line.split()[0]=='214' for line in evidence['cleanup'].splitlines() if line.split())
finally:
 evidence['final']=status();evidence['production_after']=production()
 evidence['scope_preserved']=all(initial[k]==evidence['final'][k] for k in KEYS)
 (OUT/'profiles-live-results.json').write_text(json.dumps(evidence,ensure_ascii=False,indent=2))
 assert before==evidence['production_after'] and evidence['scope_preserved']
print('PROFILES_LIVE_VERIFIED')
