#!/usr/bin/env python3
"""Real narrow HTTP profile workflow; no experimental main-LAN activation."""
import pathlib,subprocess,json,shlex,urllib.request,time,sys
ROOT=pathlib.Path(__file__).resolve().parents[1]
SSH=['ssh','-o','BatchMode=yes','-o','ConnectTimeout=7','root@192.168.1.1']
PROFILES=['alt1','stock','overlap','fake','fake_split','fake_disorder']
TARGETS=['gitlab','unitask','tavily','youtube','discord']
SELECTED=PROFILES if '--all' in sys.argv else PROFILES[:2]
KEYS=('running','table_present','autostart','clients','destinations','client_mode','lists','auto_update','profile_id')
def remote(cmd):
 p=subprocess.run(SSH+[cmd],capture_output=True,timeout=40)
 if p.returncode:raise RuntimeError('Remote operation failed: '+p.stderr.decode())
 return p.stdout.decode()
def native(obj,method,args=None):return json.loads(remote('ubus call '+obj+' '+method+' '+shlex.quote(json.dumps(args or {}))) or '{}')
def main():return native('zapret2_home','status')
def prod():return remote('sha256sum /etc/config/podkop /etc/sing-box/config.json /etc/config/firewall; pidof sing-box')
def health():
 with urllib.request.urlopen('http://192.168.1.1:9090/proxies/main-out/delay?url=https%3A%2F%2Fwww.gstatic.com%2Fgenerate_204&timeout=10000',timeout=13) as r:d=json.load(r)
 assert isinstance(d.get('delay'),int) and d['delay']>0,d
 return d
base=main();before=prod();engine=remote('cat /var/run/zapret2-home/engine.pid').strip()
cfg=remote('sha256sum /etc/config/zapret2_home').strip()
assert base['running'] and base['integrity_ok'] and base['package_version']=='0.2.7' and base['profile_id'] in PROFILES
sid=None;out={'initial':base,'checks':[],'scope':'HTTP workflow; experimental candidates only isolated queue214'}
OUT=ROOT/'dist'/(('profiles-http-all-v%s.json' if '--all' in sys.argv else 'profiles-http-v%s.json') % base['package_version'])
def check(name,condition):
 assert condition,name
 out['checks'].append(name)
def http(method,args=None):
 b=json.dumps({'jsonrpc':'2.0','id':1,'method':'call','params':[sid,'zapret2_home',method,args or {}]}).encode()
 req=urllib.request.Request('http://192.168.1.1/ubus',data=b,headers={'Content-Type':'application/json'})
 with urllib.request.urlopen(req,timeout=20) as r:d=json.load(r)
 assert d.get('result',[None])[0]==0,{'method':method,'status':d.get('result',[None])[0]}
 return d['result'][1]
def write_evidence():OUT.write_text(json.dumps(out,ensure_ascii=False,indent=2))
try:
 out['vpn_before']=health()
 sid=native('session','create',{'timeout':1800})['ubus_rpc_session']
 methods=['profiles_catalog','profiles_status','profiles_test','profiles_apply','status']
 native('session','grant',{'ubus_rpc_session':sid,'scope':'ubus','objects':[['zapret2_home',m] for m in methods]})
 cat=http('profiles_catalog');check('real HTTP catalog with transport metadata',cat['ok'])
 c=cat['catalog'];check('fixed six profiles and five resources, manual apply available',[p['id'] for p in c['profiles']]==PROFILES and [t['id'] for t in c['targets']]==TARGETS and c['apply_supported'])
 try:http('control',{'action':'restart'})
 except AssertionError:check('ungranted main control denied',True)
 else:raise AssertionError('Unrelated main control unexpectedly granted')
 for name,args in [('unknown target',{'profiles':'alt1','targets':'https://evil.invalid','repeat':1}),('command injection',{'profiles':'alt1;id','targets':'gitlab','repeat':1}),('invalid repeat',{'profiles':'alt1','targets':'gitlab','repeat':3})]:
  r=http('profiles_test',args);check(name+' rejected without starting a test',not r['ok'])
 for name,args in [('unknown profile',{'profile':'ALT9'}),('apply injection',{'profile':'alt1;id'})]:
  r=http('profiles_apply',args);check(name+' rejected before mutation',not r['ok'])
 check('invalid requests leave exact config and main generation unchanged',cfg==remote('sha256sum /etc/config/zapret2_home').strip() and engine==remote('cat /var/run/zapret2-home/engine.pid').strip())
 r=http('profiles_apply',{'profile':base['profile_id']})
 if r.get('pending'):
  for _ in range(150):
   s=http('status');rr=s.get('configure_result')
   if s.get('configure_job_id')==r['job_id'] and rr and rr.get('job_id')==r['job_id']:
    r=rr;break
   time.sleep(1)
  else:raise AssertionError('No matching no-op apply result')
 check('real HTTP same-profile apply confirmed as no-op',r.get('ok') and r.get('unchanged') and main()['profile_id']==base['profile_id'] and engine==remote('cat /var/run/zapret2-home/engine.pid').strip())
 t=time.monotonic();launch=http('profiles_test',{'profiles':' '.join(SELECTED),'targets':' '.join(TARGETS),'repeat':1});elapsed=time.monotonic()-t
 out['launch']=launch;out['acceptance_seconds']=elapsed
 check('pending accepted inside rpcd deadline',launch['ok'] and launch['pending'] and elapsed<15)
 duplicate=http('profiles_test',{'profiles':'alt1','targets':'tavily','repeat':1})
 check('second diagnostic job refused',not duplicate['ok'])
 other=next(p for p in PROFILES if p!=base['profile_id'])
 refused=http('profiles_apply',{'profile':other});check('main profile switch refused while isolated job active',not refused['ok'] and main()['profile_id']==base['profile_id'])
 out['vpn_during']=health()
 deadline=time.monotonic()+1400
 while time.monotonic()<deadline:
  r=http('profiles_status');assert r['ok']
  d=r['data'];assert d['job_id']==launch['job_id'];out['diagnostics']=d;write_evidence()
  if not d['running']:break
  time.sleep(1)
 else:raise RuntimeError('Test still active; preserve exact ownership and investigate; no blanket kill')
 expected={(p,t,1) for p in SELECTED for t in TARGETS};rows=d['results']
 check('matching complete Cartesian batch read back',d['state']=='results' and not d['error'] and len(rows)==len(expected) and {(x['profile'],x['target'],x['repeat']) for x in rows}==expected)
 check('alt1 all five full hashes, verified TLS and WAN response tuples match',all(x['full_match'] for x in rows if x['profile']=='alt1'))
 check('all successful resources have strict proof',all(x['hash_match'] and x['route_verified'] and x['tls_verified'] and x['bytes']==x['expected_bytes'] and x['status']==200 and x['exit']==0 for x in rows if x['full_match']))
 queues=remote('if nft list table inet zapret2_home_profiles >/dev/null 2>&1; then exit 1; fi; cat /proc/net/netfilter/nfnetlink_queue')
 ids=[line.split()[0] for line in queues.splitlines() if line.split()]
 check('owned test table and queue cleaned; main queue retained','214' not in ids and '213' in ids)
 out['vpn_after']=health()
 check('isolated diagnostics never restarted main engine',remote('cat /var/run/zapret2-home/engine.pid').strip()==engine)
finally:
 if sid:
  native('session','destroy',{'ubus_rpc_session':sid})
  try:access=native('session','access',{'ubus_rpc_session':sid,'scope':'ubus','object':'zapret2_home','function':'profiles_apply'}).get('access',False)
  except RuntimeError:access=False
  check('temporary narrow session destroyed',not access)
 final=main();check('complete original scope/profile/running state preserved',all(base[k]==final[k] for k in KEYS))
 check('exact own config unchanged',cfg==remote('sha256sum /etc/config/zapret2_home').strip())
 check('VPN production hashes and PID unchanged',prod()==before)
 out['final']=final;write_evidence()
summary={'checks':len(out['checks']),'rows':len(out['diagnostics']['results']),'acceptance_seconds':out['acceptance_seconds'],'per_profile':{p:{'full':sum(x['full_match'] for x in out['diagnostics']['results'] if x['profile']==p),'total':sum(x['profile']==p for x in out['diagnostics']['results'])} for p in SELECTED},'vpn_controls':[out.get('vpn_'+x) for x in ['before','during','after']]}
print(json.dumps(summary,ensure_ascii=False))
