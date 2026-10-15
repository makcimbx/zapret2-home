#!/usr/bin/env python3
"""Real HTTP manual changes while STOPPED; never activate experimental LAN preset."""
import json,pathlib,shlex,subprocess,time,urllib.request
ROOT=pathlib.Path(__file__).resolve().parents[1]
SSH=['ssh','-o','BatchMode=yes','-o','ConnectTimeout=7','root@192.168.1.1']
KEYS=('autostart','clients','destinations','client_mode','lists','auto_update')
def remote(cmd):
 p=subprocess.run(SSH+[cmd],capture_output=True,timeout=45)
 if p.returncode:raise RuntimeError(p.stderr.decode())
 return p.stdout.decode()
def native(method,args=None):return json.loads(remote('ubus call zapret2_home '+method+' '+shlex.quote(json.dumps(args or {}))))
def prod():return remote('sha256sum /etc/config/podkop /etc/sing-box/config.json /etc/config/firewall; pidof sing-box')
def session(method,args):return json.loads(remote('ubus call session '+method+' '+shlex.quote(json.dumps(args))) or '{}')
def apply(profile):
 b=json.dumps({'jsonrpc':'2.0','id':1,'method':'call','params':[sid,'zapret2_home','profiles_apply',{'profile':profile}]}).encode()
 req=urllib.request.Request('http://192.168.1.1/ubus',data=b,headers={'Content-Type':'application/json'})
 with urllib.request.urlopen(req,timeout=20) as r:d=json.load(r)
 assert d['result'][0]==0;accepted=d['result'][1];assert accepted['ok'],accepted
 result=accepted
 if accepted.get('pending'):
  deadline=time.monotonic()+150
  while time.monotonic()<deadline:
   s=native('status');rr=s.get('configure_result')
   if s.get('configure_job_id')==accepted['job_id'] and rr and rr.get('job_id')==accepted['job_id']:
    result=rr;break
   time.sleep(1)
  else:raise RuntimeError('Apply still uncertain; retain state and investigate, do not force config overwrite')
 assert result['ok'],result
 s=native('status');assert s['profile_id']==profile and not s['running'] and not s['table_present'] and not s['configure_pending'] and not s['configure_recovery_required'],s
 assert all(s[k]==base[k] for k in KEYS)
 out['steps'].append({'requested':profile,'accepted':accepted,'terminal':result,'readback':s})
 return s
base=native('status');before=prod();assert base['package_version']=='0.2.5' and base['running'] and base['profile_id']=='alt1' and not base['configure_pending'] and not base['configure_recovery_required']
diag=native('profiles_status');assert diag['ok'] and not diag['data']['running']
sid=None;out={'initial':base,'steps':[],'scope':'inactive-only real HTTP preset changes; experimental preset never started'}
try:
 sid=session('create',{'timeout':300})['ubus_rpc_session']
 session('grant',{'ubus_rpc_session':sid,'scope':'ubus','objects':[['zapret2_home','profiles_apply']]})
 assert native('control',{'action':'stop'})['ok']
 apply('stock');apply(base['profile_id'])
finally:
 try:
  s=native('status')
  if s['configure_pending'] or s['configure_recovery_required']:raise RuntimeError('Uncertain transaction: service remains stopped for safe recovery')
  if s['profile_id']!=base['profile_id']:
   if not sid:raise RuntimeError('Original profile restoration lacks authorized test session')
   apply(base['profile_id'])
  if base['running'] and not s['running']:assert native('control',{'action':'start'})['ok']
  final=native('status');assert all(final[k]==base[k] for k in KEYS) and final['profile_id']==base['profile_id'] and final['running']==base['running'] and final['table_present']==base['table_present'] and final['integrity_ok']
  assert before==prod(),'Production VPN state changed'
  out['final']=final;out['production_unchanged']=True
 finally:
  if sid:
   session('destroy',{'ubus_rpc_session':sid})
   try:
    access=session('access',{'ubus_rpc_session':sid,'scope':'ubus','object':'zapret2_home','function':'profiles_apply'}).get('access',False)
   except RuntimeError as e:
    if '(Not found)' not in str(e):raise
    access=False
   assert not access;out['session_destroyed']=True
  (ROOT/'dist/profiles-apply-inactive-http-v0.2.5.json').write_text(json.dumps(out,ensure_ascii=False,indent=2))
print(json.dumps({'inactive_changes':len(out['steps']),'restored_profile':out['final']['profile_id'],'running':out['final']['running'],'production_unchanged':out['production_unchanged'],'session_destroyed':out['session_destroyed']}))
