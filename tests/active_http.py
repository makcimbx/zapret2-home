#!/usr/bin/env python3
"""Actual HTTP save/apply while running. Toggle only update scheduling; restore.
Preserve client eligibility, all selected lists, autostart and main VPN. Auth
session is narrow, ephemeral, never printed or saved, destroyed afterwards.
"""
import pathlib,subprocess,json,shlex,urllib.request,time
ROOT=pathlib.Path(__file__).resolve().parents[1]
SSH=['ssh','-o','BatchMode=yes','-o','ConnectTimeout=7','root@192.168.1.1']
KEYS=('clients','destinations','autostart','client_mode','lists','auto_update')
def remote(cmd):
 p=subprocess.run(SSH+[cmd],capture_output=True,timeout=65)
 if p.returncode:raise RuntimeError('Remote operation failed')
 return p.stdout.decode()
def native(obj,method,args={}):return json.loads(remote('ubus call '+obj+' '+method+' '+shlex.quote(json.dumps(args))) or '{}')
def status():return native('zapret2_home','status')
def engine_pid():return remote('cat /var/run/zapret2-home/engine.pid').strip()
def prod():return remote('sha256sum /etc/config/podkop /etc/sing-box/config.json /etc/config/firewall; pidof sing-box')
base=status();assert base['running'] and base['table_present'] and not base['update_running'],base
original={k:base[k] for k in KEYS};original_profile=base.get('profile_id','alt1');before=prod();sid=None;results={};restored=False
pid=engine_pid()
def http(method,args={}):
 body=json.dumps({'jsonrpc':'2.0','id':1,'method':'call','params':[sid,'zapret2_home',method,args]}).encode()
 req=urllib.request.Request('http://192.168.1.1/ubus',data=body,headers={'Content-Type':'application/json'})
 start=time.monotonic()
 with urllib.request.urlopen(req,timeout=65) as r:d=json.load(r)
 if d.get('result',[None])[0]!=0:raise RuntimeError('HTTP RPC transport returned failure')
 return d['result'][1],time.monotonic()-start
def settled(reply):
 if not reply.get('pending'):return reply
 deadline=time.monotonic()+90
 while time.monotonic()<deadline:
  s=status()
  assert str(s.get('configure_job_id'))==str(reply['job_id']),s
  result=s.get('configure_result')
  if result is not None and str(result.get('job_id'))==str(reply['job_id']):return result
  if not s.get('configure_pending'):raise RuntimeError('Configure job did not finish; recovery required')
  time.sleep(1)
 raise RuntimeError('Configure completion was not confirmed')
try:
 sid=native('session','create',{'timeout':600})['ubus_rpc_session']
 native('session','grant',{'ubus_rpc_session':sid,'scope':'ubus','objects':[['zapret2_home','configure'],['zapret2_home','status']]})
 bad,t=http('configure',dict(original,client_mode='selected',clients=''))
 assert not bad['ok'] and engine_pid()==pid and all(status()[k]==original[k] for k in KEYS),bad
 results['invalid_rejected_without_restart']=True
 candidate=dict(original,auto_update=not original['auto_update'])
 response,t=http('configure',candidate);results['apply_response']=response;results['apply_duration']=t
 assert response.get('ok'),response
 completion=settled(response);results['apply_completion']=completion;assert completion.get('ok'),completion
 applied=status();newpid=engine_pid()
 assert applied['running'] and applied['table_present'] and newpid!=pid and all(applied[k]==candidate[k] for k in KEYS),applied
 assert prod()==before
 results['applied_running']=True;results['only_own_engine_restarted']=True
 response,t=http('configure',original);results['restore_response']=response;results['restore_duration']=t
 assert response.get('ok'),response
 completion=settled(response);results['restore_completion']=completion;assert completion.get('ok'),completion
 final=status();assert final['running'] and final['table_present'] and final['integrity_ok'] and all(final[k]==original[k] for k in KEYS),final
 restored=True;results['original_settings_restored']=True
finally:
 try:
  if not restored:
   r=settled(native('zapret2_home','configure',original))
   if not r.get('ok'):raise RuntimeError('Failed to restore original settings: '+str(r))
   current=status()
   if not current['running']:
    assert native('zapret2_home','control',{'action':'start'}).get('ok')
 finally:
  if sid:
   native('session','destroy',{'ubus_rpc_session':sid})
   try:access=native('session','access',{'ubus_rpc_session':sid,'scope':'ubus','object':'zapret2_home','function':'configure'}).get('access',False)
   except RuntimeError:access=False
   assert not access
   results['session_destroyed']=True
 final=status();assert all(final[k]==original[k] for k in KEYS) and final['running'] and final['table_present']
 assert prod()==before
 assert final.get('profile_id','alt1')==original_profile,'Legacy settings save changed the selected profile'
 results.update(production_unchanged=True,profile_preserved=True,final_status=final)
 version=final['package_version']
 (ROOT/'dist'/('active-http-v'+version+'.json')).write_text(json.dumps(results,ensure_ascii=False,indent=2))
print(json.dumps({k:v for k,v in results.items() if k!='final_status'},ensure_ascii=False))
