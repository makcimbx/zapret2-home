#!/usr/bin/env python3
"""Exercise the actual uhttpd/rpcd boundary using an ephemeral narrowly granted
session. No passwords, browser cookies or tokens are printed/persisted. Service
remains stopped; configuration/autostart are restored, session destroyed.
"""
import subprocess,json,shlex,pathlib,urllib.request,sys
ROOT=pathlib.Path(__file__).resolve().parents[1]
SSH=['ssh','-o','BatchMode=yes','-o','ConnectTimeout=7','root@192.168.1.1']
def native(obj,method,args={}):
 p=subprocess.run(SSH+['ubus call '+obj+' '+method+' '+shlex.quote(json.dumps(args))],capture_output=True,timeout=25)
 if p.returncode: raise RuntimeError('Native RPC failed: '+obj+'.'+method) # Never include session-bearing commands.
 return json.loads(p.stdout or b'{}')
def prod():
 p=subprocess.run(SSH+['sha256sum /etc/config/podkop /etc/sing-box/config.json /etc/config/firewall; pidof sing-box'],capture_output=True,check=True,timeout=12)
 return p.stdout.decode()
base=native('zapret2_home','status'); assert not base['running'] and not base['table_present'] and not base['autostart']
keys=['clients','destinations','autostart','client_mode','lists','auto_update']
restore={k:base[k] for k in keys}; before=prod();sid=None; results={}
def http(method,args={}):
 body=json.dumps({'jsonrpc':'2.0','id':1,'method':'call','params':[sid,'zapret2_home',method,args]}).encode()
 req=urllib.request.Request('http://192.168.1.1/ubus',data=body,headers={'Content-Type':'application/json'})
 with urllib.request.urlopen(req,timeout=25) as r:return json.load(r)
try:
 sid=native('session','create',{'timeout':90})['ubus_rpc_session']
 native('session','grant',{'ubus_rpc_session':sid,'scope':'ubus','objects':[['zapret2_home','status'],['zapret2_home','configure']]})
 assert native('session','access',{'ubus_rpc_session':sid,'scope':'ubus','object':'zapret2_home','function':'configure'})['access']
 denied=http('logs');assert denied.get('result',[None])[0]==6 or denied.get('error',{}).get('code')==-32002,denied
 response=http('configure',{'clients':'','destinations':'65.108.59.85/32 107.175.71.2/32 52.85.154.99/32','autostart':True,'client_mode':'all','lists':'','auto_update':False})
 assert response.get('result',[None])[0]==0,response
 result=response['result'][1]
 if '--expect-bug' in sys.argv:
  assert result.get('ok') is False and result.get('error')=='Неизвестное поле',result
  results={'reproduced_through_http':True,'error':result['error']}
 else:
  assert result.get('ok') is True,result
  read=http('status')['result'][1]
  assert read['client_mode']=='all' and read['clients']=='' and read['autostart'] and not read['running'] and not read['table_present'],read
  assert read['destinations']=='65.108.59.85/32 107.175.71.2/32 52.85.154.99/32'
  invalid=http('configure',dict(restore,unknown_option='bad'))
  assert invalid['result'][0]==0 and invalid['result'][1]['ok'] is False,invalid
  results={'http_save':True,'readback_all_mode':True,'autostart_saved_without_start':True,'unknown_field_rejected':True,'ungranted_method_denied':True}
finally:
 try:
  assert native('zapret2_home','configure',restore)['ok']
 finally:
  if sid:
   native('session','destroy',{'ubus_rpc_session':sid})
   p=subprocess.run(SSH+['ubus call session access '+shlex.quote(json.dumps({'ubus_rpc_session':sid,'scope':'ubus','object':'zapret2_home','function':'configure'}))],capture_output=True,timeout=10)
   assert p.returncode or not json.loads(p.stdout or b'{}').get('access',False)
 final=native('zapret2_home','status')
 assert all(final[k]==restore[k] for k in keys) and not final['running'] and not final['table_present']
 assert prod()==before
results.update(session_destroyed=True,original_settings_restored=True,production_unchanged=True)
if '--expect-bug' not in sys.argv:(ROOT/'dist/http-rpc-tests.json').write_text(json.dumps(results,ensure_ascii=False,indent=2))
print(json.dumps(results,ensure_ascii=False))
