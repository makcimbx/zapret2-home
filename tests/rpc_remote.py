#!/usr/bin/env python3
"""Exercise real rpcd methods while service remains stopped; no traffic capture."""
import subprocess,json,pathlib
ROOT=pathlib.Path(__file__).resolve().parents[1]
SSH=['ssh','-o','BatchMode=yes','-o','ConnectTimeout=7','root@192.168.1.1']
import shlex
def rpc(method,payload={}):
 p=subprocess.run(SSH+['ubus call zapret2_home '+method+' '+shlex.quote(json.dumps(payload))],capture_output=True,timeout=20)
 if p.returncode:return {'ok':False,'error':p.stderr.decode(),'transport_exit':p.returncode}
 return json.loads(p.stdout)
results=[]
def check(name,method,payload,valid):
 r=rpc(method,payload);assert valid(r),(name,r);results.append({'case':name,'result':r});print(name,json.dumps(r,ensure_ascii=False))
base=rpc('status');assert not base['running'] and not base['table_present'] and not base['autostart']
def bad(r):return r.get('ok') is False
try:
 check('real status','status',{},lambda r:r['integrity_ok'] and not r['running'])
 check('runtime dry-run+nft syntax','check',{},lambda r:r.get('ok') is True)
 for name,args in [('shell injection',{'clients':'192.168.1.20; touch /tmp/z2-should-not-exist','destinations':base['destinations'],'autostart':False}),('CIDR host bits',{'clients':'192.168.1.20/24','destinations':base['destinations'],'autostart':False}),('public client',{'clients':'8.8.8.8','destinations':base['destinations'],'autostart':False}),('fakeip destination',{'clients':base['clients'],'destinations':'198.18.0.1','autostart':False}),('bool type',{'clients':base['clients'],'destinations':base['destinations'],'autostart':'false'})]:
  check(name,'configure',args,bad)
 check('unknown action','control',{'action':'start; touch /tmp/z2-should-not-exist'},bad)
 check('autostart enable without launch','configure',{'clients':base['clients'],'destinations':base['destinations'],'autostart':True},lambda r:r.get('ok') is True)
 check('autostart readback','status',{},lambda r:r['autostart'] and not r['running'] and not r['table_present'])
 check('restore autostart disabled','configure',{'clients':base['clients'],'destinations':base['destinations'],'autostart':False},lambda r:r.get('ok') is True)
 check('bounded logs','logs',{},lambda r:isinstance(r.get('log'),str))
 check('final stopped state','status',{},lambda r:not r['running'] and not r['table_present'] and not r['autostart'])
 p=subprocess.run(SSH+['test ! -e /tmp/z2-should-not-exist; sha256sum /etc/config/podkop /etc/sing-box/config.json /etc/config/firewall; pidof sing-box'],capture_output=True,timeout=12)
 assert p.returncode==0;pstate=p.stdout.decode();assert pstate==(ROOT/'dist/production-before.txt').read_text()
 (ROOT/'dist/rpc-tests.json').write_text(json.dumps({'passed':len(results),'cases':results,'production_after':pstate},ensure_ascii=False,indent=2))
finally:
 rpc('control',{'action':'stop'});rpc('control',{'action':'disable'})
