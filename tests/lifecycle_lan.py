#!/usr/bin/env python3
"""Real procd lifecycle + bounded LAN forwarded-traffic canary; always stop afterwards."""
import pathlib,subprocess,json,hashlib,shlex,time,urllib.request
ROOT=pathlib.Path(__file__).resolve().parents[1]
SSH=['ssh','-o','BatchMode=yes','-o','ConnectTimeout=7','root@192.168.1.1']
def remote(s):
 p=subprocess.run(SSH+[s],capture_output=True,timeout=35)
 if p.returncode:raise RuntimeError(s+'\n'+p.stdout.decode()+p.stderr.decode())
 return p.stdout.decode()
def rpc(m,args={}):return json.loads(remote('ubus call zapret2_home '+m+' '+shlex.quote(json.dumps(args))))
rows=[];controls=[]
def state():
 s=rpc('status');rows.append({'type':'status','value':s});print(json.dumps({k:v for k,v in s.items() if k!='rule_counters'},ensure_ascii=False));return s
URL='https://gitlab.hotreload.net/assets/webpack/main.4e9cbf4e.chunk.js'
def gitlab(label):
 cmd=['curl','-4','--noproxy','*','--http1.1','-H','Accept-Encoding: identity','--resolve','gitlab.hotreload.net:443:65.108.59.85','--connect-timeout','8','--max-time','12','--limit-rate','192k','-sS','-o',str(ROOT/'dist'/('canary-'+label+'.bin')),'-w','%{json}',URL]
 p=subprocess.run(cmd,capture_output=True,timeout=18);r=json.loads(p.stdout);b=(ROOT/'dist'/('canary-'+label+'.bin')).read_bytes();r.update(label=label,exit=p.returncode,stderr=p.stderr.decode(),sha256=hashlib.sha256(b).hexdigest());rows.append(r);print(json.dumps({k:r.get(k) for k in ['label','exit','http_code','size_download','remote_ip','time_total','sha256']},ensure_ascii=False));return r

def vpn(label):
 url='https://raw.githubusercontent.com/python/cpython/main/Lib/pathlib/__init__.py'
 p=subprocess.Popen(['curl','-4','--noproxy','*','--connect-timeout','12','--max-time','18','--limit-rate','32k','-sS','-o','/dev/null','-w','%{json}',url],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
 hits=[]
 for _ in range(5):
  time.sleep(.15)
  d=json.load(urllib.request.urlopen('http://192.168.1.1:9090/connections',timeout=2))
  hits.extend(c.get('chains') for c in d.get('connections',[]) if c.get('metadata',{}).get('host')=='raw.githubusercontent.com')
 o,e=p.communicate(timeout=22);r=json.loads(o);r.update(label=label,exit=p.returncode,chains=hits,stderr=e.decode());controls.append(r);print('VPN',json.dumps({k:r.get(k) for k in ['label','exit','http_code','size_download','chains']}));assert p.returncode==0 and r['size_download']>20000 and any('main-out' in h for h in hits),r
before=remote('sha256sum /etc/config/podkop /etc/sing-box/config.json /etc/config/firewall; pidof sing-box')
assert before==(ROOT/'dist/production-before.txt').read_text()
try:
 vpn('before');s=state();assert not s['running'] and not s['table_present']
 gitlab('direct')
 r=rpc('control',{'action':'start'});print('START',r);assert r['ok'],r
 s=state();assert s['running'] and s['table_present']
 for n in range(3):
  r=gitlab('on-'+str(n));assert r['exit']==0 and r['size_download']==1008147 and r['sha256']=='5053a171a0c992f64cc32266e635101af57d3df66509d0a0cb311a36d0fe3777',r
 s=state();assert 'counter packets 0 bytes 0 queue' not in s['rule_counters'],s
 vpn('during')
 r=rpc('control',{'action':'restart'});print('RESTART',r);assert r['ok'];s=state();assert s['running'] and s['table_present']
 r=gitlab('after-restart');assert r['exit']==0 and r['size_download']==1008147
 remote('/usr/libexec/zapret2-home-ctl reconcile');s=state();assert s['running'] and s['table_present']
 remote('/etc/init.d/zapret2-home reload');time.sleep(2);s=state();assert s['running'] and s['table_present']
 r=rpc('control',{'action':'stop'});print('STOP',r);assert r['ok'];s=state();assert not s['running'] and not s['table_present'];vpn('after')
finally:
 print('FINAL_STOP',rpc('control',{'action':'stop'}));rpc('control',{'action':'disable'})
 after=remote('sha256sum /etc/config/podkop /etc/sing-box/config.json /etc/config/firewall; pidof sing-box')
 assert after==before
 (ROOT/'dist/lifecycle-lan-results.json').write_text(json.dumps({'rows':rows,'vpn_controls':controls,'production_before':before,'production_after':after,'final_status':state()},ensure_ascii=False,indent=2))
