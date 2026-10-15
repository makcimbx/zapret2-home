#!/usr/bin/env python3
"""Repeated certified HTTP/1.1 and HTTP/2 LAN requests, no router writes.
Keep individual failures, identify the actual negotiated version. Not a
browser/full-application or whole-network availability guarantee.
"""
import subprocess,pathlib,json,hashlib,time,urllib.request
ROOT=pathlib.Path(__file__).resolve().parents[1];OUT=ROOT/'dist'/'reliability';OUT.mkdir(parents=True,exist_ok=True)
targets=[('gitlab','https://gitlab.hotreload.net/assets/webpack/main.4e9cbf4e.chunk.js','65.108.59.85',1008147,'5053a171a0c992f64cc32266e635101af57d3df66509d0a0cb311a36d0fe3777'),('unitask','https://download.openupm.com/verdaccio/com.cysharp.unitask/com.cysharp.unitask-2.5.11.tgz','107.175.71.2',180175,'f502c3d1e56afee722c2707ba7370562446a6f3d4684a27afb74fd5817ab0a5b'),('tavily','https://app.tavily.com/home','52.85.154.99',25846,'bb9228ba69540910159ef83d1fffb54fa90d329d39415da238e974a573886175')]
SSH=['ssh','-o','BatchMode=yes','-o','ConnectTimeout=7','root@192.168.1.1']
def state():
 p=subprocess.run(SSH+["ubus call zapret2_home status '{}'"],capture_output=True,check=True,timeout=20)
 return json.loads(p.stdout)
initial=state();assert initial['running'];rows=[]
try:
 for ver in ('--http1.1','--http2'):
  for rep in range(3):
   for n,(label,url,ip,size,sha) in enumerate(targets):
    host=__import__('urllib.parse',fromlist=['urlparse']).urlparse(url).hostname
    body=OUT/(label+'-'+ver[2:]+'-'+str(rep)+'.bin')
    cmd=['curl','-4','--noproxy','*',ver,'--resolve',host+':443:'+ip,'-H','Accept-Encoding: identity','--connect-timeout','12','--max-time','18','--max-filesize','2097152','--limit-rate','192k','-sS','-o',str(body),'-w','%{json}',url]
    p=subprocess.run(cmd,capture_output=True,timeout=23);d=json.loads(p.stdout or '{}');b=body.read_bytes() if body.exists() else b''
    r={k:d.get(k) for k in ('http_code','http_version','remote_ip','time_total','time_connect','time_appconnect','size_download','ssl_verify_result')};r.update(target=label,repeat=rep,requested=ver,exit=p.returncode,stderr=p.stderr.decode(),sha256=hashlib.sha256(b).hexdigest())
    r['full_hash_match']=p.returncode==0 and len(b)==size and r['sha256']==sha and d.get('ssl_verify_result')==0
    rows.append(r);(OUT/'curl-results.json').write_text(json.dumps(rows,ensure_ascii=False,indent=2));print(json.dumps(r),flush=True)
    time.sleep(.2)
finally:
 final=state();keys=('clients','destinations','client_mode','lists','auto_update','autostart')
 assert final['running'] and final['table_present'] and all(final[k]==initial[k] for k in keys)
 (OUT/'curl-summary.json').write_text(json.dumps({'initial_status':initial,'final_status':final,'trials':len(rows),'successes':sum(r['full_hash_match'] for r in rows),'failures':[r for r in rows if not r['full_hash_match']]},ensure_ascii=False,indent=2))
print('RESULT',len(rows),sum(r['full_hash_match'] for r in rows))
