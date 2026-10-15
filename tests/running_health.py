#!/usr/bin/env python3
"""Read-only running-service/LAN/VPN canary. Never stop or reconfigure service."""
import subprocess,pathlib,json,time,threading,urllib.request,hashlib,select,re,shlex
ROOT=pathlib.Path(__file__).resolve().parents[1]
OUT=ROOT/'dist'/'running-health'/str(time.time_ns());OUT.mkdir(parents=True,exist_ok=True)
SSH=['ssh','-o','BatchMode=yes','-o','ConnectTimeout=7','root@192.168.1.1']
def remote(s):
 p=subprocess.run(SSH+[s],capture_output=True,timeout=40)
 if p.returncode:raise RuntimeError(p.stderr.decode())
 return p.stdout.decode()
def status():return json.loads(remote("ubus call zapret2_home status '{}'"))
def snapshot():return remote('sha256sum /etc/config/podkop /etc/sing-box/config.json /etc/config/firewall; pidof sing-box')
targets=[
 ('GitLab','https://gitlab.hotreload.net/assets/webpack/main.4e9cbf4e.chunk.js','65.108.59.85',1008147,'5053a171a0c992f64cc32266e635101af57d3df66509d0a0cb311a36d0fe3777'),
 ('Unitask','https://download.openupm.com/verdaccio/com.cysharp.unitask/com.cysharp.unitask-2.5.11.tgz','107.175.71.2',180175,'f502c3d1e56afee722c2707ba7370562446a6f3d4684a27afb74fd5817ab0a5b'),
 ('Tavily','https://app.tavily.com/home','52.85.154.99',25846,None),
 ('Exa','https://exa.ai/','216.150.1.1',208920,None)]
# Headers only, restricted to our canary ports; no plaintext application capture.
filt='tcp port 443 and portrange 63500-63509'
capcmd='tcpdump -p -nn -l -s 80 -i pppoe-wan '+shlex.quote(filt)+' & P=$!; (sleep 100; kill "$P" 2>/dev/null) & W=$!; trap \'kill "$P" "$W" 2>/dev/null\' EXIT TERM INT; wait "$P"; kill "$W" 2>/dev/null'
cap=None;reader=None;errfile=None;rows=[];result={}
def probe(label,url,ip=None,size=None,expected=None,port=63508):
 body=OUT/(label+'.bin');host=urllib.request.urlparse(url).hostname if hasattr(urllib.request,'urlparse') else __import__('urllib.parse',fromlist=['urlparse']).urlparse(url).hostname
 args=['curl','-4','--noproxy','*','--http1.1','--local-port',str(port),'-H','Accept-Encoding: identity','--connect-timeout','12','--max-time','20','--max-filesize','2097152','--limit-rate','192k','-sS','-o',str(body),'-w','%{json}']
 if ip:args+=['--resolve',host+':443:'+ip]
 args.append(url);hits=[];stop=threading.Event()
 def observe():
  while not stop.wait(.12):
   try:
    d=json.load(urllib.request.urlopen('http://192.168.1.1:9090/connections',timeout=2))
    for c in d.get('connections',[]):
     m=c.get('metadata',{})
     if str(m.get('sourcePort'))==str(port) and m.get('sourceIP')=='192.168.1.20':
      item={'host':m.get('host'),'destinationIP':m.get('destinationIP'),'chains':c.get('chains')}
      if item not in hits:hits.append(item)
   except Exception as e:hits.append({'observation_error':str(e)})
 t=threading.Thread(target=observe);t.start()
 try:p=subprocess.run(args,capture_output=True,timeout=25)
 finally:stop.set();t.join(timeout=3)
 d=json.loads(p.stdout or '{}');b=body.read_bytes() if body.exists() else b''
 r={k:d.get(k) for k in ('http_code','remote_ip','local_ip','local_port','size_download','time_total','time_connect','time_appconnect','ssl_verify_result')}
 r.update(label=label,port=port,url=url,ip=ip,exit=p.returncode,sha256=hashlib.sha256(b).hexdigest(),stderr=p.stderr.decode(),proxy_observations=hits)
 r['full_ok']=p.returncode==0 and d.get('http_code')==200 and (size is None or len(b)==size) and (expected is None or r['sha256']==expected) and d.get('ssl_verify_result')==0
 rows.append(r);(OUT/'transfers.json').write_text(json.dumps(rows,ensure_ascii=False,indent=2));print(json.dumps(r,ensure_ascii=False),flush=True)
 return r
before=snapshot();initial=status();assert initial['running'] and initial['table_present'],initial
try:
 errfile=(OUT/'wan.stderr').open('w+')
 cap=subprocess.Popen(SSH+[capcmd],stdout=subprocess.PIPE,stderr=errfile,text=True)
 ready=False
 for _ in range(50):
  time.sleep(.1);errfile.flush()
  if 'listening on' in (OUT/'wan.stderr').read_text():ready=True;break
  if cap.poll() is not None:break
 if not ready:raise RuntimeError('WAN capture was not ready; no route assertion possible')
 lines=[]
 def readcap():
  for line in cap.stdout:lines.append(line)
 reader=threading.Thread(target=readcap,daemon=True);reader.start()
 raw='https://raw.githubusercontent.com/python/cpython/main/Lib/pathlib/__init__.py'
 probe('VPN-before',raw,port=63508)
 for n,t in enumerate(targets):probe(*t,port=63500+n)
 probe('VPN-after',raw,port=63509)
finally:
 if cap:
  cleanup = r'''for x in /proc/[0-9]*/cmdline; do c=$(tr '\000' ' ' <"$x" 2>/dev/null); case "$c" in 'tcpdump -p -nn -l -s 80 -i pppoe-wan tcp port 443 and portrange 63500-63509 '*) p=${x#/proc/}; p=${p%/cmdline}; kill "$p" 2>/dev/null;; esac; done'''
  subprocess.run(SSH+[cleanup],capture_output=True,timeout=15)
  try:cap.wait(timeout=5)
  except subprocess.TimeoutExpired:cap.terminate();cap.wait(timeout=5)
  if reader:reader.join(timeout=2)
  (OUT/'wan.txt').write_text(''.join(locals().get('lines',[])))
 if errfile:errfile.close()
 after=snapshot();final=status();text=(OUT/'wan.txt').read_text() if (OUT/'wan.txt').exists() else ''
 for r in rows:
  if r['ip']:
   r['wan_connection_verified']=bool(re.search(r'46\.148\.248\.123\.'+str(r['port'])+r' > '+re.escape(r['ip'])+r'\.443:',text))
  r['main_out_verified']=any('main-out' in x.get('chains',[]) for x in r['proxy_observations'])
 result={'initial_status':initial,'final_status':final,'production_before':before,'production_after':after,'rows':rows,'config_preserved':all(initial[k]==final[k] for k in ('client_mode','clients','destinations','lists','auto_update','autostart')),'queue_readback':remote('cat /proc/net/netfilter/nfnetlink_queue; cat /proc/loadavg')}
 (ROOT/'dist'/'running-health-results.json').write_text(json.dumps(result,ensure_ascii=False,indent=2))
 assert before==after,'Production state changed'
 assert final['running'] and final['table_present'] and result['config_preserved'],'Live scope/state changed'
assert all(r['full_ok'] for r in rows),rows
assert all(r['main_out_verified'] for r in rows if r['label'].startswith('VPN')),rows
assert next(r for r in rows if r['label']=='GitLab')['wan_connection_verified'],rows
print('RUNNING_HEALTH_PASS',flush=True)
