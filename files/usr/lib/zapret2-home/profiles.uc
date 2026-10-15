// Fixed public diagnostics; never import UCI or accept executable arguments.
import { open, readfile, writefile, rename, unlink, stat, lstat, lsdir, mkdir } from 'fs';
const RUN = '/var/run/zapret2-home/profiles';
const PROC = '/proc';
const MAIN = '/var/run/zapret2-home';
const CATALOG = '/usr/lib/zapret2-home/profile-catalog.json';
const MAX_STATE = 131072;
const TARGETS = [
 { id:'gitlab', host:'gitlab.hotreload.net', ip:'65.108.59.85', path:'/assets/webpack/main.4e9cbf4e.chunk.js', bytes:1008147, sha256:'5053a171a0c992f64cc32266e635101af57d3df66509d0a0cb311a36d0fe3777' },
 { id:'unitask', host:'download.openupm.com', ip:'107.175.71.2', path:'/verdaccio/com.cysharp.unitask/com.cysharp.unitask-2.5.11.tgz', bytes:180175, sha256:'f502c3d1e56afee722c2707ba7370562446a6f3d4684a27afb74fd5817ab0a5b' },
 { id:'tavily', host:'app.tavily.com', ip:'52.85.154.99', path:'/_next/static/chunks/polyfills-42372ed130431b0a.js', bytes:112594, sha256:'0973c1d64c88adc8e3c950410cb58b288f72118d5965b78049438deb8f2f9683' },
 { id:'youtube', host:'i.ytimg.com', ip:'142.251.14.119', path:'/vi/dQw4w9WgXcQ/maxresdefault.jpg', bytes:65324, sha256:'263dedc00c8521ab388aa6385c36c28be9e02c8e7bb6f8edbe6240f5cdd9bdbd' },
 { id:'discord', host:'discord.com', ip:'162.159.136.232', path:'/assets/193433.6c7be9d5d6e8b51f.css', bytes:40369, sha256:'08e410da21d9ee31496ae6f55981de3b0232de0b23f5caa8d52a119e9b0ec170' }
];
function profiles() {
 let file=stat(CATALOG);
 if (!file || file.size>16384) fail('Missing or oversized shared profile catalog');
 let source;
 try { source=json(readfile(CATALOG)); } catch(e) { fail('Invalid shared profile catalog'); }
 let ids=['alt1','stock','overlap','fake','fake_split','fake_disorder'], result=[];
 if (type(source)!='array' || length(source)!=length(ids)) fail('Invalid shared profile catalog');
 for (let i=0; i<length(ids); i++) {
  let p=source[i];
  if (type(p)!='object' || p.id!=ids[i] || type(p.title)!='string' || length(p.title)>256 || type(p.strategy)!='string' || length(p.strategy)>2048 || index(['previously_verified','experimental'],p.evidence)<0 || type(p.args)!='array' || !length(p.args)) fail('Invalid shared profile catalog');
  push(result,{id:p.id,title:p.title,evidence:p.evidence,strategy:p.strategy});
 }
 return result;
}
// Cleanup and process identity must work even if the shared catalog is damaged.
const PROFILES = index(['catalog','status','validate','validate-protocol','protocols-catalog','plan','row'],ARGV[0])>=0?profiles():[];
const QUIC_TARGETS = [{id:'youtube_h3',host:'i.ytimg.com',ip:'142.251.1.119',path:'/vi/dQw4w9WgXcQ/maxresdefault.jpg',bytes:65324,sha256:'263dedc00c8521ab388aa6385c36c28be9e02c8e7bb6f8edbe6240f5cdd9bdbd'}];
const UDP_TARGETS = [{id:'stun_google',host:'stun.l.google.com',ip:'74.125.250.129',port:19302}];
const H3_REASON = 'Приватный диагностический curl HTTP3 недоступен или повреждён; тест QUIC недоступен. TCP не используется вместо QUIC.';
function protocol(p) { if (index(['tcp','quic','udp'],p)<0) fail('Invalid protocol'); return p; }
function targets(p) { return p=='tcp'?TARGETS:(p=='quic'?QUIC_TARGETS:UDP_TARGETS); }
function candidates(p) { return p=='tcp'?PROFILES:map(p=='quic'?['quic_google','quic_zero','quic_google_badsum','quic_google_ttl2','quic_zero_badsum','quic_zero_ttl2']:['udp_fake2','udp_fake6','udp_protocol_fake2','udp_badsum2','udp_ttl2','udp_protocol_badsum2'],id=>({id:id})); }
function emit(x) { print(sprintf('%J\n', x)); }
function fail(s) { emit({ok:false,error:s}); exit(1); }
function obj(path) {
 let file=stat(path); if (file && file.size>MAX_STATE) fail('State file bound exceeded');
 try { return json(readfile(path) || '{}'); } catch(e) { return {}; }
}
function strict_obj(path, optional) {
 let file=lstat(path);
 if (!file && optional) {
  let names=lsdir(RUN);
  if (type(names)=='array' && index(names,substr(path,length(RUN)+1))<0) return null;
 }
 if (!file || file.type!='file' || file.size>MAX_STATE) fail('Unsafe or oversized state file');
 let f=open(path,'r'), raw=f && f.read(MAX_STATE+1), value;
 if (f) f.close();
 if (!raw || length(raw)>MAX_STATE) fail('Unreadable or oversized state file');
 try { value=json(raw); } catch(e) { fail('Malformed state file'); }
 if (type(value)!='object') fail('Expected state object');
 return value;
}
function ownership(name) {
 let x=strict_obj(RUN+'/'+name,true);
 if (x==null) return null;
 if (type(x.pid)!='string' || !match(x.pid,/^[1-9][0-9]*$/) || type(x.ticks)!='string' || !match(x.ticks,/^[0-9]+$/)) fail('Invalid diagnostic ownership identity');
 if (name=='owner' && (type(x.job)!='string' || !match(x.job,/^[0-9]+\.[0-9]+$/) || index(['int','double'],type(x.started))<0 || !(x.started>=0) || ('protocol' in x && index(['tcp','quic','udp'],x.protocol)<0))) fail('Invalid diagnostic owner');
 return x;
}
function atomic(path, value) {
 let raw=sprintf('%J\n',value);
 if (length(raw)>MAX_STATE) fail('State file bound exceeded');
 if (!writefile(path+'.new',raw) || !rename(path+'.new',path)) fail('State write failed');
}
function ident(pid, parent) {
 if (!match(''+pid,/^[1-9][0-9]*$/)) return null;
 let raw=readfile(PROC+'/'+pid+'/stat') || '', at=rindex(raw,') ');
 if (at<0) return null;
 let fields=split(substr(raw,at+2),' ');
 if (!fields[19] || fields[0]=='Z' || (parent!=null && fields[1]!=''+parent)) return null;
 return {pid:''+pid,ticks:fields[19]};
}
function alive(x) {
 let now=x && ident(x.pid);
 return now && now.ticks==x.ticks;
}
function child_ended(pid, parent) {
 if (!match(''+pid,/^[1-9][0-9]*$/) || !match(''+parent,/^[1-9][0-9]*$/)) return false;
 let raw=readfile(PROC+'/'+pid+'/stat'), at=raw?rindex(raw,') '):-1;
 if (at>=0) {
  let fields=split(substr(raw,at+2),' ');
  return fields[0]=='Z' && fields[1]==''+parent && !!fields[19];
 }
 let names=lsdir(PROC);
 return type(names)=='array' && index(names,''+pid)<0;
}
function selection(x, catalog) {
 if (type(x)!='string' || length(x)>128 || !match(x,/^[a-z0-9_ ]+$/)) fail('Invalid selection');
 let words=filter(split(x,' '), w=>length(w)>0), result=[];
 if (!length(words)) fail('Empty selection');
 for (let w in words) if (!length(filter(catalog,c=>c.id==w))) fail('Unknown catalog ID');
 for (let c in catalog) if (index(words,c.id)>=0) push(result,c.id);
 return join(' ',result);
}
function catalog() { return {profiles:PROFILES,targets:TARGETS,limits:{repeat:2,queue:214,uid:1,ports:'12600-12659',max_rows:60,max_seconds:1350,max_state_bytes:MAX_STATE,max_bytes:2097152,rate_bytes:65536},apply_supported:true}; }
let cmd=ARGV[0], job=ARGV[1];
if (cmd=='catalog') { emit({ok:true,catalog:catalog()}); exit(0); }
if (cmd=='protocols-catalog') {
 let f=open('/dev/stdin','r'), raw=f && f.read(16385), source;
 if (!raw || length(raw)>16384) fail('Invalid protocol metadata');
 try { source=json(raw); } catch(e) { fail('Invalid protocol metadata'); }
 if (source.ok!=true || type(source.catalog?.groups)!='array' || length(source.catalog.groups)!=3) fail('Invalid protocol metadata');
 let groups=[];
 for (let p in ['tcp','quic','udp']) {
  let g=filter(source.catalog.groups,g=>g.id==p);
  if (length(g)!=1 || type(g[0].title)!='string' || type(g[0].description)!='string') fail('Invalid protocol metadata');
  g=g[0]; let list=p=='tcp'?PROFILES:g.profiles, expected=candidates(p), public=[];
  if (type(list)!='array' || length(list)!=length(expected)) fail('Invalid protocol metadata');
  for (let i=0;i<length(expected);i++) {
   let x=list[i];
   if (x.id!=expected[i].id || type(x.title)!='string' || type(x.strategy)!='string' || index(['experimental','previously_verified'],x.evidence)<0) fail('Invalid protocol metadata');
   push(public,{id:x.id,title:x.title,evidence:x.evidence,strategy:x.strategy});
  }
  let ts=map(targets(p),t=>({id:t.id,title:t.id=='youtube_h3'?'YouTube: изображение по HTTP/3':(t.id=='stun_google'?'Google STUN: Binding':(t.id=='youtube'?'YouTube: изображение':(t.id=='discord'?'Discord: CSS':t.id))),description:p=='udp'?'Только STUN Binding, не проверка голосового соединения Discord.':('Полный HTTPS-ресурс '+t.host+t.path)}));
  push(groups,{id:p,title:g.title,description:g.description,profiles:public,targets:ts,test_supported:p!='quic' || job=='HTTP3',test_unavailable_reason:p=='quic' && job!='HTTP3'?H3_REASON:''});
 }
 emit({ok:true,catalog:{groups:groups}}); exit(0);
}
if (cmd=='validate' || cmd=='validate-empty' || cmd=='validate-protocol') {
 let f=open('/dev/stdin','r'), raw=f && f.read(4097), x;
 if (cmd=='validate-empty' && !raw) exit(0);
 if (!raw || length(raw)>4096 || index(raw,'\u0000')>=0) fail('Invalid or oversized JSON');
 try { x=json(raw); } catch(e) { fail('Invalid JSON'); }
 if (type(x)!='object') fail('Expected object');
 let fields=cmd=='validate-empty'?['ubus_rpc_session']:['profiles','targets','repeat','ubus_rpc_session'];
 if (cmd=='validate-protocol') push(fields,'protocol');
 for (let k in x) if (index(fields,k)<0) fail('Unknown field');
 if (x.ubus_rpc_session!=null && (type(x.ubus_rpc_session)!='string' || length(x.ubus_rpc_session)!=32 || index(x.ubus_rpc_session,'\u0000')>=0 || !match(x.ubus_rpc_session,/^[a-f0-9]{32}$/))) fail('Invalid RPC session');
 // Null metadata is not a valid transport token either.
 if ('ubus_rpc_session' in x && x.ubus_rpc_session==null) fail('Invalid RPC session');
 if (cmd=='validate-empty') exit(0);
 if (type(x.repeat)!='int' || (x.repeat!=1 && x.repeat!=2)) fail('repeat must be 1 or 2');
 let p=cmd=='validate-protocol'?protocol(x.protocol):'tcp';
 if (p=='quic' && job!='HTTP3') fail(H3_REASON);
 print(selection(x.profiles,candidates(p))+'\n'+selection(x.targets,targets(p))+'\n'+x.repeat+'\n'+(cmd=='validate-protocol'?p+'\n':'')); exit(0);
}
if (cmd=='identity') { let x=ident(job,ARGV[2]); if (!x) exit(1); print(x.ticks+'\n'); exit(0); }
if (cmd=='child-ended') exit(child_ended(job,ARGV[2])?0:1);
if (cmd=='rules') {
 if (!match(job||'',/^[0-9]+\.[0-9]+$/)) fail('Invalid generation');
 let p=protocol(ARGV[2] || 'tcp'), transport=p=='tcp'?'tcp':'udp', port=p=='udp'?19302:443;
 let tuple='ip daddr @targets '+transport+' sport 12600-12659 '+transport+' dport '+port;
 print('create table inet zapret2_home_profiles { comment "z2profiles:'+job+'"; }\n'+'table inet zapret2_home_profiles {\n set targets { type ipv4_addr; elements = { '+join(', ',map(targets(p),t=>t.ip))+' } }\n chain mark_test { type route hook output priority -160; policy accept;\n  meta skuid 1 '+tuple+' ct mark set 0x5a1724 meta mark set 0x200000 counter\n  meta mark & 0x40000000 != 0 '+tuple+' meta mark set 0x200000 counter\n }\n chain queue_test { type filter hook output priority 0; policy accept;\n  meta skuid 1 '+tuple+' ct mark 0x5a1724 ct original packets <= 20 counter queue num 214 bypass\n }\n'+(p=='tcp'?' chain synack_test { type filter hook input priority 0; policy accept;\n  ip saddr @targets tcp sport 443 tcp dport 12600-12659 ct mark 0x5a1724 tcp flags & (syn | ack) == (syn | ack) counter queue num 214 bypass\n }\n':'')+'}\n'); exit(0);
}
if (cmd=='target') {
 let t=filter(targets(protocol(ARGV[2] || 'tcp')),t=>t.id==job)[0]; if (!t) exit(1);
 print(t.host+'\n'+t.ip+'\n'+(t.path?'https://'+t.host+t.path:'')+'\n'); exit(0);
}
if (cmd=='health') {
 let inputs={};
 for (let name in ['stat','loadavg','net/netfilter/nfnetlink_queue']) {
  let f=open(PROC+'/'+name,'r'), raw=f && f.read(MAX_STATE+1);
  if (f) f.close();
  if (type(raw)!='string' || length(raw)>MAX_STATE) fail('Cannot safely read health metadata: '+name);
  inputs[name]=raw;
 }
 // /proc/stat lists online CPUs, unlike the configured/possible CPU count.
 let cpus=0, seen={};
 for (let line in split(inputs.stat,'\n')) {
  if (!match(line,/^cpu/)) continue;
  if (!match(line,/^cpu(0|[1-9][0-9]*)?[ \t]+[0-9]+([ \t]+[0-9]+){3,9}[ \t]*$/)) fail('Invalid online CPU metadata');
  let name=split(trim(line),/[ \t]+/)[0];
  if (name=='cpu') continue;
  if (name in seen) fail('Duplicate online CPU metadata');
  seen[name]=true; cpus++;
 }
 if (!cpus) fail('Missing online CPU metadata');
 let raw=inputs.loadavg;
 if (length(raw)>256 || !match(raw,/^[0-9]+(\.[0-9]+)?[ \t]+[0-9]+(\.[0-9]+)?[ \t]+[0-9]+(\.[0-9]+)?[ \t]+[0-9]+\/[1-9][0-9]*[ \t]+[0-9]+\n?$/)) fail('Invalid load metadata');
 let load=+split(raw,/[ \t]+/)[0];
 if (!(load<=cpus)) {
  emit({ok:false,error:'Router load per online CPU above 1.0',load_1m:load,online_cpus:cpus,load_limit:cpus}); exit(2);
 }
 for (let line in split(inputs['net/netfilter/nfnetlink_queue'],'\n')) {
  line=trim(line); if (!length(line)) continue;
  if (!match(line,/^[0-9]+([ \t]+[0-9]+){8}$/)) fail('Invalid queue health metadata');
  let f=split(line,/[ \t]+/);
  if (f[0]=='214' && (+f[2]>64 || +f[5]>0 || +f[6]>0)) {
   emit({ok:false,error:'Isolated queue overloaded or dropping packets',queue:214,pending:+f[2],drops:+f[5],user_drops:+f[6]}); exit(3);
  }
 }
 exit(0);
}
if (cmd=='preflight') {
 for (let p in lsdir(PROC) || []) {
  if (!match(p,/^[0-9]+$/)) continue;
  if (match(readfile(PROC+'/'+p+'/status') || '',/\nUid:\s+1\s/)) fail('UID 1 already in use');
 }
 for (let line in split(readfile(PROC+'/net/netfilter/nfnetlink_queue')||'','\n')) {
  if (match(line,/^\s*214\s/)) fail('Queue 214 already in use');
 }
 let p=protocol(ARGV[2] || 'tcp');
 for (let name in p=='tcp'?['tcp','tcp6']:['udp','udp6']) {
  for (let line in split(readfile(PROC+'/net/'+name)||'','\n')) {
   let fields=filter(split(trim(line),' '),x=>length(x)>0), endpoint=split(fields[1]||'',':');
   let port=hex(endpoint[-1]);
   if (port>=12600 && port<=12659) fail('Reserved source port already in use');
  }
 }
 let rules=readfile(RUN+'/'+job+'/ruleset') || '';
 if (index(rules,'zapret2_home_profiles')>=0 || match(lc(rules),/0x0*5a1724|5904164/)) fail('Diagnostic scope conflict');
 for (let line in split(rules,'\n')) {
  // Quoted names/comments are not packet predicates.
  line=replace(line,/"([^"\\]|\\.)*"/g,'""');
  if (match(line,/(^|[[:space:]])queue([[:space:]]|$)/)) {
   let normalized=replace(line,/queue[[:space:]]+(flags[[:space:]]+(bypass|fanout)(,[[:space:]]*(bypass|fanout))?[[:space:]]+)?to[[:space:]]+/,'queue num ');
   let q=match(normalized,/queue num ([0-9]+)(-([0-9]+))?([[:space:]]+(bypass|fanout)){0,2}([[:space:]]+comment[[:space:]]+"")?[[:space:]]*$/);
   if (!q || +q[1]>+(q[3]||q[1]) || +(q[3]||q[1])>65535 || (+q[1]<=214 && +(q[3]||q[1])>=214)) fail('Diagnostic queue scope conflict');
  }
  for (let port in match(line,p=='tcp'?/(^|[[:space:]])(tcp|th)[[:space:]]+(sport|dport)[[:space:]]*(\{[^}]*\}|[^[:space:];]*)([[:space:]]+(\.|map|vmap))?/g:/(^|[[:space:]])(udp|th)[[:space:]]+(sport|dport)[[:space:]]*(\{[^}]*\}|[^[:space:];]*)([[:space:]]+(\.|map|vmap))?/g) || []) {
   let value=port[4];
   if (port[5]) fail('Diagnostic port scope conflict');
   if (substr(value,0,1)=='{') value=substr(value,1,length(value)-2);
   for (let token in split(value,',')) {
    token=trim(token);
    if (!match(token,/^[0-9]+(-[0-9]+)?$/)) fail('Diagnostic port scope conflict');
    let range=split(token,'-'), low=+range[0], high=+(range[1]||range[0]);
    if (low>high || high>65535 || (low<=12659 && high>=12600)) fail('Diagnostic port scope conflict');
   }
  }
 }
 exit(0);
}
if (!stat(RUN)) {
 if (cmd=='status' || cmd=='protocols-status') {
  let s={state:'idle',running:false,job_id:'',error:'',protocol:'tcp',results:[]};
  emit(cmd=='status'?{ok:true,catalog:catalog(),data:s}:{ok:true,data:s}); exit(0);
 }
 fail('Missing protected runtime directory');
}
let guard=open(RUN+'/guard','a');
if (!guard || !guard.lock('x')) fail('Cannot lock diagnostics');
let owner=ownership('owner') || {}, finishing=ownership('finishing');
if (cmd=='acquire') {
 if (trim(readfile(MAIN+'/control.lock/pid') || '')!=job || !ident(job)) fail('Main control guard required');
 if (stat(MAIN+'/configure.job')) {
  let id=trim(readfile(MAIN+'/configure.job') || '');
  if (!match(id,/^[1-9][0-9]*$/)) fail('Configure recovery required');
  let result=obj(MAIN+'/configure-job.'+id+'/result');
  if (type(result.ok)!='bool' || (result.ok==false && result.rolled_back!=true)) fail('Configure pending or recovery required');
 }
 if (owner.job || alive(finishing)) fail('Diagnostic busy or cleanup required');
 unlink(RUN+'/finishing');
 let me=ident(job); if (!me) fail('Launcher disappeared');
 me.job=me.pid+'.'+me.ticks; me.started=+(split(readfile(PROC+'/uptime') || '0',' ')[0]); me.protocol=protocol(ARGV[2] || 'tcp');
 if (!mkdir(RUN+'/'+me.job,0700)) fail('Cannot create job');
 unlink(RUN+'/ack'); atomic(RUN+'/owner',me); print(me.job+'\n'); exit(0);
}
if (cmd=='status' || cmd=='protocols-status') {
 let s=obj(RUN+'/result'), legacy=!('protocol' in s);
 if (!s.state) s={state:'idle',results:[]};
 if (owner.job && s.job_id!=owner.job) s={state:'pending',job_id:owner.job,protocol:owner.protocol || 'tcp',results:[]};
 s.running=!!owner.job || !!alive(finishing);
 s.protocol=owner.protocol || s.protocol || 'tcp'; s.job_id=s.job_id || ''; s.error=s.error || '';
 // Pre-protocol TCP history has no protocol tags; normalize only that legacy shape, without rewriting evidence.
 if (legacy && s.protocol=='tcp') {
  for (let row in (s.results || [])) if (type(row)=='object' && !('protocol' in row)) row.protocol='tcp';
  if (type(s.plan)=='object' && !('protocol' in s.plan)) s.plan.protocol='tcp';
 }
 // The worker stores shell selections as strings; the RPC plan exposes arrays without rewriting history.
 if (type(s.plan)=='object') for (let key in ['profiles','targets']) if (type(s.plan[key])=='string') s.plan[key]=filter(split(s.plan[key],' '), value=>length(value)>0);
 if (owner.job && s.state!='error' && !alive(owner) && !alive(obj(RUN+'/'+owner.job+'/watchdog'))) { s.state='error'; s.error='Worker lost; cleanup required'; }
 if (cmd=='status' && s.protocol!='tcp') s={state:s.running?'running':'idle',job_id:s.running?(owner.job || s.job_id):'',running:s.running,error:'',results:[]};
 emit(cmd=='status'?{ok:true,catalog:catalog(),data:s}:{ok:true,data:s}); exit(0);
}
if (!job || owner.job!=job) exit(1);
let base=RUN+'/'+job;
if (cmd=='handoff') {
 if (owner.pid!=ARGV[3] || !alive(owner)) exit(1);
 let me=ident(ARGV[2]); if (!me) exit(1); me.job=job; me.started=owner.started; me.protocol=owner.protocol || 'tcp'; atomic(RUN+'/owner',me); exit(0);
}
if (cmd=='owner-alive') exit(alive(owner)?0:1);
if (cmd=='deadline') exit((+(split(readfile(PROC+'/uptime') || '999999999',' ')[0])-owner.started)<1350?0:1);
if (cmd=='owner-pid') { if (!alive(owner)) exit(1); print(owner.pid+'\n'); exit(0); }
if (cmd=='cleanup-claim') {
 if (alive(owner.cleaner)) exit(1);
 let me=ident(ARGV[2]); if (!me) exit(1);
 owner.cleaner=me; atomic(RUN+'/owner',owner); exit(0);
}
if (cmd=='has-table' || cmd=='table-owned') {
 let objects=strict_obj(base+'/table.json',false).nftables;
 if (type(objects)!='array') fail('Invalid nftables probe');
 for (let o in objects) {
  if (o.table?.family=='inet' && o.table.name=='zapret2_home_profiles') {
   if (cmd=='has-table') exit(0);
   exit(o.table.comment=='z2profiles:'+job?0:1);
  }
 }
 exit(cmd=='has-table'?3:1);
}
if (cmd=='is-owner') exit(owner.pid==ARGV[2] && alive(owner)?0:1);
if (cmd=='remember') {
 let name=ARGV[2], me=ident(ARGV[3]);
 if (index(['watchdog','worker-sleep','watchdog-sleep','engine','curl'],name)<0) exit(1);
 // Unknown identity is not proof of exit; the spawning shell must prove/reap completion.
 if (!me) exit(1);
 atomic(base+'/'+name,me); exit(0);
}
if (cmd=='child-alive' || cmd=='child-pid') {
 let x=obj(base+'/'+ARGV[2]); if (!alive(x)) exit(1);
 if (cmd=='child-pid') print(x.pid+'\n'); exit(0);
}
if (cmd=='health-error') {
 let source=ARGV[2], rc=ARGV[3], raw=ARGV[4] || '', details;
 if (index(['watchdog','worker'],source)<0 || index(['1','2','3'],rc)<0 || length(raw)>4096) fail('Invalid health failure');
 try { details=json(raw); } catch (e) { details=null; }
 if (type(details)!='object' || details.ok!=false || type(details.error)!='string') {
  rc='1'; details={ok:false,error:'Health probe returned no valid resource snapshot'};
 }
 let s=obj(RUN+'/result');
 if (s.job_id!=job) s={job_id:job,protocol:owner.protocol || 'tcp',results:[]};
 if (s.state=='error' && s.guard_failure) exit(0);
 s.state='error'; s.error=rc=='2'?'Превышен лимит нагрузки на процессор':(rc=='3'?'Очередь 214 переполнена или теряет пакеты':'Не удалось безопасно проверить нагрузку и очередь');
 s.guard_failure={source:source,exit_code:+rc,details:details}; atomic(RUN+'/result',s); exit(0);
}
if (cmd=='state' || cmd=='interrupted') {
 let s=obj(RUN+'/result');
 if (s.job_id!=job) s={job_id:job,protocol:owner.protocol || 'tcp',results:[]};
 if (cmd=='interrupted' && s.state!='pending' && s.state!='running') exit(0);
 s.state=ARGV[2]; s.error=ARGV[3] || ''; atomic(RUN+'/result',s); exit(0);
}
if (cmd=='plan') {
 let p=protocol(ARGV[2]); if (p!=(owner.protocol || 'tcp') || index(['1','2'],ARGV[5])<0) fail('Invalid plan');
 let plan={protocol:p,profiles:selection(ARGV[3],candidates(p)),targets:selection(ARGV[4],targets(p)),repeat:+ARGV[5]};
 atomic(RUN+'/result',{state:'pending',job_id:job,protocol:p,error:'',results:[],plan:plan}); exit(0);
}
if (cmd=='row') {
 let s=obj(RUN+'/result'), m=obj(base+'/metrics'), p=protocol(owner.protocol || 'tcp'), t=filter(targets(p),t=>t.id==ARGV[3])[0];
 let rc=+ARGV[5], bytes=+ARGV[7], port=+ARGV[8], hash=ARGV[6];
 if (s.job_id!=job || !t || !length(filter(candidates(p),p=>p.id==ARGV[2])) || index(['1','2'],ARGV[4])<0 || !match(hash,/^[a-f0-9]{64}$/) || !match(ARGV[5],/^[0-9]+$/) || !match(ARGV[7],/^[0-9]+$/) || bytes>2097152 || port!=12600+length(s.results || []) || port>12659) fail('Invalid result row');
 if (length(filter(s.results || [],r=>r.profile==ARGV[2] && r.target==t.id && r.repeat==+ARGV[4]))) fail('Duplicate result row');
 let route=m.local_ip=='192.0.2.2' && m.remote_ip==t.ip && +m.local_port==port;
 let tls=m.ssl_verify_result!=null && +m.ssl_verify_result==0 && +m.time_appconnect>0;
 let full=rc==0 && tls && +m.http_code==200 && bytes==t.bytes && hash==t.sha256 && route && (p!='quic' || m.http_version=='3');
 let row={profile:ARGV[2],target:t.id,repeat:+ARGV[4],exit:rc,status:+m.http_code||0,bytes:bytes,expected_bytes:t.bytes,sha256:hash,expected_sha256:t.sha256,hash_match:hash==t.sha256,full_match:full,tls_verified:tls,ssl_verify_result:m.ssl_verify_result,time_connect:+m.time_connect||0,time_tls:+m.time_appconnect||0,time_total:+m.time_total||0,remote_ip:m.remote_ip||'',local_ip:m.local_ip||'',source_port:+m.local_port||0,expected_source_port:port,route_verified:route,http_version:m.http_version||'',failure:full?'':(!(+m.time_connect)?'connect_or_setup':(!tls?'tls':(!route?'route':(+m.http_code!=200?'http':'body'))))};
 if (p=='quic' && !full && m.http_version!='3' && rc==0) row.failure='http3_required';
 if (p=='udp') {
  route=route && +m.remote_port==t.port && m.mapped_ip=='192.0.2.2' && +m.mapped_port==port;
  full=rc==0 && m.binding_success==true && type(m.binding_success)=='bool' && route;
  row={profile:ARGV[2],target:t.id,repeat:+ARGV[4],exit:rc,binding_success:m.binding_success==true && type(m.binding_success)=='bool',full_match:full,route_verified:route,remote_ip:m.remote_ip||'',remote_port:+m.remote_port||0,local_ip:m.local_ip||'',source_port:+m.local_port||0,expected_source_port:port,mapped_ip:m.mapped_ip||'',mapped_port:+m.mapped_port||0,time_total:+m.time_total||0,ignored_transactions:+m.ignored_transactions||0,failure:full?'':(m.binding_success==true && !route?'route':(m.failure || 'stun'))};
 }
 row.protocol=p;
 if (!s.results || length(s.results)>=60) fail('Result bound exceeded');
 push(s.results,row); atomic(RUN+'/result',s);
 // Failed TLS setup may erase curl's entire socket tuple; absence is not an observed wrong route.
 let early_no_tuple=p!='udp' && rc>0 && bytes==0 && !(+m.http_code) && !(+m.time_appconnect) && !length(m.local_ip || '') && !length(m.remote_ip || '') && +m.local_port<=0;
 // A replying wrong tuple is an isolation failure, not a failed candidate.
 exit(((p=='udp'?m.binding_success==true:+m.time_connect>0) && !route && !early_no_tuple)?2:0);
}
if (cmd=='release') {
 if (!(ARGV[2]==owner.pid && alive(owner)) && !(ARGV[2]==obj(base+'/watchdog').pid && alive(obj(base+'/watchdog')))) exit(1);
 let watcher=obj(base+'/watchdog');
 if (alive(watcher)) atomic(RUN+'/finishing',watcher);
 unlink(RUN+'/owner'); exit(0);
}
exit(1);
