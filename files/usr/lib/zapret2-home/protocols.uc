import { readfile } from 'fs';
const LIB='/usr/lib/zapret2-home';
function fail(s) { warn(s+'\n'); exit(1); }
const IDS={tcp:['alt1','stock','overlap','fake','fake_split','fake_disorder'],quic:['quic_google','quic_zero','quic_google_badsum','quic_google_ttl2','quic_zero_badsum','quic_zero_ttl2'],udp:['udp_fake2','udp_fake6','udp_protocol_fake2','udp_badsum2','udp_ttl2','udp_protocol_badsum2']};
function profile(protocol,id) {
 if(index(IDS[protocol] || [],id)<0) fail('Unknown protocol/profile');
 if(protocol!='tcp') return id;
 let p=filter(json(readfile(LIB+'/profile-catalog.json')),p=>p.id==id);
 if(length(p)!=1 || type(p[0].args)!='array' || !length(p[0].args) || length(p[0].args)>3) fail('Invalid TCP catalog');
 for(let a in p[0].args) if(type(a)!='string' || index(a,'\u0000')>=0 || index(a,'\n')>=0 || index(a,'\r')>=0 || !match(a,/^--lua-desync=[A-Za-z0-9_:.,=+-]+$/)) fail('Invalid TCP argument');
 return p[0];
}
function branch(protocol,id) {
 let p=profile(protocol,id), a=[];
 if(protocol=='tcp') a=['--filter-tcp=443','--filter-l7=tls','--in-range=x',id=='fake_split'?'--out-range=-n20':'--out-range=-n6','--payload=tls_client_hello',...p.args];
 else {
  let suffix=index(id,'badsum')>=0?':badsum':(index(id,'ttl2')>=0?':ip_ttl=2':'');
  if(protocol=='quic') a=['--filter-udp=443','--filter-l7=quic','--in-range=x','--out-range=-n6','--payload=quic_initial','--lua-desync=fake:blob='+(index(id,'quic_google')==0?'quic_google':'fake_default_quic')+':repeats=6'+suffix];
  else {
   a=['--filter-udp=19294-19344,50000-50100','--filter-l7=discord,stun','--in-range=x','--out-range=-n6'];
   if(index(['udp_protocol_fake2','udp_protocol_badsum2'],id)>=0) push(a,'--payload=discord_ip_discovery','--lua-desync=fake:blob=discord_discovery:repeats=2'+suffix,'--payload=stun','--lua-desync=fake:blob=stun_binding:repeats=2'+suffix);
   else push(a,'--payload=discord_ip_discovery,stun','--lua-desync=fake:blob=0x00000000000000000000000000000000:repeats='+(id=='udp_fake6'?'6':'2')+suffix);
  }
 }
 return a;
}
function argv(queue,mode,branches) {
 if(index(['213','214'],queue)<0 || index(['run','dry-run'],mode)<0) fail('Invalid queue/mode');
 let diagnostic_quic=queue=='214' && length(filter(branches,b=>b[0]=='quic'));
 let a=[LIB+(diagnostic_quic?'/nfqws2-quic':'/nfqws2')]; if(mode=='dry-run') push(a,'--dry-run');
 if(diagnostic_quic) push(a,'--reasm-disable=quic_initial');
 push(a,'--qnum='+queue,'--lua-init=@'+LIB+'/lua/zapret-lib.lua','--lua-init=@'+LIB+'/lua/zapret-antidpi.lua','--lua-init=@'+LIB+'/lua/hostfakesplit-alt1.lua');
 if(length(filter(branches,b=>b[0]=='quic' && index(['quic_google','quic_google_badsum','quic_google_ttl2'],b[1])>=0))) push(a,'--blob=quic_google:@'+LIB+'/fake/quic-google.bin');
 if(length(filter(branches,b=>b[0]=='udp' && index(['udp_protocol_fake2','udp_protocol_badsum2'],b[1])>=0))) push(a,'--blob=discord_discovery:@'+LIB+'/fake/discord-ip-discovery-without-port.bin','--blob=stun_binding:@'+LIB+'/fake/stun.bin');
 if(!length(branches)) fail('All protocols disabled; use global Stop instead');
 for(let i=0;i<length(branches);i++) { if(i) push(a,'--new'); for(let v in branch(...branches[i])) push(a,v); }
 return a;
}
function mainargs(values,queue,mode) {
 if(length(values)!=6) fail('Invalid branch count');
 let branches=[], groups=['tcp','quic','udp'];
 for(let i=0;i<3;i++) {
  let enabled=values[i*2], id=values[i*2+1];
  if(index(['0','1'],enabled)<0) fail('Invalid saved protocol boolean');
  profile(groups[i],id);
  if(enabled=='1') push(branches,[groups[i],id]);
 }
 return argv(queue,mode,branches);
}
let command=shift(ARGV), a;
if(command=='catalog' && !length(ARGV)) {
 let tcp=json(readfile(LIB+'/profile-catalog.json'));
 let groups=[{id:'tcp',title:'TCP / HTTPS',description:'IPv4 TCP/443 TLS profiles.',profiles:map(tcp,p=>({id:p.id,title:p.title,evidence:p.evidence,strategy:p.strategy}))},...json(readfile(LIB+'/protocol-catalog.json'))];
 for(let g in groups) { g.targets=[]; g.test_supported=false; g.test_unavailable_reason=''; }
 print(sprintf('%J\n',{ok:true,catalog:{groups:groups}})); exit(0);
}
if(command=='argv' && length(ARGV)==4) a=argv(ARGV[0],ARGV[2],[[ARGV[3],ARGV[1]]]);
else if(command=='main-argv' && length(ARGV)==8) a=mainargs(slice(ARGV,2),ARGV[0],ARGV[1]);
else if(command=='main-match' && length(ARGV)==8) {
 a=mainargs(slice(ARGV,2),'213','run');
 if(!match(ARGV[0],/^[1-9][0-9]*$/)) fail('Invalid engine PID');
 let actual=split(readfile('/proc/'+ARGV[0]+'/cmdline') || '','\u0000'); pop(actual);
 // The deployed legacy TCP-only alt1 omitted the explicit default incoming range.
 if(ARGV[1]=='legacy' && ARGV[2]=='1' && ARGV[3]=='alt1' && ARGV[4]=='0' && ARGV[6]=='0' && index(actual,'--in-range=x')<0) splice(a,index(a,'--in-range=x'),1);
 exit(join('\u0000',a)==join('\u0000',actual)?0:1);
}
else fail('Invalid fixed helper operation');
print(join('\n',a)+'\n');
