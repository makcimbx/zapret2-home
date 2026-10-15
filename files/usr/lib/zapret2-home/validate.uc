import { open, readfile } from 'fs';
function fail(s) { print(sprintf('%J\n', { ok:false,error:s })); exit(1); }
let input=open('/dev/stdin','r'), raw=input && input.read(4097);
if (!raw || length(raw)>4096 || index(raw,'\u0000')>=0) fail('Некорректный размер запроса');
let x; try { x=json(raw); } catch(e) { fail('Некорректный JSON'); }
if (type(x)!='object') fail('Ожидается объект');
// rpcd/uhttpd forwards its authenticated session metadata along with method
// arguments. It is not a setting and must never be written to UCI or echoed.
// Authentication/ACL checks remain rpcd's responsibility, not this validator's.
let apply=ARGV[0]=='profile', protocol=ARGV[0]=='protocol';
const IDS={tcp:['alt1','stock','overlap','fake','fake_split','fake_disorder'],quic:['quic_google','quic_zero','quic_google_badsum','quic_google_ttl2','quic_zero_badsum','quic_zero_ttl2'],udp:['udp_fake2','udp_fake6','udp_protocol_fake2','udp_badsum2','udp_ttl2','udp_protocol_badsum2']};
for (let k in x) if (index(protocol?['protocol','enabled','profile','ubus_rpc_session']:apply?['profile','ubus_rpc_session']:['clients','destinations','autostart','client_mode','lists','auto_update','profile','tcp_enabled','quic_enabled','quic_profile','udp_enabled','udp_profile','ubus_rpc_session'],k)<0) fail('Неизвестное поле: '+k);
if ('ubus_rpc_session' in x && (type(x.ubus_rpc_session)!='string' || length(x.ubus_rpc_session)!=32 || index(x.ubus_rpc_session,'\u0000')>=0 || !match(x.ubus_rpc_session,/^[0-9a-f]{32}$/))) fail('Некорректные служебные данные RPC');
if (protocol) {
 if(type(x.protocol)!='string' || index(['tcp','quic','udp'],x.protocol)<0 || type(x.enabled)!='bool' || type(x.profile)!='string' || index(IDS[x.protocol],x.profile)<0) fail('Некорректный протокол, enabled или профиль');
 print(sprintf('%J\n',{ok:true,protocol:x.protocol,enabled:x.enabled,profile:x.profile})); exit(0);
}
for(let group in ['tcp','quic','udp']) {
 let key=group+'_enabled', pkey=group=='tcp'?'profile':group+'_profile';
 if(key in x && type(x[key])!='bool') fail(key+' должен быть boolean');
 if(pkey in x && (type(x[pkey])!='string' || index(IDS[group],x[pkey])<0)) fail('Неизвестный профиль '+group);
}
if (apply || 'profile' in x) {
 let catalog; try { catalog=json(readfile('/usr/lib/zapret2-home/profile-catalog.json')); } catch(e) { fail('Каталог профилей недоступен'); }
 if(type(x.profile)!='string' || index(x.profile,'\u0000')>=0 || index(['alt1','stock','overlap','fake','fake_split','fake_disorder'],x.profile)<0 || length(filter(catalog,p=>p.id==x.profile))!=1) fail('Неизвестный профиль');
}
if(apply) { print(sprintf('%J\n',{ok:true,profile:x.profile})); exit(0); }
let mode=x.client_mode ?? 'selected', selected=x.lists ?? '', auto=x.auto_update ?? false;
if(index(['selected','all'],mode)<0) fail('Некорректный режим клиентов');
if(type(selected)!='string' || type(auto)!='bool') fail('Некорректные настройки списков');
let lists=[];
for(let id in split(trim(selected), /[[:space:]]+/)) {
 if(!length(id)) continue;
 if(index(['flowseal','cloudflare','hetzner','cloudfront','ovh','digitalocean'],id)<0) fail('Неизвестный список');
 if(index(lists,id)<0) push(lists,id);
}
function nets(s, maxn, clients, empty) {
 if(type(s)!='string') fail('Область обработки должна быть строкой');
 if(!length(trim(s))) { if(empty) return ''; fail('Область обработки не может быть пустой'); }
 let out=[];
 for (let n in split(trim(s), /[[:space:],]+/)) {
  let m=match(n,/^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})(\/([0-9]{1,2}))?$/);
  if (!m) fail('Только IPv4/CIDR: '+n);
  let a=[];
  for (let i=1;i<=4;i++) { let v=int(m[i]); if(v>255 || (length(m[i])>1 && substr(m[i],0,1)=='0')) fail('Некорректный IPv4: '+n); push(a,v); }
  let p=m[6]==null?32:int(m[6]);
  if(p>32 || p<(clients?24:16)) fail('Префикс клиента должен быть 24–32, назначения 16–32');
  let ip=((a[0]*256+a[1])*256+a[2])*256+a[3], block=1;
  for(let i=p;i<32;i++) block*=2;
  if(ip%block) fail('В CIDR должны быть нулевые биты адреса сети: '+n);
  if(clients) {
   if(!(a[0]==10 || (a[0]==172 && a[1]>=16 && a[1]<=31) || (a[0]==192 && a[1]==168))) fail('Клиенты должны быть из частной IPv4-сети');
  } else {
   if(a[0]==0 || a[0]==10 || a[0]==127 || a[0]>=224 || (a[0]==100 && a[1]>=64 && a[1]<=127) || (a[0]==169 && a[1]==254) || (a[0]==172 && a[1]>=16 && a[1]<=31) || (a[0]==192 && a[1]==168) || (a[0]==198 && (a[1]==18 || a[1]==19))) fail('Назначение должно быть публичным IPv4');
  }
  if(index(out,n)<0) push(out,n);
 }
 if(length(out)>maxn) fail('Слишком много сетей');
 return join(' ',out);
}
if(type(x.autostart)!='bool') fail('autostart должен быть boolean');
let c=nets(x.clients,16,true,mode=='all'),d=nets(x.destinations,64,false,length(lists)>0);
let result={ok:true,clients:c,destinations:d,autostart:x.autostart,client_mode:mode,lists:join(' ',lists),auto_update:auto};
for(let key in ['profile','tcp_enabled','quic_enabled','quic_profile','udp_enabled','udp_profile']) if(key in x) result[key]=x[key];
if('tcp_enabled' in x && 'quic_enabled' in x && 'udp_enabled' in x && !x.tcp_enabled && !x.quic_enabled && !x.udp_enabled) fail('Нельзя отключить все протоколы; используйте общую кнопку Stop (Остановить)');
print(sprintf('%J\n',result));
