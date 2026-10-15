// Internal fixed admission protocol. Never unlink the guard inode, even on removal.
import { open, readfile, writefile, stat, mkdir, rmdir, unlink, lsdir, rename, readlink } from 'fs';
const RUN='/var/run/zapret2-home';
let mode=ARGV[0], name=ARGV[1], me=ARGV[2], parent=ARGV[3], parent_ticks=ARGV[4];
function fail(s) { warn(s+'\n'); exit(1); }
function ident(pid) {
 if (!match(''+pid,/^[1-9][0-9]*$/)) return null;
 let raw=readfile('/proc/'+pid+'/stat') || '', at=rindex(raw,') '), f=split(substr(raw,at+2),' ');
 return at>=0 && f[0]!='Z' && f[19] ? {pid:''+pid,ticks:f[19],ppid:f[1]} : null;
}
function alive(x) { let p=x && ident(x.pid); return p && p.ticks==x.ticks; }
// Never accept a caller-supplied PID as proof of ownership.
let caller=ident(readlink('/proc/self'));
let original_me=ident(me);
if(!caller || caller.ppid!=me || !original_me) fail('Admission caller PID mismatch');
function obj(path) {
 let f=open(path,'r'), raw=f && f.read(131073), x;
 if (!raw || length(raw)>131072 || index(raw,'\u0000')>=0) fail('Unreadable admission state');
 try { x=json(raw); } catch(e) { fail('Invalid admission state'); }
 if (type(x)!='object') fail('Invalid admission state'); return x;
}
function atomic(path,x) {
 if (!writefile(path+'.new',sprintf('%J\n',x)) || !rename(path+'.new',path)) fail('Admission write failed');
}
function package_owner(pid) {
 for(let i=0;i<32;i++) {
  let p=ident(pid); if(!p) break;
  let args=split(readfile('/proc/'+pid+'/cmdline') || '', '\u0000');
  if (match(args[0] || '',/(^|\/)opkg$/)) return p;
  if(p.ppid==pid || p.ppid=='0') break; pid=p.ppid;
 }
 fail('Package owner must be an opkg ancestor');
}
if (!mkdir(RUN,0700) && !stat(RUN)) fail('Missing runtime');
let guard=open(RUN+'/admission.guard','a');
if (!guard || !guard.lock('x')) fail('Cannot lock admission');
// Waiting may orphan this helper or permit reuse of its parent's PID.
let guarded_caller=ident(readlink('/proc/self'));
if(!guarded_caller || guarded_caller.pid!=caller.pid || guarded_caller.ticks!=caller.ticks ||
   guarded_caller.ppid!=me || !alive(original_me)) fail('Admission caller identity changed while waiting');
let gate=stat(RUN+'/lifecycle.json') ? obj(RUN+'/lifecycle.json') : null;
if(gate && (type(gate.token)!='string' || length(gate.token)!=36 || index(gate.token,'\u0000')>=0 || !match(gate.token,/^[a-f0-9-]{36}$/) ||
 type(gate.owner)!='object' || !match(gate.owner.pid || '',/^[1-9][0-9]*$/) || !match(gate.owner.ticks || '',/^[0-9]+$/) || index(['installer','package'],gate.kind)<0)) fail('Invalid lifecycle ownership; manual recovery required');
let token=getenv('Z2_LIFECYCLE_TOKEN') || '';
function descendant(pid,owner) {
 for(let i=0;i<32;i++) {
  let p=ident(pid); if(!p) return false;
  if(p.pid==owner.pid) return p.ticks==owner.ticks;
  if(p.ppid==pid || p.ppid=='0') return false; pid=p.ppid;
 }
 return false;
}
let authenticated=gate && token && token==gate.token && alive(gate.owner);
let authorized=authenticated && descendant(me,gate.owner);
let restore_worker=authenticated && gate.worker && alive(gate.worker) && descendant(me,gate.worker);
if (mode=='abi') { print('1\n'); exit(0); }
if(mode=='restore-begin') {
 if(!authorized || me!=gate.owner.pid || gate.kind!='installer' || gate.restore) fail('Not lifecycle restore owner');
 gate.restore=true; atomic(RUN+'/lifecycle.json',gate); exit(0);
}
if(mode=='restore-context') {
 if(!authorized || gate.kind!='installer' || gate.restore!=true || gate.worker) fail('Not lifecycle restore caller');
 print(token+'\n'); exit(0);
}
if(mode=='shutdown' || mode=='restore-check') {
 if(gate && !authorized) fail('Package lifecycle frozen');
 if(mode=='restore-check' && (!gate || gate.restore!=true)) fail('No lifecycle restore');
 exit(0);
}
if(mode=='worker-acquire') {
 let self=original_me;
 if(!self) fail('Worker disappeared');
 if(gate) {
  // procd does not inherit the installer's environment; init sets this one-use grant explicitly.
  if(!authenticated || gate.kind!='installer' || gate.restore!=true || gate.worker ||
     self.ppid!='1' || readlink('/proc/'+self.ppid+'/exe')!='/sbin/procd') fail('Not lifecycle procd worker');
 }
 if(!stat(RUN+'/requested') || stat(RUN+'/stopping')) fail('Worker not requested');
 let wg=open(RUN+'/worker.guard','a'); if(!wg || !wg.lock('x')) fail('Cannot lock worker');
 let old=trim(readfile(RUN+'/worker.pid') || ''), argv=split(readfile('/proc/'+old+'/cmdline') || '', '\u0000');
 if(ident(old) && index(argv,'/usr/libexec/zapret2-home-worker')>=0) fail('Worker already alive');
 unlink(RUN+'/worker.pid');
 if(stat(RUN+'/worker.lock') && !rmdir(RUN+'/worker.lock')) fail('Cannot reap worker');
 if(!mkdir(RUN+'/worker.lock',0700) || !writefile(RUN+'/worker.pid',me+'\n')) fail('Cannot acquire worker');
 if(gate) { gate.worker=self; atomic(RUN+'/lifecycle.json',gate); }
 exit(0);
}
if (mode=='freeze' || mode=='package-freeze' || mode=='recover') {
 let owner=mode=='package-freeze' ? package_owner(me) : original_me;
 if(!owner) fail('Lifecycle owner disappeared');
 if(mode=='recover') {
  if(!gate || !token || token!=gate.token || alive(gate.owner)) fail('Recovery requires dead owner and exact retained token');
  gate=null; // Keep the old on-disk freeze until all idle/recovery preconditions pass.
 }
 if(gate) {
  if((mode=='freeze' && authorized && gate.owner.pid==owner.pid && gate.owner.ticks==owner.ticks) ||
     (mode=='package-freeze' && (authorized || (gate.kind=='package' && alive(gate.owner) && gate.owner.pid==owner.pid && gate.owner.ticks==owner.ticks)))) {
   print(gate.token+'\n'); exit(0);
  }
  fail('Lifecycle frozen; retained explicit recovery required');
 }
 for(let n in ['control','rules','list-update','shutdown','service']) if(stat(RUN+'/'+n+'.lock')) fail('Mutation lock present');
 for(let n in lsdir(RUN) || []) if(match(n,/^configure\.[0-9]+$/)) fail('Configure backup retained');
 if(stat(RUN+'/configure.job')) {
  let id=trim(readfile(RUN+'/configure.job') || '');
  if(!match(id,/^[1-9][0-9]*$/)) fail('Invalid configure marker');
  let r=obj(RUN+'/configure-job.'+id+'/result');
  if(type(r.ok)!='bool' || r.recovery_required || (!r.ok && r.rolled_back!=true)) fail('Configure pending or recovery required');
 }
 // Same order as diagnostic acquisition: admission guard, then diagnostics guard.
 if(stat(RUN+'/profiles')) {
  let dg=open(RUN+'/profiles/guard','a'); if(!dg || !dg.lock('x')) fail('Cannot lock diagnostics');
  if(stat(RUN+'/profiles/owner')) fail('Diagnostic active or cleanup required');
  if(stat(RUN+'/profiles/finishing')) {
   let f=obj(RUN+'/profiles/finishing');
   if(!match(f.pid || '',/^[1-9][0-9]*$/) || !match(f.ticks || '',/^[0-9]+$/)) fail('Invalid diagnostic finisher');
   if(alive(f)) fail('Diagnostic finishing');
  }
  if(stat(RUN+'/profiles/result') && index(['idle','results','error'],obj(RUN+'/profiles/result').state)<0) fail('Diagnostic state incomplete');
 }
 let uuid=trim(readfile('/proc/sys/kernel/random/uuid') || '');
 if(!match(uuid,/^[a-f0-9-]{36}$/)) fail('Cannot generate lifecycle token');
 gate={token:uuid,owner:owner,kind:mode=='package-freeze'?'package':'installer'};
 atomic(RUN+'/lifecycle.json',gate); print(uuid+'\n'); exit(0);
}
if(mode=='finish' || mode=='package-finish') {
 if(!gate) exit(mode=='package-finish'?0:1);
 if(mode=='package-finish') {
  let owner=package_owner(me);
  // An installer owns its freeze until its own readback/restore is complete.
  if(authorized && gate.kind=='installer') exit(0);
  if(gate.kind!='package' || !alive(gate.owner) || owner.pid!=gate.owner.pid || owner.ticks!=gate.owner.ticks) fail('Not lifecycle package owner');
 } else if(!authorized || me!=gate.owner.pid || !alive(gate.owner)) fail('Not lifecycle owner/token');
 if(!unlink(RUN+'/lifecycle.json')) fail('Cannot finish lifecycle'); exit(0);
}
if(index(['acquire','release','handoff','reap'],mode)<0 || index(['control','rules','list-update','shutdown','service'],name)<0 || !alive(original_me)) fail('Invalid internal lock command');
let path=RUN+'/'+name+'.lock', owner=trim(readfile(path+'/pid') || ''), ticks=trim(readfile(path+'/ticks') || ''), current=ident(owner);
let live=current && (!ticks || ticks==current.ticks);
if(stat(path) && !match(owner,/^[1-9][0-9]*$/)) fail('Invalid lock owner; recovery required');
if(mode=='release') {
 let self=original_me;
 if(owner==me && ticks==self.ticks) { unlink(path+'/pid'); unlink(path+'/ticks'); if(!rmdir(path)) fail('Cannot release lock'); }
 exit(0);
}
if(mode=='handoff') {
 if(gate || owner!=parent || !live || !ticks || !parent_ticks || ticks!=parent_ticks) fail('Lock handoff rejected');
 let self=original_me;
 if(!writefile(path+'/ticks',self.ticks+'\n') || !writefile(path+'/pid',me+'\n')) fail('Lock handoff failed'); exit(0);
}
// Owner descendants may stop/restore; only the registered procd worker may apply rules.
if(gate && !((name=='rules' && (authorized || restore_worker)) || (index(['shutdown','service'],name)>=0 && authorized))) fail('Package lifecycle frozen');
if(live) exit(1);
if(stat(path)) { unlink(path+'/pid'); unlink(path+'/ticks'); if(!rmdir(path)) fail('Cannot reap lock'); }
if(mode=='acquire') {
 let self=original_me;
 if(!mkdir(path,0700) || !writefile(path+'/ticks',self.ticks+'\n') || !writefile(path+'/pid',me+'\n')) fail('Cannot acquire lock');
}
