// Fixed IPv4 subnet validator. Never pass downloaded text directly to nft.
import { open } from 'fs';
function fail(s) {
 warn(sprintf('%J\n', {ok:false, error:s}));
 exit(1);
}
let mode = ARGV[0] || 'elements';
if (index(['elements','normalize','check'], mode) < 0) fail('Unknown validator mode');
let f = open('/dev/stdin', 'r');
if (!f) fail('Cannot read input');
let raw = f.read(2097153);
f.close();
if (type(raw) != 'string' || length(raw) > 2097152) fail('Input exceeds 2 MiB');
// POSIX regex stops at embedded NUL; reject it before trim()/matching.
if (index(raw, '\x00') >= 0) fail('NUL byte in input');
// Exclude whole networks overlapping special-use ranges (no unsafe broad CIDRs).
let excluded = [
 [0,8], [167772160,8], [1681915904,10], [2130706432,8],
 [2851995648,16], [2886729728,12], [3221225472,24],
 [3221225984,24], [3227017984,24], [3232235520,16],
 [3323068416,15], [3325256704,24], [3405803776,24], [3758096384,3]
];
// Precompute CIDR widths and exclusion endpoints once. Repeating a 24-iteration
// power loop for every excluded range of every entry was too slow on OpenWrt.
let widths=[]; widths[32]=1;
for (let p=31;p>=0;p--) widths[p]=widths[p+1]*2;
let excluded_ends=[];
for (let r in excluded) push(excluded_ends,[r[0],r[0]+widths[r[1]]]);
let out=[], seen={}, discarded=0, skipped=0, source_count=0;
for (let line in split(raw, '\n')) {
 let n=trim(line);
 if (!length(n) || substr(n,0,1)=='#') { skipped++; continue; }
 // Only address-shaped IPv6 lines may be skipped; shell/nft syntax still fails.
 if (index(n, ':') >= 0 && match(n,/^[0-9a-fA-F:]+(\/[0-9]{1,3})?$/)) { skipped++; continue; }
 let m=match(n,/^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})(\/([0-9]{1,2}))?$/);
 if (!m) fail('Malformed IPv4/CIDR input');
 let a=[];
 for (let i=1;i<=4;i++) {
  if ((length(m[i])>1 && substr(m[i],0,1)=='0') || int(m[i])>255) fail('Invalid IPv4 octet');
  push(a,int(m[i]));
 }
 let p=m[6]==null?32:int(m[6]);
 if (p<8 || p>32 || (m[6]!=null && length(m[6])>1 && substr(m[6],0,1)=='0')) fail('Prefix must be 8..32');
 let ip=((a[0]*256+a[1])*256+a[2])*256+a[3], b=widths[p];
 if (ip%b) fail('Noncanonical network address');
 source_count++;
 if (source_count>60000) fail('More than 60000 entries');
 let reject=false;
 for (let r in excluded_ends) if (ip < r[1] && r[0] < ip+b) { reject=true; break; }
 if (reject) { discarded++; continue; }
 let canonical=join('.',a)+'/'+p;
 if (!seen[canonical]) { seen[canonical]=true; push(out,canonical); }
}
if (!length(out)) fail('No public IPv4 networks remain');
let meta={ok:true,count:length(out),source_count:source_count,discarded:discarded,skipped:skipped};
if (mode=='check') print(sprintf('%J\n',meta));
else {
 if (mode=='normalize') warn(sprintf('%J\n',meta));
 print(join('\n',out)+'\n');
}
