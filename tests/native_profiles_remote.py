#!/usr/bin/env python3
"""Real target dry-runs/parser/nft syntax in private staging; never bind/apply."""
import hashlib,json,pathlib,shlex,subprocess
ROOT=pathlib.Path(__file__).resolve().parents[1]
SSH=['ssh','-o','BatchMode=yes','-o','ConnectTimeout=7','root@192.168.1.1']
IDS=['alt1','stock','overlap','fake','fake_split','fake_disorder']
def remote(cmd,data=None):
 p=subprocess.run(SSH+[cmd],input=data,capture_output=True,timeout=45)
 if p.returncode:raise RuntimeError(p.stdout.decode()+p.stderr.decode())
 return p.stdout.decode()
def before():return remote('sha256sum /etc/config/zapret2_home /etc/config/podkop /etc/sing-box/config.json /etc/config/firewall; pidof sing-box; cat /var/run/zapret2-home/engine.pid')
initial=before();out={'checks':[],'scope':'actual target ucode/engine dry-run/nft syntax; no engine start or rules activation'}
stage=remote('umask 077; mktemp -d /tmp/hermes-z2-native.XXXXXX').strip()
assert stage.startswith('/tmp/hermes-z2-native.') and '\n' not in stage
try:
 remote('mkdir '+shlex.quote(stage+'/lib')+'; ln -s /usr/lib/zapret2-home/nfqws2 '+shlex.quote(stage+'/lib/nfqws2')+'; ln -s /usr/lib/zapret2-home/lua '+shlex.quote(stage+'/lib/lua'))
 for src,dest,mode in [('usr/lib/zapret2-home/profile-catalog.json','lib/profile-catalog.json','644'),('usr/libexec/zapret2-home-engine','engine','755'),('usr/lib/zapret2-home/profiles.uc','profiles.uc','644'),('usr/lib/zapret2-home/validate.uc','validate.uc','644')]:
  b=(ROOT/'files'/src).read_bytes()
  if src.endswith('.uc') or src.endswith('-engine'):b=b.replace(b'/usr/lib/zapret2-home',(stage+'/lib').encode())
  remote('dd of='+shlex.quote(stage+'/'+dest)+' 2>/dev/null',b);remote('chmod '+mode+' '+shlex.quote(stage+'/'+dest))
  assert remote('sha256sum '+shlex.quote(stage+'/'+dest)).split()[0]==hashlib.sha256(b).hexdigest()
  out['checks'].append('private staged hash '+dest)
 for i in IDS:
  log=remote(shlex.quote(stage+'/engine')+' 214 '+i+' dry-run 2>&1')
  assert 'command line parameters verified' in log.lower(),log
  out['checks'].append('real target engine dry-run '+i)
 cat=json.loads(remote('ucode '+shlex.quote(stage+'/profiles.uc')+' catalog'))
 assert cat['ok'] and [p['id'] for p in cat['catalog']['profiles']]==IDS and cat['catalog']['limits']['max_rows']==60
 out['catalog']=cat['catalog'];out['checks'].append('actual ucode six/five shared catalog')
 payload=json.dumps({'profiles':' '.join(IDS),'targets':'gitlab unitask tavily youtube discord','repeat':2}).encode()
 normalized=remote('ucode '+shlex.quote(stage+'/profiles.uc')+' validate',payload).splitlines()
 assert normalized==[' '.join(IDS),'gitlab unitask tavily youtube discord','2'];out['checks'].append('actual ucode all sixty-row selection')
 for i in IDS:
  r=json.loads(remote('ucode '+shlex.quote(stage+'/validate.uc')+' profile',json.dumps({'profile':i}).encode()))
  assert r=={'ok':True,'profile':i};out['checks'].append('actual ucode profile apply validation '+i)
 remote('ucode '+shlex.quote(stage+'/profiles.uc')+' rules 123.456 >'+shlex.quote(stage+'/rules.nft')+' && nft -c -f '+shlex.quote(stage+'/rules.nft'))
 out['checks'].append('actual target nft -c five resources/sixty ports, no activation')
finally:
 remote('rm -rf '+shlex.quote(stage))
 out['production_unchanged']=before()==initial
 assert out['production_unchanged'],'Native staging changed production state'
 (ROOT/'dist/native-profiles-target.json').write_text(json.dumps(out,ensure_ascii=False,indent=2))
print(json.dumps({'checks':len(out['checks']),'profiles':IDS,'production_unchanged':out['production_unchanged'],'activated':False}))
