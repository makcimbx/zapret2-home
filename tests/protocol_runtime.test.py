#!/usr/bin/env python3
"""Real fixed ucode argv/validation and pinned-engine init; no NFQUEUE or traffic."""
import hashlib,json,pathlib,subprocess,tempfile,unittest
ROOT=pathlib.Path(__file__).resolve().parents[1]
from local_env import SCRATCH, UCODE as UC, MODULES, NFQWS2_NATIVE, NFQWS2_GSO_NATIVE
IDS={'tcp':['alt1','stock','overlap','fake','fake_split','fake_disorder'],'quic':['quic_google','quic_zero','quic_google_badsum','quic_google_ttl2','quic_zero_badsum','quic_zero_ttl2'],'udp':['udp_fake2','udp_fake6','udp_protocol_fake2','udp_badsum2','udp_ttl2','udp_protocol_badsum2']}
ZERO='0x00000000000000000000000000000000'
BLOBS={'quic-google.bin':(1200,'f4589c57749f956bb30538197a521d7005f8b0a8723b4707e72405e51ddac50a'),'discord-ip-discovery-without-port.bin':(74,'3f63c3a0cc63b90a6a8c50ffc61a32cc7d1f1b60457a96b90719256744df0e96'),'stun.bin':(100,'9cd5469309780ca56c0bd97266524a48c7ee529d02c3179cfecb20b260a59641')}
class ProtocolRuntime(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(prefix='z2-protocol-',dir=SCRATCH); self.lib=pathlib.Path(self.tmp.name)
  for name in ('protocols.uc','validate.uc','profile-catalog.json','protocol-catalog.json'):
   src=ROOT/'files/usr/lib/zapret2-home'/name
   (self.lib/name).write_text(src.read_text().replace('/usr/lib/zapret2-home',str(self.lib)))
 def tearDown(self): self.tmp.cleanup()
 def call(self,*args): return subprocess.run([str(UC),'-L',str(MODULES),str(self.lib/'protocols.uc'),*args],text=True,capture_output=True)
 def test_catalog_exact_groups_and_fixed_profiles(self):
  p=self.call('catalog');self.assertEqual(p.returncode,0,p.stderr);x=json.loads(p.stdout);self.assertTrue(x['ok'])
  groups=x['catalog']['groups'];self.assertEqual([g['id'] for g in groups],list(IDS));self.assertEqual([len(g['profiles']) for g in groups],[6,6,6])
  for g in groups:
   self.assertEqual([p['id'] for p in g['profiles']],IDS[g['id']]);self.assertFalse(g['test_supported']);self.assertEqual(g['targets'],[])
   if g['id']!='tcp':self.assertTrue(all(p['evidence']=='experimental' for p in g['profiles']))
  split=next(p for p in groups[0]['profiles'] if p['id']=='fake_split')
  self.assertEqual(split['title'],'Fake TLS badsum + split');self.assertEqual(split['evidence'],'experimental')
  self.assertEqual(split['strategy'],' → '.join(v.removeprefix('--lua-desync=') for v in self.expected_branch('tcp','fake_split')[-2:]))
 def expected_branch(self,group,profile):
  if group=='tcp':
   if profile=='fake_split':return ['--filter-tcp=443','--filter-l7=tls','--in-range=x','--out-range=-n20','--payload=tls_client_hello','--lua-desync=fake:blob=fake_default_tls:tls_mod=rnd,dupsid,sni=ya.ru:badsum:repeats=10','--lua-desync=multisplit:pos=1,midsld']
   catalog=json.loads((self.lib/'profile-catalog.json').read_text())
   return ['--filter-tcp=443','--filter-l7=tls','--in-range=x','--out-range=-n6','--payload=tls_client_hello',*next(p['args'] for p in catalog if p['id']==profile)]
  suffix=':badsum' if 'badsum' in profile else ':ip_ttl=2' if 'ttl2' in profile else ''
  if group=='quic':return ['--filter-udp=443','--filter-l7=quic','--in-range=x','--out-range=-n6','--payload=quic_initial','--lua-desync=fake:blob='+('quic_google' if profile.startswith('quic_google') else 'fake_default_quic')+':repeats=6'+suffix]
  a=['--filter-udp=19294-19344,50000-50100','--filter-l7=discord,stun','--in-range=x','--out-range=-n6']
  if profile in ('udp_protocol_fake2','udp_protocol_badsum2'):
   return a+['--payload=discord_ip_discovery','--lua-desync=fake:blob=discord_discovery:repeats=2'+suffix,'--payload=stun','--lua-desync=fake:blob=stun_binding:repeats=2'+suffix]
  return a+['--payload=discord_ip_discovery,stun','--lua-desync=fake:blob='+ZERO+':repeats='+('6' if profile=='udp_fake6' else '2')+suffix]
 def test_all_fixed_branches_exact_and_blob_loading_scoped(self):
  for group,profiles in IDS.items():
   for profile in profiles:
    for queue in ('213','214'):
     for mode in ('run','dry-run'):
      with self.subTest(group=group,profile=profile,queue=queue,mode=mode):
       p=self.call('argv',queue,profile,mode,group);self.assertEqual(p.returncode,0,p.stderr);a=p.stdout.splitlines()
       branch=self.expected_branch(group,profile)
       expected=[str(self.lib/('nfqws2-quic' if queue=='214' and group=='quic' else 'nfqws2'))]
       if mode=='dry-run':expected+=['--dry-run']
       if queue=='214' and group=='quic':expected+=['--reasm-disable=quic_initial']
       expected+=['--qnum='+queue,*['--lua-init=@'+str(self.lib/'lua'/name) for name in ('zapret-lib.lua','zapret-antidpi.lua','hostfakesplit-alt1.lua')]]
       if profile.startswith('quic_google'):expected+=['--blob=quic_google:@'+str(self.lib/'fake/quic-google.bin')]
       if profile in ('udp_protocol_fake2','udp_protocol_badsum2'):expected+=['--blob=discord_discovery:@'+str(self.lib/'fake/discord-ip-discovery-without-port.bin'),'--blob=stun_binding:@'+str(self.lib/'fake/stun.bin')]
       self.assertEqual(a,expected+branch)
       if group!='tcp':
        metadata=next(p for g in json.loads((self.lib/'protocol-catalog.json').read_text()) if g['id']==group for p in g['profiles'] if p['id']==profile)
        self.assertEqual(metadata['strategy'],' + '.join(v.removeprefix('--lua-desync=') for v in branch if v.startswith('--lua-desync=')))
 def test_main_dispatch_and_disabled_branches(self):
  for flags,count in [(('1','0','0'),1),(('0','1','0'),1),(('0','0','1'),1),(('1','1','1'),3)]:
   p=self.call('main-argv','213','run',flags[0],'alt1',flags[1],'quic_google',flags[2],'udp_fake2');self.assertEqual(p.returncode,0,p.stderr);a=p.stdout.splitlines();self.assertEqual(a.count('--new'),count-1);self.assertEqual(sum(v.startswith('--qnum=') for v in a),1)
   self.assertEqual('--filter-tcp=443' in a,flags[0]=='1');self.assertEqual('--filter-udp=443' in a,flags[1]=='1');self.assertEqual('--filter-udp=19294-19344,50000-50100' in a,flags[2]=='1')
   self.assertEqual(a[0],str(self.lib/'nfqws2'));self.assertFalse(any(v.startswith('--reasm-') for v in a))
  self.assertNotEqual(self.call('main-argv','213','run','0','alt1','0','quic_google','0','udp_fake2').returncode,0)
  for enabled in ('0','1'):
   p=self.call('main-argv','214','run','1','alt1',enabled,'quic_google','1','udp_fake2');self.assertEqual(p.returncode,0,p.stderr);a=p.stdout.splitlines()
   self.assertEqual(a[0],str(self.lib/('nfqws2-quic' if enabled=='1' else 'nfqws2')))
   self.assertEqual([v for v in a if v.startswith('--reasm-')],['--reasm-disable=quic_initial'] if enabled=='1' else [])
 def test_fake_split_main_argv_preserves_other_protocol_ranges(self):
  p=self.call('main-argv','213','run','1','fake_split','1','quic_google','1','udp_fake2');self.assertEqual(p.returncode,0,p.stderr)
  expected=self.expected_branch('tcp','fake_split')+['--new']+self.expected_branch('quic','quic_google')+['--new']+self.expected_branch('udp','udp_fake2')
  self.assertEqual(p.stdout.splitlines()[-len(expected):],expected)
 def test_diagnostic_and_saved_allowlists_reject_crossgroup_and_injection(self):
  for group,profiles in IDS.items():
   for profile in profiles:
    for selected in IDS:
     payload={'protocol':selected,'enabled':True,'profile':profile}
     p=subprocess.run([str(UC),'-L',str(MODULES),str(self.lib/'validate.uc'),'protocol'],input=json.dumps(payload),text=True,capture_output=True)
     self.assertEqual(p.returncode==0,selected==group,(payload,p.stdout,p.stderr))
     self.assertEqual(self.call('argv','214',profile,'run',selected).returncode==0,selected==group)
    payload=dict(clients='192.168.1.2',destinations='1.1.1.1',autostart=False,**{('profile' if group=='tcp' else group+'_profile'):profile})
    p=subprocess.run([str(UC),'-L',str(MODULES),str(self.lib/'validate.uc')],input=json.dumps(payload),text=True,capture_output=True)
    self.assertEqual(p.returncode,0,(payload,p.stdout,p.stderr))
  for args in [('argv','215','alt1','run','tcp'),('argv','213','alt1;bad','run','tcp'),('argv','214','udp_protocol_fake2:badsum','run','udp'),('argv','214','quic_google\n--drop','run','quic'),('main-argv','213','run','true','alt1','0','quic_google','0','udp_fake2')]:self.assertNotEqual(self.call(*args).returncode,0)
  for group in ('quic','udp'):
   for invalid in [None,True,[],IDS[group][-1]+':badsum','../../fake','--lua-desync=drop','quic_google\n--drop']:
    for mode in ('protocol','configure'):
     payload=dict(protocol=group,enabled=True,profile=invalid) if mode=='protocol' else dict(clients='192.168.1.2',destinations='1.1.1.1',autostart=False,**{group+'_profile':invalid})
     p=subprocess.run([str(UC),'-L',str(MODULES),str(self.lib/'validate.uc'),mode],input=json.dumps(payload),text=True,capture_output=True)
     self.assertNotEqual(p.returncode,0,(payload,p.stdout,p.stderr))
 def test_native_pinned_engine_all_18_dry_runs_and_real_lua_init(self):
  native=NFQWS2_NATIVE
  quic_native=NFQWS2_GSO_NATIVE
  self.assertTrue(native.exists(),'pinned native engine is required for this proof')
  self.assertTrue(quic_native.exists(),'GSO native diagnostic engine is required for this proof')
  self.assertEqual(hashlib.sha256(quic_native.read_bytes()).hexdigest(),'622c1782236c2630a1c279f9c6bd0b983aced35db8034dff037a6ac5bc1c0114')
  version=subprocess.run([str(native),'--version'],text=True,capture_output=True,check=True);self.assertIn('v1.0.5.2',version.stdout+version.stderr)
  (self.lib/'nfqws2').symlink_to(native);(self.lib/'nfqws2-quic').symlink_to(quic_native)
  (self.lib/'lua').symlink_to(ROOT/'files/usr/lib/zapret2-home/lua',target_is_directory=True)
  (self.lib/'fake').symlink_to(ROOT/'files/usr/lib/zapret2-home/fake',target_is_directory=True)
  commands=[('argv','214',profile,'dry-run',group) for group,profiles in IDS.items() for profile in profiles]
  commands += [('main-argv','213','dry-run','1','alt1','1',q,'1',u) for q in IDS['quic'] for u in IDS['udp']]
  commands += [('main-argv','213','dry-run','1','fake_split','1','quic_google','1','udp_fake2')]
  for command in commands:
   with self.subTest(command=command):
    p=self.call(*command);self.assertEqual(p.returncode,0,p.stderr);engine,*args=p.stdout.splitlines()
    diagnostic_quic=command[0]=='argv' and command[-1]=='quic'
    self.assertEqual(pathlib.Path(engine).resolve(),quic_native if diagnostic_quic else native)
    self.assertEqual([v for v in args if v.startswith('--reasm-')],['--reasm-disable=quic_initial'] if diagnostic_quic else [])
    if command[0]=='main-argv':
     q,u=command[6],command[8]
     expected=['--dry-run','--qnum=213',*['--lua-init=@'+str(self.lib/'lua'/name) for name in ('zapret-lib.lua','zapret-antidpi.lua','hostfakesplit-alt1.lua')]]
     if q.startswith('quic_google'):expected+=['--blob=quic_google:@'+str(self.lib/'fake/quic-google.bin')]
     if u in ('udp_protocol_fake2','udp_protocol_badsum2'):expected+=['--blob=discord_discovery:@'+str(self.lib/'fake/discord-ip-discovery-without-port.bin'),'--blob=stun_binding:@'+str(self.lib/'fake/stun.bin')]
     self.assertEqual(args,expected+self.expected_branch('tcp',command[4])+['--new']+self.expected_branch('quic',q)+['--new']+self.expected_branch('udp',u))
    # Test-only UID override avoids an unmapped default nobody GID in the container.
    p=subprocess.run([engine,'--uid=0:0',*args],text=True,capture_output=True,timeout=5);self.assertEqual(p.returncode,0,p.stdout+p.stderr)
    args.remove('--dry-run')
    p=subprocess.run([engine,'--uid=0:0','--intercept=0',*args],text=True,capture_output=True,timeout=5);self.assertEqual(p.returncode,0,p.stdout+p.stderr)
    self.assertIn('LUA v',p.stdout+p.stderr)
    self.assertNotIn('ERROR',p.stdout+p.stderr)
 def test_pinned_blobs(self):
  for name,(size,digest) in BLOBS.items():
   raw=(ROOT/'files/usr/lib/zapret2-home/fake'/name).read_bytes();self.assertEqual(len(raw),size);self.assertEqual(hashlib.sha256(raw).hexdigest(),digest)
if __name__=='__main__':unittest.main(verbosity=2)
