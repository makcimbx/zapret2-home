#!/usr/bin/env python3
"""Real ucode validation/state/row proofs and namespace nft, no router/network."""
import json, os, pathlib, subprocess, tempfile
ROOT=pathlib.Path(__file__).resolve().parents[1]
from local_env import UCODE, MODULES as MODULE
IDS={'tcp':['alt1','stock','overlap','fake','fake_split','fake_disorder'],'quic':['quic_google','quic_zero','quic_google_badsum','quic_google_ttl2','quic_zero_badsum','quic_zero_ttl2'],'udp':['udp_fake2','udp_fake6','udp_protocol_fake2','udp_badsum2','udp_ttl2','udp_protocol_badsum2']}
with tempfile.TemporaryDirectory(prefix='z2-protocols-',dir=tempfile.gettempdir()) as d:
    tmp=pathlib.Path(d); run=tmp/'profiles'; run.mkdir(); main=tmp/'main'; main.mkdir()
    catalog=ROOT/'files/usr/lib/zapret2-home/profile-catalog.json'
    source=(ROOT/'files/usr/lib/zapret2-home/profiles.uc').read_text().replace("const RUN = '/var/run/zapret2-home/profiles';",f"const RUN = '{run}';").replace("const MAIN = '/var/run/zapret2-home';",f"const MAIN = '{main}';").replace("const CATALOG = '/usr/lib/zapret2-home/profile-catalog.json';",f"const CATALOG = '{catalog}';")
    uc=tmp/'profiles.uc'; uc.write_text(source)
    def u(cmd,*args,payload=None,good=None,no_dac=False):
        prefix=['/usr/bin/setpriv','--bounding-set=-dac_override,-dac_read_search'] if no_dac else []
        p=subprocess.run([*prefix,UCODE,'-L',MODULE,str(uc),cmd,*map(str,args)],input=json.dumps(payload).encode() if payload is not None else None,capture_output=True,timeout=10)
        if good is not None: assert (p.returncode==0)==good,(cmd,args,p.stdout,p.stderr)
        return p
    def status(cmd='protocols-status'): return json.loads(u(cmd,good=True).stdout)['data']
    for protocol,profiles,targets in [('tcp','alt1','tavily'),('quic','quic_google quic_zero','youtube_h3'),('udp','udp_fake6 udp_fake2','stun_google')]:
        p=u('validate-protocol','HTTP3',payload=dict(protocol=protocol,profiles=profiles,targets=targets,repeat=2),good=True)
        assert p.stdout.decode().splitlines()==[('udp_fake2 udp_fake6' if protocol=='udp' else profiles),targets,'2',protocol]
    for protocol,target in [('tcp','tavily'),('quic','youtube_h3'),('udp','stun_google')]:
        selected=' '.join(IDS[protocol])
        p=u('validate-protocol','HTTP3',payload=dict(protocol=protocol,profiles=' '.join(reversed(IDS[protocol])),targets=target,repeat=2),good=True)
        assert p.stdout.decode().splitlines()==[selected,target,'2',protocol]
        for profile in IDS[protocol]:
            u('validate-protocol','HTTP3',payload=dict(protocol=protocol,profiles=profile,targets=target,repeat=1),good=True)
        for other in IDS:
            if other!=protocol:
                u('validate-protocol','HTTP3',payload=dict(protocol=protocol,profiles=IDS[other][-1],targets=target,repeat=1),good=False)
    u('validate-protocol','HTTP3',payload=dict(protocol='udp',profiles='udp_fake2'+' '*120,targets='stun_google',repeat=1),good=False)
    good=dict(protocol='udp',profiles='udp_fake2',targets='stun_google',repeat=1)
    for change in [dict(protocol='bogus'),dict(protocol=None),dict(protocol=True),dict(profiles='alt1'),dict(targets='youtube_h3'),dict(targets='74.125.250.129'),dict(repeat=True),dict(repeat=3),dict(cmd='id'),dict(ubus_rpc_session=None),dict(ubus_rpc_session='a'*31),dict(ubus_rpc_session='a'*32+'\x00')]:
        u('validate-protocol','HTTP3',payload=dict(good,**change),good=False)
    u('validate-protocol','',payload=dict(protocol='quic',profiles='quic_google',targets='youtube_h3',repeat=1),good=False)
    assert not (run/'owner').exists() and not (run/'guard').exists()
    print('PASS strict per-protocol allowlists/types/metadata and HTTP3 capability gate')
    metadata={'ok':True,'catalog':{'groups':[dict(id='tcp',title='tcp',description='tcp',profiles=json.loads(catalog.read_text())),*json.loads((ROOT/'files/usr/lib/zapret2-home/protocol-catalog.json').read_text())]}}
    groups=json.loads(u('protocols-catalog','',payload=metadata,good=True).stdout)['catalog']['groups']
    assert [g['id'] for g in groups]==['tcp','quic','udp'] and not groups[1]['test_supported'] and 'HTTP3' in groups[1]['test_unavailable_reason']
    assert groups[2]['test_supported'] and groups[2]['targets'][0]['id']=='stun_google'
    assert [len(g['profiles']) for g in groups]==[6,6,6]
    assert 'Приватный диагностический curl' in groups[1]['test_unavailable_reason']
    available=json.loads(u('protocols-catalog','HTTP3',payload=metadata,good=True).stdout)['catalog']['groups']
    assert available[1]['test_supported'] and available[1]['test_unavailable_reason']==''
    assert [t['id'] for t in available[1]['targets']]==['youtube_h3']
    assert [t['id'] for t in available[2]['targets']]==['stun_google']
    for mutate in ['missing','reordered','unknown']:
        bad=json.loads(json.dumps(metadata)); items=bad['catalog']['groups'][1]['profiles']
        if mutate=='missing': items.pop()
        elif mutate=='reordered': items.reverse()
        else: items[-1]['id']='quic_custom'
        u('protocols-catalog','HTTP3',payload=bad,good=False)
    assert all(set(p)=={'id','title','evidence','strategy'} for g in groups for p in g['profiles'])
    for protocol,port in [('tcp',443),('quic',443),('udp',19302)]:
        rules=u('rules','123.456',protocol,good=True).stdout
        fixture=tmp/'rules.nft'; fixture.write_bytes(rules)
        subprocess.run(['unshare','-Urn','/usr/sbin/nft','-c','-f',str(fixture)],check=True,capture_output=True)
        transport='tcp' if protocol=='tcp' else 'udp'
        assert f'{transport} sport 12600-12659 {transport} dport {port}'.encode() in rules
        assert b'queue num 214 bypass' in rules and b'0x40000000' in rules and b'hook forward' not in rules
        if protocol!='tcp': assert b'synack_test' not in rules and b'tcp ' not in rules
    print('PASS runtime metadata merge and all three REAL private-namespace nft syntax checks')
    # Real Podkop Discord destination range must not collide with the reserved source range.
    proc=tmp/'preflight-proc'; (proc/'net/netfilter').mkdir(parents=True)
    (proc/'net/netfilter/nfnetlink_queue').write_text('')
    for name in ['tcp','tcp6','udp','udp6']: (proc/'net'/name).write_text('')
    assert "const PROC = '/proc';" in source
    preflight=tmp/'preflight.uc'; preflight.write_text(source.replace("const PROC = '/proc';",f"const PROC = '{proc}';"))
    probe=run/'123.456'; probe.mkdir()
    podkop='iifname @interfaces ip daddr @podkop_discord_subnets udp dport { 19000-20000, 50000-65535 } meta mark set 0x00100000\n'
    def scope(protocol,text,allowed):
        (probe/'ruleset').write_text(text)
        result=subprocess.run([UCODE,'-L',MODULE,str(preflight),'preflight','123.456',protocol],capture_output=True,timeout=10)
        assert (result.returncode==0)==allowed,(protocol,text,result.stderr)
    for protocol in ['tcp','quic','udp']:
        scope(protocol,podkop,True)
        transport='tcp' if protocol=='tcp' else 'udp'
        for direction in ['sport','dport']: scope(protocol,podkop+f'{transport} {direction} 12600-12659\n',False)
        scope(protocol,podkop+'queue num 214 bypass\n',False)
    (probe/'ruleset').unlink(); probe.rmdir()
    print('PASS actual Podkop Discord port range coexists with 12600-12659; true reserved ports and queue conflicts still reject')
    # Relocate only health inputs: process identity must keep using real /proc.
    healthuc=tmp/'health.uc'
    healthuc.write_text(source.replace("open(PROC+'/'+name,'r')",f"open('{proc}/'+name,'r')"))
    realuc=uc; uc=healthuc
    try:
        stat=proc/'stat'; load=proc/'loadavg'; queue=proc/'net/netfilter/nfnetlink_queue'
        for cpus in [1,4]:
            cpu_stat='cpu 1 2 3 4 5 6 7 8 9 10\n'+''.join(f'cpu{i} 1 2 3 4 5 6 7 8 9 10\n' for i in range(cpus))
            stat.write_text(cpu_stat)
            for value,code in [('0.00',0),('1.01',0 if cpus==4 else 2),(str(cpus),0),(str(cpus)+'.01',2)]:
                load.write_text(f'{value} 0.00 0.00 1/1 1\n')
                result=u('health'); assert result.returncode==code,(cpus,value,result.stdout,result.stderr)
                if code:
                    details=json.loads(result.stdout)
                    assert not details['ok'] and details['online_cpus']==cpus and details['load_limit']==cpus and details['load_1m']==float(value)
        load.write_text('1.01 0 0 1/1 1\n')
        for pending,drops,user_drops,code in [(64,0,0,0),(65,0,0,3),(0,1,0,3),(0,0,1,3)]:
            queue.write_text(f'213 123 999 2 65535 99 99 0 1\n214 123 {pending} 2 65535 {drops} {user_drops} 0 1\n')
            result=u('health'); assert result.returncode==code,(result.stdout,result.stderr)
            if code: assert 'queue' in json.loads(result.stdout)['error'].lower()
        queue.write_text('')
        for path,bad_values in [(stat,['','intr 1\n','cpu0 bad\n','cpu0 1 2 3 4\ncpu0 1 2 3 4\n','cpu0 -1 2 3 4\n','x'*131073]),(load,['','garbage\n','NaN 0 0 1/1 1\n','-1 0 0 1/1 1\n','1e999 0 0 1/1 1\n','0.1bad 0 0 1/1 1\n','0.1 0 bad 1/1 1\n','x'*257]),(queue,['214 bad\n','214 123 NaN 2 65535 0 0 0 1\n','x'*131073])]:
            original=path.read_text()
            for raw in bad_values:
                path.write_text(raw); result=u('health')
                assert result.returncode==1 and json.loads(result.stdout)['error'],(path,raw[:80],result.stdout,result.stderr)
            path.write_text(original); path.chmod(0)
            assert u('health',no_dac=True).returncode==1
            path.chmod(0o600); path.unlink()
            assert u('health').returncode==1
            path.write_text(original)
    finally:
        uc=realuc
    print('PASS native health: online CPU normalization/boundaries, independent queue pressure, malformed/missing/unreadable/bounded inputs fail closed')
    legacy=json.loads((ROOT/'tests/fixtures/protocols-status-legacy-router.json').read_text())
    legacy['plan']=dict(profiles='alt1 stock',targets='gitlab unitask',repeat=1)
    (run/'result').write_text(json.dumps(legacy)); before=(run/'result').read_bytes()
    for cmd in ['status','protocols-status']:
        normalized=status(cmd)
        assert normalized['protocol']=='tcp' and not normalized['running']
        assert normalized['plan']==dict(legacy['plan'],protocol='tcp',profiles=legacy['plan']['profiles'].split(),targets=legacy['plan']['targets'].split())
        assert normalized['results']==[dict(row,protocol='tcp') for row in legacy['results']]
        assert normalized['job_id']==legacy['job_id'] and normalized['state']==legacy['state']
        assert (run/'result').read_bytes()==before
    (run/'result').unlink()
    print('PASS actual 0.3.1 history fixture normalizes TCP tags without changing evidence or disk state')
    control=main/'control.lock'; control.mkdir(); (control/'pid').write_text(str(os.getpid()))
    # Ownership is a trust boundary: only actual absence may admit a new job.
    ticks=u('identity',os.getpid(),good=True).stdout.decode().strip()
    assert u('identity',os.getpid(),os.getppid(),good=True).stdout.decode().strip()==ticks
    u('identity',os.getpid(),os.getpid(),good=False)
    u('identity',os.getpid(),'invalid',good=False)
    print('PASS native identity optional parent check rejects a PID no longer owned by the spawning shell')
    u('child-ended',os.getpid(),os.getppid(),good=False)
    child=os.fork()
    if child==0: os._exit(7)
    try:
        os.waitid(os.P_PID,child,os.WEXITED|os.WNOWAIT)
        u('identity',child,good=False)
        u('child-ended',child,os.getpid(),good=True)
        u('child-ended',child,os.getpid()+1,good=False)
    finally:
        assert os.waitpid(child,0)[1]==7<<8
    u('child-ended',child,os.getpid(),good=True)
    fakeproc=tmp/'proc'; fakeproc.mkdir(); (fakeproc/'123').mkdir()
    fakeuc=tmp/'proc-proof.uc'; fakeuc.write_text(source.replace("const PROC = '/proc';",f"const PROC = '{fakeproc}';"))
    realuc=uc; uc=fakeuc
    try:
        for raw in ['', '{', '123 (x) Z 456']:
            (fakeproc/'123/stat').write_text(raw)
            u('child-ended',123,456,good=False)
        (fakeproc/'123/stat').chmod(0)
        assert u('child-ended',123,456,no_dac=True).returncode!=0
        (fakeproc/'123/stat').chmod(0o600); (fakeproc/'123/stat').unlink()
        u('child-ended',123,456,good=False)
        fakeproc.chmod(0)
        assert u('child-ended',999,456,no_dac=True).returncode!=0
        fakeproc.chmod(0o700)
        u('child-ended',999,456,good=True)
    finally:
        fakeproc.chmod(0o700); uc=realuc
    print('PASS native fast-child exit proof requires own zombie or verified proc absence, never unreadable or malformed live identity')
    identity=dict(pid=str(os.getpid()),ticks=ticks)
    valid=dict(identity,job='123.456',started=0)
    corrupt=['', '{', 'null', '[]', 'true', '"owner"', '{}', ' '*131073]
    for name in ['owner','finishing']:
        path=run/name
        cases=corrupt+[json.dumps(x) for x in [dict(pid=identity['pid']),dict(ticks=ticks),dict(pid='0',ticks=ticks),dict(pid=True,ticks=ticks),dict(pid=identity['pid'],ticks='bad')]]
        if name=='owner':
            cases += [json.dumps(x) for x in [identity,dict(valid,job='../escape'),dict(valid,job=None),dict(valid,started='0'),dict(valid,protocol='bogus')]]
        for raw in cases:
            path.write_text(raw)
            before=path.read_bytes()
            for cmd,args in [('acquire',(os.getpid(),'udp')),('status',()),('protocols-status',()),('release',('123.456',os.getpid()))]:
                u(cmd,*args,good=False)
                assert path.read_bytes()==before,(name,raw,cmd)
            assert not [x for x in run.iterdir() if x.is_dir()]
        path.write_text(json.dumps(valid if name=='owner' else identity)); path.chmod(0)
        for cmd,args in [('acquire',(os.getpid(),'udp')),('status',()),('release',('123.456',os.getpid()))]:
            assert u(cmd,*args,good=False,no_dac=True).returncode==1
        path.chmod(0o600); path.unlink()
        for nonfile in ['directory','dangling-link']:
            if nonfile=='directory': path.mkdir()
            else: path.symlink_to(tmp/'missing')
            u('acquire',os.getpid(),'udp',good=False); u('protocols-status',good=False)
            if nonfile=='directory': path.rmdir()
            else: path.unlink()
    # A valid live owner without protocol is still a legacy TCP owner.
    (run/'owner').write_text(json.dumps(valid))
    assert status()['running'] and status()['protocol']=='tcp'
    u('acquire',os.getpid(),'udp',good=False)
    (run/'owner').unlink()
    (run/'finishing').write_text(json.dumps(identity))
    assert status()['running']
    u('acquire',os.getpid(),'udp',good=False)
    (run/'finishing').write_text(json.dumps(dict(identity,ticks='0')))
    print('PASS native owner/finishing corruption, bounds, unreadable files and nonfiles refuse acquire/status/release; legacy identity remains valid')
    (run/'result').write_text(json.dumps(dict(state='results',job_id='old.job',protocol='tcp',results=[dict(profile='alt1')])))
    job=u('acquire',os.getpid(),'udp',good=True).stdout.decode().strip(); base=run/job
    assert status()['results']==[] and status()['protocol']=='udp' and status()['state']=='pending'
    probe=base/'table.json'
    for raw in ['', '{', 'null', '[]', '{}', '{"nftables":null}', '{"nftables":{}}', ' '*131073]:
        probe.write_text(raw)
        for cmd in ['has-table','table-owned']:
            result=u(cmd,job,good=False)
            assert result.returncode!=3,(cmd,raw,result.stdout,result.stderr)
    probe.write_text('{"nftables":[]}'); probe.chmod(0)
    assert u('has-table',job,good=False,no_dac=True).returncode==1
    probe.chmod(0o600); probe.unlink()
    assert u('has-table',job,good=False).returncode!=3
    probe.mkdir(); assert u('has-table',job,good=False).returncode!=3; probe.rmdir()
    for absent in [dict(nftables=[]),dict(nftables=[dict(table=dict(family='inet',name='unrelated'))])]:
        probe.write_text(json.dumps(absent))
        assert u('has-table',job,good=False).returncode==3
        assert u('table-owned',job,good=False).returncode==1
    for comment in ['foreign','z2profiles:'+job]:
        probe.write_text(json.dumps(dict(nftables=[dict(table=dict(family='inet',name='zapret2_home_profiles',comment=comment))])))
        u('has-table',job,good=True)
        u('table-owned',job,good=comment=='z2profiles:'+job)
    # Corrupt finishing must also prevent release of an otherwise valid owner.
    (run/'finishing').write_text('{')
    owner_before=(run/'owner').read_bytes()
    u('release',job,os.getpid(),good=False)
    assert (run/'owner').read_bytes()==owner_before and (run/'finishing').read_text()=='{'
    (run/'finishing').unlink()
    print('PASS native table present=0 / valid absent=3 / malformed, missing, nonobject, nonarray, oversize and read errors=1; unsafe finishing blocks release')
    u('plan',job,'udp','udp_fake2','stun_google',1,good=True)
    s=status(); assert s['protocol']=='udp' and s['plan']==dict(good,profiles=good['profiles'].split(),targets=good['targets'].split()) and s['running']
    old=status('status'); assert old['state']=='running' and old['running'] and old['results']==[] and 'plan' not in old
    m=dict(binding_success=True,route_verified=True,remote_ip='74.125.250.129',remote_port=19302,local_ip='192.0.2.2',local_port=12600,mapped_ip='192.0.2.2',mapped_port=12600,time_total=.1,ignored_transactions=1)
    (base/'metrics').write_text(json.dumps(m)); h='0'*64
    u('row',job,'udp_fake2','stun_google',1,0,h,0,12600,good=True)
    row=status()['results'][0]
    assert row['protocol']=='udp' and row['full_match'] and row['binding_success'] and row['route_verified'] and 'tls_verified' not in row
    assert status('status')['results']==[]
    for delta in [dict(binding_success=False),dict(binding_success='true'),dict(mapped_ip='192.0.2.1'),dict(mapped_port=12601),dict(remote_port=443),dict(remote_ip='192.0.2.1'),dict(local_ip='192.0.2.1')]:
        result=json.loads((run/'result').read_text()); result['results']=[]; (run/'result').write_text(json.dumps(result))
        (base/'metrics').write_text(json.dumps(dict(m,**delta)))
        u('row',job,'udp_fake2','stun_google',1,0,h,0,12600)
        assert not status()['results'][0]['full_match'],delta
    u('release',job,os.getpid(),good=True)
    import shutil
    shutil.rmtree(base)
    assert status('status')['state']=='idle' and not status('status')['running']
    print('PASS UDP mapped/direct tuple conjunction and busy-safe legacy TCP status')
    job=u('acquire',os.getpid(),'quic',good=True).stdout.decode().strip(); base=run/job
    u('plan',job,'quic','quic_google','youtube_h3',1,good=True)
    target=dict(ip='142.251.1.119',bytes=65324,sha='263dedc00c8521ab388aa6385c36c28be9e02c8e7bb6f8edbe6240f5cdd9bdbd')
    m=dict(remote_ip=target['ip'],local_ip='192.0.2.2',local_port=12600,time_connect=.1,time_appconnect=.2,ssl_verify_result=0,http_code=200,http_version='3')
    for version,verify in [('2',0),('3',0),('3.0',0),('3',None)]:
        result=json.loads((run/'result').read_text()); result['results']=[]; (run/'result').write_text(json.dumps(result))
        (base/'metrics').write_text(json.dumps(dict(m,http_version=version,ssl_verify_result=verify)))
        u('row',job,'quic_google','youtube_h3',1,0,target['sha'],target['bytes'],12600,good=True)
        assert status()['results'][0]['full_match']==(version=='3' and verify==0)
    print('PASS QUIC success requires HTTP version 3 as well as TLS/body/hash/direct tuple (synthetic metrics only)')
    u('release',job,os.getpid(),good=True); shutil.rmtree(base)
    for protocol,target,profile in [('tcp','tavily','alt1'),('quic','youtube_h3','quic_google')]:
        job=u('acquire',os.getpid(),protocol,good=True).stdout.decode().strip(); base=run/job
        u('plan',job,protocol,profile,target,2,good=True)
        # Actual curl 35 after TLS setup failed: time_connect exists, but getinfo forgot the socket.
        missing=dict(remote_ip='',local_ip='',local_port=-1,time_connect=.027984,time_appconnect=0,http_code=0,http_version='0',ssl_verify_result=0)
        for rc in (35,28):
            result=json.loads((run/'result').read_text()); result['results']=[]; (run/'result').write_text(json.dumps(result))
            (base/'metrics').write_text(json.dumps(missing))
            u('row',job,profile,target,1,rc,'0'*64,0,12600,good=True)
            row=status()['results'][0]; assert row['exit']==rc and not row['full_match'] and not row['route_verified'] and not row['tls_verified']
            (base/'metrics').write_text(json.dumps(dict(missing,local_port=12601,time_connect=0)))
            u('row',job,profile,target,2,rc,'0'*64,0,12601,good=True)
            assert len(status()['results'])==2
        for delta,rc,size in [(dict(remote_ip='192.0.2.1'),35,0),(dict(time_appconnect=.2),35,0),(dict(http_code=200),35,0),({},35,1),({},0,0)]:
            result=json.loads((run/'result').read_text()); result['results']=[]; (run/'result').write_text(json.dumps(result))
            (base/'metrics').write_text(json.dumps(dict(missing,**delta)))
            assert u('row',job,profile,target,1,rc,'0'*64,size,12600).returncode==2
            assert not status()['results'][0]['full_match']
        u('release',job,os.getpid(),good=True); shutil.rmtree(base)
    print('PASS failed TLS/setup without any socket tuple is a failed candidate, never success; observed contradictory or missing responding tuples still abort')
    for protocol,target in [('quic','youtube_h3'),('udp','stun_google')]:
        job=u('acquire',os.getpid(),protocol,good=True).stdout.decode().strip(); base=run/job
        selected=' '.join(IDS[protocol])
        u('plan',job,protocol,selected,target,2,good=True)
        assert status()['plan']==dict(protocol=protocol,profiles=selected.split(),targets=[target],repeat=2)
        for profile in IDS[protocol]:
            for repeat in [1,2]:
                port=12600+len(status()['results'])
                metrics=dict(remote_ip='142.251.1.119',local_ip='192.0.2.2',local_port=port,time_connect=.1,time_appconnect=.2,ssl_verify_result=0,http_code=200,http_version='3') if protocol=='quic' else dict(binding_success=True,remote_ip='74.125.250.129',remote_port=19302,local_ip='192.0.2.2',local_port=port,mapped_ip='192.0.2.2',mapped_port=port)
                (base/'metrics').write_text(json.dumps(metrics))
                u('row',job,profile,target,repeat,0,'263dedc00c8521ab388aa6385c36c28be9e02c8e7bb6f8edbe6240f5cdd9bdbd' if protocol=='quic' else '0'*64,65324 if protocol=='quic' else 0,port,good=True)
        rows=status()['results']; assert len(rows)==12 and all(row['full_match'] and row['protocol']==protocol for row in rows)
        assert status('status')['results']==[] and status('status')['running']
        u('release',job,os.getpid(),good=True); shutil.rmtree(base)
    print('PASS all six QUIC and UDP plans/rows and repeats (synthetic metrics only; not bypass evidence)')
    job=u('acquire',os.getpid(),'tcp',good=True).stdout.decode().strip(); base=run/job
    alltargets=['gitlab','unitask','tavily','youtube','discord']
    u('plan',job,'tcp',' '.join(IDS['tcp']),' '.join(alltargets),2,good=True)
    for profile in IDS['tcp']:
        for target in alltargets:
            for repeat in [1,2]:
                u('row',job,profile,target,repeat,1,'0'*64,0,12600+len(status()['results']),good=True)
    assert len(status()['results'])==60
    u('row',job,'alt1','gitlab',1,1,'0'*64,0,12660,good=False)
    assert len(status()['results'])==60
    limits=json.loads(u('catalog',good=True).stdout)['catalog']['limits']
    assert limits['max_rows']==60 and limits['ports']=='12600-12659' and limits['max_seconds']==1350
    u('release',job,os.getpid(),good=True); shutil.rmtree(base)
    print('PASS unchanged 60-row/source-port/1350-second limits; expanded catalog adds no targets')
    result=json.loads((run/'result').read_text()); result['job_id']='previous.job'; (run/'result').write_text(json.dumps(result))
    job=u('acquire',os.getpid(),'tcp',good=True).stdout.decode().strip()
    assert status('status')['protocol']=='tcp' and status('status')['results']==[] and status('status')['state']=='pending'
    print('PASS acquisition/plan publication race never mixes previous protocol rows with a new owner')
    u('release',job,os.getpid(),good=True); shutil.rmtree(run/job)
