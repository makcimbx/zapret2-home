#!/usr/bin/env python3
"""Check exact source rule generation in selected/all modes using real target nft -c.
The list payload is an explicit synthetic fixture; no list download or rule activation.
"""
import pathlib, subprocess, tempfile, json, shlex
ROOT=pathlib.Path(__file__).resolve().parents[1]
source=(ROOT/'files/usr/libexec/zapret2-home-ctl').read_text()
fun=source[source.index('make_rules() {'):source.index('\nprepare() {')]
rows=[]
SSH=['ssh','-o','BatchMode=yes','-o','ConnectTimeout=7','root@192.168.1.1']
remote_path='/tmp/hermes-z2-scope-check.nft'
try:
    for mode,manual,nets in [('selected','65.108.59.85/32',''),('all','65.108.59.85/32',''),('selected','','65.108.0.0/15\n107.175.64.0/20\n'),('all','','65.108.0.0/15\n107.175.64.0/20\n')]:
        with tempfile.TemporaryDirectory(prefix='z2-scope-',dir=tempfile.gettempdir()) as tmp:
            d=pathlib.Path(tmp);(d/'fixture').write_text(nets)
            stub=d/'lists';stub.write_text('#!/bin/sh\ncase "$1" in ensure) exit 0;; elements) dd if='+shlex.quote(str(d/'fixture'))+' 2>/dev/null;; esac\n');stub.chmod(0o755)
            fun2=fun.replace('/usr/libexec/zapret2-home-lists',shlex.quote(str(stub)))
            script='set -e\nRUN='+shlex.quote(tmp)+'\nTABLE=zapret2_home\nQUEUE=213\nC=192.168.1.20/32\nM='+mode+'\nD='+shlex.quote(manual)+'\nvalidated_cfg(){ return 0; }\nwan(){ W=pppoe-wan; }\nnft(){ return 1; }\n'+fun2+'\nmake_rules || true\ntest -s "$RUN/rules.nft"\n'
            subprocess.run(['sh'],input=script,text=True,check=True)
            data=(d/'rules.nft').read_bytes();text=data.decode()
            assert ('0.0.0.0/0' in text)==(mode=='all')
            assert 'iifname "br-lan" oifname "pppoe-wan"' in text
            assert 'meta mark & 0x00100000 != 0 return' in text
            assert '192.0.2.1/32' in text and 'ct status dnat return' in text
            assert 'ct original packets <= 20' in text and 'queue num 213 bypass' in text
            p=subprocess.run(SSH+['dd of='+remote_path+' 2>/dev/null; nft -c -f '+remote_path],input=data,capture_output=True,timeout=20)
            assert p.returncode==0,p.stderr.decode()
            rows.append({'client_mode':mode,'community_fixture':bool(nets),'manual_destination':bool(manual),'actual_target_nft_check':True})
    print(json.dumps({'ok':True,'cases':rows},ensure_ascii=False))
finally:
    subprocess.run(SSH+['rm -f '+remote_path],capture_output=True,timeout=15)
(ROOT/'dist').mkdir(exist_ok=True)
(ROOT/'dist/scope-tests.json').write_text(json.dumps(rows,indent=2))
