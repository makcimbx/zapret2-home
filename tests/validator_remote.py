#!/usr/bin/env python3
import pathlib, subprocess, json
ROOT=pathlib.Path(__file__).resolve().parents[1]
SSH=['ssh','-o','BatchMode=yes','-o','ConnectTimeout=7','root@192.168.1.1']
p=ROOT/'files/usr/lib/zapret2-home/validate.uc'
r=subprocess.run(SSH+['dd of=/tmp/hermes-z2-validate.uc 2>/dev/null'],input=p.read_bytes(),capture_output=True);assert r.returncode==0,r.stderr
fixtures=[
({'clients':'192.168.1.20/32','destinations':'65.108.59.85/32','autostart':False},True),
({'clients':'192.168.1.0/24','destinations':'65.108.0.0/16','autostart':True},True),
({'clients':'192.168.1.20,192.168.1.21','destinations':'65.108.59.85 107.175.71.2','autostart':False},True),
({'clients':'0.0.0.0/0','destinations':'65.108.59.85','autostart':False},False),
({'clients':'192.168.1.20; touch /tmp/X','destinations':'65.108.59.85','autostart':False},False),
({'clients':'192.168.1.20/24','destinations':'65.108.59.85','autostart':False},False),
({'clients':'192.168.1.20','destinations':'198.18.0.0/16','autostart':False},False),
({'clients':'192.168.1.20','destinations':'1.1.1.1/0','autostart':False},False),
({'clients':'192.168.1.20','destinations':'65.108.59.85','autostart':'false'},False),
({'clients':'192.168.1.20','destinations':'65.108.59.85','autostart':False,'args':'--danger'},False),
({'clients':'192.168.1.20','destinations':'65.108.59.85\nflush ruleset','autostart':False},False),
({'clients':'192.168.001.20','destinations':'65.108.59.85','autostart':False},False),
({'clients':'','destinations':'','autostart':False,'client_mode':'all','lists':'flowseal','auto_update':True},True),
({'clients':'','destinations':'65.108.59.85','autostart':False,'client_mode':'selected'},False),
({'clients':'192.168.1.20','destinations':'','autostart':False,'lists':'cloudflare hetzner'},True),
({'clients':'','destinations':'','autostart':False,'client_mode':'all','lists':''},False),
({'clients':'192.168.1.20','destinations':'','autostart':False,'lists':'flowseal;touch /tmp/X'},False),
({'clients':'192.168.1.20','destinations':'65.108.59.85','autostart':False,'client_mode':'any'},False),
({'clients':'192.168.1.20','destinations':'65.108.59.85','autostart':False,'auto_update':'true'},False),
({'clients':'','destinations':'65.108.59.85/32 107.175.71.2/32 52.85.154.99/32','autostart':True,'client_mode':'all','lists':'','auto_update':False,'ubus_rpc_session':'0123456789abcdef0123456789abcdef'},True),
({'clients':'192.168.1.20','destinations':'65.108.59.85','autostart':False,'ubus_rpc_session':'00000000000000000000000000000000'},True),
({'clients':'192.168.1.20','destinations':'65.108.59.85','autostart':False,'ubus_rpc_session':True},False),
({'clients':'192.168.1.20','destinations':'65.108.59.85','autostart':False,'ubus_rpc_session':'invalid'},False),
({'clients':'192.168.1.20','destinations':'65.108.59.85','autostart':False,'ubus_rpc_session':'0'*32,'args':'--danger'},False),
]
try:
 for x,expected in fixtures:
  r=subprocess.run(SSH+['ucode /tmp/hermes-z2-validate.uc'],input=json.dumps(x).encode(),capture_output=True)
  result=json.loads(r.stdout)
  assert (r.returncode==0)==expected,(x,r.stdout,r.stderr)
  assert result['ok']==expected,(x,result)
 print(f'validator: {len(fixtures)}/{len(fixtures)} actual ucode tests passed')
finally: subprocess.run(SSH+['rm -f /tmp/hermes-z2-validate.uc'],check=True)
