#!/usr/bin/env python3
"""Real lists/scope RPC and bounded forwarded canary. Never activates all-client scope."""
import ast,json,pathlib,time,subprocess,ipaddress
ROOT=pathlib.Path(__file__).resolve().parents[1]
SSH=['ssh','-o','BatchMode=yes','-o','ConnectTimeout=7','root@192.168.1.1']
URL='https://gitlab.hotreload.net/assets/webpack/main.4e9cbf4e.chunk.js'
rows=[];controls=[]
module=ast.parse((ROOT/'tests/lifecycle_lan.py').read_text())
exec(compile(ast.Module(body=[n for n in module.body if isinstance(n,(ast.Import,ast.ImportFrom,ast.FunctionDef))],type_ignores=[]),'lifecycle_helpers','exec'))
original=rpc('status');before=remote('sha256sum /etc/config/podkop /etc/sing-box/config.json /etc/config/firewall; pidof sing-box')
keys=['clients','destinations','autostart','client_mode','lists','auto_update']
original_cfg={k:original[k] for k in keys}
evidence={'checks':[], 'original':original}
def configure(**change):
 c=dict(original_cfg);c.update(change);r=rpc('configure',c);assert r.get('ok'),r;return c
try:
 assert not original['running'] and not original['autostart']
 vpn('lists-before')
 configure(client_mode='all',clients='',lists='',destinations='65.108.59.85/32')
 assert rpc('status')['client_mode']=='all'
 check=rpc('check');assert check.get('ok'),check
 evidence['checks'].append({'all_clients_saved_without_activation':True,'nft_check':check})
 invalid=rpc('configure',dict(original_cfg,clients='',client_mode='selected'))
 assert not invalid.get('ok'),invalid
 evidence['checks'].append({'empty_selected_rejected':invalid})
 configure(client_mode='selected',clients='192.168.1.20/32',destinations='',lists='flowseal cloudflare hetzner cloudfront ovh digitalocean',auto_update=False)
 r=rpc('update_lists');assert r.get('ok'),r
 for n in range(180):
  s=rpc('status')
  if not s['update_running']:break
  time.sleep(1)
 else:raise AssertionError('List updater deadline exceeded')
 assert not s.get('update_error'),s
 evidence['list_status']=s
 assert all(s['list_state'][k]['count']>0 for k in ['flowseal','cloudflare','hetzner','cloudfront','ovh','digitalocean']),s['list_state']
 configure(client_mode='selected',clients='192.168.1.20/32',destinations='',lists='flowseal',auto_update=False)
 check=rpc('check');assert check['ok'],check
 gitlab('lists-direct')
 start=rpc('control',{'action':'start'});assert start.get('ok'),start
 for n in range(2):
  r=gitlab('lists-on-'+str(n))
  assert r['exit']==0 and r['size_download']==1008147 and r['sha256']=='5053a171a0c992f64cc32266e635101af57d3df66509d0a0cb311a36d0fe3777',r
 s=rpc('status');assert s['running'] and 'counter packets 0 bytes 0 queue' not in s['rule_counters'],s
 evidence['active_status']=s
 evidence['nft_membership']=remote("nft get element inet zapret2_home destinations '{ 65.108.59.85 }'")
 vpn('lists-during')
 r=rpc('control',{'action':'stop'});assert r.get('ok'),r
 vpn('lists-after')
finally:
 rpc('control',{'action':'stop'});rpc('control',{'action':'disable'})
 # Restore the existing bounded selection; caches remain available for the user.
 r=rpc('configure',original_cfg);assert r.get('ok'),r
 after=remote('sha256sum /etc/config/podkop /etc/sing-box/config.json /etc/config/firewall; pidof sing-box')
 assert after==before,(before,after)
 evidence.update(rows=rows,vpn_controls=controls,production_before=before,production_after=after,final_status=rpc('status'))
 (ROOT/'dist/lists-lan-results.json').write_text(json.dumps(evidence,ensure_ascii=False,indent=2))
print(json.dumps({'list_counts':{k:v['count'] for k,v in evidence['list_status']['list_state'].items()},'production_unchanged':True,'final_running':evidence['final_status']['running']},ensure_ascii=False))
