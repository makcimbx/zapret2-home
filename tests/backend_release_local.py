#!/usr/bin/env python3
"""Reproduce backend-only local release evidence; never calls remote test runners."""
import concurrent.futures,hashlib,json,os,pathlib,re,subprocess,sys,time
ROOT=pathlib.Path(__file__).resolve().parents[1];OUT=ROOT/'dist/backend-release-local';OUT.mkdir(parents=True,exist_ok=True)
commands={name:[sys.executable,'tests/'+name+'.test.py'] for name in ('active_config','lifecycle','admission','install_transaction','legacy_transition','profiles','protocol_runtime','protocol_diagnostics','protocol_status_ui','stun_probe','protocol_rpc','install_protocols','package_protocols','http3_client','quic_gso')}
commands['lists']=[sys.executable,'tests/lists.test.py']
commands['local_harness']=[sys.executable,'tests/local_harness.test.py']
commands['audit_fixes']=[sys.executable,'tests/audit_fixes.py']
paths=[p for p in (ROOT/'files').rglob('*') if p.is_file() and p.suffix!='.js']+list((ROOT/'src').glob('*.c'))+[ROOT/x for x in ('build.py','runtime-pins.json','install.py','install_live.py')]+[ROOT/c[1] for c in commands.values()]+[pathlib.Path(__file__)]
paths += [ROOT/'tests/fixtures/protocols-status-legacy-router.json',ROOT/'files/www/luci-static/resources/view/services/zapret2home.js',ROOT/'tests/local_env.py',ROOT/'tests/stun_peer_fixture.py',ROOT/'tests/http3_peer_fixture.py',ROOT/'tests/quic_gso_peer_fixture.py']
def hashes():return {str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}
before=hashes()
def run(entry):
 name,command=entry;start=time.monotonic();log=OUT/(name+'.log')
 error=None
 with log.open('w') as output:
  try:
   p=subprocess.run(command,cwd=ROOT,stdout=output,stderr=subprocess.STDOUT,text=True,timeout=540)
   exit_code=p.returncode
  except (OSError,subprocess.TimeoutExpired) as exc:
   exit_code=124 if isinstance(exc,subprocess.TimeoutExpired) else 127
   error=str(exc);output.write('\nHARNESS ERROR: '+error+'\n')
 text=log.read_text()
 count=None;m=re.search(r'Ran (\d+) tests? in ',text)
 if m:count=int(m[1])
 else:
  for line in text.splitlines():
   try:value=json.loads(line)
   except ValueError:continue
   if isinstance(value,dict) and 'passed' in value:count=value['passed']
  m=re.search(r'AUDIT_FIXES_PASS (\d+)',text) or re.search(r'backend/timer: (\d+)/\1 sandbox tests passed',text)
  if m:count=int(m[1])
  if count is None:
   passed_lines=re.findall(r'^PASS\s',text,re.M)
   if passed_lines:count=len(passed_lines)
 result={'command':command,'exit_code':exit_code,'error':error,'passed':count if exit_code==0 else None,'seconds':round(time.monotonic()-start,3),'log':str(log.relative_to(ROOT)),'log_sha256':hashlib.sha256(log.read_bytes()).hexdigest()}
 print(name,json.dumps(result),flush=True);return name,result
with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:results=dict(pool.map(run,commands.items()))
after=hashes();ok=before==after and all(v['exit_code']==0 and v['passed'] is not None for v in results.values())
evidence={'scope':'SOURCE-ONLY local fixtures. No router/network calls. Real ash/ucode/jshn/flock/proc identities; UCI/nft/engine/network/procd doubles explicitly labelled in suites. Real nft syntax is namespace-only.','all_passed':ok,'passed_total':sum(v['passed'] or 0 for v in results.values()),'suites':results,'source_unchanged':before==after,'source_sha256':after,'legacy_maintenance':'BLOCKED: no safe bootstrap/override provided; legacy_transition tests are counterexamples, not migration proof. Explicit own-service downtime approval and independently guaranteed offline own-mutator quiescence with external verified recovery are required.'}
(OUT/'summary.json').write_text(json.dumps(evidence,ensure_ascii=False,indent=2)+'\n');print('BACKEND_LOCAL_RELEASE',ok,evidence['passed_total'],flush=True)
sys.exit(0 if ok else 1)
