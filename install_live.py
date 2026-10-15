#!/usr/bin/env python3
"""Gated own-package upgrade including original running/stopped intent restore.
Never downgrade through legacy hooks automatically; failures retain recovery.
"""
import json
from install import ROOT,install,snap

def main():
 before=snap();evidence={'restored':False}
 try:
  original,final=install(upgrade=True,live=True)
  evidence.update(initial=original,final=final,restored=True)
 except Exception as error:
  evidence['error']=str(error)
  raise
 finally:
  evidence['production_before']=before;evidence['production_after']=snap()
  (ROOT/'dist/live-upgrade-results.json').write_text(json.dumps(evidence,ensure_ascii=False,indent=2))
 print('LIVE_UPGRADE_PRESERVED',json.dumps(evidence['final'],ensure_ascii=False))
if __name__=='__main__':main()
