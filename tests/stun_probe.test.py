#!/usr/bin/env python3
"""Native parser, CLI and socket IO; private namespace, never external network."""
import os, pathlib, subprocess, sys, tempfile
ROOT = pathlib.Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory(dir=tempfile.gettempdir()) as d:
    exe = pathlib.Path(d)/'stun-probe'
    subprocess.run(['gcc','-std=c99','-Wall','-Wextra','-Werror','-O2',str(ROOT/'src/stun-probe.c'),'-o',str(exe)],check=True)
    p=subprocess.run([str(exe),'--selftest'],capture_output=True,text=True,check=True)
    assert p.stdout.strip()=='STUN selftest passed',p
    for args in [[],['12599'],['12660'],['12600x'],['12600','74.125.250.129'],['+12600'],[' 12600']]:
        p=subprocess.run([str(exe),*args],capture_output=True,text=True)
        assert p.returncode!=0 and not p.stdout,args
    subprocess.run(['aarch64-linux-gnu-gcc','-Os','-std=c11','-Wall','-Wextra','-Werror','-static','-s',str(ROOT/'src/stun-probe.c'),'-o',str(pathlib.Path(d)/'stun-probe-aarch64')],check=True)
    subprocess.run(['unshare','-Urn',sys.executable,str(ROOT/'tests/stun_peer_fixture.py'),str(exe)],check=True,timeout=15)
print('PASS native STUN parser, strict fixed-port CLI and static aarch64 compilation (no external network)')
