#!/usr/bin/env python3
"""Build reproducible small OpenWrt ipk; does not contact or modify the router."""
import hashlib,io,json,pathlib,shutil,subprocess,tarfile,tempfile,os
ROOT=pathlib.Path(__file__).resolve().parent
VER='0.4.5'
assert f"package_version '{VER}'" in (ROOT/'files/usr/libexec/zapret2-home-ctl').read_text(), 'RPC/build version mismatch'
# External binaries are deliberately not redistributed; see docs/BUILD.md.
for rel,digest in json.loads((ROOT/'runtime-pins.json').read_text()).items():
 asset=ROOT/'files/usr/lib/zapret2-home'/rel
 if not asset.is_file():raise SystemExit(f'Missing runtime asset: {rel}; see docs/BUILD.md')
 if hashlib.sha256(asset.read_bytes()).hexdigest()!=digest:raise SystemExit(f'Runtime pin mismatch: {rel}')
probe=ROOT/'files/usr/lib/zapret2-home/stun-probe'
subprocess.run(['aarch64-linux-gnu-gcc','-Os','-std=c11','-Wall','-Wextra','-Werror','-static','-s','-o',str(probe),str(ROOT/'src/stun-probe.c')],check=True)
manifest=[]
assert hashlib.sha256((ROOT/'files/usr/lib/zapret2-home/nfqws2-quic').read_bytes()).hexdigest()=='5a40e3e823082a5788c7bc7d4e78ed9d2d5c6edb37f4580e300700694adac23b', 'QUIC diagnostic engine pin mismatch'
assert hashlib.sha256((ROOT/'files/usr/lib/zapret2-home/curl-http3').read_bytes()).hexdigest()=='a5b0f6cde4b0e0d6be09bd92ee24fc63f8a3cb20810bc3dc531ee33f0a2d8ae9', 'HTTP3 client pin mismatch'
for rel in ['nfqws2','nfqws2-quic','lua/zapret-lib.lua','lua/zapret-antidpi.lua','lua/hostfakesplit-alt1.lua','profile-catalog.json','protocol-catalog.json','protocols.uc','stun-probe','curl-http3','fake/quic-google.bin','fake/discord-ip-discovery-without-port.bin','fake/stun.bin','../../libexec/zapret2-home-engine']:
 manifest.append(hashlib.sha256((ROOT/'files/usr/lib/zapret2-home'/rel).read_bytes()).hexdigest()+'  '+rel)
(ROOT/'files/usr/lib/zapret2-home/SHA256SUMS').write_text('\n'.join(manifest)+'\n')
required=['usr/lib/zapret2-home/lock.uc','usr/libexec/zapret2-home-engine','usr/lib/zapret2-home/profile-catalog.json','usr/libexec/zapret2-home-profiles','usr/lib/zapret2-home/profiles.uc','www/luci-static/resources/view/services/zapret2home.js','usr/share/luci/menu.d/luci-app-zapret2-home.json','usr/share/rpcd/acl.d/luci-app-zapret2-home.json','usr/share/licenses/zapret2-home/UPSTREAM-LICENSE.txt']
for r in required:assert (ROOT/'files'/r).is_file(),r
# Include the independently tested isolated diagnostics backend.
paths = list((ROOT/'files').rglob('*'))
for p in paths:
 if not p.is_file():continue
 if p.read_bytes().startswith(b'#!/bin/sh'):
  subprocess.run(['sh','-n',str(p)],check=True)
 if p.suffix=='.json':json.loads(p.read_text())
 if p.suffix=='.js':subprocess.run(['node','--check',str(p)],check=True)
 def executable(path):
  return path.read_bytes().startswith(b'#!/') or path.name in ('nfqws2','nfqws2-quic','stun-probe','curl-http3')
 p.chmod(0o755 if executable(p) else 0o644)
control={
 'control':f'''Package: zapret2-home
Version: {VER}
Architecture: aarch64_cortex-a53
Maintainer: Local network operations
Section: net
Priority: optional
Depends: luci-base, rpcd, ucode, ucode-mod-fs, kmod-nft-queue, kmod-nfnetlink-queue, curl, ca-bundle
Description: Scoped zapret2 service with custom native LuCI management
''',
 'conffiles':'/etc/config/zapret2_home\n',
 'postinst':'''#!/bin/sh
[ -n "$IPKG_INSTROOT" ] && exit 0
# Fresh installs stay disabled; upgrades retain the user's rc.d setting.
/etc/init.d/zapret2-home enabled || /etc/init.d/zapret2-home disable || exit 1
ucode /usr/lib/zapret2-home/lock.uc package-finish '' "$$" || exit 1
rm -f /tmp/luci-indexcache
rm -rf /tmp/luci-modulecache
exit 0
''',
 'prerm':'''#!/bin/sh
# Admission-ABI: 1
[ -n "$IPKG_INSTROOT" ] && exit 0
# Freeze and preconditions are one transaction, not a status/check-then-stop.
Z2_LIFECYCLE_TOKEN=$(ucode /usr/lib/zapret2-home/lock.uc package-freeze '' "$$") || exit 1
export Z2_LIFECYCLE_TOKEN
# Retained on removal/failure for explicit root-only recovery; never delete backups.
cp /usr/lib/zapret2-home/lock.uc /var/run/zapret2-home/lifecycle-recovery.uc || exit 1
/etc/init.d/zapret2-home stop || exit 1
case "$1" in upgrade) :;; *) /etc/init.d/zapret2-home disable || exit 1;; esac
exit 0
''',
 'postrm':'''#!/bin/sh
# Admission-ABI: 1
[ -n "$IPKG_INSTROOT" ] && exit 0
rm -f /tmp/luci-indexcache
rm -rf /tmp/luci-modulecache
# Keep admission guard, freeze, configure backups and diagnostic recovery state.
exit 0
'''}
OUT=ROOT/'dist';OUT.mkdir(exist_ok=True)
with tempfile.TemporaryDirectory(prefix='z2-ipk-') as t:
 t=pathlib.Path(t)
 (t/'debian-binary').write_text('2.0\n')
 with tarfile.open(t/'control.tar.gz','w:gz') as a:
  for name,text in control.items():
   b=text.encode();i=tarfile.TarInfo('./'+name);i.size=len(b);i.mode=0o755 if name in ['postinst','prerm','postrm'] else 0o644;i.mtime=0;a.addfile(i,io.BytesIO(b))
 with tarfile.open(t/'data.tar.gz','w:gz') as a:
  for p in sorted(paths):
   name='./'+p.relative_to(ROOT/'files').as_posix()
   if p.is_dir():
    i=tarfile.TarInfo(name+'/');i.type=tarfile.DIRTYPE;i.mode=0o755;i.uid=i.gid=0;i.mtime=0;a.addfile(i)
   elif p.is_file():
    b=p.read_bytes();i=tarfile.TarInfo(name);i.size=len(b);i.mode=p.stat().st_mode&0o777;i.uid=i.gid=0;i.mtime=0;a.addfile(i,io.BytesIO(b))
 out=OUT/f'zapret2-home_{VER}_aarch64_cortex-a53.ipk'
 if out.exists():out.unlink()
 with tarfile.open(out,'w:gz') as outer:
  for name in ['debian-binary','control.tar.gz','data.tar.gz']:
   b=(t/name).read_bytes()
   if name.endswith('.gz'):
    b=b[:4]+bytes(4)+b[8:]
   i=tarfile.TarInfo('./'+name);i.size=len(b);i.mode=0o644;i.mtime=0;outer.addfile(i,io.BytesIO(b))
 b=out.read_bytes();out.write_bytes(b[:4]+bytes(4)+b[8:])
 records={p.relative_to(ROOT/'files').as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in paths if p.is_file()}
 (OUT/'files-manifest.json').write_text(json.dumps(records,indent=2)+'\n')
 modes={p.relative_to(ROOT/'files').as_posix():format(p.stat().st_mode&0o777,'o') for p in paths if p.is_file()}
 (OUT/'file-modes.json').write_text(json.dumps(modes,indent=2)+'\n')
 (OUT/'package.sha256').write_text(hashlib.sha256(out.read_bytes()).hexdigest()+'  '+out.name+'\n')
 print(json.dumps({'package':str(out),'bytes':out.stat().st_size,'files':len(records),'sha256':hashlib.sha256(out.read_bytes()).hexdigest()}))
