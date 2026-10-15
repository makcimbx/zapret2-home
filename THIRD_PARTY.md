# Third-party components

The project MIT license covers original project code only. Upstream files retain their original licenses and notices.

- **zapret2 v1.0.5.2**, commit `6b6c63e3385fa73f8af3be4a69171e947f5a319d`: upstream Lua, small fake-packet data and adapted `hostfakesplit-alt1.lua`. Source: https://github.com/bol-van/zapret2/tree/v1.0.5.2 . MIT notice: `files/usr/share/licenses/zapret2-home/UPSTREAM-LICENSE.txt`.
- **Private GSO engine patch**: `files/usr/share/licenses/zapret2-home/quic-diagnostics/nfqa-gso.patch`. Dependency notices and source hashes are kept beside it / in `files/usr/share/zapret2-home/quic-diagnostic-engine.json`. No compiled engine is distributed by this repository.
- **static-curl 8.23.0**: provenance and pinned archive/ELF hashes in `files/usr/share/zapret2-home/http3-client.json`; component notices under `files/usr/share/licenses/zapret2-home/http3/`. No curl ELF, archives or static libraries are distributed here.
- **LuCI/OpenWrt assets used by offline browser tests** are external fixture inputs, not bundled theme assets. They retain upstream licenses.

## Binary redistribution is deliberately not enabled

The recorded private static builds have unresolved corresponding-source/relinking compliance work, including GPL/LGPL libraries and toolchain inventory. Adjacent copyright notices and upstream links are provenance, **not** a complete compliance claim or source offer. Local IPKs and binary inputs are ignored by Git; this project does not upload them to GitHub Releases or CI artifacts. Complete the applicable obligations before distributing a binary package.
