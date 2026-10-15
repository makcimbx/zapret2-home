# Fixed community IPv4 list backend: executable contract

Owned implementation files:

- `files/usr/libexec/zapret2-home-lists` (0755)
- `files/usr/libexec/zapret2-home-list-timer` (0755)
- `files/usr/lib/zapret2-home/netlist.uc`
- `files/usr/share/zapret2-home/lists.json`

No controller/frontend/build changes or router installation are part of this work.

## Production commands (after the parent packages/installs these files)

```sh
/usr/libexec/zapret2-home-lists catalog
/usr/libexec/zapret2-home-lists status
/usr/libexec/zapret2-home-lists ensure-idle
/usr/libexec/zapret2-home-lists ensure
/usr/libexec/zapret2-home-lists elements
/usr/libexec/zapret2-home-ctl update_lists
# Internal serialized synchronous operation; no additional arguments accepted:
/usr/libexec/zapret2-home-lists update-run
# Worker child; optional numeric argument pins the owning worker PID:
/usr/libexec/zapret2-home-list-timer "$WORKER_PID"
```

`catalog`: JSON array of `{id,title,description,url}`. Fixed IDs only:
`flowseal cloudflare hetzner cloudfront ovh digitalocean`.

`status`: JSON `{list_state:{ID:{count,updated,sha256,error,source_count,discarded}},update_running:boolean,update_error:string,last_success:integer}`.
`updated` is UNIX seconds of the latest successful selected-source check. Latest
runtime metadata overlays persistent metadata without unchanged-SHA flash writes.
The list snapshot stores timestamps of changed content; a reboot naturally loses
newer runtime-only check timestamps. Errors are bounded to 240 bytes.

`update`: helper async launcher returns exactly `{"ok":true,"pending":true}` only
after a detached child accepts the PID-lock handoff. `pending` is launch acceptance,
not completed download success: observe status/error afterward. Launch failures or
an already active updater return nonzero and JSON `{ok:false,error:...}`. Public
clients and the timer must call controller `update_lists` so the parent's control
lock serializes update launch versus configure. Actual target lacks `nohup`:
BusyBox `start-stop-daemon -S -b -x FIXED_HELPER -- update-run --handoff PID` is the
supported fallback; all stdio is detached, no dependency installation is needed.
The private `--handoff` form is launcher-internal, not a public API.

`ensure-idle`: exit 0 only without a pending/running updater; nonzero while the
PID marker is owned. Kernel-backed `ucode fs.file.lock()` guards stale PID cleanup
and ownership handoff; long-running ownership is
`/var/run/zapret2-home/list-update.lock/pid`.

`ensure`: exits nonzero if any selected cache is missing/invalid, metadata/hash
mismatch, or the selected union exceeds parser bounds. No launch or download.
Missing UCI `zapret2_home.main.lists` means empty selection and success.

`elements`: newline IPv4/CIDR output only, no JSON; all selected reads and the
complete union validate before any stdout. Exact duplicates are removed. Parents
must use an interval nft set with `auto-merge` to handle overlapping networks and
apply its complete replacement atomically after `nft -c`.

## Cache and lifecycle

One fixed HTTPS download at a time; normal certificate validation, no curlrc,
proxy, arbitrary URL, redirect, auth, user profile or user shell. Per download:
60-second total timeout, 15-second connect timeout, 256 KiB/s rate, 2 MiB maximum.
An actual file-size rlimit additionally bounds chunked replies on older curl.
The portable rlimit can be stricter on shells whose `ulimit -f` unit is 512 bytes;
all six currently verified sources are below that stricter bound.

The parser reads <=2 MiB, permits <=60000 IPv4 source entries, requires canonical
IPv4 CIDRs with prefixes 8..32 and octets without leading zeroes, rejects malformed
input/HTML/JSON/NUL/nft and shell injection, skips comments/address-shaped IPv6,
and discards public networks overlapping private/FakeIP/CGNAT/reserved ranges.
Discard counts are explicit. Empty/public-empty lists fail.

Stage every selected source on tmpfs, validate the complete union, recheck the UCI
selection before creating and before committing a snapshot. The protected 0700
persistent cache is `/etc/zapret2-home/lists`, with atomic `current` symlink to
` snapshot.TIMESTAMP.PID` (no leading space in actual names). Changed sources are
written to a coherent new generation; unchanged source data is hardlinked, and an
entirely unchanged update makes zero persistent payload/symlink writes. Preserve
current + previous generation for readers. Failed downloads/parse/empty/size/check
or selection mutation cannot replace current.

After swapping, call only fixed controller `reconcile`, and only if controller
`running` returned success. Failed reconcile restores the previous cache pointer;
parent's atomic nft transaction must leave previous rules unchanged. **Parent
must make reconcile apply-only/no-start**, including a stop race between `running`
and `reconcile`: helper must never resurrect an engine. No routing/sysctl/firewall
ownership beyond that parent's own table is granted.

TERM/INT/HUP cleanup reaps the actual curl PID before clearing long ownership and
rolls back an interrupted swap. SIGKILL cannot execute shell traps; stale owner
markers are reclaimed on the next command. Power-loss/SIGKILL exactly during the
cache/nft commit boundary is not covered by the tested rollback guarantee.

Timer starts only as a worker child after engine/rules readiness. It checks the
owner PID, worker command and requested/stopping markers; auto_update false or no
selected IDs causes no job. On startup it updates only selected cache timestamps
older than 24h (future timestamps trigger refresh after clock correction). It then
waits 24h between attempts, in 30s liveness-check increments. Worker normal stop
kills+waits timer; timer traps reap its sleeps/controller child but do not kill the
accepted detached updater. A dead worker is noticed within 30 seconds.

## Local tests and historical evidence

See [README.md](README.md) for portable dependency setup and commands. Run
`python3 tests/lists_validator.py` and `python3 tests/lists.test.py` locally;
`UCODE`, `UCODE_MODULE_DIR`, `JSHN`, and `JSHN_SH` override installed runtimes.
`--remote` and `--fetch` are opt-in live tests, not part of the local gate.

Results: actual local parser 24/24; actual target router parser + six real HTTPS
sources 30/30; sandbox backend/timer 34/34. Backend tests use **explicit mocked
network/UCI/controller/nft failure**, but actual ucode, native libubox jshn, BusyBox
ash/SSD, filesystem, limits, PID handoff, sleeps, process termination and cache
rollback. No production nft transaction or timer was installed/run on the router.

Real source accepted counts: Flowseal 26037, Cloudflare 15, Hetzner 81,
CloudFront 211, OVH 630, DigitalOcean 167. Flowseal raw 539879 bytes, 26038 IPv4
source entries, 1 discarded reserved network, 7011 skipped comment/empty/IPv6
lines. Verified retained networks contain GitLab 65.108.59.85,
OpenUPM 107.175.71.2, Exa 216.150.1.1 and Tavily 52.85.154.99.

Found and fixed through actual tests: POSIX regex silently stops at embedded NUL,
so raw NUL rejection precedes trim/match. Atomic rollback necessarily changes the
`current` symlink mtime; tests assert restored pointer and unchanged bytes/inodes,
not the impossible promise that rollback does not write that pointer. BusyBox
ash can resolve applets before PATH mocks; launch-failure fault uses an explicit
mock executable path. Four `Terminated` diagnostic lines in sandbox output are
intentional worker termination, not failed assertions.
