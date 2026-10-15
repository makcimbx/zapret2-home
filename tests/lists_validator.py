#!/usr/bin/env python3
"""Actual ucode parser tests; --remote writes only an owned temporary /tmp file.
Real HTTPS source validation is opt-in --fetch; no router installation/update.
"""
import argparse, hashlib, ipaddress, json, os, pathlib, shlex, subprocess, time
ROOT = pathlib.Path(__file__).resolve().parents[1]
PARSER = ROOT / 'files/usr/lib/zapret2-home/netlist.uc'
p = argparse.ArgumentParser()
p.add_argument('--ucode', default=os.environ.get('UCODE', 'ucode'))
p.add_argument('--module-dir', default=os.environ.get('UCODE_MODULE_DIR'))
p.add_argument('--remote', help='SSH destination, e.g. root@192.168.1.1')
p.add_argument('--fetch', action='store_true')
p.add_argument('--results', type=pathlib.Path)
a = p.parse_args()
ssh = ['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=7', a.remote] if a.remote else None
remote_path = f'/tmp/hermes-z2-netlist-{os.getpid()}.uc'
results = []

def run(raw, mode='check'):
    if ssh:
        cmd = ssh + [f'ucode {shlex.quote(remote_path)} {mode}']
    else:
        cmd = [a.ucode] + (['-L', a.module_dir] if a.module_dir else []) + [str(PARSER), mode]
    return subprocess.run(cmd, input=raw.encode() if isinstance(raw, str) else raw,
                          capture_output=True, timeout=120)

def case(name, raw, expected, count=None, discarded=None):
    r = run(raw)
    assert (r.returncode == 0) == expected, (name, r.returncode, r.stdout, r.stderr)
    if expected:
        v = json.loads(r.stdout)
        assert v['ok'] and (count is None or v['count'] == count), (name, v)
        assert discarded is None or v['discarded'] == discarded, (name, v)
        e = run(raw, 'elements')
        assert e.returncode == 0 and not e.stderr, (name, e.stderr)
        for line in e.stdout.decode().splitlines():
            n = ipaddress.ip_network(line, strict=True)
            assert n.version == 4 and 8 <= n.prefixlen <= 32
    else:
        assert not r.stdout and json.loads(r.stderr)['ok'] is False, (name, r.stdout, r.stderr)
    results.append({'name': name, 'passed': True})
    print('PASS '+name, flush=True)

try:
    if ssh:
        r = subprocess.run(ssh + [f'umask 077; dd of={remote_path} 2>/dev/null'],
                           input=PARSER.read_bytes(), capture_output=True, timeout=20)
        assert r.returncode == 0, r.stderr
    case('four verified service addresses', '65.108.59.85\n107.175.71.2\n216.150.1.1\n52.85.154.99\n', True, 4)
    case('POSIX regex, CRLF, dedup, comments and IPv6', '# hi\r\n65.108.0.0/16\r\n65.108.0.0/16\n65.108.59.85\n65.108.59.85/32\n2606:4700::/32\n', True, 2)
    case('minimum /8', '11.0.0.0/8\n', True, 1)
    excluded = ['0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8',
                '169.254.0.0/16', '172.16.0.0/12', '192.0.0.0/24', '192.0.2.0/24',
                '192.88.99.0/24', '192.168.0.0/16', '198.18.0.0/15',
                '198.51.100.0/24', '203.0.113.0/24', '224.0.0.0/8', '240.0.0.0/8',
                '100.0.0.0/8', '169.0.0.0/8', '172.0.0.0/8', '192.0.0.0/8',
                '198.0.0.0/8', '203.0.0.0/8']
    case('all reserved ranges + broad overlap rejected', '\n'.join(excluded + ['65.108.59.85']), True, 1, len(excluded))
    for name, text in [
        ('empty', ''), ('comments only', '# no addresses\n'),
        ('IPv6 only', '2606:4700::/32\n'), ('private only', '10.0.0.0/8\n'),
        ('host bits', '65.108.59.85/16\n'), ('leading octet zero', '065.108.59.85\n'),
        ('leading prefix zero', '65.0.0.0/08\n'), ('bad octet', '999.108.59.85\n'),
        ('wide prefix', '0.0.0.0/0\n'), ('narrow prefix', '65.108.59.85/33\n'),
        ('nft injection', '65.108.59.85\n}; flush ruleset; #\n'),
        ('shell injection', '65.108.59.85; touch /tmp/X\n'),
        ('IPv6 injection', '::1; flush ruleset\n'), ('NUL', '65.108.59.85\x00\n'),
        ('JSON input', '{"elements":["65.108.59.85"]}\n'),
        ('HTML error', '<html>503</html>\n'), ('inline junk', '65.108.59.85 # bad\n'),
    ]:
        case(name, text, False)
    case('60000 source entries accepted/deduped', '65.108.59.85\n' * 60000, True, 1)
    case('60001 source entries rejected', '65.108.59.85\n' * 60001, False)
    case('2 MiB hard read bound', b'#' * 2097153, False)
    if a.fetch:
        catalog = json.loads((ROOT / 'files/usr/share/zapret2-home/lists.json').read_text())
        for item in catalog:
            start = time.monotonic()
            r = subprocess.run(['curl', '-q', '--proxy', '', '--proto', '=https', '--tlsv1.2',
                                '--fail', '--silent', '--show-error', '--max-time', '60',
                                '--limit-rate', '256K', '--max-filesize', '2097152', item['url']],
                               capture_output=True, timeout=70)
            assert r.returncode == 0, (item['id'], r.stderr)
            v = run(r.stdout)
            assert v.returncode == 0, (item['id'], v.stderr)
            meta = json.loads(v.stdout)
            assert meta['count'] > 0
            normalized = run(r.stdout, 'elements')
            assert normalized.returncode == 0
            nets = [ipaddress.ip_network(x) for x in normalized.stdout.decode().splitlines()]
            covers = {}
            if item['id'] == 'flowseal':
                for ip in ['65.108.59.85', '107.175.71.2', '216.150.1.1', '52.85.154.99']:
                    covers[ip] = any(ipaddress.ip_address(ip) in n for n in nets)
                assert all(covers.values()), covers
            row = dict(name='real HTTPS ' + item['id'], passed=True, bytes=len(r.stdout),
                       sha256_raw=hashlib.sha256(r.stdout).hexdigest(),
                       sha256_normalized=hashlib.sha256(normalized.stdout).hexdigest(),
                       metadata=meta, covers=covers, seconds=round(time.monotonic()-start, 3))
            results.append(row)
            print(json.dumps(row, ensure_ascii=False), flush=True)
    print(f'actual {"router" if ssh else "local"} ucode parser: {len(results)}/{len(results)} passed')
    if a.results:
        a.results.write_text(json.dumps({'runtime': a.remote or a.ucode, 'tests': results}, indent=2) + '\n')
finally:
    if ssh:
        subprocess.run(ssh + [f'rm -f {remote_path}'], check=True, timeout=20)
