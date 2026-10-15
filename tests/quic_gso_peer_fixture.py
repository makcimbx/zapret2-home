"""Real I/O only; run via quic_gso.test.py, never in the host network namespace."""
import asyncio
import hashlib
import json
import os
import re
import signal
import socket
import struct
import subprocess
import sys
from pathlib import Path

from aioquic.asyncio import serve
from aioquic.h3.connection import H3_ALPN
from aioquic.quic.configuration import QuicConfiguration
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from http3_peer_fixture import BODY, Server, certificate

ROOT = Path(__file__).resolve().parents[1]
LIB = ROOT / 'files/usr/lib/zapret2-home'
from local_env import NFQWS2_GSO_NATIVE as ENGINE
QUEUE = Path('/proc/net/netfilter/nfnetlink_queue')
RULES = '''table ip quic_gso_test {
 chain output {
  type filter hook output priority mangle; policy accept;
  meta skuid 32771 oifname "lo" ip daddr 127.0.0.1 udp dport 18443 counter queue num 215 bypass
 }
}
'''


def queue_row(pid):
    for line in QUEUE.read_text().splitlines():
        fields = [int(v) for v in line.split()]
        if fields[0] == 215:
            assert fields[1] == pid, fields
            return fields
    return None


def stop(proc):
    if proc.returncode is None:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=3)


async def main():
    # Refuse direct invocation in the caller's netns before touching nft or interfaces.
    assert len(sys.argv) == 2 and os.readlink('/proc/self/ns/net') != sys.argv[1]
    links = json.loads(subprocess.check_output(['ip', '-j', 'link'], text=True))
    assert [link['ifname'] for link in links] == ['lo'], links
    assert not subprocess.check_output(['ip', 'route', 'show']).strip()
    assert not subprocess.check_output(['nft', 'list', 'ruleset']).strip()
    subprocess.run(['ip', 'link', 'set', 'lo', 'up'], check=True)
    assert not QUEUE.read_text().strip()

    args = [str(ENGINE), '--debug=@nfqws2.log', '--uid=0:0', '--qnum=215',
            '--lua-init=@' + str(LIB / 'lua/zapret-lib.lua'),
            '--lua-init=@' + str(LIB / 'lua/zapret-antidpi.lua'),
            '--blob=quic_google:@' + str(LIB / 'fake/quic-google.bin'),
            '--reasm-disable=quic_initial', '--filter-udp=18443', '--filter-l7=quic',
            '--in-range=x', '--out-range=-n6', '--payload=quic_initial',
            '--lua-desync=fake:blob=quic_google:repeats=6']
    log_path = Path('nfqws2.log')
    results, captures = [], []
    engine = server = capture = None
    loop = asyncio.get_running_loop()
    with Path('nfqws2-stderr.log').open('w') as log:
        try:
            engine = subprocess.Popen(args, stdout=log, stderr=subprocess.STDOUT)
            deadline = loop.time() + 5
            while True:
                debug = log_path.read_text() if log_path.exists() else ''
                assert engine.poll() is None, debug + Path('nfqws2-stderr.log').read_text()
                if queue_row(engine.pid) and 'receive buffer size' in debug:
                    break
                assert loop.time() < deadline, debug
                await asyncio.sleep(0.02)
            assert engine.poll() is None
            ready_row = queue_row(engine.pid)
            assert "binding this socket to queue '215'" in log_path.read_text(), log_path.read_text()
            assert "can't set queue flags" not in log_path.read_text()
            subprocess.run(['nft', '-f', '-'], input=RULES, text=True, check=True)
            rules = subprocess.check_output(['nft', 'list', 'table', 'ip', 'quic_gso_test'], text=True)
            assert '32771' in rules and '215' in rules and '127.0.0.1' in rules, rules

            # virtio_net_hdr exposes actual kernel GSO metadata, not a length-based guess.
            capture = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
            capture.setsockopt(263, 15, 1)  # SOL_PACKET, PACKET_VNET_HDR
            capture.bind(('lo', 0))
            capture.setblocking(False)
            fake = (LIB / 'fake/quic-google.bin').read_bytes()

            def drain_capture():
                while True:
                    try:
                        data, address = capture.recvfrom(65536)
                    except BlockingIOError:
                        return
                    if address[2] != socket.PACKET_OUTGOING or len(data) < 52:
                        continue
                    _, gso_type, _, gso_size, _, _ = struct.unpack_from('<BBHHHH', data)
                    ip = data[24:]  # ten-byte virtio header, fourteen-byte loopback Ethernet header
                    if data[22:24] != b'\x08\x00' or ip[9] != 17 or ip[16:20] != b'\x7f\x00\x00\x01':
                        continue
                    ihl = (ip[0] & 15) * 4
                    if len(ip) < ihl + 8:
                        continue
                    sport, dport, length = struct.unpack_from('!HHH', ip, ihl)
                    if dport == 18443:
                        captures.append({'sport': sport, 'udp_length': length,
                                         'gso_type': gso_type, 'gso_size': gso_size,
                                         'google_fake': ip[ihl + 8:] == fake})

            loop.add_reader(capture.fileno(), drain_capture)
            ca_key = ec.generate_private_key(ec.SECP256R1())
            ca = certificate(ca_key, 'private GSO test CA', ca=True)
            key = ec.generate_private_key(ec.SECP256R1())
            wrong_key = ec.generate_private_key(ec.SECP256R1())
            wrong_ca = certificate(wrong_key, 'untrusted CA', ca=True)
            config = QuicConfiguration(is_client=False, alpn_protocols=H3_ALPN)
            config.certificate = certificate(key, 'localhost', ca, ca_key)
            config.private_key = key
            server = await serve('127.0.0.1', 18443, configuration=config, create_protocol=Server)
            for label, trust, hostname, expected in [
                ('trusted_ca', ca, 'localhost', 0),
                ('untrusted_ca_rejected', wrong_ca, 'localhost', 60),
                ('wrong_hostname_rejected', ca, 'wrong.invalid', 60),
            ]:
                fd = os.memfd_create('private-gso-ca')
                proc = None
                start = len(log_path.read_text())
                captured_start = len(captures)
                try:
                    os.write(fd, trust.public_bytes(serialization.Encoding.PEM))
                    command = ['./curl', '-q', '--noproxy', '*', '--http3-only',
                               '--cacert', f'/proc/self/fd/{fd}', '--resolve', f'{hostname}:18443:127.0.0.1',
                               '--max-time', '5', '--silent', '--show-error', '--write-out',
                               '\nHTTP_VERSION=%{http_version} CODE=%{http_code} SSL_VERIFY=%{ssl_verify_result}\n',
                               f'https://{hostname}:18443/']
                    # Keep the engine owner root; only curl uses the isolated, non-shared UID.
                    proc = await asyncio.create_subprocess_exec(
                        *command, user=32771, group=32771, extra_groups=[], pass_fds=(fd,),
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, env={'PATH': '/usr/bin:/bin'})
                    stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=8)
                    drain_capture()
                    phase_log = log_path.read_text()[start:]
                    callbacks = len(re.findall(r'^packet: id=\d+ len=', phase_log, re.M))
                    fake_logs = len(re.findall(r'^LUA: fake: ', phase_log, re.M))
                    fake_count = sum(c['google_fake'] for c in captures[captured_start:])
                    result = {'test': label, 'uid': 32771, 'gid': 32771,
                              'returncode': proc.returncode, 'stdout': stdout.decode(), 'stderr': stderr.decode(),
                              'callback_count': callbacks, 'fake_log_count': fake_logs,
                              'fake_packets_captured': fake_count}
                    results.append(result)
                    assert proc.returncode == expected, result
                    assert callbacks > 0 and fake_logs > 0 and fake_count == fake_logs * 6, (result, phase_log)
                    assert engine.poll() is None, log_path.read_text()
                    if expected == 0:
                        body, metadata = stdout.rsplit(b'\nHTTP_VERSION=', 1)
                        assert metadata == b'3 CODE=200 SSL_VERIFY=0\n', result
                        assert body == BODY, result
                        result['body_sha256'] = hashlib.sha256(body).hexdigest()
                finally:
                    if proc is not None and proc.returncode is None:
                        proc.terminate()
                        try:
                            await asyncio.wait_for(proc.wait(), timeout=3)
                        except asyncio.TimeoutError:
                            proc.kill()
                            await proc.wait()
                    os.close(fd)
            stats = queue_row(engine.pid)
            assert stats is not None and stats[5:7] == [0, 0], stats
            rules = subprocess.check_output(['nft', 'list', 'table', 'ip', 'quic_gso_test'], text=True)
        finally:
            if server is not None:
                server.close()
            if capture is not None:
                loop.remove_reader(capture.fileno())
                capture.close()
            if engine is not None:
                stop(engine)
    debug = log_path.read_text()
    assert not queue_row(engine.pid)
    callbacks = re.findall(r'^packet: id=\d+ len=(\d+).*$', debug, re.M)
    assert int(re.search(r'counter packets (\d+)', rules)[1]) == len(callbacks), rules
    evidence_lines = [line for line in debug.splitlines() if
                      re.match(r'packet: id=\d+ len=|UDP: len=|LUA: fake: |rawsend', line)]
    print(json.dumps({
        'passed': True, 'network': 'private netns; loopback only; no TCP fallback or external traffic',
        'queue': 215, 'engine_pid': engine.pid, 'ready_queue_row': ready_row,
        'engine_command': args, 'engine_reaped': engine.returncode is not None,
        'queue_drops': stats[5:7], 'nft_readback': rules, 'results': results,
        'callback_count': len(callbacks), 'callback_ip_lengths': [int(n) for n in callbacks],
        'fake_log_count': sum(r['fake_log_count'] for r in results),
        'fake_packets_captured': sum(c['google_fake'] for c in captures),
        'outgoing_udp_captures': len(captures),
        'gso_aggregates': [c for c in captures if c['gso_type'] and c['gso_size']],
        'gso_note': 'Observed metadata only; aggregate delivery is host-kernel dependent, not a required baseline failure.',
        'engine_debug_evidence': evidence_lines,
        'limits': 'Local integration regression, not router NSS, DPI-bypass, or throughput proof.',
    }, indent=2))


if __name__ == '__main__':
    def terminate(signum, frame):
        raise SystemExit(128 + signum)

    signal.signal(signal.SIGTERM, terminate)
    asyncio.run(main())
