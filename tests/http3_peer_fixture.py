"""Loopback-only QUIC proof; invoke inside a fresh netns with an unused non-root UID."""
import asyncio
import datetime
import json
import os
import subprocess
from pathlib import Path

from aioquic.asyncio import QuicConnectionProtocol, serve
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

ROOT = Path.cwd()
CURL = './curl'
BODY = b'private-static-curl-http3-validation\n'


def certificate(key, name, issuer=None, issuer_key=None, ca=False):
    now = datetime.datetime.now(datetime.timezone.utc)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    builder = (x509.CertificateBuilder().subject_name(subject)
               .issuer_name(issuer.subject if issuer else subject)
               .public_key(key.public_key()).serial_number(x509.random_serial_number())
               .not_valid_before(now - datetime.timedelta(minutes=5))
               .not_valid_after(now + datetime.timedelta(days=1))
               .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
    if not ca:
        builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost')]), critical=False)
    return builder.sign(issuer_key or key, hashes.SHA256())


class Server(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.http = H3Connection(self._quic)

    def quic_event_received(self, event):
        for http_event in self.http.handle_event(event):
            if isinstance(http_event, HeadersReceived):
                self.http.send_headers(http_event.stream_id, [(b':status', b'200'), (b'content-length', str(len(BODY)).encode())])
                self.http.send_data(http_event.stream_id, BODY, end_stream=True)
                self.transmit()


async def main():
    os.chdir(ROOT)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca = certificate(ca_key, 'local isolated validation CA', ca=True)
    key = ec.generate_private_key(ec.SECP256R1())
    cert = certificate(key, 'localhost', ca, ca_key)
    wrong_key = ec.generate_private_key(ec.SECP256R1())
    wrong_ca = certificate(wrong_key, 'untrusted CA', ca=True)
    config = QuicConfiguration(is_client=False, alpn_protocols=H3_ALPN)
    config.certificate = cert
    config.private_key = key
    server = await serve('127.0.0.1', 18443, configuration=config, create_protocol=Server)
    os.setgroups([])
    os.setgid(32771)
    os.setuid(32771)
    assert os.getuid() == 32771 and os.getgid() == 32771
    results = []
    try:
        for label, trust, hostname, expected in [
            ('trusted_ca', ca, 'localhost', 0),
            ('untrusted_ca_rejected', wrong_ca, 'localhost', 60),
            ('wrong_hostname_rejected', ca, 'wrong.invalid', 60),
        ]:
            fd = os.memfd_create('local-http3-ca')
            try:
                os.write(fd, trust.public_bytes(serialization.Encoding.PEM))
                args = [CURL, '-q', '--noproxy', '*', '--http3-only', '--cacert', f'/proc/self/fd/{fd}', '--resolve', f'{hostname}:18443:127.0.0.1', '--max-time', '5', '--silent', '--show-error', '--write-out', '\nHTTP_VERSION=%{http_version} CODE=%{http_code} SSL_VERIFY=%{ssl_verify_result}\n', f'https://{hostname}:18443/']
                proc = await asyncio.create_subprocess_exec(*args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, pass_fds=(fd,), env={'PATH': '/usr/bin:/bin'})
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=8)
                result = {'test': label, 'uid': os.getuid(), 'gid': os.getgid(), 'command': args, 'returncode': proc.returncode, 'stdout': stdout.decode(), 'stderr': stderr.decode()}
                results.append(result)
                assert proc.returncode == expected, result
                if expected == 0:
                    assert BODY in stdout and b'HTTP_VERSION=3 CODE=200 SSL_VERIFY=0' in stdout, result
            finally:
                os.close(fd)
    finally:
        server.close()
    print(json.dumps({'network': 'fresh network namespace, loopback only; no external routes or firewall changes', 'server': 'aioquic UDP 127.0.0.1:18443, no TCP listener', 'results': results, 'passed': True}, indent=2))


if __name__ == '__main__':
    asyncio.run(main())
