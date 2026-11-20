"""Old embedded TLS stacks (HPE iLO 3, Dell iDRAC 6) and OpenSSL 3.5's larger first message.

Since OpenSSL 3.5, offering TLS 1.3 adds a post-quantum key share (X25519MLKEM768) and the
ClientHello grows from about 500 bytes to over 1,600. iLO 3 answers that with an "internal
error" alert (issue #14). The fake server here does the same: it refuses a first message over
1,024 bytes, or one carrying the ML-KEM group, and otherwise talks TLS 1.2 at most.
"""
import asyncio
import datetime
import socket
import ssl
import struct
import sys
import tempfile
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "rollcall" / "app"))

import ilo  # noqa: E402
import main  # noqa: E402
from test_ilo import ILO3  # noqa: E402

# iLO 3 is TLS 1.0 only on early firmware; later firmware, iLO 4 and iDRAC 6 go up to TLS 1.1 or 1.2.
VERSIONS = [ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1, ssl.TLSVersion.TLSv1_2]
NAMES = {ssl.TLSVersion.TLSv1: "TLSv1", ssl.TLSVersion.TLSv1_1: "TLSv1.1", ssl.TLSVersion.TLSv1_2: "TLSv1.2"}
pytestmark = pytest.mark.filterwarnings("ignore:ssl.TLSVersion.TLSv1:DeprecationWarning")

ALERT_INTERNAL_ERROR = bytes([0x15, 0x03, 0x01, 0x00, 0x02, 0x02, 0x50])
MLKEM = b"\x11\xec"


def _cert(tmp: Path) -> tuple[str, str]:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ilo.example.local")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(1).not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=30)).sign(key, hashes.SHA256()))
    c, k = tmp / "c.pem", tmp / "k.pem"
    c.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    k.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                                    serialization.NoEncryption()))
    return str(c), str(k)


def _client_hello(ctx: ssl.SSLContext) -> bytes:
    """The first record the context sends."""
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    got = {}

    def accept():
        s, _ = srv.accept()
        s.settimeout(3)
        b = b""
        while len(b) < 5 or len(b) < 5 + struct.unpack(">H", b[3:5])[0]:
            x = s.recv(65536)
            if not x:
                break
            b += x
        got["b"] = b
        s.close()

    t = threading.Thread(target=accept)
    t.start()
    try:
        ctx.wrap_socket(socket.create_connection(srv.getsockname())).close()
    except (ssl.SSLError, OSError):
        pass
    t.join()
    srv.close()
    return got["b"]


class OldStack:
    """A server that talks only one old TLS version, with an old RSA cipher, and refuses a large
    or post-quantum ClientHello, as iLO 3 does."""

    def __init__(self, reply: bytes, version: ssl.TLSVersion = ssl.TLSVersion.TLSv1_2):
        self.reply = reply
        self.refused = 0
        self.served = 0
        self.versions = []
        self.tmp = tempfile.TemporaryDirectory()
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.minimum_version = self.ctx.maximum_version = version
        self.ctx.set_ciphers("AES128-SHA:@SECLEVEL=0")
        self.ctx.load_cert_chain(*_cert(Path(self.tmp.name)))
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self):
        while True:
            try:
                s, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._one, args=(s,), daemon=True).start()

    def _one(self, s: socket.socket):
        s.settimeout(5)
        try:
            head = b""
            while len(head) < 5 or len(head) < 5 + struct.unpack(">H", head[3:5])[0]:
                head = s.recv(65536, socket.MSG_PEEK)
                if not head:
                    return
            rec = head[:5 + struct.unpack(">H", head[3:5])[0]]
            if len(rec) > 1024 or MLKEM in rec[5:]:
                self.refused += 1
                s.sendall(ALERT_INTERNAL_ERROR)
                return
            t = self.ctx.wrap_socket(s, server_side=True)
            self.versions.append(t.version())
            req = b""
            while b"\r\n\r\n" not in req:
                req += t.recv(65536)
            h, _, body = req.partition(b"\r\n\r\n")
            n = next((int(l.split(b":")[1]) for l in h.split(b"\r\n") if l.lower().startswith(b"content-length")), 0)
            while len(body) < n:
                body += t.recv(65536)
            self.served += 1
            t.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n" % len(self.reply) + self.reply)
            t.close()
        except (OSError, ssl.SSLError):
            pass
        finally:
            s.close()

    def close(self):
        self.sock.close()
        self.tmp.cleanup()


def _modern_hello_is_large() -> bool:
    return len(_client_hello(main._permissive_tls_context(max_tls12=False))) > 1024


def test_legacy_context_sends_a_small_hello_with_no_post_quantum_key():
    hello = _client_hello(main.legacy_tls_context())
    assert len(hello) <= 600 and MLKEM not in hello[5:]
    assert main.legacy_tls_context().maximum_version == ssl.TLSVersion.TLSv1_2
    assert main.legacy_tls_context().minimum_version <= ssl.TLSVersion.TLSv1   # iLO 3 and iDRAC 6 still need TLS 1.0


@pytest.mark.parametrize("version", VERSIONS, ids=lambda v: NAMES[v])
def test_ilo_poll_reads_an_old_stack_with_the_legacy_context(version):
    srv = OldStack(ILO3.encode(), version)
    try:
        d = asyncio.run(ilo.poll("127.0.0.1", "admin", "secret", main.legacy_tls_context(), timeout=10, port=srv.port))
        assert d["backplanes"][0]["bays"][1]["status"] == "Fault" and srv.served == 1
        assert srv.versions == [NAMES[version]]
        if _modern_hello_is_large():   # the failure from issue #14, with OpenSSL 3.5 or later
            with pytest.raises(ilo.IloError, match="TLS handshake failed"):
                asyncio.run(ilo.poll("127.0.0.1", "admin", "secret", main.health_tls_context(), timeout=10, port=srv.port))
    finally:
        srv.close()


def test_ilo_check_uses_the_legacy_context(monkeypatch):
    from test_ilo import _monitor
    m, h, calls = _monitor(monkeypatch, [ILO3])
    seen = []

    async def fake_poll(host, user, pw, tls, timeout=60):
        seen.append(tls)
        return ilo.parse(ILO3)

    monkeypatch.setattr(main.ilolib, "poll", fake_poll)
    asyncio.run(m.ilo_check(h, 1000))
    assert seen == [main.legacy_tls_context()]


@pytest.mark.parametrize("version", VERSIONS, ids=lambda v: NAMES[v])
def test_https_check_falls_back_to_tls12_for_an_old_stack(version):
    srv = OldStack(b"ok", version)
    try:
        ok, ms, detail, sch = asyncio.run(main.http_check(f"https://127.0.0.1:{srv.port}/", 10))
        assert ok is True and detail == "HTTP 200" and sch == "https"
        assert srv.versions == [NAMES[version]]
        assert srv.served == 1 and srv.refused == (1 if _modern_hello_is_large() else 0)
    finally:
        srv.close()


def test_https_check_still_reports_a_real_tls_failure():
    """A port that never does TLS still fails after the second try, with the reason."""
    async def run():
        async def handle(reader, writer):
            await reader.read(5)
            writer.write(b"SSH-2.0-OpenSSH_9.6\r\n" * 4)
            await writer.drain()
            writer.close()
        s = await asyncio.start_server(handle, "127.0.0.1", 0)
        port = s.sockets[0].getsockname()[1]
        try:
            return await main.http_check(f"https://127.0.0.1:{port}/", 5)
        finally:
            s.close()

    ok, ms, detail, sch = asyncio.run(run())
    assert ok is False and ms is None and detail.startswith("tls handshake failed")
