"""Rollcall's own HTTPS for agents (1.93.0), end to end against the real add-on, for the Windows agent (Windows
PowerShell 5.1 on Windows, else PowerShell 7) and the Linux agent:

1. An existing install: HTTPS off, the agent reports over plain HTTP.
2. An admin turns HTTPS on: at its next report the agent gets the port and key (signed with the update key), and
   from the run after it reports over HTTPS.
3. Plain HTTP turned off: it still reports.
4. Something else, with another key, takes the HTTPS port the agent knows (plain HTTP back on): the agent refuses
   it before sending anything (the impostor receives nothing, the token included), reports over HTTP instead, and
   follows Rollcall to its new port.

Run from the repository root:  python3 -m pytest tests/test_agent_https_e2e.py
"""
import datetime
import json
import socket
import ssl
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_update_signing_e2e import (HAVE_ADDON_DEPS, PWSH, UI, WINDOWS, Addon, LinuxAgent, WindowsAgent,  # noqa: E402
                                     call, free_port)


class Impostor:
    """A TLS server with its own key on a port: records every byte anyone sends it after the handshake."""

    def __init__(self, port, tmp: Path):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import NameOID
        k = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Rollcall agents")])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(k.public_key())
                .serial_number(1).not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=30))
                .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost"), x509.IPAddress(__import__("ipaddress").ip_address("127.0.0.1"))]), critical=False)
                .sign(k, hashes.SHA256()))
        (tmp / "imp.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        (tmp / "imp.key").write_bytes(k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(tmp / "imp.pem", tmp / "imp.key")
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", port))
        self.sock.listen(5)
        self.connections, self.received = 0, b""
        threading.Thread(target=self.serve, daemon=True).start()

    def serve(self):
        while True:
            try:
                c, _ = self.sock.accept()
            except OSError:
                return
            self.connections += 1
            try:
                s = self.ctx.wrap_socket(c, server_side=True)
                s.settimeout(5)
                while True:
                    d = s.recv(4096)
                    if not d:
                        break
                    self.received += d
            except (OSError, ssl.SSLError):
                pass
            finally:
                c.close()

    def stop(self):
        self.sock.close()


def scenario(agent, tmp: Path):
    addon = Addon(tmp / "addon", https=False).start()
    imp = None
    try:
        # 1. Plain HTTP, as an existing install
        script = call(f"{addon.ui}/api/agents/script?os={agent.os_name}&server={addon.agent_url}", headers=UI)[1]
        agent.installed.parent.mkdir(parents=True, exist_ok=True)
        agent.installed.write_bytes(script)
        agent.run()
        addon.approve_all()
        agent.run()
        assert addon.agent()["sent_to"] == addon.agent_url, agent.log()[-2000:]
        assert addon.api("/api/status").get("tls_prompt") is True          # admins are offered HTTPS

        # 2. Turned on: the next report hands over the port and key, the one after uses them
        tls = addon.api("/api/agents/tls", {"https": True}, "POST")["tls"]
        assert tls["on"] and tls["pin"] and "127.0.0.1" in tls["names"]
        agent.run()
        assert "Rollcall's HTTPS is on" in agent.log(), agent.log()[-2000:]
        agent.run()
        https_url = f"https://127.0.0.1:{addon.https_port}"
        assert addon.agent()["sent_to"] == https_url, agent.log()[-3000:]
        assert addon.api("/api/agents")["tls"]["agents_https"] == 1

        # Every agent is on HTTPS, plain HTTP still open: the Overview suggests closing it
        assert addon.api("/api/status")["tls_plain_prompt"] is True

        # 3. Plain HTTP off: still reporting
        addon.api("/api/agents/tls", {"plain_http": False}, "POST")
        assert addon.api("/api/status")["tls_plain_prompt"] is False
        with pytest.raises(OSError):
            socket.create_connection(("127.0.0.1", addon.agent_port), 2).close()
        before = addon.agent()["last_report"]
        agent.run()
        assert addon.agent()["last_report"] > before and addon.agent()["sent_to"] == https_url, agent.log()[-3000:]
        # Settings → Agent port says so (it used to say "HTTP"), and won't take your own certificate on top
        meta = addon.api("/api/settings")
        assert meta["agent_tls"]["builtin"] and meta["agent_tls"]["plain_http"] is False
        st, body = call(addon.ui + "/api/settings", {"values": {"agent_ssl": True}}, UI, "POST")
        assert st == 400 and b"Use one or the other" in body, body[:300]
        # ...and stays off after a restart (security review RC-03)
        addon.stop()
        addon.start()
        with pytest.raises(OSError):
            socket.create_connection(("127.0.0.1", addon.agent_port), 2).close()
        before = addon.agent()["last_report"]
        agent.run()
        assert addon.agent()["last_report"] > before and addon.agent()["sent_to"] == https_url, agent.log()[-3000:]
        assert addon.api("/api/agents")["tls"]["plain_http"] is False

        # 4. An impostor on the HTTPS port the agent knows; Rollcall's HTTPS moves to another port
        addon.api("/api/agents/tls", {"plain_http": True}, "POST")
        addon.stop()
        old_port = addon.https_port
        addon.https_port = free_port()
        addon.start()
        imp = Impostor(old_port, tmp)
        before = addon.agent()["last_report"]
        agent.run()
        assert imp.connections >= 1, "the agent didn't try its HTTPS address first"
        assert imp.received == b"", f"the agent sent the impostor {len(imp.received)} bytes: {imp.received[:200]!r}"
        assert "doesn't have Rollcall's key" in agent.log(), agent.log()[-3000:]
        assert addon.agent()["last_report"] > before and addon.agent()["sent_to"] == addon.agent_url   # over HTTP instead
        agent.run()                                                           # Rollcall's signed reply: the new port
        agent.run()
        assert addon.agent()["sent_to"] == f"https://127.0.0.1:{addon.https_port}", agent.log()[-3000:]
        assert imp.received == b""
    finally:
        if imp:
            imp.stop()
        addon.stop()


@pytest.mark.skipif(not HAVE_ADDON_DEPS, reason="needs the add-on's packages (aiohttp, cryptography)")
@pytest.mark.skipif(WINDOWS, reason="the Linux agent runs on Linux")
def test_linux_agent_moves_to_rollcalls_own_https(tmp_path):
    scenario(LinuxAgent(tmp_path), tmp_path)


@pytest.mark.skipif(not HAVE_ADDON_DEPS, reason="needs the add-on's packages (aiohttp, cryptography)")
@pytest.mark.skipif(not PWSH, reason="needs PowerShell")
def test_windows_agent_moves_to_rollcalls_own_https(tmp_path):
    scenario(WindowsAgent(tmp_path), tmp_path)


@pytest.mark.skipif(not HAVE_ADDON_DEPS, reason="needs the add-on's packages (aiohttp, cryptography)")
@pytest.mark.skipif(WINDOWS, reason="the Linux agent runs on Linux")
def test_a_new_install_starts_with_https_and_downloads_are_pinned(tmp_path):
    """A new install has HTTPS on, and an agent downloaded from it reports over HTTPS from its first report."""
    addon = Addon(tmp_path / "addon", https=None).start()
    try:
        assert addon.api("/api/agents")["tls"]["on"] is True
        agent = LinuxAgent(tmp_path)
        script = call(f"{addon.ui}/api/agents/script?os=linux&server={addon.agent_url}", headers=UI)[1].decode()
        assert 'TLS_PIN = "__PM_TLS_PIN__"' not in script and f"TLS_PORT = {addon.https_port}" in script
        agent.installed.parent.mkdir(parents=True, exist_ok=True)
        agent.installed.write_text(script)
        agent.run()
        addon.approve_all()
        agent.run()
        assert addon.agent()["sent_to"] == f"https://127.0.0.1:{addon.https_port}", agent.log()[-3000:]
        assert addon.api("/api/status").get("tls_prompt") is False
    finally:
        addon.stop()
