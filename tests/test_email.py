"""Email alerts: through an SMTP relay, an SMTP server with STARTTLS and a sign-in, and Microsoft 365
(Graph), each against a stand-in server on this machine. Also: a burst of alerts arrives as one email.

Run from the repository root:  python3 -m pytest tests/test_email.py   (needs aiosmtpd and cryptography)
"""
import asyncio
import datetime
import email
import socket
import sys
from email import policy
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "rollcall" / "app"))
import emailer as E  # noqa: E402

aiosmtpd = pytest.importorskip("aiosmtpd")
from aiosmtpd.controller import Controller  # noqa: E402
from aiosmtpd.smtp import AuthResult, LoginPassword  # noqa: E402


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Inbox:
    def __init__(self):
        self.got = []

    async def handle_DATA(self, server, session, envelope):  # noqa: N802
        self.got.append((envelope.mail_from, list(envelope.rcpt_tos), email.message_from_bytes(envelope.content, policy=policy.default)))
        return "250 OK"


def auth_ok(server, session, envelope, mechanism, data):
    ok = isinstance(data, LoginPassword) and data.login == b"svc_rollcall" and data.password == b"right"
    return AuthResult(success=ok, handled=False)


def self_signed(tmp_path):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "mail.example.local")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(1).not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1)).sign(key, hashes.SHA256()))
    (tmp_path / "c.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (tmp_path / "k.pem").write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    import ssl
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.load_cert_chain(tmp_path / "c.pem", tmp_path / "k.pem")
    return ctx


BASE = {"email_send": "smtp", "email_to": ["it@example.local", "oncall@example.local"], "email_from": "rollcall@example.local",
        "smtp_host": "127.0.0.1", "smtp_security": "none", "smtp_username": "", "smtp_password": "", "smtp_check_certificate": True}


def mailer(opts):
    return E.Emailer(lambda: opts, {}, lambda: None)


def test_internal_relay_without_signing_in():
    inbox, port = Inbox(), free_port()
    c = Controller(inbox, hostname="127.0.0.1", port=port)
    c.start()
    try:
        opts = {**BASE, "smtp_port": port}
        asyncio.run(mailer(opts).send("Rollcall: SRV01 is down", "SRV01 is down", "<p>SRV01 is down</p>"))
        frm, to, msg = inbox.got[0]
        assert frm == "rollcall@example.local" and to == ["it@example.local", "oncall@example.local"]
        assert msg["Subject"] == "Rollcall: SRV01 is down"
        assert msg.get_body(("html",)).get_content().strip() == "<p>SRV01 is down</p>"
        assert msg.get_body(("plain",)).get_content().strip() == "SRV01 is down"
    finally:
        c.stop()


def test_starttls_with_sign_in_and_an_internal_certificate(tmp_path):
    inbox, port = Inbox(), free_port()
    c = Controller(inbox, hostname="127.0.0.1", port=port, tls_context=self_signed(tmp_path), require_starttls=True,
                   authenticator=auth_ok, auth_require_tls=True, auth_exclude_mechanism=["LOGIN"])
    c.start()
    try:
        opts = {**BASE, "smtp_port": port, "smtp_security": "starttls", "smtp_username": "svc_rollcall", "smtp_password": "right"}
        with pytest.raises(E.EmailError, match="turn off Check the server's certificate"):
            asyncio.run(mailer(opts).send("t", "t", "<p>t</p>"))
        opts["smtp_check_certificate"] = False
        asyncio.run(mailer(opts).send("Rollcall test email", "t", "<p>t</p>"))
        assert inbox.got and inbox.got[0][2]["Subject"] == "Rollcall test email"
        with pytest.raises(E.EmailError, match="user name or password"):
            asyncio.run(mailer({**opts, "smtp_password": "wrong"}).send("t", "t", "<p>t</p>"))
    finally:
        c.stop()


def test_unreachable_server_says_so():
    with pytest.raises(E.EmailError, match="couldn't reach 127.0.0.1"):
        asyncio.run(mailer({**BASE, "smtp_port": free_port()}).send("t", "t", "<p>t</p>"))


def test_microsoft_365_through_graph(monkeypatch):
    from aiohttp import web
    seen = {}

    async def token(req):
        f = await req.post()
        seen["token"] = (req.match_info["tenant"], dict(f))
        if f["client_secret"] != "s3cret":
            return web.json_response({"error": "invalid_client", "error_description": "AADSTS7000215: Invalid client secret provided.\r\nTrace ID: x"}, status=401)
        return web.json_response({"access_token": "tok", "expires_in": 3599})

    async def send(req):
        seen["send"] = (req.match_info["user"], req.headers.get("Authorization"), await req.json())
        if req.match_info["user"] == "nobody@example.local":
            return web.json_response({"error": {"code": "ErrorAccessDenied", "message": "Access is denied."}}, status=403)
        return web.Response(status=202)

    async def run():
        app = web.Application()
        app.router.add_post("/{tenant}/oauth2/v2.0/token", token)
        app.router.add_post("/v1.0/users/{user}/sendMail", send)
        runner = web.AppRunner(app)
        await runner.setup()
        port = free_port()
        await web.TCPSite(runner, "127.0.0.1", port).start()
        monkeypatch.setattr(E, "LOGIN", f"http://127.0.0.1:{port}")
        monkeypatch.setattr(E, "GRAPH", f"http://127.0.0.1:{port}")
        opts = {**BASE, "email_send": "microsoft365", "m365_tenant_id": "contoso.onmicrosoft.com", "m365_client_id": "app-id",
                "m365_client_secret": "s3cret"}
        try:
            await mailer(opts).send("Rollcall: SRV01 is down", "x", "<p>down</p>")
            user, auth, body = seen["send"]
            assert user == "rollcall@example.local" and auth == "Bearer tok"
            assert seen["token"][0] == "contoso.onmicrosoft.com" and seen["token"][1]["grant_type"] == "client_credentials"
            assert body["message"]["subject"] == "Rollcall: SRV01 is down" and body["message"]["body"]["content"] == "<p>down</p>"
            assert [r["emailAddress"]["address"] for r in body["message"]["toRecipients"]] == BASE["email_to"]
            with pytest.raises(E.EmailError, match="Mail.Send"):
                await mailer({**opts, "email_from": "nobody@example.local"}).send("t", "t", "<p>t</p>")
            with pytest.raises(E.EmailError, match="Invalid client secret provided.$"):
                await mailer({**opts, "m365_client_secret": "wrong"}).send("t", "t", "<p>t</p>")
        finally:
            await runner.cleanup()
    asyncio.run(run())


def test_a_burst_of_red_alerts_is_one_email_and_amber_waits_for_the_summary(monkeypatch):
    sent = []
    monkeypatch.setattr(E, "GROUP_SECONDS", 0.05)

    async def run():
        m = mailer({**BASE, "email_recovery": True})

        async def fake_send(subject, text, html_body, opts=None):
            sent.append((subject, text))
        m.send = fake_send
        m.alert("🔴 SRV01 is down", "No reply from 192.168.1.20", "red")
        m.alert("🟠 DC01: Disk", "C: 2% free", "red")
        m.alert("⚠️ DC01: Kernel-Power event 41", "Critical: rebooted", "event")
        await asyncio.sleep(0.2)
        assert len(sent) == 1 and sent[0][0] == "Rollcall: 2 alerts (SRV01 is down, …)"
        assert "DC01: Disk" in sent[0][1] and "Kernel-Power" not in sent[0][1]
        m.alert("🟢 SRV01 is back up", "Replying again", "ok")
        await asyncio.sleep(0.2)
        assert sent[-1][0] == "Rollcall: SRV01 is back up"
        await m.digest([("Amber", [("amber", "DC01 · Disk", "C: 12% free")])], "13 of 14 devices up.")
        assert sent[-1][0] == "Rollcall daily summary: 1 thing needs attention"
        assert "Kernel-Power" in sent[-1][1]                          # the event went in the summary
    asyncio.run(run())


def test_nothing_sent_when_off():
    m = mailer({**BASE, "email_send": "off"})
    m.alert("🔴 SRV01 is down", "x", "red")
    assert not m.queue
    with pytest.raises(E.EmailError, match="turned off"):
        asyncio.run(m.send("t", "t", "<p>t</p>"))


def test_ticked_choices_decide_what_is_emailed(monkeypatch):
    sent = []
    monkeypatch.setattr(E, "GROUP_SECONDS", 0.05)

    async def run():
        opts = {**BASE, "email_about_backups": False, "email_recovery": False}
        m = mailer(opts)

        async def fake_send(subject, text, html_body, opts=None):
            sent.append(subject)
        m.send = fake_send
        m.alert("🔴 BK01: backup failed", "Job failed", "red", "backups")       # backups unticked
        m.alert("🟢 SRV01 is back up", "", "ok", "devices")                    # recovery unticked
        m.alert("⚠️ DC01: event 41", "rebooted", "event", "agents")           # waits for the summary
        await asyncio.sleep(0.2)
        assert sent == [] and len(m.recent) == 1
        opts["email_warnings"] = True                                          # warnings as they happen
        m.alert("🟠 BK02: backup overdue", "late", "amber", "backups")         # still unticked
        m.alert("⚠️ DC01: event 6008", "unexpected shutdown", "event", "agents")
        m.alert("⬆️ SRV02: Immich v2 available", "", "info", "updates")
        await asyncio.sleep(0.2)
        assert sent == ["Rollcall: 2 alerts (DC01: event 6008, …)"] and len(m.recent) == 1
        opts["email_red"], opts["email_about_updates"] = False, False
        m.alert("🔴 SRV01 is down", "x", "red", "devices")
        m.alert("⬆️ SRV02: Immich v3 available", "", "info", "updates")
        await asyncio.sleep(0.2)
        assert len(sent) == 1
        assert E.describe(opts) == "You'll get amber warnings and events as they happen, about devices not responding, " \
            "service checks, SNMP and syslog, agent checks and security."
    asyncio.run(run())
