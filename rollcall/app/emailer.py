"""Email alerts: red alerts as they happen (a burst grouped into one email), each "back up" if wanted,
and a daily digest of everything that needs attention.

Sent through any SMTP server (an internal relay with no sign-in, or with a user name and password,
over STARTTLS, SSL or plain), or through Microsoft 365 with Microsoft Graph (an app registration
with the Mail.Send application permission), so no mailbox password is needed.
"""
from __future__ import annotations

import asyncio
import html
import logging
import os
import smtplib
import ssl
import time
from email.message import EmailMessage
from email.utils import formatdate, make_msgid

import aiohttp
from urllib.parse import quote

log = logging.getLogger("rollcall.email")

CATEGORIES = ("devices", "services", "network", "agents", "backups", "security", "updates")
DOT = {"ok": "#16a34a", "red": "#dc2626", "amber": "#d97706", "event": "#d97706", "info": "#2563eb"}
GROUP_SECONDS = 60      # alerts arriving within this long of the first go in one email
MASK = "••••••••"       # a saved password, as the Settings dialog shows it
LOGIN = os.environ.get("PM_M365_LOGIN", "https://login.microsoftonline.com")   # overridable for testing
GRAPH = os.environ.get("PM_M365_GRAPH", "https://graph.microsoft.com")


CAT_LABELS = {"devices": "devices not responding", "services": "service checks", "network": "SNMP and syslog",
              "agents": "agent checks", "backups": "backups", "security": "security",
              "updates": "updates"}


def describe(opts: dict) -> str:
    """One sentence on what these settings email, for the test email."""
    now = [w for k, d, w in (("email_red", True, "red alerts"), ("email_warnings", False, "amber warnings and events")) if opts.get(k, d)]
    when = [" and ".join(now) + " as they happen"] if now else []
    if opts.get("email_recovery", True):
        when.append("an email when things come back")
    if opts.get("email_digest", True) and opts.get("email_digest_time"):
        when.append(f"a daily summary at {opts['email_digest_time']}")
    about = [CAT_LABELS[c] for c in CATEGORIES if opts.get(f"email_about_{c}", True)]
    if not when or not about:
        return "With these settings nothing else will be emailed."
    j = lambda xs: xs[0] if len(xs) == 1 else ", ".join(xs[:-1]) + " and " + xs[-1]  # noqa: E731
    return f"You'll get {j(when)}, about {'everything' if len(about) == len(CATEGORIES) else j(about)}."


class EmailError(Exception):
    pass


def configured(opts: dict) -> bool:
    return opts.get("email_send", "off") != "off" and bool(opts.get("email_to"))


def _check(opts: dict) -> None:
    mode = opts.get("email_send", "off")
    if mode == "off":
        raise EmailError("Email is turned off (Send email with)")
    if not opts.get("email_to"):
        raise EmailError("No recipients: add at least one address under Send email to")
    if not opts.get("email_from"):
        raise EmailError("No sender: fill in Send email from")
    if mode == "smtp" and not opts.get("smtp_host"):
        raise EmailError("No SMTP server: fill in SMTP server")
    if mode == "microsoft365" and not all(opts.get(k) for k in ("m365_tenant_id", "m365_client_id", "m365_client_secret")):
        raise EmailError("Microsoft 365 needs the tenant ID, application (client) ID and client secret")


class Emailer:
    def __init__(self, opts_getter, state: dict, save_state):
        self._opts = opts_getter          # the add-on's current options (they can change in Settings)
        self.state, self._save = state, save_state
        self.queue: list[tuple[float, str, str, str]] = []
        self._flush_task: asyncio.Task | None = None
        self._token: tuple[str, float] | None = None
        self.recent: list[tuple[float, str, str]] = []   # alerts not emailed (amber, events): for the digest
        self.last_error = ""

    # -- what gets sent -------------------------------------------------------------------
    def alert(self, title: str, message: str, level: str, cat: str | None = None) -> None:
        """Called for every notification. level: red, ok (its "back up"), amber, event or info.
        cat: what it's about (CATEGORIES), each of which can be ticked off in Settings.
        Red, back up (email_recovery) and info are emailed now; amber and events too with
        email_warnings, otherwise they wait for the daily summary."""
        opts = self._opts()
        if not configured(opts) or (cat and not opts.get(f"email_about_{cat}", True)):
            return
        now = time.time()
        if level == "red":
            send_now = opts.get("email_red", True)
        elif level == "ok":
            send_now = opts.get("email_recovery", True)
        elif level in ("amber", "event"):
            send_now = opts.get("email_warnings", False)
            if not send_now:
                self.recent = [r for r in self.recent if r[0] > now - 86400][-200:] + [(now, title, message)]
        else:
            send_now = level == "info"
        if send_now:
            self.queue.append((now, title, message, level))
            if not self._flush_task or self._flush_task.done():
                self._flush_task = asyncio.get_event_loop().create_task(self._flush_later())

    async def _flush_later(self) -> None:
        await asyncio.sleep(GROUP_SECONDS)
        items, self.queue = self.queue, []
        if not items:
            return
        problems = [i for i in items if i[3] != "ok"]
        names = [_plain(i[1]) for i in items]
        if len(items) == 1:
            subject = f"Rollcall: {names[0]}"
        else:
            subject = (f"Rollcall: {len(problems)} alert{'s' if len(problems) != 1 else ''}" if problems else "Rollcall: back to normal") \
                + (f" ({names[0]}, …)" if len(items) > 1 else "")
        rows = [(time.strftime("%H:%M", time.localtime(t)), level, _plain(ti), msg) for t, ti, msg, level in items]
        text = "\n".join(f"{w}  {'BACK UP ' if lv == 'ok' else ''}{ti}\n      {m}" for w, lv, ti, m in rows)
        body = "".join(
            f'<tr><td style="{TD};color:#6b7280;white-space:nowrap">{w}</td><td style="{TD}">'
            f'<span style="display:inline-block;width:10px;height:10px;border-radius:50%;background:{DOT.get(lv, "#dc2626")};margin-right:6px"></span>'
            f'<b>{html.escape(ti)}</b><br><span style="color:#4b5563">{html.escape(m)}</span></td></tr>' for w, lv, ti, m in rows)
        try:
            await self.send(subject, text + self._footer_text(), _page("Rollcall alerts", f'<table style="border-collapse:collapse;width:100%">{body}</table>', self._link()))
        except EmailError as e:
            log.warning("Couldn't send the alert email: %s", e)

    async def digest(self, sections: list[tuple[str, list[tuple[str, str, str]]]], summary: str) -> None:
        """The daily email. sections: [(heading, [(dot colour, name and check, detail)])]."""
        rec = [r for r in self.recent if r[0] > time.time() - 86400]
        if rec:
            sections = sections + [("Alerts in the last 24 hours (not emailed at the time)",
                                     [("amber", _plain(t), f"{m} · {time.strftime('%d %b %H:%M', time.localtime(w))}") for w, t, m in rec])]
        n = sum(len(s[1]) for s in sections if not s[0].startswith("Alerts in"))
        subject = f"Rollcall daily summary: {'all clear' if not n else str(n) + (' things need' if n != 1 else ' thing needs') + ' attention'}"
        text = summary + "\n\n" + "\n\n".join(h + "\n" + "\n".join(f"- {w}: {d}" for _c, w, d in rows) for h, rows in sections)
        colours = {"red": "#dc2626", "amber": "#d97706", "grey": "#9ca3af", "green": "#16a34a"}
        body = f'<p style="margin:0 0 14px;color:#374151">{html.escape(summary)}</p>' + "".join(
            f'<h3 style="font-size:13px;text-transform:uppercase;letter-spacing:.04em;color:#6b7280;margin:18px 0 6px">{html.escape(h)}</h3>'
            f'<table style="border-collapse:collapse;width:100%">' + "".join(
                f'<tr><td style="{TD}"><span style="display:inline-block;width:10px;height:10px;border-radius:50%;background:{colours.get(c, "#9ca3af")};margin-right:6px"></span>'
                f'<b>{html.escape(w)}</b><br><span style="color:#4b5563">{html.escape(d)}</span></td></tr>' for c, w, d in rows) + "</table>"
            for h, rows in sections)
        await self.send(subject, text + self._footer_text(), _page("Rollcall daily summary", body, self._link()))
        self.recent = []

    def _link(self) -> str:
        return str(self._opts().get("notification_url") or "")

    def _footer_text(self) -> str:
        link = self._link()
        return f"\n\n{'Open Rollcall: ' + link if link else ''}\nSent by Rollcall. Change what's emailed under Manage > Settings > Email alerts."

    # -- sending --------------------------------------------------------------------------
    async def send(self, subject: str, text: str, html_body: str, opts: dict | None = None) -> None:
        opts = opts or self._opts()
        _check(opts)
        try:
            if opts["email_send"] == "microsoft365":
                await self._graph(opts, subject, html_body)
            else:
                await asyncio.to_thread(self._smtp, opts, subject, text, html_body)
        except EmailError as e:
            self.last_error = str(e)
            raise
        self.last_error = ""
        log.info("Emailed %s: %s", ", ".join(opts["email_to"]), subject)

    @staticmethod
    def _smtp(opts: dict, subject: str, text: str, html_body: str) -> None:
        msg = EmailMessage()
        msg["Subject"], msg["From"], msg["To"] = subject, opts["email_from"], ", ".join(opts["email_to"])
        msg["Date"], msg["Message-ID"] = formatdate(localtime=True), make_msgid(domain=opts["email_from"].split("@")[-1] or None)
        msg.set_content(text)
        msg.add_alternative(html_body, subtype="html")
        host, port, sec = opts["smtp_host"], int(opts.get("smtp_port") or 25), opts.get("smtp_security", "starttls")
        ctx = ssl.create_default_context()
        if not opts.get("smtp_check_certificate", True):
            ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE  # an internal server's own certificate
        try:
            if sec == "ssl":
                s = smtplib.SMTP_SSL(host, port, timeout=20, context=ctx)
            else:
                s = smtplib.SMTP(host, port, timeout=20)
            with s:
                s.ehlo()
                if sec == "starttls":
                    if not s.has_extn("starttls"):
                        raise EmailError(f"{host} doesn't offer STARTTLS on port {port}; choose SSL or none")
                    s.starttls(context=ctx)
                    s.ehlo()
                if opts.get("smtp_username"):
                    s.login(opts["smtp_username"], opts.get("smtp_password") or "")
                refused = s.send_message(msg)
                if refused:
                    raise EmailError("refused for " + ", ".join(refused))
        except smtplib.SMTPAuthenticationError as e:
            raise EmailError(f"the server didn't accept the user name or password ({e.smtp_code})") from None
        except smtplib.SMTPRecipientsRefused as e:
            raise EmailError("the server refused the recipients: " + ", ".join(e.recipients)) from None
        except smtplib.SMTPSenderRefused as e:
            raise EmailError(f"the server refused the sender address ({e.smtp_code} {e.smtp_error.decode(errors='replace')[:120]})") from None
        except smtplib.SMTPResponseException as e:
            raise EmailError(f"the server said {e.smtp_code} {e.smtp_error.decode(errors='replace')[:160]}") from None
        except ssl.SSLError as e:
            hint = ("; if it's an internal server with its own certificate, turn off Check the server's certificate"
                    if "CERTIFICATE_VERIFY_FAILED" in str(e) else "; check the port and security setting")
            raise EmailError(f"TLS failed ({e.reason or e}){hint}") from None
        except (OSError, smtplib.SMTPException) as e:
            raise EmailError(f"couldn't reach {host}:{port} ({e})") from None

    async def _graph(self, opts: dict, subject: str, html_body: str) -> None:
        timeout = aiohttp.ClientTimeout(total=30)
        async with aiohttp.ClientSession(timeout=timeout) as s:
            if not self._token or self._token[1] < time.time() + 60:
                try:
                    async with s.post(f"{LOGIN}/{opts['m365_tenant_id']}/oauth2/v2.0/token", data={
                            "client_id": opts["m365_client_id"], "client_secret": opts["m365_client_secret"],
                            "scope": "https://graph.microsoft.com/.default", "grant_type": "client_credentials"}) as r:
                        j = await r.json(content_type=None)
                except (aiohttp.ClientError, asyncio.TimeoutError, ValueError) as e:
                    raise EmailError(f"couldn't reach Microsoft's sign-in ({e})") from None
                if r.status != 200 or "access_token" not in j:
                    raise EmailError("Microsoft 365 sign-in failed: " + str(j.get("error_description") or j.get("error") or r.status).split("\r\n")[0][:200])
                self._token = (j["access_token"], time.time() + int(j.get("expires_in", 3600)))
            body = {"message": {"subject": subject, "body": {"contentType": "HTML", "content": html_body},
                                "toRecipients": [{"emailAddress": {"address": a}} for a in opts["email_to"]]},
                    "saveToSentItems": False}
            try:
                async with s.post(f"{GRAPH}/v1.0/users/{quote(opts['email_from'])}/sendMail", json=body,
                                  headers={"Authorization": f"Bearer {self._token[0]}"}) as r:
                    if r.status != 202:
                        j = await r.json(content_type=None)
                        err = (j.get("error") or {}) if isinstance(j, dict) else {}
                        if r.status in (401, 403):
                            self._token = None
                        hint = " (has the app got the Mail.Send application permission, with admin consent?)" if r.status == 403 else ""
                        raise EmailError(f"Microsoft 365 didn't send it: {err.get('code') or r.status} {str(err.get('message') or '')[:160]}{hint}")
            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                raise EmailError(f"couldn't reach Microsoft Graph ({e})") from None


TD = "padding:8px 10px;border-top:1px solid #e5e7eb;vertical-align:top;font-size:14px"


def _plain(title: str) -> str:
    """A notification title without its emoji, for subjects."""
    t = title.strip()
    return t.split(" ", 1)[1] if t and not t[0].isascii() and " " in t else t


def _page(heading: str, body: str, link: str) -> str:
    btn = (f'<p style="margin:18px 0 0"><a href="{html.escape(link)}" style="background:#2563eb;color:#fff;text-decoration:none;'
           f'padding:8px 14px;border-radius:6px;font-size:14px">Open Rollcall</a></p>') if link else ""
    return (f'<!doctype html><html><body style="margin:0;padding:20px;background:#f5f6f8;font-family:Segoe UI,Arial,sans-serif;color:#111827">'
            f'<div style="max-width:680px;margin:0 auto;background:#fff;border:1px solid #e5e7eb;border-radius:10px;padding:18px 20px">'
            f'<h2 style="margin:0 0 12px;font-size:18px">{html.escape(heading)}</h2>{body}{btn}'
            f'<p style="margin:18px 0 0;font-size:12px;color:#9ca3af">Sent by Rollcall. Change what\'s emailed under Manage &gt; Settings &gt; Email alerts.</p>'
            f'</div></body></html>')
