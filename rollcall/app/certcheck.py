"""Read the TLS certificate a service presents (directly, or after STARTTLS for mail ports)
and report when it expires. Certificates aren't verified: internal and self-signed ones count too."""
from __future__ import annotations

import asyncio
import datetime as dt
import ssl

STARTTLS_PORTS = {25: "smtp", 587: "smtp", 110: "pop3", 143: "imap", 21: "ftp"}


def _context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.minimum_version = ssl.TLSVersion.TLSv1  # old kit still deserves an expiry check
        ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
    except (ValueError, ssl.SSLError):
        pass
    return ctx


async def _line(reader: asyncio.StreamReader, timeout: float) -> bytes:
    return await asyncio.wait_for(reader.readline(), timeout)


async def _smtp_reply(reader, timeout) -> bytes:
    while True:  # multi-line replies: "250-..." until "250 ..."
        ln = await _line(reader, timeout)
        if not ln or ln[3:4] != b"-":
            return ln


async def _starttls(proto: str, reader, writer, timeout: float) -> None:
    if proto == "smtp":
        await _smtp_reply(reader, timeout)
        writer.write(b"EHLO rollcall\r\n")
        await _smtp_reply(reader, timeout)
        writer.write(b"STARTTLS\r\n")
        r = await _smtp_reply(reader, timeout)
        if not r.startswith(b"220"):
            raise ConnectionError("the server doesn't offer STARTTLS")
    elif proto == "imap":
        await _line(reader, timeout)
        writer.write(b"a1 STARTTLS\r\n")
        while True:
            r = await _line(reader, timeout)
            if r.startswith(b"a1 "):
                break
        if not r.startswith(b"a1 OK"):
            raise ConnectionError("the server doesn't offer STARTTLS")
    elif proto == "pop3":
        await _line(reader, timeout)
        writer.write(b"STLS\r\n")
        if not (await _line(reader, timeout)).startswith(b"+OK"):
            raise ConnectionError("the server doesn't offer STLS")
    elif proto == "ftp":
        await _smtp_reply(reader, timeout)
        writer.write(b"AUTH TLS\r\n")
        if not (await _smtp_reply(reader, timeout)).startswith(b"234"):
            raise ConnectionError("the server doesn't offer AUTH TLS")
    await writer.drain()


async def fetch(ip: str, port: int, server_name: str | None, timeout: float = 5.0) -> bytes:
    """The DER certificate the service presents."""
    proto = STARTTLS_PORTS.get(port)
    sni = server_name if server_name and not server_name.replace(".", "").isdigit() and ":" not in server_name else None
    if proto:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout)
        try:
            await asyncio.wait_for(_starttls(proto, reader, writer, timeout), timeout * 2)
            await asyncio.wait_for(writer.start_tls(_context(), server_hostname=sni), timeout)
            return writer.get_extra_info("ssl_object").getpeercert(binary_form=True)
        finally:
            writer.close()
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(ip, port, ssl=_context(), server_hostname=sni), timeout)
    try:
        return writer.get_extra_info("ssl_object").getpeercert(binary_form=True)
    finally:
        writer.close()


def describe(der: bytes) -> dict:
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    c = x509.load_der_x509_certificate(der)
    try:
        expires = c.not_valid_after_utc
    except AttributeError:  # cryptography < 42
        expires = c.not_valid_after.replace(tzinfo=dt.timezone.utc)

    def cn(name):
        v = name.get_attributes_for_oid(NameOID.COMMON_NAME)
        return v[0].value if v else name.rfc4514_string()[:80]
    try:
        sans = c.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        sans = []
    return {"expires": expires.timestamp(), "subject": str(cn(c.subject))[:120], "issuer": str(cn(c.issuer))[:120],
            "self_signed": c.subject == c.issuer, "names": sans[:20]}


async def check(ip: str, port: int, server_name: str | None, warn_days: int, crit_days: int, timeout: float = 5.0) -> tuple:
    """(ok, None, detail[, "warn"]) in the form Rollcall's service checks return."""
    try:
        info = describe(await fetch(ip, port, server_name, timeout))
    except ssl.SSLError as err:
        why = "the port doesn't use TLS" if "WRONG_VERSION_NUMBER" in str(err) or "record layer" in str(err) else str(err)
        return False, None, f"couldn't read the certificate: {why}", "warn"
    except asyncio.TimeoutError:
        return False, None, "couldn't read the certificate: no answer in time", "warn"
    except (OSError, ConnectionError) as err:
        return False, None, f"couldn't read the certificate: {err.strerror or err if isinstance(err, OSError) else err}", "warn"
    except ValueError as err:
        return False, None, f"couldn't understand the certificate: {err}", "warn"
    now = dt.datetime.now(dt.timezone.utc).timestamp()
    days = (info["expires"] - now) / 86400
    when = dt.datetime.fromtimestamp(info["expires"], dt.timezone.utc).strftime("%d %b %Y")
    who = info["subject"] + (" (self-signed)" if info["self_signed"] else f", from {info['issuer']}")
    if days < 0:
        return False, None, f"expired {when} ({int(-days)} days ago): {who}"
    left = f"{int(days)} day{'s' if int(days) != 1 else ''}" if days >= 1 else "less than a day"
    if days <= crit_days:
        return False, None, f"expires {when}, in {left}: {who}"
    if days <= warn_days:
        return False, None, f"expires {when}, in {left}: {who}", "warn"
    return True, None, f"valid until {when} ({left}): {who}"
