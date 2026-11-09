"""SIP check: send an OPTIONS request over UDP and see whether the device's SIP service answers.

Any SIP reply counts (200 OK, or 401/403/404/405 from devices that challenge or refuse OPTIONS):
it shows the phone, ATA or PBX is running its SIP service on that port. It doesn't show whether
a line is registered with the provider; that comes from the device's syslog."""
from __future__ import annotations

import asyncio
import secrets
import time


class _Proto(asyncio.DatagramProtocol):
    def __init__(self):
        self.reply: asyncio.Future = asyncio.get_running_loop().create_future()

    def datagram_received(self, data, addr):
        if not self.reply.done() and data[:8] == b"SIP/2.0 ":
            self.reply.set_result(data)

    def error_received(self, exc):
        if not self.reply.done():
            self.reply.set_exception(exc)


def _request(ip: str, port: int, local: tuple[str, int], call_id: str, branch: str, tag: str) -> bytes:
    lip, lport = local
    host = f"[{ip}]" if ":" in ip else ip
    target = f"sip:{host}:{port}" if port != 5060 else f"sip:{host}"
    lines = [
        f"OPTIONS {target} SIP/2.0",
        f"Via: SIP/2.0/UDP {lip}:{lport};branch=z9hG4bK{branch};rport",
        "Max-Forwards: 70",
        f"To: <{target}>",
        f"From: <sip:rollcall@{lip}>;tag={tag}",
        f"Call-ID: {call_id}@{lip}",
        "CSeq: 1 OPTIONS",
        f"Contact: <sip:rollcall@{lip}:{lport}>",
        "Accept: application/sdp",
        "User-Agent: Rollcall",
        "Content-Length: 0",
        "", ""]
    return "\r\n".join(lines).encode()


def _parse(data: bytes) -> tuple[int, str, str]:
    """(status code, reason, Server/User-Agent)"""
    text = data.decode("utf-8", "replace")
    head = text.split("\r\n\r\n", 1)[0].split("\n")
    parts = head[0].strip().split(" ", 2)
    code = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
    reason = parts[2] if len(parts) > 2 else ""
    agent = ""
    for ln in head[1:]:
        k, _, v = ln.partition(":")
        if k.strip().lower() in ("server", "user-agent") and v.strip():
            agent = v.strip()
            break
    return code, reason, agent[:80]


async def options(ip: str, port: int = 5060, timeout: float = 3.0) -> tuple[int, str, str, float]:
    """Send OPTIONS (re-sent like a SIP client would) and return (code, reason, agent, ms).
    Raises asyncio.TimeoutError if nothing answers."""
    loop = asyncio.get_running_loop()
    transport, proto = await loop.create_datagram_endpoint(_Proto, remote_addr=(ip, port))
    try:
        sock = transport.get_extra_info("sockname")
        packet = _request(ip, port, (sock[0], sock[1]), secrets.token_hex(8), secrets.token_hex(6), secrets.token_hex(4))
        start = time.monotonic()
        wait = 0.5
        while True:
            transport.sendto(packet)
            left = timeout - (time.monotonic() - start)
            if left <= 0:
                raise asyncio.TimeoutError
            try:
                data = await asyncio.wait_for(asyncio.shield(proto.reply), min(wait, left))
                break
            except asyncio.TimeoutError:
                wait = min(wait * 2, 2.0)  # SIP timer A: 500 ms, doubling
        code, reason, agent = _parse(data)
        return code, reason, agent, (time.monotonic() - start) * 1000
    finally:
        transport.close()


async def check(ip: str, port: int, timeout: float = 3.0) -> tuple:
    """(ok, ms, detail) in the form Rollcall's service checks return."""
    try:
        code, reason, agent, ms = await options(ip, port, timeout)
    except asyncio.TimeoutError:
        return False, None, f"no SIP reply on UDP {port}"
    except OSError as err:
        return False, None, f"no SIP reply on UDP {port} ({err.strerror or err})"
    if code >= 500:
        return False, None, f"SIP {code} {reason}".strip() + (f" · {agent}" if agent else ""), "warn"
    return True, round(ms, 1), f"SIP {code} {reason}".strip() + (f" · {agent}" if agent else "")
