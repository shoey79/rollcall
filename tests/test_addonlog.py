"""Manage > Log: the add-on's log from the Supervisor (or, failing that, what's been logged since it
started), cleaned of colour codes and with secrets masked.

Run from the repository root:  python3 -m pytest tests/test_addonlog.py
"""
import asyncio
import logging
import socket
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "rollcall" / "app"))
import addonlog as L  # noqa: E402


def test_secrets_are_masked():
    assert L.mask("smtp_password: hunter22 next") == "smtp_password: •••• next"
    assert L.mask('{"token": "abc123def456"}') == '{"token": "••••"}'
    assert L.mask("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.x.y") == "Authorization: Bearer ••••"
    assert L.mask("GET /x?key=s3cr3t&page=2") == "GET /x?key=••••&page=2"
    assert L.mask("SNMP community=public on 192.168.1.1") == "SNMP community=•••• on 192.168.1.1"
    assert L.mask("2026-11-16 17:00:00 INFO SRV01 is back up") == "2026-11-16 17:00:00 INFO SRV01 is back up"


def test_colour_codes_and_blank_tail_are_removed():
    text = "\x1b[32m2026-11-16 17:00:00 INFO started\x1b[0m\r\n\x1b[33mWARNING slow\x1b[0m\n\n"
    assert L.clean(text, 100) == ["2026-11-16 17:00:00 INFO started", "WARNING slow"]
    assert L.clean("a\nb\nc", 2) == ["b", "c"]


def test_supervisor_log_then_fallback_to_memory():
    from aiohttp import ClientSession, web
    buf = L.Buffer()
    lg = logging.getLogger("test_addonlog")
    lg.addHandler(buf)
    lg.setLevel(logging.INFO)
    lg.warning("Since start: password=abc12345")

    def free_port():
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            return s.getsockname()[1]

    async def run():
        seen = {}

        async def logs(req):
            seen["auth"], seen["range"] = req.headers.get("Authorization"), req.headers.get("Range")
            return web.Response(text="\x1b[36m2026-11-16 09:00:00 INFO from before the restart\x1b[0m\n")
        app = web.Application()
        app.router.add_get("/addons/self/logs", logs)
        runner = web.AppRunner(app)
        await runner.setup()
        port = free_port()
        await web.TCPSite(runner, "127.0.0.1", port).start()
        try:
            async with ClientSession() as s:
                src, lines = await L.read(s, f"http://127.0.0.1:{port}", "tok", buf, 500)
                assert (src, lines) == ("supervisor", ["2026-11-16 09:00:00 INFO from before the restart"])
                assert seen == {"auth": "Bearer tok", "range": "entries=:-500:"}
                src, lines = await L.read(s, f"http://127.0.0.1:{free_port()}", "tok", buf, 500)   # Supervisor not answering
                assert src == "memory" and lines[-1].endswith("WARNING Since start: password=••••")
                assert (await L.read(s, "http://unused", None, buf))[0] == "memory"                # no token
        finally:
            await runner.cleanup()
    asyncio.run(run())
