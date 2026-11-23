"""A stand-in Fire TV stick for tests: speaks ADB over TCP the way adbd does (CNXN, AUTH with a real RSA check of the
signature, OPEN/WRTE/OKAY/CLSE), and answers Rollcall's shell commands with made-up output. Everything here is made
up; nothing comes from a real stick."""
from __future__ import annotations

import asyncio
import base64
import os
import re
import struct
import sys
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "rollcall" / "app"))
import firetv as ft  # noqa: E402

PROPS = """[ro.product.manufacturer]: [Amazon]
[ro.product.model]: [AFTMM]
[ro.product.device]: [mantis]
[ro.build.version.release]: [7.1.2]
[ro.build.version.sdk]: [25]
[ro.build.version.fireos]: [6.0]
[ro.build.mktg.fireos]: [Fire OS 6.7.1.1]
[ro.build.display.id]: [NS6711]
[ro.build.version.security_patch]: [2025-11-01]
[ro.serialno]: [G000TEST0000000]
[service.adb.tcp.port]: [5555]
"""


def outputs(cpu_busy=False, disabled=27, launcher_running=True, free_kb=2264108):
    a, b = (1000, 0, 500, 8000, 100), (1030, 0, 520, 8340, 110)
    if cpu_busy:
        b = (1900, 0, 520, 8100, 100)
    return {
        "props": PROPS,
        "uptime": "3418.83 9914.83\n",
        "cpu": "4\ncpu  %d %d %d %d %d 0 10 0 0 0\ncpu  %d %d %d %d %d 0 12 0 0 0\n" % (a + b),
        "meminfo": "MemTotal:        1836856 kB\nMemFree:          146664 kB\nMemAvailable:     462304 kB\n",
        "df": f"Filesystem 1K-blocks Used Available Use% Mounted on\n/dev/block/by-name/userdata 5534816 3254324 {free_kb} 59% /data\n",
        "wifi": "Wi-Fi is enabled\nmWifiInfo SSID: \"TestNet\", BSSID: 02:00:00:00:00:01, MAC: 02:00:00:00:00:02, Supplicant state: COMPLETED, RSSI: -64, Link speed: 650Mbps, Frequency: 5240MHz\n",
        "thermal": "ls: /sys/class/thermal: Permission denied\n",
        "power": "  mWakefulness=Awake\nDisplay Power: state=ON\n",
        "focus": "  mCurrentFocus=Window{9efb09b u0 com.example.tvplayer/com.example.Main}\n",
        "packages_3p": "package:com.example.tvplayer  installer=com.amazon.venezia\npackage:com.example.news  installer=com.amazon.venezia\npackage:local.example.launcher  installer=null\n",
        "packages_disabled": "".join(f"package:com.amazon.example{i}\n" for i in range(disabled)),
        "versions": "  Package [com.example.tvplayer] (1a2b3c):\n    versionName=4.2.1\n  Package [com.example.news] (4d5e):\n    versionName=10.0\n  Package [local.example.launcher] (6f):\n    versionName=1.3\n",
        "boot_count": "1543\n",
        "_launcher": ("4321\n" if launcher_running else "") + ("1\n" if launcher_running else "0\n"),
    }


def _pub_numbers(android_b64: bytes):
    raw = base64.b64decode(android_b64.split(b" ")[0].rstrip(b"\x00"))
    n = int.from_bytes(raw[8:8 + 256], "little")
    e = struct.unpack("<I", raw[-4:])[0]
    from cryptography.hazmat.primitives.asymmetric import rsa
    return rsa.RSAPublicNumbers(e, n).public_key()


class FakeStick:
    def __init__(self, allow=True):
        self.allow = allow            # what "someone" does when the TV asks: True Allow, False nothing
        self.trusted: list = []       # public keys allowed so far
        self.prompts = 0              # how many times the TV asked
        self.commands: list[str] = []
        self.out = outputs()
        self.port = 0
        self._loop = asyncio.new_event_loop()
        self._ready = threading.Event()
        threading.Thread(target=self._run, daemon=True).start()
        self._ready.wait(5)

    def _run(self):
        asyncio.set_event_loop(self._loop)

        async def start():
            srv = await asyncio.start_server(self._client, "127.0.0.1", 0)
            self.port = srv.sockets[0].getsockname()[1]
            self._ready.set()
        self._loop.run_until_complete(start())
        self._loop.run_forever()

    async def _read(self, r):
        head = await r.readexactly(24)
        cmd, a0, a1, n, crc, magic = struct.unpack("<6I", head)
        assert magic == cmd ^ 0xFFFFFFFF
        data = await r.readexactly(n) if n else b""
        assert crc == sum(data) & 0xFFFFFFFF
        return cmd, a0, a1, data

    async def _client(self, r, w):
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding, utils
        send = lambda *a: w.write(ft.message(*a))  # noqa: E731
        try:
            cmd, *_ = await self._read(r)
            assert cmd == ft.A_CNXN
            token = os.urandom(20)
            send(ft.A_AUTH, ft.AUTH_TOKEN, 0, token)
            await w.drain()
            while True:
                cmd, a0, _a1, data = await self._read(r)
                assert cmd == ft.A_AUTH
                if a0 == ft.AUTH_SIGNATURE:
                    ok = False
                    for k in self.trusted:
                        try:
                            k.verify(data, token, padding.PKCS1v15(), utils.Prehashed(hashes.SHA1()))
                            ok = True
                        except InvalidSignature:
                            pass
                    if ok:
                        break
                    token = os.urandom(20)
                    send(ft.A_AUTH, ft.AUTH_TOKEN, 0, token)
                elif a0 == ft.AUTH_RSAPUBLICKEY:
                    self.prompts += 1
                    if not self.allow:
                        await asyncio.sleep(30)      # nobody presses Allow
                        return
                    self.trusted.append(_pub_numbers(data))
                    break
                await w.drain()
            send(ft.A_CNXN, ft.VERSION, 4096, b"device::ro.product.name=mantis;ro.product.model=AFTMM;\x00")
            await w.drain()
            remote = 100
            while True:
                cmd, a0, a1, data = await self._read(r)
                if cmd != ft.A_OPEN:
                    continue
                remote += 1
                text = data.rstrip(b"\x00").decode()
                assert text.startswith("shell:")
                c = text[len("shell:"):]
                self.commands.append(c)
                send(ft.A_OKAY, remote, a0)
                body = self.answer(c).encode()
                for i in range(0, len(body), 4000):  # in chunks, each acknowledged
                    send(ft.A_WRTE, remote, a0, body[i:i + 4000])
                    await w.drain()
                    ack = await self._read(r)
                    assert ack[0] == ft.A_OKAY
                send(ft.A_CLSE, remote, a0)
                await w.drain()
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        finally:
            w.close()

    def answer(self, c: str) -> str:
        out = []
        for name, cmd in ft.SECTIONS:
            if f"echo {ft.MARK}{name}; {cmd}" in c:
                out.append(ft.MARK + name + "\n" + self.out[name])
        for p in re.findall(r"echo " + re.escape(ft.MARK) + r"([A-Za-z0-9_.]+); pidof", c):
            out.append(ft.MARK + p + "\n" + (self.out["_launcher"] if "launcher" in p else "0\n"))
        # only the commands Rollcall is allowed to run
        allowed = {f"echo {ft.MARK}{n}; {cmd}" for n, cmd in ft.SECTIONS}
        rest = c
        for a in allowed:
            rest = rest.replace(a, "")
        rest = re.sub(r"echo " + re.escape(ft.MARK) + r"[A-Za-z0-9_.]+; pidof [A-Za-z0-9_.]+; dumpsys activity services [A-Za-z0-9_.]+ \| grep -c ServiceRecord", "", rest)
        assert not rest.replace(";", "").strip(), f"unexpected command: {rest!r}"
        return "".join(out)
