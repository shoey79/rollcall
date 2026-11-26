"""Agent updates signed with Rollcall's own key (1.92.1), end to end, against the real add-on.

Each agent (Windows: Windows PowerShell 5.1 on Windows, PowerShell 7 elsewhere; Linux: Python) reports through a
proxy that can act as an attacker on the network path, reading the agent's token and changing Rollcall's replies:

1. The released agent (Windows 1.0.52, Linux 1.0.20, kept in tests/fixtures) moves to this version the old way
   (HMAC keyed by its token), then keeps reporting.
2. A later version (the add-on started from a copy with the agent's version raised) arrives signed with Rollcall's
   key and is installed; the agent reports on it.
3. The proxy attacks: an update signed with the captured token (the old way), one signed with another key, a
   real signature on a different script, a downgrade offer, and new addresses without a good signature. Each must
   be refused, the installed agent must be unchanged, nothing the attacker sent may run, and every report must
   still reach the add-on.

Run from the repository root:  python3 -m pytest tests/test_update_signing_e2e.py
"""
import base64
import hashlib
import hmac
import http.server
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "rollcall" / "app"
FIXTURES = ROOT / "tests" / "fixtures" / "released_agents"
WINDOWS = sys.platform == "win32"
PWSH = shutil.which("powershell.exe") if WINDOWS else (os.environ.get("PWSH") or shutil.which("pwsh"))
UI = {"X-Remote-User-Id": "u-owner", "X-Remote-User-Name": "admin"}

try:
    import aiohttp  # noqa: F401
    import cryptography  # noqa: F401
    HAVE_ADDON_DEPS = True
except ImportError:
    HAVE_ADDON_DEPS = False

FAILING = "#!/bin/sh\necho \"ERROR: not here\" >&2\nexit 1\n"


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def call(url, data=None, headers=None, method=None, timeout=30):
    req = urllib.request.Request(url, data=json.dumps(data).encode() if data is not None else None,
                                 headers={"Content-Type": "application/json", **(headers or {})}, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


class Addon:
    """The real add-on (main.py), on free ports, with its data in a folder of its own."""

    def __init__(self, data: Path, https: bool | None = False):
        self.data, self.proc = data, None
        data.mkdir(parents=True, exist_ok=True)
        (data / "options.json").write_text("{}")
        self.ui_port, self.agent_port, self.https_port = free_port(), free_port(), free_port()
        if https is not None:  # Rollcall's own HTTPS (1.93.0); None: as a new install decides (on)
            (data / "agent_tls").mkdir(exist_ok=True)
            (data / "agent_tls" / "state.json").write_text(json.dumps({"https": https, "plain_http": True}))

    def start(self, app: Path = APP, extra_env: dict | None = None, ready: int = 200):
        env = {**os.environ, "PM_OPTIONS": str(self.data / "options.json"), "PM_DB": str(self.data / "ping_monitor.db"),
               "PM_PORT": str(self.ui_port), "PM_AGENT_PORT": str(self.agent_port), "PM_AGENT_HTTPS_PORT": str(self.https_port),
               "PM_SYSLOG_PORT": str(free_port()),
               "PM_SSL_DIR": str(self.data / "ssl"), "PM_HA_API": "http://127.0.0.1:9/api",
               "PM_SUPERVISOR_API": "http://127.0.0.1:9", "PM_HA_WS": "ws://127.0.0.1:9/ws", "PYTHONUNBUFFERED": "1"}
        env.pop("SUPERVISOR_TOKEN", None)  # outside Home Assistant: the test is the admin
        env.update(extra_env or {})
        self.log = open(self.data / "addon.log", "a")
        self.proc = subprocess.Popen([sys.executable, "-u", str(app / "main.py")], env=env, stdout=self.log, stderr=subprocess.STDOUT)
        for _ in range(120):
            try:
                if call(self.ui + "/api/status", headers=UI, timeout=2)[0] == ready:
                    return self
            except OSError:
                pass
            if self.proc.poll() is not None:
                break
            time.sleep(0.5)
        raise AssertionError("the add-on didn't start:\n" + (self.data / "addon.log").read_text()[-3000:])

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(20)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        self.log.close()

    @property
    def ui(self):
        return f"http://127.0.0.1:{self.ui_port}"

    @property
    def agent_url(self):
        return f"http://127.0.0.1:{self.agent_port}"

    def api(self, path, data=None, method=None):
        st, body = call(self.ui + path, data, UI, method)
        assert st == 200, (path, st, body[:300])
        return json.loads(body or b"{}")

    def enrol_key(self, os_name, server):
        st, body = call(f"{self.ui}/api/agents/script?os={os_name}&server={urllib.request.quote(server, safe='')}", headers=UI)
        assert st == 200, body[:300]
        return re.search(r"""ENROL_KEY\s*=\s*"([^"]+)"|\$EnrolKey = '([^']+)'""", body.decode("utf-8-sig")).group(1) or \
            re.search(r"\$EnrolKey = '([^']+)'", body.decode("utf-8-sig")).group(1)

    def agent(self, hostname=None):
        rows = self.api("/api/agents")["agents"]
        return rows[0] if hostname is None else next(r for r in rows if r["hostname"] == hostname)

    def approve_all(self):
        for p in self.api("/api/agents")["pending"]:
            self.api(f"/api/agents/approve/{p['id']}", {}, "POST")


class Proxy:
    """Between the agent and the add-on, like an attacker on the network: forwards everything (so reports reach
    the add-on), records the agent's token, and can change Rollcall's replies."""

    def __init__(self, target):
        self.target, self.mode, self.token, self.reports, self.update_requests = target, "pass", None, [], []
        self.last_config_sig = None
        proxy = self

        class H(http.server.BaseHTTPRequestHandler):
            def _forward(self, method):
                body = self.rfile.read(int(self.headers.get("Content-Length") or 0)) if method == "POST" else None
                auth = self.headers.get("Authorization", "")
                if auth.lower().startswith("bearer "):
                    proxy.token = auth[7:].strip()  # the attacker reads the token on its way past
                if self.path.startswith("/agent/update"):
                    proxy.update_requests.append(self.path)
                    forged = proxy.forged_update()
                    if forged:
                        return self._send(*forged)
                headers = {k: v for k, v in self.headers.items() if k.lower() in ("authorization", "content-type")}
                req = urllib.request.Request(proxy.target + self.path, data=body, headers=headers, method=method)
                try:
                    with urllib.request.urlopen(req, timeout=60) as r:
                        status, out, ctype, extra = r.status, r.read(), r.headers.get("Content-Type", ""), {
                            k: v for k, v in r.headers.items() if k.lower() == "x-rollcall-signature"}
                except urllib.error.HTTPError as e:
                    status, out, ctype, extra = e.code, e.read(), e.headers.get("Content-Type", ""), {}
                if self.path.startswith("/agent/report"):
                    proxy.reports.append(status)
                    if status == 200:
                        out = proxy.tamper_reply(out)
                self._send(status, out, ctype, extra)

            def _send(self, status, out, ctype="application/json", extra=None):
                self.send_response(status)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(out)))
                for k, v in (extra or {}).items():
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(out)

            def do_POST(self):  # noqa: N802
                self._forward("POST")

            def do_GET(self):  # noqa: N802
                self._forward("GET")

            def log_message(self, *_a):
                pass

        self.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.srv.server_address[1]}"
        self.evil = {}

    def tamper_reply(self, out):
        try:
            body = json.loads(out)
        except ValueError:
            return out
        if body.get("config_sig"):
            self.last_config_sig = body["config_sig"]
        if self.mode == "record":      # keeps a real, signed reply to send again later (review F7)
            self.recorded = dict(body)
        elif self.mode == "replay":
            body = dict(self.recorded)
        elif self.mode == "strip":     # the recorded reply, without its serial: the old signature alone
            body = {k: v for k, v in self.recorded.items() if k not in ("sig_serial", "config_sig2", "tls_sig2")}
        if self.mode.startswith("offer_"):
            body["agent_update"] = {"version": "9.9.9"}
        elif self.mode == "downgrade":
            body["agent_update"] = {"version": "1.0.1"}
        elif self.mode == "redirect":  # its own address, keeping Rollcall's (now wrong) signature
            body["servers"] = ["http://127.0.0.1:9"]
            body["route"] = {"inside": "http://127.0.0.1:9", "outside": "http://127.0.0.1:9", "networks": ["0.0.0.0/0"]}
        elif self.mode == "redirect_unsigned":
            body["servers"] = ["http://127.0.0.1:9"]
            body.pop("config_sig", None)
        return json.dumps(body).encode()

    def forged_update(self):
        script = self.evil.get("script")
        if self.mode == "offer_hmac":  # the old way, keyed by the token it just read
            key = hashlib.sha256(self.token.encode()).digest()
            return 200, script, "application/octet-stream", {"X-Rollcall-Signature": hmac.new(key, script, hashlib.sha256).hexdigest()}
        if self.mode == "offer_otherkey":
            return 200, json.dumps({"script": base64.b64encode(script).decode(), "signature": self.evil["other_sig"]}).encode()
        if self.mode == "offer_swapped":  # a genuine signature by Rollcall's key, of something else
            return 200, json.dumps({"script": base64.b64encode(script).decode(), "signature": self.last_config_sig}).encode()
        return None

    def stop(self):
        self.srv.shutdown()


def other_key_signature(data: bytes) -> str:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    k = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    return base64.b64encode(k.sign(data, padding.PKCS1v15(), hashes.SHA256())).decode()


class LinuxAgent:
    kind, os_name = "linux", "linux"

    def __init__(self, tmp: Path):
        self.prefix = tmp / "root"
        self.installed = self.prefix / "usr/local/lib/pingmonitor/pingmonitor-agent.py"
        self.log_path = self.prefix / "var/lib/pingmonitor/agent.log"
        self.marker = tmp / "evil-ran"

    def install_released(self, server, enrol_key):
        text = (FIXTURES / "pingmonitor-agent-1.0.20.py").read_text()
        text = text.replace('SERVER = "__PM_SERVER__"', f'SERVER = "{server}"', 1).replace('ENROL_KEY = "__PM_ENROL_KEY__"', f'ENROL_KEY = "{enrol_key}"', 1)
        self.installed.parent.mkdir(parents=True, exist_ok=True)
        self.installed.write_text(text)
        self.installed.chmod(0o700)

    def version(self):
        return re.search(r'^AGENT_VERSION = "([^"]+)"', self.installed.read_text(), re.M).group(1)

    def evil_script(self):
        return (f'AGENT_VERSION = "9.9.9"\nopen({str(self.marker)!r}, "w").write("ran")\n').encode()

    def run(self):
        env = {**os.environ, "PM_PREFIX": str(self.prefix)}
        p = subprocess.run([sys.executable, str(self.installed)], env=env, capture_output=True, text=True, timeout=600)
        return p

    def log(self):
        return self.log_path.read_text(errors="replace") if self.log_path.exists() else ""


class WindowsAgent:
    kind, os_name = "windows", "windows"

    def __init__(self, tmp: Path):
        self.data = tmp / "data"
        self.data.mkdir(parents=True, exist_ok=True)
        self.installed = self.data / "PingMonitorAgent.ps1"
        self.marker = tmp / "evil-ran"
        self.bin = tmp / "bin"

    def install_released(self, server, enrol_key):
        text = (FIXTURES / "PingMonitorAgent-1.0.52.ps1").read_text(encoding="utf-8-sig")
        text = text.replace("[string]$Server = '__PM_SERVER__'", f"[string]$Server = '{server}'", 1)
        text = text.replace("[string]$EnrolKey = '__PM_ENROL_KEY__'", f"[string]$EnrolKey = '{enrol_key}'", 1)
        self.installed.write_bytes(b"\xef\xbb\xbf" + text.replace("\r\n", "\n").replace("\n", "\r\n").encode("utf-8"))

    def version(self):
        return re.search(r"\$AgentVersion = '([^']+)'", self.installed.read_text(encoding="utf-8-sig")).group(1)

    def evil_script(self):
        return ("﻿$AgentVersion = '9.9.9'\r\nSet-Content -Path '" + str(self.marker).replace("'", "''") + "' -Value ran\r\n").encode("utf-8")

    def run(self):
        if WINDOWS:
            cmd = [PWSH, "-NoLogo", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(self.installed), "-DataPath", str(self.data)]
            env = {k: v for k, v in os.environ.items() if k != "PSModulePath"}
        else:
            self.bin.mkdir(exist_ok=True)
            for name in ("schtasks.exe", "quser.exe", "netsh.exe"):
                p = self.bin / name
                p.write_text(FAILING)
                p.chmod(0o755)
            cmd = [PWSH, "-NoLogo", "-NoProfile", "-File", str(self.installed), "-DataPath", str(self.data)]
            env = {**os.environ, "PATH": f"{self.bin}{os.pathsep}{os.environ.get('PATH', '')}"}
        return subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=600)

    def log(self):
        p = self.data / "agent.log"
        return p.read_text(errors="replace") if p.exists() else ""


def raised_copy(tmp: Path, kind: str, version: str) -> Path:
    """The add-on's app folder with the agent's version raised: what a later release would offer."""
    app = tmp / "app_next"
    shutil.copytree(APP, app, ignore=shutil.ignore_patterns("__pycache__"))
    if kind == "windows":
        p = app / "agent" / "RollcallAgent.ps1"
        p.write_text(re.sub(r"\$AgentVersion = '[^']+'", f"$AgentVersion = '{version}'", p.read_text(encoding="utf-8"), count=1), encoding="utf-8")
    else:
        p = app / "agent" / "rollcall-agent.py"
        p.write_text(re.sub(r'^AGENT_VERSION = "[^"]+"', f'AGENT_VERSION = "{version}"', p.read_text(), count=1, flags=re.M))
    return app


def current_version(kind):
    if kind == "windows":
        return re.search(r"\$AgentVersion = '([^']+)'", (APP / "agent" / "RollcallAgent.ps1").read_text()).group(1)
    return re.search(r'^AGENT_VERSION = "([^"]+)"', (APP / "agent" / "rollcall-agent.py").read_text(), re.M).group(1)


def run_and_check_report(agent, addon, proxy, what):
    """One agent run: its report must reach the add-on (through the proxy) whatever else happens."""
    before = len([s for s in proxy.reports if s == 200])
    p = agent.run()
    got = len([s for s in proxy.reports if s == 200])
    assert got > before, f"{what}: no report reached the add-on\nagent log:\n{agent.log()[-3000:]}\nstderr:\n{p.stderr[-2000:]}"
    return p


@pytest.fixture
def e2e(tmp_path):
    made = []
    yield made
    for thing in made:
        thing.stop()


def scenario(agent, tmp: Path, made: list):
    data = tmp / "addon"
    addon = Addon(data).start()
    made.append(addon)
    proxy = Proxy(addon.agent_url)
    made.append(proxy)

    # 1. The released agent, approved and reporting through the proxy
    agent.install_released(proxy.url, addon.enrol_key(agent.os_name, proxy.url))
    agent.run()                             # enrols: waits for approval
    addon.approve_all()
    run_and_check_report(agent, addon, proxy, "released agent")
    aid = addon.agent()["id"]
    released = agent.version()

    # ... moves to this version the old way (it only knows the token-keyed signature). Over plain HTTP that's only
    # done when an admin allows it (review F5): first not, then allowed for the week
    if agent.version() < "1.0.53" if agent.kind == "windows" else agent.version() < "1.0.21":
        addon.api(f"/api/agents/{aid}/update-now", {}, "POST")
        run_and_check_report(agent, addon, proxy, "old way, not allowed")
        assert agent.version() == released, "updated the old way over plain HTTP without an admin's go-ahead"
        assert addon.agent()["legacy_update"] is True
        addon.api("/api/agents/legacy-updates", {"allow": True}, "POST")
    addon.api(f"/api/agents/{aid}/update-now", {}, "POST")
    run_and_check_report(agent, addon, proxy, "moving across")
    new = current_version(agent.kind)
    assert agent.version() == new, f"didn't move from {released} to {new}\n{agent.log()[-3000:]}"
    assert "__PM_UPDATE_KEY__" not in agent.installed.read_text(encoding="utf-8-sig"), "the update key wasn't built in"
    run_and_check_report(agent, addon, proxy, "first run of the new version")
    assert addon.agent()["version"] == new
    assert "without a good signature" not in agent.log(), agent.log()[-2000:]   # Rollcall's own addresses are signed

    # 2. A later release, signed with Rollcall's key (same data folder, so the same key)
    addon.stop()
    made.remove(addon)
    later = "1.0.99"
    nxt = Addon.__new__(Addon)
    nxt.data, nxt.proc, nxt.ui_port, nxt.agent_port, nxt.https_port = data, None, addon.ui_port, addon.agent_port, addon.https_port
    nxt.start(raised_copy(tmp, agent.kind, later))
    made.append(nxt)
    addon = nxt
    addon.api(f"/api/agents/{aid}/update-now", {}, "POST")
    run_and_check_report(agent, addon, proxy, "signed update")
    assert agent.version() == later, f"the signed update wasn't installed\n{agent.log()[-3000:]}"
    if agent.kind == "linux":  # review F2: the copy kept for rollback holds the enrolment key too: root only
        old = agent.installed.with_name(agent.installed.name + ".old")
        assert old.exists() and old.stat().st_mode & 0o777 == 0o700, oct(old.stat().st_mode)
    assert any("sig=rsa" in u for u in proxy.update_requests[-1:]), proxy.update_requests
    run_and_check_report(agent, addon, proxy, "first run of the signed update")
    assert addon.agent()["version"] == later

    # 3. Attacks from the network path: refused, nothing runs, the agent unchanged, reports carry on
    good = agent.installed.read_bytes()
    proxy.evil["script"] = agent.evil_script()
    proxy.evil["other_sig"] = other_key_signature(proxy.evil["script"])
    for mode, says in (("offer_hmac", "came without a signature"), ("offer_otherkey", "failed its signature check"),
                       ("offer_swapped", "failed its signature check"), ("downgrade", None),
                       ("redirect", "without a good signature"), ("redirect_unsigned", "without a good signature")):
        proxy.mode = mode
        asked = len(proxy.update_requests)
        log_before = len(agent.log())
        run_and_check_report(agent, addon, proxy, mode)
        assert agent.installed.read_bytes() == good, f"{mode}: the installed agent changed\n{agent.log()[-3000:]}"
        assert not agent.marker.exists(), f"{mode}: the attacker's script ran"
        new_log = agent.log()[log_before:]
        if says:
            assert says in new_log, f"{mode}: expected '{says}' in the log\n{new_log[-2000:]}"
        if mode == "downgrade":
            assert len(proxy.update_requests) == asked, "a downgrade offer was even downloaded"
        # and the next run, with nothing changed on the way, reports normally to the real address
        proxy.mode = "pass"
        run_and_check_report(agent, addon, proxy, f"after {mode}")
        assert not agent.marker.exists()
    assert addon.agent()["version"] == later

    # 4. Review F7: a signed reply recorded earlier and sent again after what agents are told has changed is
    # refused (its serial is lower); so is the same reply with its serial taken off
    proxy.mode = "record"
    run_and_check_report(agent, addon, proxy, "recorded")
    assert proxy.recorded.get("sig_serial") and proxy.recorded.get("config_sig2")
    time.sleep(1.1)  # the serial is the time of the change, in seconds
    addon.api("/api/agents/servers", {"inside": proxy.url, "outside": ""}, "POST")
    proxy.mode = "pass"
    run_and_check_report(agent, addon, proxy, "new addresses")
    for mode, says in (("replay", "signed earlier than one this agent already had"), ("strip", "had no serial, though earlier ones did")):
        proxy.mode = mode
        before = len(agent.log())
        run_and_check_report(agent, addon, proxy, mode)
        assert says in agent.log()[before:], f"{mode}: expected '{says}'\n{agent.log()[before:][-2000:]}"
    proxy.mode = "pass"
    before = len(agent.log())
    run_and_check_report(agent, addon, proxy, "after replays")
    assert "signed earlier" not in agent.log()[before:] and "no serial" not in agent.log()[before:]


@pytest.mark.skipif(not HAVE_ADDON_DEPS, reason="needs the add-on's packages (aiohttp, cryptography)")
@pytest.mark.skipif(WINDOWS, reason="the Linux agent runs on Linux")
def test_linux_agent_updates_only_with_rollcalls_signature(tmp_path, e2e):
    scenario(LinuxAgent(tmp_path), tmp_path, e2e)


@pytest.mark.skipif(not HAVE_ADDON_DEPS, reason="needs the add-on's packages (aiohttp, cryptography)")
@pytest.mark.skipif(not PWSH, reason="needs PowerShell")
def test_windows_agent_updates_only_with_rollcalls_signature(tmp_path, e2e):
    scenario(WindowsAgent(tmp_path), tmp_path, e2e)
