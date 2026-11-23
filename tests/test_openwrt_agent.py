"""The OpenWrt agent (rollcall-agent.sh): a shell script for routers too small for Python.

Local: runs it with BusyBox's shell and tools (as on OpenWrt) in a fake OpenWrt made under a temporary
folder, with stand-ins for ubus, jsonfilter, uci and logread, against a stand-in Rollcall. Checks the
report, and the whole ask-to-join / approved / report exchange. Needs busybox; skipped without it.

Real OpenWrt: with Docker and OPENWRT_IMAGE set (e.g. openwrt/rootfs:x86-64-23.05.5, as GitHub's tests
do), also runs it inside that image: its report must be valid JSON from OpenWrt's own BusyBox, it must
reach a stand-in Rollcall with uclient-fetch, and every jsonfilter expression it uses must give the same
answers from OpenWrt's real jsonfilter as from the stand-in.

Run from the repository root:  python3 -m pytest tests/test_openwrt_agent.py
"""
import http.server
import json
import os
import re
import shutil
import subprocess
import sys
import threading
from pathlib import Path

import pytest

AGENT = Path(__file__).resolve().parents[1] / "rollcall" / "app" / "agent" / "rollcall-agent.sh"
BUSYBOX = shutil.which("busybox")
IMAGE = os.environ.get("OPENWRT_IMAGE")
DOCKER = shutil.which("docker")

# What OpenWrt's ubus says about its interfaces and services (shapes from a real 23.05 router)
UBUS = {
    "wan": {"up": True, "pending": False, "available": True, "autostart": True, "uptime": 273600, "l3_device": "eth1", "proto": "dhcp",
            "device": "eth1", "ipv4-address": [{"address": "203.0.113.25", "mask": 24}], "ipv6-address": [],
            "route": [{"target": "0.0.0.0", "mask": 0, "nexthop": "203.0.113.1", "source": "203.0.113.25/32"}],
            "dns-server": ["203.0.113.53", "192.0.2.53"], "data": {}},
    "wan6": {"up": False, "pending": False, "available": True, "autostart": True, "proto": "dhcpv6", "device": "eth1",
             "ipv4-address": [], "ipv6-address": [], "route": [], "dns-server": [],
             "errors": [{"subsystem": "dhcpv6", "code": "NO_ADDRESS"}], "inactive": {"route": [{"target": "::", "mask": 0}]}},
    "lan": {"up": True, "autostart": True, "proto": "static", "l3_device": "br-lan",
            "ipv4-address": [{"address": "192.168.1.1", "mask": 24}], "route": []},
}
SERVICES = {"dnsmasq": True, "dropbear": True, "uhttpd": True, "rpcd": False}
# The jsonfilter expressions the agent uses, with the documents they're used on
EXPRESSIONS = [(i, e) for i in ("wan", "wan6") for e in (
    "@.proto", "@.autostart", "@.up", "@.uptime", "@.l3_device", '@["ipv4-address"][0].address', '@["ipv6-address"][0].address',
    "@.route[*].target", "@.inactive.route[*].target", '@.route[@.target="0.0.0.0"].nexthop', '@["dns-server"][*]', "@.errors[0].code")]

JSONFILTER = r'''#!/usr/bin/env python3
# Stand-in for OpenWrt's jsonfilter: the expressions the Rollcall agent uses
import json, re, sys
args = sys.argv[1:]; expr = args[args.index("-e") + 1]
data = json.load(open(args[args.index("-i") + 1]) if "-i" in args else sys.stdin)
toks = re.findall(r'\.\*|\.[A-Za-z_][\w-]*|\["[^"]+"\]|\[\d+\]|\[\*\]|\[@\.[\w-]+="[^"]*"\]', expr[1:])
cur = [data]
for t in toks:
    nxt = []
    for v in cur:
        if t in (".*", "[*]"):
            nxt += list(v.values()) if isinstance(v, dict) else list(v) if isinstance(v, list) else []
        elif t.startswith("[@"):
            k, want = re.match(r'\[@\.([\w-]+)="([^"]*)"\]', t).groups()
            nxt += [x for x in (v if isinstance(v, list) else []) if isinstance(x, dict) and x.get(k) == want]
        elif t.startswith('["'):
            if isinstance(v, dict) and t[2:-2] in v: nxt.append(v[t[2:-2]])
        elif t.startswith("["):
            i = int(t[1:-1])
            if isinstance(v, list) and i < len(v): nxt.append(v[i])
        elif isinstance(v, dict) and t[1:] in v:
            nxt.append(v[t[1:]])
    cur = nxt
if not cur: sys.exit(1)
for v in cur:
    print("true" if v is True else "false" if v is False else json.dumps(v) if isinstance(v, (dict, list)) else v)
'''

LOGREAD = '''#!/bin/sh
now=$(date +%s)
echo "Mon Nov 17 06:50:01 2026 [$((now-600)).101] authpriv.warn dropbear[2101]: Bad password attempt for 'root' from 192.168.1.66:51234"
echo "Mon Nov 17 06:50:05 2026 [$((now-596)).220] authpriv.warn dropbear[2101]: Bad password attempt for 'root' from 192.168.1.66:51240"
echo "Mon Nov 17 06:51:00 2026 [$((now-540)).010] authpriv.warn dropbear[2110]: Login attempt for nonexistent user from 10.0.1.9:40022"
echo "Mon Nov 17 06:52:00 2026 [$((now-480)).500] daemon.info luci: failed login on / for admin from 192.168.1.70"
echo "Mon Nov 17 06:53:00 2026 [$((now-420)).000] daemon.info dnsmasq[1]: read /etc/hosts - 4 names"
'''


@pytest.fixture
def openwrt(tmp_path):
    """A fake OpenWrt: its files under root/, BusyBox for every command, stand-ins for OpenWrt's own."""
    if not BUSYBOX:
        pytest.skip("needs busybox")
    root, bb, shims, ub = tmp_path / "root", tmp_path / "bb", tmp_path / "shims", tmp_path / "ubus"
    for d in (root / "etc" / "rc.d", root / "tmp" / "sysinfo", root / "sbin", bb, shims, ub):
        d.mkdir(parents=True)
    (root / "etc" / "openwrt_release").write_text("DISTRIB_ID='OpenWrt'\nDISTRIB_RELEASE='23.05.5'\n"
                                                  "DISTRIB_DESCRIPTION='OpenWrt 23.05.5 r24106-10cc5fcd00'\n")
    (root / "tmp" / "sysinfo" / "model").write_text("Test Router Model X\n")
    for n in ("S00sysfixtime", "S10boot", "S19dnsmasq", "S19dropbear", "S50uhttpd", "S12rpcd"):
        (root / "etc" / "rc.d" / n).symlink_to("/bin/true")
    (root / "sbin" / "logread").write_text(LOGREAD)
    applets = subprocess.run([BUSYBOX, "--list"], capture_output=True, text=True).stdout.split()
    for a in applets:
        (bb / a).symlink_to(BUSYBOX)
    for name, data in UBUS.items():
        (ub / f"{name}.json").write_text(json.dumps(data))
    for name, running in SERVICES.items():
        (ub / f"svc_{name}.json").write_text(json.dumps({name: {"instances": {"instance1": {"running": running}}}}))
    (shims / "jsonfilter").write_text(JSONFILTER.replace("/usr/bin/env python3", sys.executable + " -I"))
    (shims / "uci").write_text("#!/bin/sh\necho Lab-Router\n")
    (shims / "ubus").write_text(f'''#!/bin/sh
[ "$1" = -t ] && shift 2
[ "$1" = list ] && {{ for i in lan loopback wan wan6; do echo network.interface.$i; done; exit 0; }}
if [ "$1" = call ] && [ "$2" = service ]; then n=$(echo "$4" | sed 's/.*"name":"\\([^"]*\\)".*/\\1/'); cat "{ub}/svc_$n.json" 2>/dev/null || echo '{{}}'; exit 0; fi
[ "$1" = call ] && {{ f="{ub}/${{2#network.interface.}}.json"; [ -f "$f" ] && cat "$f" && exit 0; exit 4; }}
''')
    for f in shims.iterdir():
        f.chmod(0o755)
    (root / "sbin" / "logread").chmod(0o755)
    env = {"PATH": f"{shims}:{bb}", "RC_ROOT": str(root), "RC_DIR": str(tmp_path / "rollcall"),
           "RC_LOG": str(tmp_path / "agent.log"), "RC_RUN": str(tmp_path), "TMPDIR": str(tmp_path), "HOME": str(tmp_path)}
    return env, tmp_path


def run(env, *args, script=AGENT):
    return subprocess.run([BUSYBOX, "sh", str(script), *args], env=env, capture_output=True, text=True, timeout=60)


def test_report(openwrt):
    env, _ = openwrt
    p = run(env, "--report")
    assert p.returncode == 0, p.stderr
    r = json.loads(p.stdout)
    assert "agent_token" not in r                                     # --report never shows the token
    assert r["agent_kind"] == "sh" and r["os_family"] == "linux" and r["agent_version"] == "1.0.4" and r["tls_capable"] is False
    assert r["hostname"] == "Lab-Router" and r["os"].startswith("OpenWrt 23.05.5 r24106") and r["os_id"] == "openwrt"
    assert r["hw_model"] == "Test Router Model X" and r["roles"] == ["Router (OpenWrt)"] and r["errors"] == []
    assert isinstance(r["cpu_pct"], float) and r["mem_total_mb"] > 0 and len(r["load"]) == 3 and r["uptime_s"] > 0
    assert isinstance(r["cpu_cores"], int) and r["cpu_cores"] >= 1   # 1.0.2: for the Resources check's load
    assert r["checks"]["nics"]["adapters"] and all("rx_bytes" in a or a["status"] != "up" for a in r["checks"]["nics"]["adapters"])
    assert r["checks"]["wan"]["interfaces"] == [
        {"name": "wan", "proto": "dhcp", "up": True, "autostart": True, "uptime_s": 273600, "device": "eth1", "ipv4": "203.0.113.25",
         "ipv6": "", "gateway": "203.0.113.1", "dns": ["203.0.113.53", "192.0.2.53"], "error": ""},
        {"name": "wan6", "proto": "dhcpv6", "up": False, "autostart": True, "uptime_s": None, "device": "", "ipv4": "",
         "ipv6": "", "gateway": "", "dns": [], "error": "NO_ADDRESS"}]
    assert {s["name"]: s["state"] for s in r["services"]["watched"]} == {"dnsmasq": "Running", "dropbear": "Running",
                                                                        "uhttpd": "Running", "rpcd": "Stopped"}
    fl = r["security"]["failed_logons"]
    assert fl["count"] == 4 and sorted((t["account"], t["source"], t["count"], t["via"]) for t in fl["top"]) == [
        ("(no such user)", "10.0.1.9", 1, "SSH"), ("admin", "192.168.1.70", 1, "LuCI"), ("root", "192.168.1.66", 2, "SSH")]


def test_awkward_names_stay_valid_json(openwrt):
    env, tmp = openwrt
    (tmp / "shims" / "uci").write_text('#!/bin/sh\nprintf \'%s\\n\' \'Lab "Router" \\ 2\'\n')
    r = json.loads(run(env, "--report").stdout)
    assert r["hostname"] == 'Lab "Router" \\ 2'


class Rollcall(http.server.BaseHTTPRequestHandler):
    """A stand-in Rollcall agent API: unknown token -> 401; enrol -> 202 pending; once approved -> 200."""
    approved, seen, headers_seen = set(), [], []

    def body(self) -> bytes:
        if self.headers.get("Content-Length"):
            return self.rfile.read(int(self.headers["Content-Length"]))
        out = b""  # chunked, as uclient-fetch may send it
        while (n := int(self.rfile.readline().split(b";")[0].strip() or b"0", 16)):
            out += self.rfile.read(n)
            self.rfile.readline()
        self.rfile.readline()
        return out

    def do_POST(self):  # noqa: N802
        type(self).headers_seen.append(dict(self.headers))
        body = json.loads(self.body())
        tok = (self.headers.get("Authorization") or "").removeprefix("Bearer ") or body.get("agent_token", "")
        type(self).seen.append((self.path, tok, body))
        if self.path == "/agent/enrol":
            code, out = (403, {"error": "wrong enrolment key"}) if body["enrol_key"] != "key-123" else (202, {"status": "pending"})
        elif tok in type(self).approved:
            code, out = 200, {"ok": True, "agent_update": {"version": "9.9.9"}}
        else:
            code, out = (202, {"status": "pending"}) if any(p == "/agent/enrol" and b["token"] == tok for p, _, b in type(self).seen) else (401, {"error": "unknown agent"})
        data = json.dumps(out).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *a):
        pass


def test_join_then_report(openwrt):
    env, tmp = openwrt
    Rollcall.approved, Rollcall.seen = set(), []
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Rollcall)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    script = tmp / "rollcall-agent.sh"
    script.write_text(AGENT.read_text().replace('SERVER="__PM_SERVER__"', f'SERVER="http://127.0.0.1:9,http://127.0.0.1:{srv.server_port}"', 1)
                      .replace('ENROL_KEY="__PM_ENROL_KEY__"', 'ENROL_KEY="key-123"', 1))
    try:
        run(env, script=script)                                       # asks to join (after the first address fails)
        token = (tmp / "rollcall" / "token").read_text()
        assert re.fullmatch(r"[0-9a-f]{64}", token)
        assert [s[0] for s in Rollcall.seen] == ["/agent/report", "/agent/enrol"]
        enrol = Rollcall.seen[1][2]
        assert enrol["token"] == token and enrol["hostname"] == "Lab-Router" and enrol["agent_kind"] == "sh"
        run(env, script=script)                                       # still waiting
        Rollcall.approved.add(token)
        run(env, script=script)                                       # approved: report accepted
        path, tok, body = Rollcall.seen[-1]
        assert path == "/agent/report" and tok == token and body["security"]["failed_logons"]["count"] == 4
        run(env, script=script)                                       # the same failed sign-ins aren't counted twice
        assert Rollcall.seen[-1][2]["security"]["failed_logons"]["count"] == 0
        log = (tmp / "agent.log").read_text()
        assert "Not enrolled yet: asking to join" in log and "Waiting for approval" in log and "Report sent to http://127.0.0.1:" in log
        assert "WARN http://127.0.0.1:9 didn't answer" in log
        assert not (tmp / "rollcall" / "agent.sh").exists()           # an offered update is ignored: it updates by download only
    finally:
        srv.shutdown()


def test_install_and_uninstall(openwrt):
    env, tmp = openwrt
    cron = tmp / "crontab"
    env = {**env, "RC_CRONTAB": str(cron)}
    script = tmp / "rollcall-agent.sh"
    script.write_text(AGENT.read_text().replace('SERVER="__PM_SERVER__"', 'SERVER="http://127.0.0.1:9"', 1))
    run(env, "--install", script=script)
    assert (tmp / "rollcall" / "agent.sh").exists() and "rollcall/agent.sh" in cron.read_text()
    run(env, "--install", script=script)                              # again: no second cron line
    assert cron.read_text().count("rollcall/agent.sh") == 1
    run(env, "--uninstall", script=script)
    assert not (tmp / "rollcall").exists() and "rollcall" not in cron.read_text()


# --- real OpenWrt (GitHub's tests run this with Docker) ----------------------------------------------
needs_openwrt = pytest.mark.skipif(not (IMAGE and DOCKER), reason="needs Docker and OPENWRT_IMAGE")


def owrt(*cmd, stdin=None, extra=()):
    """Runs OpenWrt's own shell in the image (not its init), with these arguments."""
    return subprocess.run([DOCKER, "run", "--rm", "-i", "--entrypoint", "/bin/sh", *extra, IMAGE, *cmd], input=stdin,
                          capture_output=True, text=True, timeout=120)


@needs_openwrt
def test_real_jsonfilter_matches_the_stand_in(tmp_path):
    shim = tmp_path / "jsonfilter"
    shim.write_text(JSONFILTER.replace("/usr/bin/env python3", sys.executable + " -I"))
    shim.chmod(0o755)
    script = "".join(f"echo '=={n}'; echo '{json.dumps(UBUS[i])}' | jsonfilter -e '{e}'; echo \"rc=$?\"\n" for n, (i, e) in enumerate(EXPRESSIONS))
    real = owrt("-s", stdin=script).stdout
    mine = ""
    for n, (i, e) in enumerate(EXPRESSIONS):
        p = subprocess.run([str(shim), "-e", e], input=json.dumps(UBUS[i]), capture_output=True, text=True)
        mine += f"=={n}\n{p.stdout}rc={0 if p.returncode == 0 else 1}\n"
    assert real == mine, "\n".join(f"{i} {e}" for i, e in EXPRESSIONS)


@needs_openwrt
def test_real_openwrt_reports(tmp_path):
    Rollcall.approved, Rollcall.seen = set(), []
    srv = http.server.ThreadingHTTPServer(("0.0.0.0", 0), Rollcall)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        script = AGENT.read_text().replace('SERVER="__PM_SERVER__"', f'SERVER="http://host.docker.internal:{srv.server_port}"', 1) \
            .replace('ENROL_KEY="__PM_ENROL_KEY__"', 'ENROL_KEY="key-123"', 1)
        p = owrt("-c", "cat > /tmp/a.sh; sh /tmp/a.sh --report; echo '<<SEP>>'; sh /tmp/a.sh; cat /tmp/rollcall-agent.log",
                 stdin=script, extra=("--add-host", "host.docker.internal:host-gateway"))
        report, _, rest = p.stdout.partition("<<SEP>>")
        r = json.loads(report)
        assert r["os"].startswith("OpenWrt") and r["ps_version"].startswith("BusyBox") and r["errors"] == [], r
        assert r["checks"]["nics"]["adapters"] and isinstance(r["cpu_pct"], float)
        assert "asking to join" in rest and [s[0] for s in Rollcall.seen] == ["/agent/report", "/agent/enrol"], (rest, p.stderr, Rollcall.headers_seen)
        assert Rollcall.seen[1][2]["hostname"] and Rollcall.seen[1][2]["agent_kind"] == "sh"
    finally:
        srv.shutdown()


def test_nothing_written_to_flash_after_joining_and_runs_dont_pile_up(openwrt):
    """1.0.1: the log-read marker lives in RAM (/tmp), not the router's flash, where writing it every 5 minutes
    could wear a small router down; the log is kept short; and a second run while one is going is skipped."""
    env, tmp = openwrt
    Rollcall.approved, Rollcall.seen = set(), []
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Rollcall)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    script = tmp / "rollcall-agent.sh"
    script.write_text(AGENT.read_text().replace('SERVER="__PM_SERVER__"', f'SERVER="http://127.0.0.1:{srv.server_port}"', 1)
                      .replace('ENROL_KEY="__PM_ENROL_KEY__"', 'ENROL_KEY="key-123"', 1))
    flash = tmp / "rollcall"
    try:
        run(env, script=script)                                       # joins: the token is saved (once)
        Rollcall.approved.add((flash / "token").read_text())
        (flash / "since").write_text("123")                          # left by 1.0.0
        before = {p.name: p.stat().st_mtime_ns for p in flash.iterdir() if p.name != "since"}
        for _ in range(3):
            run(env, script=script)
        assert sorted(p.name for p in flash.iterdir()) == ["token"]   # 1.0.0's marker removed, nothing new
        assert {p.name: p.stat().st_mtime_ns for p in flash.iterdir()} == before
        assert (tmp / "rollcall-since").exists()                      # in RAM instead
        # a run already going: the next is skipped
        (tmp / "rollcall.lock").mkdir()
        (tmp / "rollcall-hold.sh").write_text("sleep 30\n")                 # looks like a run: "sh .../rollcall..."
        holder = subprocess.Popen([BUSYBOX, "sh", str(tmp / "rollcall-hold.sh")])
        (tmp / "rollcall.lock" / "pid").write_text(str(holder.pid))
        try:
            n = len(Rollcall.seen)
            run(env, script=script)
            assert len(Rollcall.seen) == n and "Another run is still going" in (tmp / "agent.log").read_text()
        finally:
            holder.kill()
        run(env, script=script)                                       # it's gone: this one runs
        assert len(Rollcall.seen) == n + 1 and not (tmp / "rollcall.lock").exists()
        # the log in /tmp is trimmed
        (tmp / "agent.log").write_text("x" * 40000 + "\n")
        run(env, script=script)
        assert (tmp / "agent.log").stat().st_size < 32768
    finally:
        srv.shutdown()


# --- Rollcall's own HTTPS (router agent 1.0.3) ------------------------------------------------------------------
def _addon(tmp_path):
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from test_update_signing_e2e import HAVE_ADDON_DEPS, Addon
    if not HAVE_ADDON_DEPS:
        pytest.skip("needs the add-on's packages (aiohttp, cryptography)")
    return Addon(tmp_path / "addon", https=True)


def test_router_moves_to_rollcalls_own_https(openwrt):
    """Against the real add-on with HTTPS on: the first report hands over the certificate, kept on flash only when it
    changes; the next one goes over HTTPS trusting only that certificate (curl here; uclient-fetch on OpenWrt)."""
    env, tmp = openwrt
    curl = shutil.which("curl")
    if not curl:
        pytest.skip("needs curl")
    (tmp / "shims" / "curl").symlink_to(curl)
    addon = _addon(tmp).start()
    try:
        script = tmp / "agent.sh"
        script.write_text(AGENT.read_text().replace('SERVER="__PM_SERVER__"', f'SERVER="{addon.agent_url}"', 1)
                          .replace('ENROL_KEY="__PM_ENROL_KEY__"', f'ENROL_KEY="{addon.enrol_key("windows", addon.agent_url)}"', 1))
        run(env, script=script)                       # asks to join
        addon.approve_all()
        run(env, script=script)                       # reports over HTTP; gets the certificate
        pem = tmp / "rollcall" / "rollcall.pem"
        assert pem.exists() and (tmp / "rollcall" / "tls_port").read_text().strip() == str(addon.https_port), (tmp / "agent.log").read_text()
        stamp = pem.stat().st_mtime_ns
        run(env, script=script)
        log = (tmp / "agent.log").read_text()
        assert f"Report sent to https://127.0.0.1:{addon.https_port}" in log, log
        assert addon.agent()["sent_to"] == f"https://127.0.0.1:{addon.https_port}"
        assert pem.stat().st_mtime_ns == stamp        # not written again: unchanged
        addon.api("/api/agents/tls", {"https": False}, "POST")
        run(env, script=script)                       # over HTTPS this time fails (off): HTTP; told it's off
        run(env, script=script)
        assert not pem.exists() and "Rollcall's HTTPS was turned off" in (tmp / "agent.log").read_text()
        assert addon.agent()["sent_to"] == addon.agent_url
    finally:
        addon.stop()


@needs_openwrt
def test_real_openwrt_moves_to_https_when_it_can(tmp_path):
    """In the real OpenWrt image, against the real add-on: with uclient-fetch's TLS library present it moves to HTTPS
    (the certificate lists host.docker.internal once the router has reported from it); without one it carries on over
    HTTP. Either way every report gets through."""
    addon = _addon(tmp_path).start()
    try:
        url = f"http://host.docker.internal:{addon.agent_port}"
        script = AGENT.read_text().replace('SERVER="__PM_SERVER__"', f'SERVER="{url}"', 1) \
            .replace('ENROL_KEY="__PM_ENROL_KEY__"', f'ENROL_KEY="{addon.enrol_key("windows", url)}"', 1)
        (tmp_path / "a.sh").write_text(script)
        shell = ("cp /w/a.sh /tmp/a.sh; sh /tmp/a.sh; touch /w/go; i=0; while [ ! -f /w/approved ] && [ $i -lt 60 ]; do sleep 1; i=$((i+1)); done; "
                 "for n in 1 2 3 4; do sh /tmp/a.sh; sleep 2; done; ls /lib/libustream* /usr/lib/libustream* 2>/dev/null | head -1; echo '<<LOG>>'; cat /tmp/rollcall-agent.log")
        proc = subprocess.Popen([DOCKER, "run", "--rm", "-i", "--entrypoint", "/bin/sh", "--add-host", "host.docker.internal:host-gateway",
                                 "-v", f"{tmp_path}:/w", IMAGE, "-c", shell], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        for _ in range(120):
            if (tmp_path / "go").exists():
                break
            __import__("time").sleep(1)
        addon.approve_all()
        (tmp_path / "approved").write_text("1")
        out, err = proc.communicate(timeout=300)
        tls_lib, _, log = out.partition("<<LOG>>")
        sent = addon.agent()["sent_to"]
        print("TLS library:", tls_lib.strip() or "none", "| last report via", sent)
        assert "ERROR" not in log, log
        if tls_lib.strip():
            assert sent == f"https://host.docker.internal:{addon.https_port}", log
        else:
            assert sent == url, log
    finally:
        addon.stop()


def test_router_without_tls_stays_on_http_and_holds_plain_http_on(openwrt):
    """Issue #17: most routers have uclient-fetch without its TLS library (and no curl), so they can't use HTTPS at
    all. Router agent 1.0.4 doesn't try, says so in its report, and Rollcall lists it before plain HTTP can go off."""
    env, tmp = openwrt                                # BusyBox wget only: no curl, no TLS library
    addon = _addon(tmp).start()
    from test_update_signing_e2e import UI, call
    try:
        script = tmp / "agent.sh"
        script.write_text(AGENT.read_text().replace('SERVER="__PM_SERVER__"', f'SERVER="{addon.agent_url}"', 1)
                          .replace('ENROL_KEY="__PM_ENROL_KEY__"', f'ENROL_KEY="{addon.enrol_key("windows", addon.agent_url)}"', 1))
        run(env, script=script)
        addon.approve_all()
        run(env, script=script)
        run(env, script=script)                       # has the certificate, but can't use it
        log = (tmp / "agent.log").read_text()
        assert "didn't answer" not in log and f"Report sent to {addon.agent_url}" in log, log   # no HTTPS attempt
        rd = addon.api("/api/agents")["tls"]["readiness"]
        assert rd["no_tls"] == [addon.agent()["hostname"]] and rd["ready"] is False, rd
        assert addon.api("/api/status")["tls_plain_prompt"] is False
        st, body = call(addon.ui + "/api/agents/tls", {"plain_http": False}, UI, "POST")
        assert st == 409 and json.loads(body)["readiness"]["no_tls"], body[:300]
    finally:
        addon.stop()
