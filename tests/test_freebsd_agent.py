"""The pfSense / OPNsense / FreeBSD agent (owner's request, 23 Nov), run under sh with FreeBSD's and pfSense's
commands stood in, shaped like the owner's test output (a Hyper-V VM, one gateway, IPsec mobile clients).
Names and addresses are made up.

Run from the repository root:  python3 -m pytest tests/test_freebsd_agent.py
"""
import json
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "rollcall" / "app"))
import agents as A  # noqa: E402

AGENT = ROOT / "rollcall" / "app" / "agent" / "rollcall-agent-freebsd.sh"

SYSCTL = {
    "hw.model": "Intel(R) Xeon(R) CPU E5-2650 v2 @ 2.60GHz", "kern.vm_guest": "hv",
    "kern.boottime": "{ sec = 1764000000, usec = 123 } Mon Nov 24 16:00:00 2025", "hw.pagesize": "4096",
    "hw.physmem": str(4 * 1024 ** 3), "vm.stats.vm.v_free_count": "500000", "vm.stats.vm.v_inactive_count": "100000",
    "vm.stats.vm.v_cache_count": "0", "vm.loadavg": "{ 0.12 0.20 0.25 }", "hw.ncpu": "2",
}
IFCONFIG = {
    "hn0": "hn0: flags=1008843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST,LOWER_UP> metric 0 mtu 1500\n\tether 00:15:5d:00:00:01\n\tinet 203.0.113.2 netmask 0xffffff00 broadcast 203.0.113.255\n\tmedia: Ethernet autoselect (10Gbase-T <full-duplex>)\n\tstatus: active",
    "hn1": "hn1: flags=1008843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST,LOWER_UP> metric 0 mtu 1500\n\tether 00:15:5d:00:00:02\n\tinet 192.168.1.1 netmask 0xffffff00 broadcast 192.168.1.255\n\tinet 192.168.1.254 netmask 0xffffffff vhid 1\n\tcarp: MASTER vhid 1 advbase 1 advskew 0\n\tmedia: Ethernet autoselect (1000baseT <full-duplex>)\n\tstatus: active",
    "hn2": "hn2: flags=8802<BROADCAST,SIMPLEX,MULTICAST> metric 0 mtu 1500\n\tether 00:15:5d:00:00:03\n\tmedia: Ethernet autoselect\n\tstatus: no carrier",
    "lo0": "lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> metric 0 mtu 16384\n\tinet 127.0.0.1 netmask 0xff000000",
}
NETSTAT = """Name    Mtu Network       Address              Ipkts Ierrs Idrop     Ibytes    Opkts Oerrs     Obytes  Coll
hn0    1500 <Link#1>      00:15:5d:00:00:01  1000000     3     1 1500000000   900000     0  800000000     0
hn0       - 203.0.113.0/2 203.0.113.2         500000     -     -  700000000   400000     -  300000000     -
hn1    1500 <Link#2>      00:15:5d:00:00:02  2000000     0     0 2500000000  2100000     2 2600000000     0
hn2    1500 <Link#3>      00:15:5d:00:00:03        0     0     0          0        0     0          0     0
lo0   16384 <Link#4>      lo0                    10     0     0       1000       10     0       1000     0
"""


def make_env(tmp_path, *, gw_status="online", sas=""):
    b, root = tmp_path / "bin", tmp_path / "root"
    b.mkdir()
    (root / "etc").mkdir(parents=True)
    (root / "etc" / "platform").write_text("pfSense\n")
    (root / "etc" / "version").write_text("2.9.0-RELEASE\n")
    data = {"sysctl": SYSCTL, "ifconfig": IFCONFIG, "netstat": NETSTAT, "gw": gw_status, "sas": sas}
    (tmp_path / "data.json").write_text(json.dumps(data))
    py = sys.executable
    tools = {
        # kern.cp_time goes up between the two reads: 50 busy of 200 ticks = 25%
        "sysctl": f"""import json, sys, os
d = json.load(open({str(tmp_path / 'data.json')!r}))["sysctl"]
args = [a for a in sys.argv[1:] if a != "-n"]
if args == ["-a"]:
    print("dev.cpu.0.freq: 2600"); sys.exit(0)   # a VM: no temperature sensors
if args == ["kern.cp_time"]:
    f = {str(tmp_path / 'cp')!r}; n = int(open(f).read()) if os.path.exists(f) else 0; open(f, "w").write(str(n + 1))
    print("100 0 50 0 850" if n % 2 == 0 else "130 0 70 0 1000"); sys.exit(0)
if args[0] in d: print(d[args[0]]); sys.exit(0)
sys.exit(1)""",
        "ifconfig": f"""import json, sys
d = json.load(open({str(tmp_path / 'data.json')!r}))["ifconfig"]
a = sys.argv[1:]
if a == ["-l"]: print(" ".join(d)); sys.exit(0)
if a == ["-a", "inet"] or not a:
    print("\\n".join(d.values())); sys.exit(0)
if a[0] in d: print(d[a[0]]); sys.exit(0)
sys.exit(1)""",
        "netstat": f"import json; print(json.load(open({str(tmp_path / 'data.json')!r}))['netstat'], end='')",
        "hostname": 'import sys; print("fw01" if "-s" in sys.argv else "fw01.example.local")',
        "freebsd-version": 'print("16.0-RELEASE")',
        "df": 'print("Filesystem 1024-blocks Used Avail Capacity Mounted on\\n/dev/da0p3 20000000 4000000 16000000 20% /")',
        "pfctl": 'import sys; print("State Table                          Total             Rate\\n  current entries                     1234" if sys.argv[1] == "-si" else "states        hard limit   400000\\nsrc-nodes     hard limit   400000")',
        # pfSense's PHP: interface descriptions, and gateway status
        "php": f"""import json, sys
code = sys.argv[-1]
if "get_configured_interface_with_descr" in code: print("hn0|WAN\\nhn1|LAN")
elif "return_gateways_status" in code:
    s = json.load(open({str(tmp_path / 'data.json')!r}))["gw"]
    print("GW_ONE|198.51.100.1|4.2ms|0.3ms|" + ("100.0%" if s == "down" else "0.0%") + "|" + s + "|none")""",
        "swanctl": f"""import json, sys
if "--list-conns" in sys.argv: print("con-mobile: IKEv2, no reauthentication, rekeying every 14400s\\n  local:  %any\\n  remote: %any\\ncon1: IKEv2, reauthentication every 10800s\\n  local:  203.0.113.2\\n  remote: 198.51.100.9")
else: print(json.load(open({str(tmp_path / 'data.json')!r}))["sas"], end="")""",
        "pfSense-upgrade": 'print(">>> Updating repositories metadata...\\nYour system is up to date")',
        "date": """import subprocess, sys
a = sys.argv[1:]
if "-r" in a:   # BSD date -r SECONDS: GNU date wants -d @SECONDS
    i = a.index("-r"); a[i:i + 2] = ["-d", "@" + a[i + 1]]
sys.exit(subprocess.call(["/bin/date"] + a))""",
    }
    for name, body in tools.items():
        p = b / name
        p.write_text(f"#!{py}\n{body}\n")
        p.chmod(p.stat().st_mode | stat.S_IEXEC)
    env = {**os.environ, "PATH": f"{b}:{os.environ['PATH']}", "RC_ROOT": str(root), "RC_DIR": str(tmp_path / "etc-rollcall"),
           "RC_LOG": str(tmp_path / "agent.log"), "RC_RUN": str(tmp_path), "RC_CROND": str(tmp_path / "cron.d"), "TMPDIR": str(tmp_path)}
    return env


def report(tmp_path, **kw):
    env = make_env(tmp_path, **kw)
    p = subprocess.run(["sh", str(AGENT), "--report"], capture_output=True, text=True, env=env, timeout=60)
    assert p.returncode == 0, p.stderr
    return json.loads(p.stdout)


@pytest.mark.skipif(not shutil.which("sh"), reason="needs sh")
def test_report_from_pfsense(tmp_path):
    r = report(tmp_path)
    assert r["agent_kind"] == "sh" and r["platform"] == "freebsd" and r["roles"] == ["Firewall (pfSense)"]
    assert r["os"] == "pfSense 2.9.0-RELEASE (FreeBSD 16.0-RELEASE)" and r["os_id"] == "pfsense" and r["virtual"] is True
    assert r["hostname"] == "fw01" and r["cpu_pct"] == 25.0 and r["cpu_cores"] == 2 and r["load"] == [0.12, 0.2, 0.25]
    assert r["mem_total_mb"] == 4096 and r["mem_free_mb"] == 2343      # (500000 + 100000) pages of 4 KB
    assert r["boot_time"] == "2025-11-24T16:00:00Z" and r["uptime_s"] > 0
    assert set(r["ips"]) == {"203.0.113.2", "192.168.1.1", "192.168.1.254"}
    assert r["disks"] == [{"name": "/", "label": "/dev/da0p3", "size_gb": 19.073, "free_gb": 15.259}]
    nics = {n["name"]: n for n in r["checks"]["nics"]["adapters"]}
    assert set(nics) == {"hn0", "hn1", "hn2"}                            # not the loopback
    assert nics["hn0"]["desc"] == "WAN" and nics["hn0"]["speed_mbps"] == 10000 and nics["hn0"]["rx_errors"] == 3 and nics["hn0"]["rx_bytes"] == 1500000000
    assert nics["hn1"]["speed_mbps"] == 1000 and nics["hn1"]["tx_errors"] == 2 and nics["hn2"]["status"] == "disabled"
    fw = r["checks"]["firewall"]
    assert fw["product"] == "pfSense" and fw["version"] == "2.9.0-RELEASE"
    assert fw["gateways"] == [{"name": "GW_ONE", "monitor": "198.51.100.1", "delay_ms": 4.2, "stddev_ms": 0.3, "loss_pct": 0.0, "status": "online", "substatus": "none"}]
    assert fw["carp"] == [{"interface": "hn1", "state": "MASTER", "vhid": 1}]
    assert fw["ipsec"] == {"configured": 2, "mobile": 1, "up": 0, "down": ["con1"]}   # mobile clients aren't expected up
    assert fw["states"] == {"current": 1234, "limit": 400000}
    assert fw["update"]["available"] is False and fw["update"]["checked"].endswith("Z")
    assert r["checks"]["temps"] == {"sensors": [], "virtual": True}

    out = A.evaluate(A.normalize_report(r), {}, 1764200000.0, {})
    c = {x["key"]: x for x in out["checks"]}
    assert c["firewall"]["level"] == A.WARN and c["firewall"]["detail"] == "IPsec down: con1"


@pytest.mark.skipif(not shutil.which("sh"), reason="needs sh")
def test_gateway_down_is_red_and_tunnel_up_counts(tmp_path):
    r = report(tmp_path, gw_status="down", sas="con1: #3, ESTABLISHED, IKEv2, 1234abcd_i 5678ef01_r*\n  local  '203.0.113.2' @ 203.0.113.2[500]\n")
    fw = r["checks"]["firewall"]
    assert fw["ipsec"]["up"] == 1 and fw["ipsec"]["down"] == []
    c = A.firewall_check(A.clean_firewall(fw))
    assert c["level"] == A.CRIT and c["confirm"] and "gateway GW_ONE down (100% loss)" in c["detail"]
    ok = A.firewall_check(A.clean_firewall({**fw, "gateways": [dict(fw["gateways"][0], status="online", loss_pct=0)]}))
    assert ok["level"] == A.OK and ok["detail"] == "1 gateway online; 1 IPsec up; CARP master"


@pytest.mark.skipif(not shutil.which("sh"), reason="needs sh")
def test_install_adds_a_cron_d_job_and_uninstall_removes_it(tmp_path):
    env = make_env(tmp_path)
    env["RC_DIR"] = str(tmp_path / "rc")
    p = subprocess.run(["sh", str(AGENT), "--install"], capture_output=True, text=True, env={**env, "PATH": env["PATH"]}, timeout=60)
    cron = (tmp_path / "cron.d" / "rollcall").read_text()
    assert "*/5\t*\t*\t*\t*\troot\t/bin/sh " + str(tmp_path / "rc") + "/agent.sh" in cron
    assert oct((tmp_path / "rc").stat().st_mode & 0o777) == "0o700" and (tmp_path / "rc" / "agent.sh").exists()
    subprocess.run(["sh", str(tmp_path / "rc" / "agent.sh"), "--uninstall"], capture_output=True, text=True, env=env, timeout=60)
    assert not (tmp_path / "cron.d" / "rollcall").exists() and not (tmp_path / "rc").exists()


def test_download_builds_in_the_address_and_key(tmp_path, monkeypatch):
    import main
    body = main.build_agent_script("freebsd", "http://192.168.1.5:8099", "k" * 40, False).decode()
    assert 'SERVER="http://192.168.1.5:8099"' in body and 'ENROL_KEY="' + "k" * 40 + '"' in body
    assert body.startswith("#!/bin/sh") and "AGENT_VERSION=" in body and "\r" not in body
