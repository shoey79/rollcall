"""The Resources check (memory, CPU, router load), and the Details tidy-up: who changed the agent's folder,
Defender's last scans, and nobody shown signed in while a device is off.

Run from the repository root:  python3 -m pytest tests/test_resources_and_tidy.py
"""
import os
import re
import sqlite3
import subprocess
import sys
import time
import types
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "rollcall" / "app"))
import agents as A  # noqa: E402
import metrics as M  # noqa: E402

OPTS = {"agent_memory_warn": 90, "agent_memory_crit": 95, "agent_cpu_warn": 90, "agent_cpu_reports": 3}
AGENT = ROOT / "rollcall" / "app" / "agent" / "PingMonitorAgent.ps1"
PWSH = os.environ.get("PWSH") or "pwsh"


def res(report, settings=None, opts=OPTS):
    r = A.normalize_report({"os_family": "windows", **report})
    c = next((c for c in A.evaluate(r, opts, settings=settings or {})["checks"] if c["key"] == "resources"), None)
    return c and (c["level"], c["detail"], c["confirm"])


def mem(used_pct, **kw):
    return {"mem_total_mb": 1000, "mem_free_mb": 1000 - used_pct * 10, "cpu_pct": 10.0, **kw}


def test_memory_amber_then_red_after_two_reports():
    assert res(mem(50)) == (A.OK, "Memory 50% used, CPU 10%", False)
    assert res(mem(91)) == (A.WARN, "Memory 91% used (amber at 90%)", False)
    level, detail, confirm = res(mem(96))
    assert level == A.CRIT and confirm and detail == "Memory 96% used (red at 95%)"   # red (and alerts) only after 2 reports


def test_own_limits_turning_off_and_add_on_options():
    assert res(mem(91), {"resources": {"mem_warn": 95, "mem_crit": 98}})[0] == A.OK
    assert res(mem(99), {"resources": {"off": True}}) is None
    assert res(mem(99), {"resources": {"mem_warn": 0, "mem_crit": 0}})[0] == A.OK          # 0: memory not checked
    assert res(mem(91), opts={**OPTS, "agent_memory_warn": 0})[0] == A.OK
    assert res({"cpu_pct": None}) is None                                                  # nothing to check


def test_sql_server_and_exchange_keep_memory_for_themselves():
    level, detail, _ = res(mem(97, roles=["SQL Server"]))
    assert level == A.OK and "not checked: SQL Server keeps memory for itself" in detail
    assert res(mem(97, roles=["Exchange"]), {"resources": {"mem_crit": 98}})[0] == A.WARN  # its own limits: checked


def test_cpu_must_be_busy_in_the_last_reports_and_is_never_red():
    busy = {"cpu_pct": 97.0, "mem_total_mb": 1000, "mem_free_mb": 500}
    assert res(busy, {"cpu_recent": [97, 95]})[0] == A.OK                    # only two readings so far
    assert res(busy, {"cpu_recent": [97, 40, 95]})[0] == A.OK                # a quiet one in between
    level, detail, _ = res(busy, {"cpu_recent": [97, 95, 99, 12]})
    assert level == A.WARN and detail == "CPU 97%, at 90% or more in the last 3 reports"
    assert res(busy, {"cpu_recent": [100] * 5}, {**OPTS, "agent_cpu_reports": 5})[0] == A.WARN


def test_router_load_above_its_cores():
    r = {"agent_kind": "sh", "os_family": "linux", "cpu_pct": 20.0, "mem_total_mb": 121, "mem_free_mb": 66, "load": [3.1, 2.5, 1.4]}
    assert res({**r, "cpu_cores": 1})[:2] == (A.WARN, "15-minute load 1.40 on 1 CPU core")
    assert res({**r, "cpu_cores": 2})[:2] == (A.OK, "Memory 45.5% used, CPU 20%, load 1.40")
    assert res(r)[0] == A.OK                                                  # router agent 1.0.1: no core count, no load check


def test_recent_cpu_readings_newest_first_in_a_window():
    m = M.Metrics(sqlite3.connect(":memory:"))
    for i, v in enumerate([10, 95, 96, 97]):
        m.record("pc10", 1000 + i * 300, {"cpu": v})
    assert m.recent("pc10", "cpu", 1000 + 300, 1000 + 900, 3) == [97, 96, 95]
    assert m.recent("pc10", "cpu", 0, 1000 + 300, 3) == [95, 10]             # nothing after the report being checked


def test_who_changed_the_agent_folder():
    what = ["the agent folder was owned by CONTOSO\\admin", "CONTOSO\\admin, BUILTIN\\Users had access to the agent folder",
            "agent.log was owned by CONTOSO\\admin"]
    g = A.integrity_who(what)
    assert g == {"who": ["CONTOSO\\admin"], "access": ["BUILTIN\\Users"], "opened": False}
    assert A.integrity_by(g) == " by CONTOSO\\admin"
    assert A.integrity_by(A.integrity_who(["BUILTIN\\Users had access to agent.log"])) == " to give BUILTIN\\Users access"
    assert A.integrity_by(A.integrity_who(["state.json could be read by others (644)"])) == " so others could read them"
    at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 600))
    r = A.normalize_report({"os_family": "windows", "agent_integrity": {"at": at, "what": what}})
    assert r["agent_integrity"]["who"] == ["CONTOSO\\admin"]
    c = next(c for c in A.evaluate(r, {})["checks"] if c["key"] == "integrity")
    assert c["level"] == A.WARN and re.fullmatch(r"Its folder's permissions were changed by CONTOSO\\admin; the agent reset them at \d\d:\d\d on \d+ \w+", c["detail"])


def test_defender_scan_times_are_kept():
    r = A.normalize_report({"checks": {"defender": {"mode": "Normal", "quick_scan_end": "2026-11-19T03:12:00Z", "full_scan_end": 7}}})
    assert r["checks"]["defender"]["quick_scan_end"] == "2026-11-19T03:12:00Z" and r["checks"]["defender"]["full_scan_end"] is None


def test_nobody_signed_in_while_off_or_silent():
    import main
    me = types.SimpleNamespace(opts={"agent_stale_minutes": 15})
    host = lambda **kw: types.SimpleNamespace(**{"status": main.GREEN, "off_schedule": False, "unreachable": False, "agent_seen": time.time(), **kw})
    gone = lambda h: main.Monitor._agent_gone(me, h)
    assert not gone(host())
    assert gone(host(status=main.RED)) and gone(host(off_schedule=True)) and gone(host(unreachable=True))
    assert gone(host(agent_seen=time.time() - 20 * 60)) and not gone(host(agent_seen=time.time() - 8 * 60))


@pytest.mark.skipif(not (Path(PWSH).exists() or subprocess.run(["which", PWSH], capture_output=True).returncode == 0), reason="needs PowerShell")
def test_agent_reads_defender_scan_times():
    src = AGENT.read_text()
    snippet = re.search(r"( *# When the last quick and full scans.*?\n            \}\n)", src, re.S).group(1)
    script = f'''
$ErrorActionPreference = 'Stop'
function ConvertTo-UtcString($Date) {{ ([DateTime]$Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') }}
$mp = [pscustomobject]@{{ QuickScanEndTime = [DateTime]::new(2026, 11, 19, 3, 12, 0, [DateTimeKind]::Utc); FullScanEndTime = [DateTime]::FromFileTimeUtc(0) }}
$def = [ordered]@{{ quick_scan_end = $null; full_scan_end = $null }}
{snippet}
$def | ConvertTo-Json -Compress
'''
    p = subprocess.run([PWSH, "-NoProfile", "-NonInteractive", "-Command", script], capture_output=True, text=True, timeout=120)
    assert p.returncode == 0, p.stderr
    assert p.stdout.strip().splitlines()[-1] == '{"quick_scan_end":"2026-11-19T03:12:00Z","full_scan_end":null}'
