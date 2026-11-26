"""System file check (owner's request, 23 Nov): a weekly read-only sfc /verifyonly in its own scheduled task,
the result read from CBS.log; a "System files" check that's amber for violations. Windows is stood in.

Run from the repository root:  python3 -m pytest tests/test_sfc.py
"""
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "rollcall" / "app"))
import agents as A  # noqa: E402

AGENT = ROOT / "rollcall" / "app" / "agent" / "PingMonitorAgent.ps1"
PWSH = os.environ.get("PWSH") or shutil.which("pwsh")

HARNESS = r"""
$ErrorActionPreference = 'Stop'
$TaskName = 'Ping Monitor Agent'
$DataPath = '__DATA__'
$env:SystemRoot = '__ROOT__'
$global:Tasks = New-Object System.Collections.ArrayList
function ConvertTo-UtcString($Date) { ([DateTime]$Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') }
function Write-AgentLog([string]$M) { }
function Set-TaskTimeLimit($Names, $Limit) { }
function schtasks.exe { $null = $global:Tasks.Add(($args -join ' ')); $global:LASTEXITCODE = 0 }
"""


def run_ps(tmp_path, body):
    src = AGENT.read_text(encoding="utf-8-sig")
    block = re.search(r"(# System file check \(1\.0\.59\).*?)\nfunction Get-LapsStatus", src, re.S).group(1)
    data, root = tmp_path / "data", tmp_path / "win"
    data.mkdir(exist_ok=True)
    (root / "Logs" / "CBS").mkdir(parents=True, exist_ok=True)
    script = HARNESS.replace("__DATA__", str(data)).replace("__ROOT__", str(root)) + "\n" + block + "\n" + body
    p = subprocess.run([PWSH, "-NoProfile", "-NonInteractive", "-Command", script], capture_output=True, text=True, timeout=90)
    assert p.returncode == 0, p.stderr + p.stdout
    return p.stdout.strip().splitlines()[-1] if p.stdout.strip() else ""


@pytest.mark.skipif(not PWSH, reason="needs PowerShell")
def test_weekly_slot(tmp_path):
    out = run_ps(tmp_path, r"""
$c = @{ day = 0; hour = 3 }   # Sunday 03:00
$a = Get-SfcSlot $c ([DateTime]::new(2026, 11, 26, 10, 0, 0))   # a Thursday
$b = Get-SfcSlot $c ([DateTime]::new(2026, 11, 29, 2, 59, 0))   # Sunday, just before
$d = Get-SfcSlot $c ([DateTime]::new(2026, 11, 29, 3, 0, 0))    # Sunday, on the hour
"$($a.ToString('yyyy-MM-dd HH:mm'))|$($b.ToString('yyyy-MM-dd HH:mm'))|$($d.ToString('yyyy-MM-dd HH:mm'))"
""")
    assert out == "2026-11-22 03:00|2026-11-22 03:00|2026-11-29 03:00"


@pytest.mark.skipif(not PWSH, reason="needs PowerShell")
def test_turned_on_waits_for_the_weekly_time_then_runs_and_reads_violations(tmp_path):
    # Turned on just now: not started straight away (it'd be a weekday afternoon), "never" run yet
    out = run_ps(tmp_path, r"""
$State = @{}
$c = @{ on = $true; day = [int](Get-Date).DayOfWeek; hour = (Get-Date).AddHours(-1).Hour; dism = $false; run_now = 0 }
$r = Get-SystemFileCheck $State $c
@{ r = $r; tasks = @($global:Tasks); job = $State.sfc_job } | ConvertTo-Json -Compress -Depth 5
""")
    j = json.loads(out)
    assert j["r"]["state"] == "never" and j["tasks"] == []

    # A week on (the job says it was turned on 8 days ago): due, so it starts its own task
    out = run_ps(tmp_path, r"""
$State = @{ sfc_job = (@{ state = 'never'; since = ConvertTo-UtcString ((Get-Date).AddDays(-8)) } | ConvertTo-Json -Compress) }
$c = @{ on = $true; day = [int](Get-Date).DayOfWeek; hour = (Get-Date).AddHours(-1).Hour; dism = $true; run_now = 0 }
$r = Get-SystemFileCheck $State $c
@{ r = $r; tasks = @($global:Tasks); job = $State.sfc_job; runner = (Test-Path (Join-Path $DataPath 'sfc-run.ps1')) } | ConvertTo-Json -Compress -Depth 5
""")
    j = json.loads(out)
    assert j["r"]["state"] == "running" and j["r"]["trigger"] == "schedule" and j["runner"]
    assert any("/Create /TN Ping Monitor Agent (system file check)" in t and "-Dism" in t and "/RU SYSTEM" in t for t in j["tasks"])
    assert any(t.startswith("/Run /TN Ping Monitor Agent (system file check)") for t in j["tasks"])
    job = j["job"]

    # It finished: CBS.log (local times) names two files, DISM says the store is repairable
    started = json.loads(job)["started"]
    (tmp_path / "data" / "sfc-result.json").write_text(json.dumps({"started": started, "finished": started, "sfc_exit": 0, "dism_exit": 0}))
    (tmp_path / "data" / "sfc-output.txt").write_bytes("Windows Resource Protection found integrity violations.\r\n".encode("utf-16-le"))
    (tmp_path / "data" / "dism-output.txt").write_text("The component store is repairable.\r\n")
    out = run_ps(tmp_path, r"""
$t = (Get-Date).AddMinutes(1).ToString('yyyy-MM-dd HH:mm:ss')
$old = (Get-Date).AddDays(-3).ToString('yyyy-MM-dd HH:mm:ss')
@("$old, Info CSI 00000001 Hashes for file member [l:9]'old01.dll' do not match.",
  "$t, Info CSI 00000002 [SR] Verifying 100 components",
  "$t, Info CSI 00000003 Hashes for file member [l:10]'scesrv.dll' do not match.",
  "$t, Info CSI 00000004 [SR] Cannot verify member file [l:9]'tquery.dll' of Microsoft-Windows-Search",
  "$t, Info CSI 00000005 [SR] Verify complete") | Set-Content (Join-Path $env:SystemRoot 'Logs\CBS\CBS.log')
$State = @{ sfc_job = '__JOB__' }
$c = @{ on = $true; day = 0; hour = 3; dism = $true; run_now = 0 }
$r = Get-SystemFileCheck $State $c
$r | ConvertTo-Json -Compress -Depth 5
""".replace("__JOB__", job.replace("'", "''")))
    r = json.loads(out)
    assert r["state"] == "violations" and r["files"] == ["scesrv.dll", "tquery.dll"] and r["count"] == 2   # not the older line
    assert r["dism"]["state"] == "repairable"


@pytest.mark.skipif(not PWSH, reason="needs PowerShell")
def test_run_now_and_couldnt_run(tmp_path):
    out = run_ps(tmp_path, r"""
$State = @{}
$c = @{ on = $false; day = 0; hour = 3; dism = $false; run_now = 1764150000 }
$r = Get-SystemFileCheck $State $c
$again = Get-SystemFileCheck $State $c     # the same request isn't run twice
@{ r = $r; again = $again; n = @($global:Tasks | Where-Object { $_ -like '/Run*' }).Count; job = $State.sfc_job } | ConvertTo-Json -Compress -Depth 5
""")
    j = json.loads(out)
    assert j["r"]["state"] == "running" and j["r"]["trigger"] == "now" and j["n"] == 1
    started = json.loads(j["job"])["started"]
    (tmp_path / "data" / "sfc-result.json").write_text(json.dumps({"started": started, "finished": started, "sfc_exit": 1}))
    (tmp_path / "data" / "sfc-output.txt").write_bytes("There is a system repair pending which requires reboot to complete.\r\n".encode("utf-16-le"))
    out = run_ps(tmp_path, r"""
Set-Content (Join-Path $env:SystemRoot 'Logs\CBS\CBS.log') ''
$State = @{ sfc_job = '__JOB__' }
$r = Get-SystemFileCheck $State @{ on = $false; day = 0; hour = 3; dism = $false; run_now = 1764150000 }
$r | ConvertTo-Json -Compress -Depth 5
""".replace("__JOB__", j["job"].replace("'", "''")))
    r = json.loads(out)
    assert r["state"] == "failed" and r["detail"] == "a repair is waiting for a restart"


def test_system_files_check_levels():
    clean = A.clean_sfc({"state": "violations", "started": "2026-11-22T03:00:00Z", "finished": "2026-11-22T03:21:00Z",
                         "files": ["scesrv.dll", 5], "count": 2, "dism": {"state": "repairable"}, "evil": "x"})
    assert clean["files"] == ["scesrv.dll"] and "evil" not in clean
    c = A.sfc_check(clean)
    assert c["level"] == A.WARN and "2 file(s)" in c["detail"] and "RestoreHealth" in c["detail"]
    assert A.sfc_check(A.clean_sfc({"state": "ok", "finished": "2026-11-22T03:21:00Z"}))["level"] == A.OK
    assert A.sfc_check(A.clean_sfc({"state": "failed", "detail": "a repair is waiting for a restart"}))["level"] == A.OK
    assert A.sfc_check(A.clean_sfc({"state": "never"})) is None
    # Through evaluate: the report's checks.sfc becomes a "System files" check
    out = A.evaluate({"hostname": "PC01", "os": "Windows 11", "checks": {"sfc": clean}}, {}, 1764150000.0, {})
    assert next(x for x in out["checks"] if x["key"] == "sfc")["level"] == A.WARN


def test_which_devices_run_it_and_run_now(tmp_path, monkeypatch):
    import asyncio
    from types import SimpleNamespace
    sys.path.insert(0, str(ROOT / "tests"))
    from test_ip_change_and_acks import monitor
    m, _ = monitor(tmp_path, monkeypatch, [{"id": "srv", "name": "SRV01", "host": "10.0.1.10", "checks": []},
                                           {"id": "pc", "name": "PC01", "host": "10.0.1.20", "checks": []},
                                           {"id": "nas", "name": "NAS01", "host": "10.0.1.30", "checks": []}])
    m.hosts["srv"].agent_report, m.hosts["pc"].agent_report = {"workstation": False}, {"workstation": True}
    srv, pc = {"host_key": "srv", "os_family": "windows"}, {"host_key": "pc", "os_family": "windows"}
    nas = {"host_key": "nas", "os_family": "linux"}
    assert not m.sfc_config(srv)["on"]                                  # off by default
    m.opts.update(agent_sfc="servers", agent_sfc_day="wednesday", agent_sfc_hour=22)
    assert m.sfc_config(srv) == {"on": True, "day": 3, "hour": 22, "dism": False, "run_now": 0}
    assert not m.sfc_config(pc)["on"] and m.sfc_config(nas) == {"on": False}
    asyncio.run(m.set_sfc(m.hosts["pc"], "on", True, False, "admin"))
    assert m.sfc_config(pc)["on"] and m.sfc_config(pc)["dism"]
    asyncio.run(m.set_sfc(m.hosts["srv"], None, None, True, "admin"))
    assert m.sfc_config(srv)["run_now"] > 0
    asyncio.run(m.set_sfc(m.hosts["pc"], "default", False, False, "admin"))
    assert m.agent_settings["hosts"]["pc"]["sfc"] == {"dism": False}
