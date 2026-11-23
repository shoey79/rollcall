"""Veeam agent policies on the backup server (owner's request, 23 Nov).

A policy's own sessions ("Agent Policy job 'Laptops' finished with Success") only send its settings to the
computers, so the policy looked overdue while the computers backed up nightly. The Windows agent now reads each
computer's backups ("<policy> - <computer>" sessions) with Veeam's PowerShell (in PowerShell 7 for Backup &
Replication 13), or their restore points; the add-on judges the policy by them, or fills them in from the computers'
own Rollcall agents. Veeam itself is stood in; names are made up."""
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "rollcall" / "app"))
import agents as agentlib  # noqa: E402

AGENT = ROOT / "rollcall" / "app" / "agent" / "PingMonitorAgent.ps1"
WIN_PS = shutil.which("powershell.exe") if sys.platform == "win32" else None
PWSH = WIN_PS or os.environ.get("PWSH") or shutil.which("pwsh")

SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$ast = [Management.Automation.Language.Parser]::ParseFile('__AGENT__', [ref]$null, [ref]$null)
foreach ($n in 'Get-PreviousRun', 'Get-VeeamRunIssue', 'Get-VeeamJobs', 'Limit-Text', 'ConvertTo-UtcString', 'ConvertTo-IsoText',
             'Get-VeeamLookupScript', 'Invoke-InPwsh', 'Get-VeeamPolicyScript', 'Invoke-VeeamScript', 'Get-VeeamPolicyComputers') {
  $f = $ast.Find({ param($x) $x -is [Management.Automation.Language.FunctionDefinitionAst] -and $x.Name -eq $n }.GetNewClosure(), $true)
  if ($f) { . ([scriptblock]::Create($f.Extent.Text)) }
}
$script:agentLog = @()
function Write-AgentLog($m) { $script:agentLog += $m }
function Find-Pwsh { (Get-Process -Id $PID).Path }   # stands in for PowerShell 7
$now = (Get-Date).ToUniversalTime()
function T([double]$h) { $now.AddHours($h).ToString('yyyy-MM-ddTHH:mm:ssZ') }
$S1 = '11111111-1111-1111-1111-111111111111'; $J1 = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
function Ev($id, $rec, $level, $when, [string[]]$data, $msg) {
  $xml = '<Event><EventData>' + (($data | ForEach-Object { "<Data>$_</Data>" }) -join '') + '</EventData></Event>'
  $o = [pscustomobject]@{ Id = $id; RecordId = $rec; Level = $level; TimeCreated = [DateTime]::Parse($when).ToUniversalTime(); Message = $msg; X = $xml }
  $o | Add-Member ScriptMethod ToXml { $this.X } -PassThru
}
# The policy's settings were last sent 8 days ago
$script:finished = @((Ev 190 10 4 (T -200) @($S1, $J1, '0', '', '', 'False', 'Laptops', "Agent Policy job 'Laptops' finished with Success.") 'x'))
function Get-WinEvent { [CmdletBinding()] param($ListLog, $LogName, $FilterXPath, $MaxEvents)
  if ($ListLog) { return $true }; if ($FilterXPath -match 'Level=2') { return @() }; return $script:finished }
$script:withPs = $true; $script:needs = '5.0'; $script:calls = 0
function Get-Module { [CmdletBinding()] param([switch]$ListAvailable, $Name) if ($script:withPs) { [pscustomobject]@{ Name = $Name; PowerShellVersion = $script:needs } } }
function Import-Module { param([Parameter(ValueFromRemainingArguments = $true)]$Rest) }
function Get-VBRComputerBackupJobSession { [CmdletBinding()] param($Name)
  $script:calls++
  $d = { param($h) (Get-Date).AddHours($h) }
  @([pscustomobject]@{ Name = 'Laptops'; Result = 'Success'; EndTime = (& $d -200) },                 # settings sent
    [pscustomobject]@{ Name = 'Laptops - PC01.example.local'; Result = 'Success'; EndTime = (& $d -29) },
    [pscustomobject]@{ Name = 'Laptops - PC01.example.local'; Result = 'Warning'; EndTime = (& $d -5) },
    [pscustomobject]@{ Name = 'Laptops - PC02.example.local'; Result = 'Success'; EndTime = (& $d -50) },
    [pscustomobject]@{ Name = 'Laptops - PC02.example.local'; Result = 'Failed'; EndTime = (& $d -3) },
    [pscustomobject]@{ Name = 'Laptops - PC03.example.local'; Result = 'None'; EndTime = [DateTime]::MinValue }) }  # running
$out = @{}
$st = @{ veeam = $null; veeam_cursor = $null }
$out.ps = @(Get-VeeamJobs $st)
$null = @(Get-VeeamJobs $st); $out.calls = $script:calls          # read at most hourly
# Backup & Replication 13: in PowerShell 7, with a stand-in module there
$mods = Join-Path ([IO.Path]::GetTempPath()) ("veeamfake" + [guid]::NewGuid().ToString('N'))
$md = Join-Path $mods 'Veeam.Backup.PowerShell'; New-Item -ItemType Directory -Path $md -Force | Out-Null
Set-Content -Path (Join-Path $md 'Veeam.Backup.PowerShell.psm1') -Encoding UTF8 -Value ((Get-Command Get-VBRComputerBackupJobSession).ScriptBlock.Ast.Extent.Text + "`nExport-ModuleMember -Function *")
$env:PSModulePath = $mods + [IO.Path]::PathSeparator + $env:PSModulePath
Remove-Item Function:\Import-Module
$script:needs = '99.0'
$out.ps7 = @(Get-VeeamJobs @{ veeam = $null; veeam_cursor = $null })
Remove-Item -Recurse -Force $mods
$out.log = $script:agentLog
$out | ConvertTo-Json -Depth 8 -Compress
"""


@pytest.mark.skipif(not PWSH, reason="needs PowerShell")
def test_the_agent_lists_each_computers_backups():
    script = SCRIPT.replace("__AGENT__", str(AGENT).replace("'", "''"))
    env = {k: v for k, v in os.environ.items() if not (WIN_PS and k == "PSModulePath")}
    p = subprocess.run([PWSH, "-NoProfile", "-NonInteractive", "-Command", script], capture_output=True, text=True, timeout=180, env=env)
    assert p.returncode == 0, p.stderr
    out = json.loads(p.stdout.strip().splitlines()[-1])
    assert out["log"] == [], out["log"]
    for key in ("ps", "ps7"):
        jobs = {j["name"]: j for j in out[key]}
        assert set(jobs) == {"Laptops", "Laptops\\PC01.example.local", "Laptops\\PC02.example.local"}, jobs.keys()   # not one still running
        pc1, pc2 = jobs["Laptops\\PC01.example.local"], jobs["Laptops\\PC02.example.local"]
        assert pc1["result"] == "Warning" and pc1["type"] == "Agent backup" and len(pc1["runs"]) == 2
        assert pc2["result"] == "Failed" and pc2["last_success"] < pc2["finished"]
        assert pc1["id"] == "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa\\PC01.example.local"
        # The add-on: the policy is judged by its computers, not its 8-day-old settings session
        now = time.time()
        view = {j["name"]: j for j in agentlib.backup_jobs_view(out[key])}
        assert view["Laptops"]["policy"] == 2
        assert agentlib.backup_job_state(view["Laptops"], now) == (agentlib.OK, "")
        assert agentlib.backup_job_state(view["Laptops\\PC02.example.local"], now)[0] == agentlib.CRIT
    assert out["calls"] == 1


def T(h):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + h * 3600))


def test_the_policy_without_its_computers_isnt_overdue():
    pol = {"source": "Backup & Replication", "id": "p1", "name": "Laptops", "type": "Agent Policy", "result": "Success",
           "finished": T(-200), "last_success": T(-200), "runs": [T(-400), T(-200)]}
    j = agentlib.backup_jobs_view([pol])[0]
    assert j["policy"] == 0 and agentlib.backup_job_state(j, time.time()) == (agentlib.OK, "")
    # an ordinary job that old still is
    other = {**pol, "type": "Backup", "name": "File share"}
    assert "no successful run" in agentlib.backup_job_state(agentlib.backup_jobs_view([other])[0], time.time())[1]


def test_computers_filled_in_from_their_own_agents():
    pol = {"source": "Backup & Replication", "id": "p1", "name": "Laptops", "type": "Agent Policy", "result": "Success",
           "finished": T(-200), "last_success": T(-200)}
    pc = {"source": "Veeam Agent", "id": "agent:Laptops - PC01.example.local", "name": "Laptops - PC01.example.local",
          "type": "Agent backup (this device)", "result": "Warning", "finished": T(-8), "last_success": T(-8),
          "detail": "Backup repository is getting low on free disk space", "runs": [T(-32), T(-8)]}
    other = {**pc, "name": "Servers - SRV01.example.local"}
    jobs = agentlib.policy_computers([pol], [("PC01", [pc]), ("SRV01", [other])])
    kids = [j for j in jobs if j.get("from_device")]
    assert [(k["name"], k["from_device"], k["result"]) for k in kids] == [("Laptops\\PC01.example.local", "PC01", "Warning")]
    # worked out afresh each time, not added twice
    assert len(agentlib.policy_computers(jobs, [("PC01", [pc])])) == 2
    view = {j["name"]: j for j in agentlib.backup_jobs_view(jobs)}
    assert view["Laptops"]["policy"] == 1 and agentlib.backup_job_state(view["Laptops"], time.time())[0] == agentlib.OK
    assert agentlib.backup_job_state(view["Laptops\\PC01.example.local"], time.time()) == (agentlib.WARN, "finished with warnings")
    # the server listed them itself: nothing added
    listed = {**pc, "source": "Backup & Replication", "name": "Laptops\\PC01.example.local"}
    assert len(agentlib.policy_computers([pol, listed], [("PC01", [pc])])) == 2
