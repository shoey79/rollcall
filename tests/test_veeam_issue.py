"""Why a Veeam job warned or failed: the Windows agent's Get-VeeamJobs / Get-VeeamRunIssue.

Runs the agent's own functions on PowerShell (Windows PowerShell 5.1 on Windows, else pwsh / PWSH),
with Veeam's event log and PowerShell stood in: a job whose latest run warned gets each VM's status and
reason and the run's warning lines (from Veeam PowerShell when it's there, else the event log), once per
run; a job that succeeded has none. Veeam 13's PowerShell needs PowerShell 7.6: the lookup then runs in a separate
PowerShell 7 with a stand-in Veeam module. Names are made up.
"""
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

AGENT = Path(__file__).resolve().parents[1] / "rollcall" / "app" / "agent" / "PingMonitorAgent.ps1"
WIN_PS = shutil.which("powershell.exe") if sys.platform == "win32" else None
PWSH = WIN_PS or os.environ.get("PWSH") or shutil.which("pwsh")

SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$ast = [Management.Automation.Language.Parser]::ParseFile('__AGENT__', [ref]$null, [ref]$null)
foreach ($n in 'Get-PreviousRun', 'Get-VeeamRunIssue', 'Get-VeeamJobs', 'Limit-Text', 'ConvertTo-UtcString', 'ConvertTo-IsoText',
             'Get-VeeamLookupScript', 'Invoke-InPwsh') {
  $f = $ast.Find({ param($x) $x -is [Management.Automation.Language.FunctionDefinitionAst] -and $x.Name -eq $n }.GetNewClosure(), $true)
  if ($f) { . ([scriptblock]::Create($f.Extent.Text)) }
}
$script:agentLog = @()
function Write-AgentLog($m) { $script:agentLog += $m }
function Find-Pwsh { (Get-Process -Id $PID).Path }   # stands in for PowerShell 7
$now = (Get-Date).ToUniversalTime()
function T([double]$h) { $now.AddHours($h).ToString('yyyy-MM-ddTHH:mm:ssZ') }
$S1 = '11111111-1111-1111-1111-111111111111'; $J1 = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
$S2 = '22222222-2222-2222-2222-222222222222'; $J2 = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'
function Ev($id, $rec, $level, $when, [string[]]$data, $msg) {
  $xml = '<Event><EventData>' + (($data | ForEach-Object { "<Data>$_</Data>" }) -join '') + '</EventData></Event>'
  $o = [pscustomobject]@{ Id = $id; RecordId = $rec; Level = $level; TimeCreated = [DateTime]::Parse($when).ToUniversalTime(); Message = $msg; X = $xml }
  $o | Add-Member ScriptMethod ToXml { $this.X } -PassThru
}
$script:finished = @(
  (Ev 190 10 3 (T -3) @($S1, $J1, '1', '', '', 'False', 'Daily VMs', "Backup job 'Daily VMs' finished with Warning.") 'x'),
  (Ev 190 11 4 (T -2) @($S2, $J2, '0', '', '', 'False', 'File share', "Backup job 'File share' finished with Success.") 'x'))
$script:during = @(
  (Ev 150 5 3 (T -3.2) @($S1, 'VM01') "VM 'VM01' task has finished with 'Warning' state.`r`nmore text"),
  (Ev 150 6 2 (T -3.1) @('other') 'Something unrelated failed'))
$script:withPs = $false; $script:needs = $null; $script:lookups = 0
function Get-WinEvent { [CmdletBinding()] param($ListLog, $LogName, $FilterXPath, $MaxEvents)
  if ($ListLog) { return $true }
  if ($FilterXPath -match 'Level=2') { $script:lookups++; return $script:during }
  return $script:finished }
function Get-Module { [CmdletBinding()] param([switch]$ListAvailable, $Name) if ($script:withPs) { [pscustomobject]@{ Name = $Name; PowerShellVersion = $script:needs } } }
function Import-Module { param([Parameter(ValueFromRemainingArguments = $true)]$Rest) }
function Get-VBRBackupSession { [CmdletBinding()] param($Id)
  $s = [pscustomobject]@{ Id = $Id; Logger = [pscustomobject]@{} }
  $s.Logger | Add-Member ScriptMethod GetLog { [pscustomobject]@{ UpdatedRecords = @(
    [pscustomobject]@{ Status = 'ESucceeded'; Title = 'Processing VM02' },
    [pscustomobject]@{ Status = 'EWarning'; Title = 'VM01: Changed block tracking is disabled' }) } }
  $s }
function Get-VBRTaskSession { [CmdletBinding()] param($Session)
  $vm1 = [pscustomobject]@{ Name = 'VM01'; Status = 'Warning'; Info = [pscustomobject]@{ Reason = "Changed block tracking is disabled.`r`nFull read used." }; Logger = [pscustomobject]@{} }
  $vm1.Logger | Add-Member ScriptMethod GetLog { [pscustomobject]@{ UpdatedRecords = @(
    [pscustomobject]@{ Status = 'ESucceeded'; Title = 'Queued' },
    [pscustomobject]@{ Status = 'EWarning'; Title = "Cannot use CBT: There is no change tracking data available. Failed to query changes for disk 'D:\VMs\VM01\disk0.vhdx'." }) } }
  @([pscustomobject]@{ Name = 'VM02'; Status = 'Success'; Info = [pscustomobject]@{ Reason = '' } }, $vm1) }

$out = @{}
# Event log only (no Veeam PowerShell)
$st = @{ veeam = $null; veeam_cursor = $null }
$out.events = @(Get-VeeamJobs $st); $out.lookups1 = $script:lookups
# The next run: same session, so not looked up again
$null = @(Get-VeeamJobs $st); $out.lookups2 = $script:lookups
# On a backup server with Veeam PowerShell
$script:withPs = $true
$out.ps = @(Get-VeeamJobs @{ veeam = $null; veeam_cursor = $null })
# Veeam 13: its module needs PowerShell 7.6, so the lookup runs in PowerShell 7, with a stand-in module there
$mods = Join-Path ([IO.Path]::GetTempPath()) ("veeamfake" + [guid]::NewGuid().ToString('N'))
$md = Join-Path $mods 'Veeam.Backup.PowerShell'; New-Item -ItemType Directory -Path $md -Force | Out-Null
$fake = (Get-Command Get-VBRBackupSession).ScriptBlock.Ast.Extent.Text + "`n" + (Get-Command Get-VBRTaskSession).ScriptBlock.Ast.Extent.Text +
  "`nfunction Get-Marker { 'child' }`nExport-ModuleMember -Function *"
Set-Content -Path (Join-Path $md 'Veeam.Backup.PowerShell.psm1') -Value $fake -Encoding UTF8
$env:PSModulePath = $mods + [IO.Path]::PathSeparator + $env:PSModulePath
Remove-Item Function:\Import-Module   # the child imports the stand-in for real
$script:needs = '99.0'
$out.ps7 = @(Get-VeeamJobs @{ veeam = $null; veeam_cursor = $null })
# PowerShell 7 not installed: says so, and falls back to the event log
function Find-Pwsh { $null }
$out.nopwsh = @(Get-VeeamJobs @{ veeam = $null; veeam_cursor = $null })
$out.log = $script:agentLog
Remove-Item -Recurse -Force $mods
$out | ConvertTo-Json -Depth 8 -Compress
"""


@pytest.mark.skipif(not PWSH, reason="needs PowerShell")
def test_why_a_veeam_job_warned():
    script = SCRIPT.replace("__AGENT__", str(AGENT).replace("'", "''"))
    env = {k: v for k, v in os.environ.items() if not (WIN_PS and k == "PSModulePath")}
    p = subprocess.run([PWSH, "-NoProfile", "-NonInteractive", "-Command", script], capture_output=True, text=True, timeout=120, env=env)
    assert p.returncode == 0, p.stderr
    out = json.loads(p.stdout.strip().splitlines()[-1])
    jobs = {j["name"]: j for j in out["events"]}
    assert jobs["File share"]["issue"] is None                          # succeeded: nothing to explain
    ev = jobs["Daily VMs"]["issue"]
    assert ev["source"] == "event log" and ev["session"] == "11111111-1111-1111-1111-111111111111"
    assert ev["log"] == [{"status": "Warning", "text": "VM 'VM01' task has finished with 'Warning' state."}]   # only this run's, first line
    assert out["lookups1"] == 1 and out["lookups2"] == 1                # looked up once per run
    ps = {j["name"]: j for j in out["ps"]}["Daily VMs"]["issue"]
    assert ps["source"] == "Veeam PowerShell"
    cbt = "Cannot use CBT: There is no change tracking data available. Failed to query changes for disk 'D:\\VMs\\VM01\\disk0.vhdx'."
    assert ps["objects"] == [{"name": "VM01", "status": "Warning", "reason": "Changed block tracking is disabled. Full read used.",
                              "details": [cbt]},                                                   # the VM's own warning lines
                             {"name": "VM02", "status": "Success", "reason": "", "details": []}]  # problems first
    assert ps["log"] == [{"status": "Warning", "text": "VM01: Changed block tracking is disabled"}]
    # Veeam 13, through PowerShell 7: the same answer
    ps7 = {j["name"]: j for j in out["ps7"]}["Daily VMs"]["issue"]
    assert ps7["source"] == "Veeam PowerShell" and ps7["objects"] == ps["objects"] and ps7["log"] == ps["log"]
    # Without PowerShell 7: the event log, and the agent's log says why
    nop = {j["name"]: j for j in out["nopwsh"]}["Daily VMs"]["issue"]
    assert nop["source"] == "event log"
    assert len(out["log"]) == 1 and "needs PowerShell 99.0 or later, which isn't installed" in out["log"][0], out["log"]   # PowerShell 7 itself worked
