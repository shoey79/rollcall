"""The Windows agent's scheduled tasks stop a run after 30 minutes (Set-TaskTimeLimit).

schtasks leaves Windows' default of 72 hours, and Windows doesn't start the task again while a run is
still going, so one stuck run kept a device from reporting for days. Makes a task the way the agent does
(schtasks, as SYSTEM), then checks the agent sets its limit to 30 minutes, once, and leaves other tasks alone.

Needs Windows PowerShell on Windows, run as an administrator (GitHub's Windows tests).
"""
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

AGENT = Path(__file__).resolve().parents[1] / "rollcall" / "app" / "agent" / "RollcallAgent.ps1"
WIN_PS = shutil.which("powershell.exe") if sys.platform == "win32" else None

SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$ast = [Management.Automation.Language.Parser]::ParseFile('__AGENT__', [ref]$null, [ref]$null)
$f = $ast.Find({ param($x) $x -is [Management.Automation.Language.FunctionDefinitionAst] -and $x.Name -eq 'Set-TaskTimeLimit' }, $true)
. ([scriptblock]::Create($f.Extent.Text))
$TaskTimeLimit = 'PT30M'; $script:log = @()
function Write-AgentLog($m) { $script:log += $m }
$name = 'Rollcall Test Agent Task'; $other = 'Rollcall Test Other Task'
foreach ($n in $name, $other) { $null = & schtasks.exe /Create /TN $n /TR 'cmd.exe /c exit 0' /SC MINUTE /MO 5 /RU SYSTEM /RL HIGHEST /F }
try {
  "before=$((Get-ScheduledTask -TaskName $name).Settings.ExecutionTimeLimit)"
  Set-TaskTimeLimit @($name, 'No Such Task')
  "after=$((Get-ScheduledTask -TaskName $name).Settings.ExecutionTimeLimit)"
  "other=$((Get-ScheduledTask -TaskName $other).Settings.ExecutionTimeLimit)"
  "user=$((Get-ScheduledTask -TaskName $name).Principal.UserId)"
  Set-TaskTimeLimit @($name)
  "logged=$($script:log.Count)"
  "log=$($script:log -join '|')"
} finally { foreach ($n in $name, $other) { $null = & schtasks.exe /Delete /TN $n /F } }
"""


@pytest.mark.skipif(not WIN_PS, reason="needs Windows PowerShell on Windows")
def test_agent_tasks_stop_a_run_after_30_minutes():
    p = subprocess.run([WIN_PS, "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command",
                        SCRIPT.replace("__AGENT__", str(AGENT).replace("'", "''"))], capture_output=True, text=True, timeout=120)
    out = dict(line.split("=", 1) for line in p.stdout.splitlines() if "=" in line)
    assert out.get("before") == "PT72H", (p.stdout, p.stderr)       # what schtasks leaves
    assert out.get("after") == "PT30M" and out.get("other") == "PT72H", (p.stdout, p.stderr)
    assert out.get("user") == "SYSTEM"                               # still runs as SYSTEM
    assert out.get("logged") == "1", out                             # set once; the next run sees it's done
