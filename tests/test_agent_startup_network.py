"""The Windows agent's start-up run waits for the network before reporting.

Runs the agent's own Wait-Network on Windows PowerShell 5.1 on Windows, else PowerShell 7 (pwsh, or the
PWSH environment variable), with the boot time, reachability and sleeping stood in; skipped without either.
"""
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
$f = $ast.Find({ param($x) $x -is [Management.Automation.Language.FunctionDefinitionAst] -and $x.Name -eq 'Wait-Network' }, $true)
. ([scriptblock]::Create($f.Extent.Text))
$script:log = @(); $script:tries = 0; $script:slept = 0
function Write-AgentLog($m) { $script:log += $m }
function Get-ServerList { @('http://10.0.1.5:8100', 'https://rollcall.example.local:8100') }
function Start-Sleep([int]$Seconds) { $script:slept += $Seconds }
function Get-CimInstance { [pscustomobject]@{ LastBootUpTime = (Get-Date).AddSeconds(-$script:boot) } }

# Up for a day: no waiting, not even a reachability test
$script:boot = 86400; function Test-Reachable { $script:tries++; $false }
Wait-Network; "day tries=$($script:tries) slept=$($script:slept)"

# Just started, network up after 3 rounds of both addresses
$script:boot = 70; $script:tries = 0; $script:slept = 0
function Test-Reachable { $script:tries++; $script:tries -gt 5 }
Wait-Network; "boot tries=$($script:tries) slept=$($script:slept)"

# Just started and never reachable: gives up after the limit and carries on
$script:tries = 0; $script:slept = 0; $script:log = @()
function Test-Reachable { $script:tries++; $false }
$start = Get-Date
function Get-Date { $start.AddSeconds($script:slept) }
Wait-Network -MaxSeconds 60; "never slept=$($script:slept) log=$($script:log -join '|')"
"""


@pytest.mark.skipif(not PWSH, reason="needs PowerShell")
def test_startup_run_waits_for_the_network_then_gives_up():
    script = SCRIPT.replace("__AGENT__", str(AGENT).replace("'", "''"))
    env = {k: v for k, v in os.environ.items() if not (WIN_PS and k == "PSModulePath")}
    run = subprocess.run([PWSH, "-NoLogo", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script],
                         capture_output=True, text=True, timeout=120, env=env)
    assert run.returncode == 0, run.stderr[-2000:]
    lines = {x.split(" ", 1)[0]: x.split(" ", 1)[1] for x in run.stdout.splitlines() if " " in x}
    assert lines["day"] == "tries=0 slept=0"
    assert lines["boot"] == "tries=6 slept=20"          # answered on the third round, 10 s apart
    assert lines["never"].startswith("slept=60 log=WARN Still can't reach Rollcall 60 s after starting"), lines
