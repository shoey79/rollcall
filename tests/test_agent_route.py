"""The Windows agent's choice of address by subnet (internal networks set under Agents).

Runs the agent's own functions on Windows PowerShell 5.1 on Windows, else PowerShell 7 (pwsh, or the
PWSH environment variable); skipped without either.
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
foreach ($n in 'Test-InNetwork', 'Get-OwnIPv4', 'Get-RouteSide', 'Get-ServerList', 'Get-ServerListPlain') {
    $f = $ast.Find({ param($x) $x -is [Management.Automation.Language.FunctionDefinitionAst] -and $x.Name -eq $n }, $true)
    . ([scriptblock]::Create($f.Extent.Text))
}
$cases = @(('10.0.1.20', '10.0.1.0/24', $true), ('10.0.2.20', '10.0.1.0/24', $false), ('192.168.1.5', '192.168.0.0/16', $true),
    ('192.168.1.5', '0.0.0.0/0', $true), ('10.0.1.20', '10.0.1.20/32', $true), ('10.0.1.21', '10.0.1.20/32', $false),
    ('10.255.255.255', '10.0.0.0/8', $true), ('11.0.0.0', '10.0.0.0/8', $false), ('172.31.255.1', '172.16.0.0/12', $true),
    ('172.32.0.1', '172.16.0.0/12', $false), ('255.255.255.255', '255.255.255.0/24', $true), ('bad', '10.0.0.0/8', $false),
    ('10.0.0.1', 'bad', $false), ('10.0.0.1', '10.0.0.0/33', $false))
foreach ($c in $cases) { if ((Test-InNetwork $c[0] $c[1]) -ne $c[2]) { "FAIL $($c -join ' ')" } }
$Server = 'http://192.168.1.9:8100'
$script:PushedServers = @('http://10.0.1.5:8100', 'https://rollcall.example.local:8100')
$script:PreferredServer = 'https://rollcall.example.local:8100'
"none " + ((Get-ServerList) -join ' ')
$own = @(Get-OwnIPv4) | Select-Object -First 1
$script:Route = @{ inside = 'http://10.0.1.5:8100'; outside = 'https://rollcall.example.local:8100'; networks = @("$own/32") }
$script:RouteSide = Get-RouteSide $script:Route
"in $($script:RouteSide) " + ((Get-ServerList) -join ' ')
$script:Route.networks = @('203.0.113.0/24'); $script:RouteSide = Get-RouteSide $script:Route
"out $($script:RouteSide) " + ((Get-ServerList) -join ' ')
"""


@pytest.mark.skipif(not PWSH, reason="needs PowerShell")
def test_windows_agent_picks_its_address_by_subnet():
    script = SCRIPT.replace("__AGENT__", str(AGENT).replace("'", "''"))
    env = {k: v for k, v in os.environ.items() if not (WIN_PS and k == "PSModulePath")}
    run = subprocess.run([PWSH, "-NoLogo", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script],
                         capture_output=True, text=True, timeout=120, env=env)
    out = run.stdout.splitlines()
    assert run.returncode == 0, run.stderr[-2000:]
    assert not [x for x in out if x.startswith("FAIL")], out
    lines = {x.split(" ", 1)[0]: x.split(" ", 1)[1] for x in out if " " in x}
    # Not set: the address that worked last first (as before)
    assert lines["none"] == "https://rollcall.example.local:8100 http://10.0.1.5:8100 http://192.168.1.9:8100"
    # On an internal network: inside first, whatever worked last; the installed address stays last
    assert lines["in"] == "inside http://10.0.1.5:8100 https://rollcall.example.local:8100 http://192.168.1.9:8100", out
    assert lines["out"] == "outside https://rollcall.example.local:8100 http://10.0.1.5:8100 http://192.168.1.9:8100"
