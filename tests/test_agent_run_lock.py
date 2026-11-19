"""The Windows agent's one-run-at-a-time lock (Get-RunLock).

The scheduled task runs as SYSTEM, and a lock made with Windows' defaults was SYSTEM's alone, so running the
script by hand meanwhile failed with "Access to the path 'Global\\RollcallAgentRun' is denied". Checks that
the lock is taken and given up, that a second process waits its turn, and that an old SYSTEM-only lock
makes a run step aside quietly instead of failing.

Needs Windows PowerShell 5.1 on Windows (GitHub's Windows tests); the lock and its permissions are Windows'.
"""
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

AGENT = Path(__file__).resolve().parents[1] / "rollcall" / "app" / "agent" / "PingMonitorAgent.ps1"
WIN_PS = shutil.which("powershell.exe") if sys.platform == "win32" else None

LOAD = r"""
$ErrorActionPreference = 'Stop'
$ast = [Management.Automation.Language.Parser]::ParseFile('__AGENT__', [ref]$null, [ref]$null)
foreach ($n in 'Get-RunLock', 'Get-AgentProcess', 'Stop-AgentProcess', 'Stop-StuckRun') {
  $f = $ast.Find({ param($x) $x -is [Management.Automation.Language.FunctionDefinitionAst] -and $x.Name -eq $n }.GetNewClosure(), $true)
  . ([scriptblock]::Create($f.Extent.Text))
}
$StuckMinutes = 20; $script:Errors = New-Object System.Collections.ArrayList; $script:log = @()
function Write-AgentLog($m) { $script:log += $m }
"""

# Another process holds a lock for a while: made by the agent's own Get-RunLock, or the old way with only
# SYSTEM allowed in (as an older agent's run as SYSTEM would have left it).
HOLD = 'param([string]$Kind, [string]$Name, [string]$Label)' + LOAD + r"""
if ($Kind -eq 'agent') { if (-not (Get-RunLock $Name)) { throw 'no lock' } }
else {
  $sec = New-Object Security.AccessControl.MutexSecurity
  $sec.AddAccessRule((New-Object Security.AccessControl.MutexAccessRule((New-Object Security.Principal.SecurityIdentifier 'S-1-5-18'), 'FullControl', 'Allow')))
  $c = $false; $script:RunLock = [Threading.Mutex]::new($true, $Name, [ref]$c, $sec)
}
'holding'
Start-Sleep 25
"""

CHECK = 'param([string]$Name)' + LOAD + r"""
"lock=$(Get-RunLock $Name)"
"""


def ps(script, *args, wait=True):
    cmd = [WIN_PS, "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", "& {" + script.replace("__AGENT__", str(AGENT).replace("'", "''")) + "} " + " ".join(f"'{a}'" for a in args)]
    if not wait:
        return subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return subprocess.run(cmd, capture_output=True, text=True, timeout=90)


def holding(kind, name):
    p = ps(HOLD, kind, name, wait=False)
    assert p.stdout.readline().strip() == "holding", p.stderr.read()
    return p


@pytest.mark.skipif(not WIN_PS, reason="needs Windows PowerShell on Windows")
@pytest.mark.parametrize("kind", ["agent", "system_only"])
def test_a_run_steps_aside_while_another_holds_the_lock(kind):
    name = f"Global\\RollcallTestRun_{kind}"
    assert "lock=True" in ps(CHECK, name).stdout                    # free: taken (and let go when it ends)
    p = holding(kind, name)
    try:
        r = ps(CHECK, name)
        assert r.returncode == 0 and "lock=False" in r.stdout, (r.stdout, r.stderr)   # no "Access ... denied"
        assert "denied" not in r.stderr.lower()
    finally:
        p.kill(); p.wait()
    assert "lock=True" in ps(CHECK, name).stdout                    # free again


# A stuck run: an agent process that has held the lock too long. Its command line names the agent's script,
# as the scheduled task's does; it's treated as stuck straight away (0 minutes) for the test.
STUCK = 'param([string]$Name, [string]$Data)' + LOAD + r"""
$DataPath = $Data
[IO.File]::WriteAllText((Join-Path $Data 'run-step.txt'), "hyper-v`t2026-01-01T00:00:00Z")
"before=$(Get-RunLock $Name)"
"stopped=$(Stop-StuckRun 0)"
"after=$(Get-RunLock $Name)"
"msg=$($script:Errors -join '|')"
"""


@pytest.mark.skipif(not WIN_PS, reason="needs Windows PowerShell on Windows")
def test_a_stuck_run_is_stopped_and_says_where_it_was(tmp_path):
    name = "Global\\RollcallTestRun_stuck"
    p = ps(HOLD, "system_only", name, "PingMonitorAgent.ps1", wait=False)   # the old SYSTEM-only lock, held
    assert p.stdout.readline().strip() == "holding", p.stderr.read()
    try:
        r = ps(STUCK, name, str(tmp_path))
        out = dict(line.split("=", 1) for line in r.stdout.splitlines() if "=" in line)
        assert out.get("before") == "False" and out.get("stopped") == "True" and out.get("after") == "True", (r.stdout, r.stderr)
        assert out["msg"].startswith("agent: stopped a run stuck at step 'hyper-v' since "), out["msg"]
        assert p.wait(timeout=10) is not None                       # the stuck process is gone
    finally:
        if p.poll() is None:
            p.kill()
