"""The agents move to Rollcall's own names (owner's request, 23 Nov): an agent updated in its old place copies its
token and state across and starts the new task/unit; the old one stays as the fallback until the new one has
reported, and only then does the new one remove it. A failed move leaves the old one running and says why.

Run from the repository root:  python3 -m pytest tests/test_agent_rename.py
"""
import importlib.util
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
LINUX = ROOT / "rollcall" / "app" / "agent" / "rollcall-agent.py"
WIN = ROOT / "rollcall" / "app" / "agent" / "RollcallAgent.ps1"
PWSH = os.environ.get("PWSH") or shutil.which("pwsh")


def load_from(path: Path, prefix: Path, name: str):
    """The agent as if run from `path` (its place decides old or new names)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy(LINUX, path)
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    os.environ["PM_PREFIX"] = str(prefix)
    try:
        spec.loader.exec_module(mod)
    finally:
        os.environ.pop("PM_PREFIX", None)
    return mod


def test_linux_moves_itself_and_the_new_one_removes_the_old(tmp_path):
    old_install = tmp_path / "usr/local/lib/pingmonitor/pingmonitor-agent.py"
    old = load_from(old_install, tmp_path, "rn_old")
    assert old.LEGACY and old.DATA_DIR.endswith("/var/lib/pingmonitor") and old.UNIT == "pingmonitor-agent"
    # The old install: token, state, settings and units
    (tmp_path / "var/lib/pingmonitor").mkdir(parents=True)
    (tmp_path / "var/lib/pingmonitor/state.json").write_text(json.dumps({"token": "t" * 64, "last_run": "2026-11-26T09:00:00Z", "cursors": {"sys": 5}}))
    (tmp_path / "var/lib/pingmonitor/secrets.json").write_text("{}")
    (tmp_path / "var/lib/pingmonitor/agent.log").write_text("old log\n")
    (tmp_path / "etc/pingmonitor").mkdir(parents=True)
    (tmp_path / "etc/pingmonitor/agent.conf").write_text(json.dumps({"server": "http://192.168.1.5:8100", "enrol_key": "k"}))
    (tmp_path / "etc/systemd/system").mkdir(parents=True)
    for u in ("pingmonitor-agent.service", "pingmonitor-agent.timer"):
        (tmp_path / "etc/systemd/system" / u).write_text("[Unit]\n")

    state = json.loads((tmp_path / "var/lib/pingmonitor/state.json").read_text())
    old.move_to_new_name(state, {})
    assert state.get("rename_started_at") and not state.get("rename_error")
    new_state = json.loads((tmp_path / "var/lib/rollcall/state.json").read_text())
    assert new_state["token"] == "t" * 64 and new_state["cursors"] == {"sys": 5} and "last_run" not in new_state
    assert (tmp_path / "var/lib/rollcall/secrets.json").exists() and not (tmp_path / "var/lib/rollcall/agent.log").exists()
    assert oct((tmp_path / "var/lib/rollcall").stat().st_mode & 0o777) == "0o700"
    assert (tmp_path / "var/lib/rollcall/state.json").stat().st_mode & 0o077 == 0     # root's only
    assert json.loads((tmp_path / "etc/rollcall/agent.conf").read_text())["server"] == "http://192.168.1.5:8100"
    assert (tmp_path / "usr/local/lib/rollcall/rollcall-agent.py").exists()
    assert "rollcall/rollcall-agent.py" in (tmp_path / "etc/systemd/system/rollcall-agent.service").read_text()
    assert (tmp_path / "etc/systemd/system/pingmonitor-agent.timer").exists()   # the old one stays as the fallback

    # Until the new one has reported, the old one carries on (it isn't told to stop) ...
    conf = {"server": "http://127.0.0.1:9", "enrol_key": "k"}
    assert not json.loads((tmp_path / "var/lib/rollcall/state.json").read_text()).get("last_run")
    # ... and once it has, the old copy stands down without reporting
    new_state["last_run"] = "2026-11-26T09:05:00Z"
    (tmp_path / "var/lib/rollcall/state.json").write_text(json.dumps(new_state))
    old.agent_run(conf)   # returns at once: no network
    assert "has moved to rollcall-agent" in (tmp_path / "var/lib/pingmonitor/agent.log").read_text()

    # The new one, after its report, removes the old unit, script, settings and data
    new = load_from(tmp_path / "usr/local/lib/rollcall/rollcall-agent.py", tmp_path, "rn_new")
    assert not new.LEGACY and new.UNIT == "rollcall-agent"
    new.remove_old_name(new_state)
    for gone in ("var/lib/pingmonitor", "etc/pingmonitor", "usr/local/lib/pingmonitor",
                 "etc/systemd/system/pingmonitor-agent.timer", "etc/systemd/system/pingmonitor-agent.service"):
        assert not (tmp_path / gone).exists(), gone
    assert (tmp_path / "var/lib/rollcall/state.json").exists()


def test_linux_leaves_another_installs_files_and_a_failed_move_says_why(tmp_path):
    new = load_from(tmp_path / "usr/local/lib/rollcall/rollcall-agent.py", tmp_path, "rn_new2")
    (tmp_path / "var/lib/pingmonitor").mkdir(parents=True)
    (tmp_path / "var/lib/pingmonitor/state.json").write_text(json.dumps({"token": "other"}))
    new.remove_old_name({"token": "mine"})
    assert (tmp_path / "var/lib/pingmonitor/state.json").exists()        # not this agent's

    old = load_from(tmp_path / "x/usr/local/lib/pingmonitor/pingmonitor-agent.py", tmp_path / "x", "rn_old2")
    (tmp_path / "x/var/lib/pingmonitor").mkdir(parents=True)
    (tmp_path / "x/var/lib/pingmonitor/state.json").write_text(json.dumps({"token": "t"}))
    (tmp_path / "x/var/lib/rollcall").write_text("a file where the folder should be")   # can't make it
    st = {"token": "t"}
    old.move_to_new_name(st, {})
    assert st.get("rename_failed_at") and st.get("rename_error") and not st.get("rename_started_at")
    again = dict(st)
    old.move_to_new_name(again, {})                                    # not again for a day
    assert again == st


def test_linux_install_brings_the_old_token_across(tmp_path, monkeypatch):
    (tmp_path / "var/lib/pingmonitor").mkdir(parents=True)
    (tmp_path / "var/lib/pingmonitor/state.json").write_text(json.dumps({"token": "keep" * 16, "last_run": "x"}))
    (tmp_path / "etc/pingmonitor").mkdir(parents=True)
    (tmp_path / "etc/pingmonitor/agent.conf").write_text(json.dumps({"server": "http://192.168.1.5:8100", "enrol_key": "k"}))
    new = load_from(tmp_path / "dl/rollcall-agent.py", tmp_path, "rn_inst")
    import argparse
    args = argparse.Namespace(server=None, enrol_key=None, immich_url=None, immich_api_key=None, ignore_cert=False, interval=5)
    monkeypatch.setattr(new, "SERVER", "http://192.168.1.5:8100")
    new.install(args)
    assert json.loads((tmp_path / "var/lib/rollcall/state.json").read_text())["token"] == "keep" * 16
    assert json.loads((tmp_path / "etc/rollcall/agent.conf").read_text())["enrol_key"] == "k"
    assert (tmp_path / "etc/systemd/system/rollcall-agent.timer").exists()


# ---- Windows ------------------------------------------------------------------------------------------------
HARNESS = r"""
$ErrorActionPreference = 'Stop'
$OldDataPath = '__OLD__'; $NewDataPath = '__NEW__'
$OldTaskName, $NewTaskName = 'Ping Monitor Agent', 'Rollcall Agent'
$OldScriptName, $NewScriptName = 'PingMonitorAgent.ps1', 'RollcallAgent.ps1'
$IntervalMinutes = 5; $IgnoreCertificate = $false
$global:Tasks = New-Object System.Collections.ArrayList
$global:Existing = @{}
foreach ($t in @(__EXISTING__)) { $global:Existing[$t] = $true }
function ConvertTo-UtcString($Date) { ([DateTime]$Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') }
function Write-AgentLog([string]$M) { Add-Content -Path (Join-Path '__LOGDIR__' 'log.txt') -Value $M }
function Protect-DataFolder([string]$Path) { }
function Get-DataFolderWriters([string]$Path) { @() }
function Set-TaskTimeLimit($Names, $Limit) { }
function Get-AgentProcess { @() }
function Stop-AgentProcess($P) { }
function schtasks.exe {
    $null = $global:Tasks.Add(($args -join ' '))
    $i = [array]::IndexOf($args, '/TN'); $n = if ($i -ge 0) { $args[$i + 1] } else { '' }
    if ($args[0] -eq '/Query') { $global:LASTEXITCODE = $(if ($global:Existing[$n]) { 0 } else { 1 }); return }
    if ($args[0] -eq '/Delete') { $global:Existing.Remove($n) }
    if ($args[0] -eq '/Create') { $global:Existing[$n] = $true }
    $global:LASTEXITCODE = 0
}
"""


def run_win(tmp_path, body, layout, existing=()):
    src = WIN.read_text(encoding="utf-8-sig")
    import re
    block = re.search(r"(# The move to Rollcall's own names \(1\.0\.60\).*?)\nfunction Invoke-AgentRun", src, re.S).group(1)
    old, new = tmp_path / "PingMonitor", tmp_path / "Rollcall"
    pre = HARNESS.replace("__OLD__", str(old)).replace("__NEW__", str(new)).replace("__LOGDIR__", str(tmp_path)) \
        .replace("__EXISTING__", ", ".join("'%s'" % e for e in existing) or "")
    lay = f"$script:LegacyLayout = ${'true' if layout == 'old' else 'false'}; $DataPath = '{old if layout == 'old' else new}'\n"
    script = (old if layout == "old" else new) / ("PingMonitorAgent.ps1" if layout == "old" else "RollcallAgent.ps1")
    script.parent.mkdir(parents=True, exist_ok=True)
    script.write_text(pre + lay + block + "\n" + body, encoding="utf-8")
    p = subprocess.run([PWSH, "-NoProfile", "-NonInteractive", "-File", str(script)], capture_output=True, text=True, timeout=90)
    assert p.returncode == 0, p.stderr + p.stdout
    return p.stdout.strip().splitlines()[-1] if p.stdout.strip() else ""


@pytest.mark.skipif(not PWSH, reason="needs PowerShell")
def test_windows_moves_itself_then_the_new_one_removes_the_old(tmp_path):
    old = tmp_path / "PingMonitor"
    old.mkdir()
    (old / "state.json").write_text(json.dumps({"token": "t" * 64, "last_run": "2026-11-26T09:00:00Z", "cursors": {"System": 5}}))
    (old / "secrets.json").write_text("{}")
    (old / "agent.log").write_text("old\n")
    out = run_win(tmp_path, r"""
$State = Get-Content (Join-Path $DataPath 'state.json') -Raw | ConvertFrom-Json
$State | Add-Member rename_started_at $null; $State | Add-Member rename_failed_at $null; $State | Add-Member rename_error $null
Move-ToNewName $State
@{ s = $State; tasks = @($global:Tasks) } | ConvertTo-Json -Compress -Depth 5
""", "old", existing=["Ping Monitor Agent", "Ping Monitor Agent (start-up)"])
    j = json.loads(out)
    assert j["s"]["rename_started_at"] and not j["s"]["rename_error"]
    assert any(t.startswith("/Create /TN Rollcall Agent /TR") and str(tmp_path / "Rollcall" / "RollcallAgent.ps1") in t for t in j["tasks"])
    assert "/Run /TN Rollcall Agent" in j["tasks"]
    assert not any(t.startswith("/Delete") for t in j["tasks"])                      # the old one stays for now
    ns = json.loads((tmp_path / "Rollcall" / "state.json").read_text(encoding="utf-8-sig"))
    assert ns["token"] == "t" * 64 and ns["cursors"] == {"System": 5} and "last_run" not in ns
    assert (tmp_path / "Rollcall" / "RollcallAgent.ps1").exists() and not (tmp_path / "Rollcall" / "agent.log").exists()

    # The new one has reported: it removes the old tasks and folder, leaving a stand-in at the old name
    out = run_win(tmp_path, r"""
Remove-OldName ([pscustomobject]@{ token = '""" + "t" * 64 + r"""' })
@{ tasks = @($global:Tasks); left = @(Get-ChildItem -Path $OldDataPath -Name) } | ConvertTo-Json -Compress
""", "new", existing=["Ping Monitor Agent", "Ping Monitor Agent (start-up)", "Rollcall Agent"])
    j = json.loads(out)
    assert "/Delete /TN Ping Monitor Agent /F" in j["tasks"] and "/Delete /TN Ping Monitor Agent (start-up) /F" in j["tasks"]
    assert not any("Delete /TN Rollcall Agent" in t for t in j["tasks"])
    assert j["left"] == "PingMonitorAgent.ps1" or j["left"] == ["PingMonitorAgent.ps1"]
    stub = (tmp_path / "PingMonitor" / "PingMonitorAgent.ps1").read_text()
    assert "$AgentVersion = '99.0.0'" in stub and "schtasks.exe /Delete /TN 'Ping Monitor Agent'" in stub and "token" not in stub


@pytest.mark.skipif(not PWSH, reason="needs PowerShell")
def test_windows_failed_move_keeps_the_old_one_and_leaves_other_installs_alone(tmp_path):
    old = tmp_path / "PingMonitor"
    old.mkdir()
    (old / "state.json").write_text(json.dumps({"token": "mine"}))
    (tmp_path / "Rollcall").write_text("a file where the folder should be")   # can't make the folder
    out = run_win(tmp_path, r"""
$State = [pscustomobject]@{ token = 'mine'; rename_started_at = $null; rename_failed_at = $null; rename_error = $null }
Move-ToNewName $State
@{ s = $State; tasks = @($global:Tasks) } | ConvertTo-Json -Compress -Depth 5
""", "old", existing=["Ping Monitor Agent"])
    j = json.loads(out)
    assert j["s"]["rename_failed_at"] and j["s"]["rename_error"] and j["tasks"] == []
    (tmp_path / "Rollcall").unlink()
    (old / "state.json").write_text(json.dumps({"token": "someone else"}))
    out = run_win(tmp_path, r"""
Remove-OldName ([pscustomobject]@{ token = 'mine' })
@{ tasks = @($global:Tasks | Where-Object { $_ -like '/Delete*' }) } | ConvertTo-Json -Compress
""", "new", existing=["Ping Monitor Agent"])
    assert json.loads(out)["tasks"] == [] and (old / "state.json").exists()


def test_names_served_and_in_the_installer():
    sys.path.insert(0, str(ROOT / "rollcall" / "app"))
    import main
    import msi
    assert main.AGENT_SCRIPT.name == "RollcallAgent.ps1" and main.LINUX_AGENT_SCRIPT.name == "rollcall-agent.py"
    assert 'Name="RollcallAgent.ps1"' in msi.WXS and "RollcallAgent.ps1" in msi._PS
    assert "PingMonitor" not in msi.WXS
