"""Smaller fixes: delayed-start services just after a restart, and sizes under 1 GB shown in MB.

Run from the repository root:  python3 -m pytest tests/test_small_fixes.py
"""
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "rollcall" / "app"))
import agents as A  # noqa: E402

AGENT = ROOT / "rollcall" / "app" / "agent" / "PingMonitorAgent.ps1"
PWSH = os.environ.get("PWSH") or "pwsh"


def services(uptime_s, watched=(), stopped=()):
    report = A.normalize_report({"os_family": "windows", "uptime_s": uptime_s, "services": {"watched": list(watched), "stopped_auto": list(stopped)}})
    return next(c for c in A.evaluate(report, {})["checks"] if c["key"] == "services")


def svc(name, state="Stopped", delayed=False, role="IIS"):
    return {"name": name, "display": name, "state": state, "role": role, "delayed": delayed}


def test_delayed_start_role_service_waits_five_minutes_after_a_restart():
    c = services(120, [svc("W3SVC", delayed=True), svc("WAS", "Running")])
    assert c["level"] == A.OK and c["detail"] == "1 of 2 watched services running; still starting after a restart (delayed start): W3SVC"
    assert services(600, [svc("W3SVC", delayed=True)])["level"] == A.CRIT               # should be running by now
    assert services(120, [svc("W3SVC")])["level"] == A.CRIT                             # not delayed: no wait
    assert services(None, [svc("W3SVC", delayed=True)])["level"] == A.CRIT              # uptime unknown: no wait


def test_other_delayed_start_services_wait_too():
    assert services(60, [svc("W3SVC", "Running")], [svc("sppsvc2", delayed=True)])["level"] == A.OK
    c = services(400, [svc("W3SVC", "Running")], [svc("sppsvc2", delayed=True)])
    assert c["level"] == A.WARN and "sppsvc2" in c["detail"]


def test_delayed_flag_is_tidied():
    r = A.normalize_report({"services": {"watched": [{"name": "a", "delayed": "yes"}, {"name": "b"}]}})
    assert r["services"]["watched"] == [{"name": "a", "delayed": False}, {"name": "b"}]


@pytest.mark.skipif(not (Path(PWSH).exists() or subprocess.run(["which", PWSH], capture_output=True).returncode == 0), reason="needs PowerShell")
def test_agent_reports_delayed_start():
    script = f'''
$ErrorActionPreference = 'Stop'
$src = Get-Content -Raw '{AGENT}'
$ast = [Management.Automation.Language.Parser]::ParseInput($src, [ref]$null, [ref]$null)
foreach ($n in 'Test-DelayedStart', 'Get-ServiceReport') {{
  $f = $ast.FindAll({{ $args[0] -is [Management.Automation.Language.FunctionDefinitionAst] -and $args[0].Name -eq $n }}, $true) | Select-Object -First 1
  Invoke-Expression $f.Extent.Text
}}
$NoisyAutoServices = @()
function Test-Path {{ $false }}
$all = @(
  [pscustomobject]@{{ Name = 'W3SVC'; DisplayName = 'Web'; State = 'Running'; StartMode = 'Auto'; DelayedAutoStart = $true }},
  [pscustomobject]@{{ Name = 'Late'; DisplayName = 'Late one'; State = 'Stopped'; StartMode = 'Auto'; DelayedAutoStart = $true }},
  [pscustomobject]@{{ Name = 'Plain'; DisplayName = 'Plain one'; State = 'Stopped'; StartMode = 'Auto'; DelayedAutoStart = $false }},
  [pscustomobject]@{{ Name = 'Off'; DisplayName = 'Manual one'; State = 'Stopped'; StartMode = 'Manual'; DelayedAutoStart = $true }})
$r = Get-ServiceReport $all @{{ watch = @{{ W3SVC = 'IIS' }} }}
$r | ConvertTo-Json -Depth 5 -Compress
'''
    p = subprocess.run([PWSH, "-NoProfile", "-NonInteractive", "-Command", script], capture_output=True, text=True, timeout=120)
    assert p.returncode == 0, p.stderr
    import json
    r = json.loads(p.stdout.strip().splitlines()[-1])
    assert r["watched"][0]["delayed"] is True
    assert {s["name"]: s["delayed"] for s in r["stopped_auto"]} == {"Late": True, "Plain": False}


def test_router_flash_gets_a_disk_sensor_but_tiny_windows_volumes_dont():
    import types
    import main as M
    def sensors(report):
        h = types.SimpleNamespace(key="r1", name="R1", agent_report=report)
        return [e[0] for e in M.Monitor._metrics(None, h) if "_disk_" in e[0]]
    disks = [{"name": "/overlay", "size_gb": 0.012, "free_gb": 0.009}, {"name": "/", "size_gb": 0, "free_gb": 0}]
    assert sensors({"agent_kind": "sh", "disks": disks}) == ["sensor.ping_monitor_r1_disk_overlay_free"]
    assert sensors({"disks": [{"name": "E:", "size_gb": 0.3, "free_gb": 0.1}, {"name": "C:", "size_gb": 80, "free_gb": 30}]}) == ["sensor.ping_monitor_r1_disk_c_free"]
