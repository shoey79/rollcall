"""Hyper-V on the Roles tab (owner's request, 26 Nov): each VM's uptime, CPU, memory and checkpoints, read by the
Windows agent with Get-VM and one Get-VMSnapshot. Hyper-V is stood in; names are made up."""
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

AGENT = Path(__file__).resolve().parents[1] / "rollcall" / "app" / "agent" / "RollcallAgent.ps1"
PWSH = os.environ.get("PWSH") or shutil.which("pwsh")


@pytest.mark.skipif(not PWSH, reason="needs PowerShell")
def test_agent_reads_vm_details_and_checkpoints():
    src = AGENT.read_text(encoding="utf-8-sig")
    snippet = re.search(r"( *# Each VM's state, uptime, CPU and memory.*?\n                \}\)\r?\n)", src, re.S).group(1)
    script = r"""
$ErrorActionPreference = 'Stop'
function ConvertTo-UtcString($Date) { ([DateTime]$Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') }
function Limit-Text([string]$T, [int]$N) { if ($T.Length -gt $N) { $T.Substring(0, $N) } else { $T } }
function Get-VM { @(
  [pscustomobject]@{ Name = 'SRV01'; State = 'Running'; Status = 'Operating normally'; Uptime = [TimeSpan]::FromHours(50); CPUUsage = 7; ProcessorCount = 4
    MemoryAssigned = 8GB; MemoryDemand = 5GB; MemoryStartup = 4GB; MemoryMaximum = 16GB; DynamicMemoryEnabled = $true; Generation = 2; ReplicationHealth = 'NotApplicable' },
  [pscustomobject]@{ Name = 'PC01'; State = 'Off'; Status = 'Operating normally'; Uptime = [TimeSpan]::Zero; CPUUsage = 0; ProcessorCount = 2
    MemoryAssigned = 0; MemoryDemand = 0; MemoryStartup = 2GB; MemoryMaximum = 2GB; DynamicMemoryEnabled = $false; Generation = 1; ReplicationHealth = 'Normal' }) }
function Get-VMSnapshot { [CmdletBinding()] param([Parameter(ValueFromPipeline = $true)]$VM)
  process { if ($VM.Name -eq 'SRV01') {
    [pscustomobject]@{ VMName = 'SRV01'; Name = 'Before update'; CreationTime = [DateTime]::new(2026, 10, 1, 9, 0, 0, [DateTimeKind]::Utc); SnapshotType = 'Standard' }
    [pscustomobject]@{ VMName = 'SRV01'; Name = 'Nightly'; CreationTime = [DateTime]::new(2026, 11, 20, 2, 0, 0, [DateTimeKind]::Utc); SnapshotType = 'Production' } } } }
$checks = @{}
""" + snippet + r"""
$checks.hyperv | ConvertTo-Json -Depth 4 -Compress
"""
    p = subprocess.run([PWSH, "-NoProfile", "-NonInteractive", "-Command", script], capture_output=True, text=True, timeout=60)
    assert p.returncode == 0, p.stderr
    vms = {v["name"]: v for v in json.loads(p.stdout.strip().splitlines()[-1])}
    s1, pc = vms["SRV01"], vms["PC01"]
    assert s1["uptime_s"] == 50 * 3600 and s1["cpu_pct"] == 7 and s1["cpus"] == 4
    assert s1["mem_mb"] == 8192 and s1["mem_demand_mb"] == 5120 and s1["mem_max_mb"] == 16384 and s1["dynamic"] is True
    assert s1["checkpoints"] == 2 and s1["oldest_checkpoint"] == "2026-10-01T09:00:00Z" and s1["checkpoint_names"] == ["Before update", "Nightly"]
    assert s1["checkpoint_type"] == "Production"
    assert pc["checkpoints"] == 0 and pc["oldest_checkpoint"] is None and pc["mem_max_mb"] is None and pc["uptime_s"] == 0
