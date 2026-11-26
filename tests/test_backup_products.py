"""Other backup products in the Windows agent (owner's request, 22 Nov): Veritas NetBackup (bpdbjobs) and HPE/OpenText
Data Protector (omnirpt), each a small definition feeding the same Backups check as Veeam.

Neither product can be run here: the sample output below follows the vendors' documented formats (bpdbjobs
-all_columns: jobid, jobtype, state, status, policy, schedule, client, server, started, elapsed, ended, ...; omnirpt
-tab: # headings, then tab-separated sessions), with made-up names. Real samples from a user are needed to confirm."""
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

AGENT = ROOT / "rollcall" / "app" / "agent" / "RollcallAgent.ps1"
WIN_PS = shutil.which("powershell.exe") if sys.platform == "win32" else None
PWSH = WIN_PS or os.environ.get("PWSH") or shutil.which("pwsh")
NOW = int(time.time())

NBU = "\n".join([
    # jobid,type,state,status,policy,schedule,client,server,started,elapsed,ended,...
    f"101,0,3,0,Servers,Daily-Incr,srv01.example.local,media01,{NOW - 90000},600,{NOW - 89400},stu1,1",
    f"102,0,3,58,Servers,Daily-Incr,srv02.example.local,media01,{NOW - 4000},60,{NOW - 3940},stu1,1",
    f"103,0,3,0,Servers,Daily-Incr,srv01.example.local,media01,{NOW - 3600},600,{NOW - 3000},stu1,1",
    f"104,0,3,1,File shares,Weekly-Full,fs01.example.local,media01,{NOW - 7200},900,{NOW - 6300},stu1,1,"
    "path\\,with\\,commas",
    f"105,0,1,0,Servers,Daily-Incr,srv03.example.local,media01,{NOW - 60},0,0,stu1,1",             # still running
    f"106,2,3,0,Servers,Restore,srv01.example.local,media01,{NOW - 500},60,{NOW - 440},stu1,1",       # a restore
    f"107,6,3,0,NBU-Catalog,Full,master01,master01,{NOW - 20000},300,{NOW - 19700},stu1,1",
])
DP = "\n".join([
    "# Report: List of Sessions",
    "#",
    "#Session Type\tSpecification\tStatus\tMode\tStart Time\tStart Time_t\tEnd Time\tEnd Time_t\tErrors\tWarnings\tFailed DA\tCompleted DA\tSession ID",
    f"Backup\tFileServer Daily\tCompleted\tincr\t-\t{NOW - 8000}\t-\t{NOW - 7000}\t0\t0\t0\t3\t2026/11/22-1",
    f"Backup\tSQL Nightly\tCompleted/Errors\tfull\t-\t{NOW - 6000}\t-\t{NOW - 5000}\t3\t1\t1\t4\t2026/11/22-2",
    f"Backup\tExchange\tFailed\tfull\t-\t{NOW - 4000}\t-\t{NOW - 3990}\t1\t0\t1\t0\t2026/11/22-3",
    f"Backup\tFileServer Daily\tIn Progress\tincr\t-\t{NOW - 60}\t-\t\t0\t0\t0\t0\t2026/11/22-4",
    f"Restore\tFileServer Daily\tCompleted\t-\t-\t{NOW - 50}\t-\t{NOW - 40}\t0\t0\t0\t1\t2026/11/22-5",
])

SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$ast = [Management.Automation.Language.Parser]::ParseFile('__AGENT__', [ref]$null, [ref]$null)
foreach ($n in 'ConvertFrom-NbuJobs', 'ConvertFrom-DpSessions', 'Get-NbuStatusText', 'Get-BackupProductJobs', 'Limit-Text',
             'ConvertTo-IsoText', 'ConvertTo-UtcString') {
  $f = $ast.Find({ param($x) $x -is [Management.Automation.Language.FunctionDefinitionAst] -and $x.Name -eq $n }.GetNewClosure(), $true)
  if ($f) { . ([scriptblock]::Create($f.Extent.Text)) }
}
function Write-AgentLog($m) { }
$nbu = Get-Content -LiteralPath '__NBU__'; $dp = Get-Content -LiteralPath '__DP__'
$products = @(
  @{ name = 'NetBackup'; key = 'nbu'; find = { 'bpdbjobs' }; read = { param($exe) ConvertFrom-NbuJobs $nbu } },
  @{ name = 'Data Protector'; key = 'dp'; find = { 'omnirpt' }; read = { param($exe) ConvertFrom-DpSessions $dp } },
  @{ name = 'Not here'; key = 'none'; find = { $null }; read = { throw 'never' } })
$st = @{}
$out = @{ jobs = @(Get-BackupProductJobs $st $products) }
# The next run, with nothing new from NetBackup (its job list only goes back a few days): the history is kept
$nbu = @()
$out.again = @(Get-BackupProductJobs $st $products)
$out.none = Get-BackupProductJobs @{} @($products[2])
$out | ConvertTo-Json -Depth 8 -Compress
"""


@pytest.mark.skipif(not PWSH, reason="needs PowerShell")
def test_netbackup_and_data_protector(tmp_path):
    (tmp_path / "nbu.txt").write_text(NBU)
    (tmp_path / "dp.txt").write_text(DP)
    script = (SCRIPT.replace("__AGENT__", str(AGENT).replace("'", "''")).replace("__NBU__", str(tmp_path / "nbu.txt"))
              .replace("__DP__", str(tmp_path / "dp.txt")))
    p = subprocess.run([PWSH, "-NoProfile", "-NonInteractive", "-Command", script], capture_output=True, text=True, timeout=120)
    assert p.returncode == 0, p.stderr
    out = json.loads(p.stdout.strip().splitlines()[-1])
    jobs = {j["name"]: j for j in out["jobs"]}
    assert set(jobs) == {"Servers / srv01.example.local", "Servers / srv02.example.local", "File shares / fs01.example.local",
                         "Catalog backup / master01", "FileServer Daily", "SQL Nightly", "Exchange"}, jobs.keys()
    s1 = jobs["Servers / srv01.example.local"]
    assert s1["result"] == "Success" and len(s1["runs"]) == 2 and s1["source"] == "NetBackup" and s1["type"] == "NetBackup Daily-Incr"
    s2 = jobs["Servers / srv02.example.local"]
    assert s2["result"] == "Failed" and s2["detail"] == "status 58: can't connect to client" and s2["issue"]["log"][0]["text"] == s2["detail"]
    assert jobs["File shares / fs01.example.local"]["result"] == "Warning"
    assert jobs["SQL Nightly"]["result"] == "Warning" and jobs["SQL Nightly"]["detail"] == "completed with errors; 3 error(s); 1 warning(s); 1 of 5 disk agents failed"
    assert jobs["Exchange"]["result"] == "Failed" and jobs["FileServer Daily"]["result"] == "Success"   # not the one in progress
    assert jobs["FileServer Daily"]["source"] == "Data Protector" and jobs["FileServer Daily"]["type"] == "Data Protector incr"
    assert {j["name"] for j in out["again"]} == set(jobs)           # kept between runs
    assert out["none"] is None                                       # not installed: no Backups check
    # The add-on judges them like Veeam's: a failure is red, a partial success amber
    now = time.time()
    view = {j["name"]: j for j in agentlib.backup_jobs_view(out["jobs"])}
    assert agentlib.backup_job_state(view["Servers / srv02.example.local"], now) == (agentlib.CRIT, "failed")
    assert agentlib.backup_job_state(view["SQL Nightly"], now) == (agentlib.WARN, "finished with warnings")
    assert agentlib.backup_job_state(view["Servers / srv01.example.local"], now) == (agentlib.OK, "")


def test_hints_for_their_errors():
    import hints
    assert "couldn't reach the client" in hints.known("backups", "status 58: can't connect to client", 1)[0]["means"]
    assert "skipped some files" in hints.known("backups", "status 1: partially successful: some files were not backed up", 1)[0]["means"]
    assert "disk agent" in hints.known("backups", "completed with errors; 3 error(s); 1 of 5 disk agents failed", 1)[0]["means"]
