"""The password scan: both agents must find the same things in the test pack, and no fake password
(or any 8-character piece of one) may appear in what they report.

The Windows agent runs on Windows PowerShell 5.1 (powershell.exe) on Windows, else PowerShell 7
(pwsh, or the PWSH environment variable); that test is skipped if neither is there.
"""
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from secret_corpus import make_corpus  # noqa: E402

AGENTS = Path(__file__).resolve().parents[1] / "rollcall" / "app" / "agent"
WIN_PS = shutil.which("powershell.exe") if sys.platform == "win32" else None
PWSH = WIN_PS or os.environ.get("PWSH") or shutil.which("pwsh")


@pytest.fixture(scope="module")
def corpus(tmp_path_factory):
    root = tmp_path_factory.mktemp("scan") / "corpus"
    secrets = make_corpus(str(root))
    return root, secrets


def _norm(findings, root):
    # From the test pack's own folder down, so short (8.3) and long forms of the temp folder match
    out = []
    for f in findings:
        p = f["path"].replace("\\", "/")
        rel = p.split("/corpus/", 1)[1] if "/corpus/" in p else p
        out.append((rel, f.get("line") or 0, f["rule"], f["key"], f.get("len")))
    return sorted(out)


def _leaks(text, secrets):
    bad = []
    for s in secrets:
        pieces = {s} | {s[i:i + 8] for i in range(0, max(1, len(s) - 7))}
        bad += [p for p in pieces if len(p) >= 8 and p in text]
    return bad


def _linux(root):
    run = subprocess.run([sys.executable, str(AGENTS / "pingmonitor-agent.py"), "--secret-test", str(root)],
                         capture_output=True, text=True, timeout=300, encoding="utf-8",
                         env={**os.environ, "PYTHONIOENCODING": "utf-8"})
    assert run.returncode == 0, run.stderr
    return run.stdout


def test_linux_agent_finds_them_and_never_sends_them(corpus):
    root, secrets = corpus
    out = _linux(root)
    found = _norm(json.loads(out), root)
    assert len(found) >= 38, found
    assert not [f for f in found if "node_modules" in f[0]], "skipped folders were scanned"
    assert not _leaks(out, secrets)


@pytest.mark.skipif(not PWSH, reason="needs PowerShell")
def test_windows_agent_agrees_and_never_sends_them(corpus):
    root, secrets = corpus
    script, folder = (str(x).replace("'", "''") for x in (AGENTS / "PingMonitorAgent.ps1", root))
    cmd = ("[Console]::OutputEncoding = New-Object Text.UTF8Encoding $false; "
           f"& '{script}' -SecretTest '{folder}'")
    run = subprocess.run([PWSH, "-NoLogo", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", cmd],
                         capture_output=True, text=True, timeout=600, encoding="utf-8", errors="replace")
    assert run.returncode == 0, run.stderr[-3000:]
    start = run.stdout.find("[")
    assert start >= 0, run.stdout[-2000:] + run.stderr[-2000:]
    win = _norm(json.loads(run.stdout[start:]), root)
    lin = _norm(json.loads(_linux(root)), root)
    only_win, only_lin = sorted(set(win) - set(lin)), sorted(set(lin) - set(win))
    assert not only_win and not only_lin, f"only Windows: {only_win}\nonly Linux: {only_lin}"
    assert not _leaks(run.stdout, secrets)


@pytest.mark.skipif(sys.platform != "win32", reason="Windows PowerShell 5.1 is only on Windows")
def test_windows_agent_parses_on_windows_powershell_51():
    script = str(AGENTS / "PingMonitorAgent.ps1").replace("'", "''")
    cmd = ("$e = $null; [void][Management.Automation.Language.Parser]::ParseFile('" + script + "', [ref]$null, [ref]$e); "
           "'{0} {1}' -f $PSVersionTable.PSVersion.Major, @($e).Count; $e | ForEach-Object { $_.Extent.StartLineNumber.ToString() + ': ' + $_.Message }")
    run = subprocess.run([WIN_PS, "-NoLogo", "-NoProfile", "-Command", cmd], capture_output=True, text=True, timeout=120)
    first, *errors = run.stdout.strip().splitlines()
    major, count = first.split()
    assert major == "5", f"expected Windows PowerShell 5.1, got {major}"
    assert count == "0", "\n".join(errors)
