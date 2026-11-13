"""The Windows agent must always get its report out.

Windows PowerShell 5.1 runs the agent with $ErrorActionPreference = 'Stop', where anything a
program writes to stderr can end the run (agent 1.0.37 stopped reporting everywhere this way).
PowerShell 7 can be made just as strict with $PSNativeCommandUseErrorActionPreference, so this
runs the real agent like that, with a schtasks.exe that always fails, against a fake Rollcall,
and checks a report arrives.

On Windows it runs on the real Windows PowerShell 5.1 (powershell.exe) instead, with the real
schtasks.exe, which fails just as 1.0.37 met it on a computer without the agent's start-up task.

Needs PowerShell 7 (pwsh, or the PWSH environment variable) elsewhere; skipped without it.
"""
import http.server
import json
import os
import shutil
import subprocess
import sys
import threading
from pathlib import Path

import pytest

AGENT = Path(__file__).resolve().parents[1] / "rollcall" / "app" / "agent" / "PingMonitorAgent.ps1"
WINDOWS = sys.platform == "win32"
PWSH = shutil.which("powershell.exe") if WINDOWS else (os.environ.get("PWSH") or shutil.which("pwsh"))

FAILING_SCHTASKS = """#!/bin/sh
echo "ERROR: The system cannot find the file specified." >&2
exit 1
"""


class _Rollcall(http.server.BaseHTTPRequestHandler):
    reports: list = []

    def do_POST(self):  # noqa: N802
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        if self.path.startswith("/agent/report"):
            try:
                _Rollcall.reports.append(json.loads(body))
            except ValueError:
                _Rollcall.reports.append({"unreadable": True})
        out = json.dumps({"status": "approved"}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    do_GET = do_POST

    def log_message(self, *_a):
        pass


@pytest.mark.skipif(not PWSH, reason="needs PowerShell")
def test_windows_agent_reports_even_when_programs_fail(tmp_path):
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Rollcall)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    _Rollcall.reports = []
    try:
        data = tmp_path / "data"
        data.mkdir()
        agent = data / "PingMonitorAgent.ps1"  # run from its installed place, like the scheduled task
        shutil.copy(AGENT, agent)
        server = f"http://127.0.0.1:{srv.server_address[1]}"
        if WINDOWS:
            # The real thing: Windows PowerShell 5.1 and the real schtasks.exe
            cmd = [PWSH, "-NoLogo", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(agent),
                   "-Server", server, "-EnrolKey", "testkey", "-DataPath", str(data)]
            env = dict(os.environ)
        else:
            bin_ = tmp_path / "bin"
            bin_.mkdir()
            for name in ("schtasks.exe", "quser.exe", "netsh.exe"):
                p = bin_ / name
                p.write_text(FAILING_SCHTASKS)
                p.chmod(0o755)
            cmd = [PWSH, "-NoLogo", "-NoProfile", "-Command", "$PSNativeCommandUseErrorActionPreference = $true; "
                   f"& '{agent}' -Server {server} -EnrolKey testkey -DataPath '{data}'"]
            env = {**os.environ, "PATH": f"{bin_}{os.pathsep}{os.environ.get('PATH', '')}"}
        run = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=600)
        log = (data / "agent.log").read_text(errors="replace") if (data / "agent.log").exists() else ""
        assert _Rollcall.reports, f"no report reached Rollcall.\nagent log:\n{log[-2000:]}\nstderr:\n{run.stderr[-2000:]}"
        assert "Report sent" in log
    finally:
        srv.shutdown()
