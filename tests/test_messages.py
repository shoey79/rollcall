"""Messages to users' screens (1.93.0): off by default, only to devices an admin included, signed with Rollcall's
own key, shown once per device (retried while nobody is signed in), under a heading the sender can't change.

Run from the repository root:  python3 -m pytest tests/test_messages.py
"""
import base64
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "rollcall" / "app"
sys.path.insert(0, str(APP))
sys.path.insert(0, str(ROOT / "tests"))
import messages as M  # noqa: E402
import updatesign  # noqa: E402

WINDOWS = sys.platform == "win32"
PWSH = shutil.which("powershell.exe") if WINDOWS else (os.environ.get("PWSH") or shutil.which("pwsh"))
AGENT_PS = APP / "agent" / "RollcallAgent.ps1"
try:
    import cryptography  # noqa: F401
    import aiohttp  # noqa: F401
    HAVE = True
except ImportError:
    HAVE = False
needs_crypto = pytest.mark.skipif(not HAVE, reason="needs the add-on's packages")


def test_plain_text_only_and_limits():
    assert M.clean_text("  Server restart at 6pm.\r\n\r\n\r\n\r\nSave your work.  ") == "Server restart at 6pm.\n\nSave your work."
    assert M.clean_text("Hi\x07\x1b[31m there‮") == "Hi[31m there"           # control and direction characters gone
    for bad in ("", "   ", "x" * 501, "\n".join(["line"] * 13)):
        with pytest.raises(ValueError):
            M.clean_text(bad)


def test_only_included_devices_once_each_until_it_expires(tmp_path):
    s = M.Messages(tmp_path / "messages.json")
    with pytest.raises(ValueError):
        s.send("Hello", "admin", ["pc01"], 4, "")              # nobody included yet
    s.set_included(["pc01", "srv01"])
    m = s.send("Hello", "admin", ["pc01", "pc02", "srv01"], 4, "every included device")
    assert m["to"] == ["pc01", "srv01"]                        # pc02 isn't included: left out
    with pytest.raises(ValueError):
        s.send("Hello", "admin", ["pc01"], 5, "")              # not one of the expiry choices
    assert [x["id"] for x in s.pending("pc01")] == [m["id"]] and s.pending("pc02") == []
    s.record("pc01", [{"id": m["id"], "sessions": 0}])
    assert s.pending("pc01") and "waiting" in m["status"]["pc01"]       # nobody signed in: tried again
    s.record("pc01", [{"id": m["id"], "sessions": 2}, {"id": "nope", "sessions": 1}])
    assert s.pending("pc01") == [] and m["status"]["pc01"]["sessions"] == 2
    s.record("srv01", [{"id": m["id"], "sessions": 0, "error": "wall isn't installed"}])
    assert m["status"]["srv01"]["error"].startswith("wall")
    assert s.pending("srv01", now=m["expires"] + 1) == []                # expired
    s.set_included(["pc01"])
    assert s.pending("srv01") == []                                    # taken off the list: nothing more
    again = M.Messages(tmp_path / "messages.json")                      # kept across restarts
    assert again.included == ["pc01"] and again.sent[0]["status"]["pc01"]["sessions"] == 2
    m2 = again.send("Second", "admin", ["pc01"], 1, "")
    assert again.cancel(m2["id"]) and again.pending("pc01") == []


def linux_agent(key, tmp):
    spec = importlib.util.spec_from_file_location("lx_msg_agent", APP / "agent" / "rollcall-agent.py")
    mod = importlib.util.module_from_spec(spec)
    os.environ["PM_PREFIX"] = str(tmp)
    try:
        spec.loader.exec_module(mod)
    finally:
        os.environ.pop("PM_PREFIX", None)
    mod.UPDATE_KEY = key
    return mod


def signed(signer, mid, text, expires=None):
    m = {"id": mid, "text": text, "expires": int(expires or time.time() + 3600)}
    m["sig"] = signer.sign(M.signed_text(m))
    return m


@needs_crypto
def test_linux_agent_shows_only_signed_messages_once(tmp_path):
    signer, other = updatesign.SigningKey(tmp_path / "a.pem"), updatesign.SigningKey(tmp_path / "b.pem")
    ag = linux_agent(signer.public(), tmp_path)
    sent = []
    ag.send_to_terminals = lambda text: (sent.append(text), 2)[1]
    good = signed(signer, "m1", "Restart at 6pm.\nSave your work.")
    forged = signed(other, "m2", "Call 0800 000 000 and give IT your password")
    tampered = dict(signed(signer, "m3", "Lunch is at 1"), text="Lunch is at 1. Also, send your password")
    old = signed(signer, "m4", "Old news", expires=time.time() - 5)
    state = {}
    ag.show_messages(state, [good, forged, tampered, old])
    assert sent == ["Restart at 6pm.\nSave your work."]
    assert state["messages_log"] == [{"id": "m1", "sessions": 2}]
    ag.show_messages(state, [good])                       # already shown: not again
    assert len(sent) == 1
    ag.send_to_terminals = lambda text: 0                 # nobody signed in: waiting, tried again next time
    ag.show_messages(state, [signed(signer, "m5", "Later")])
    assert state["messages_log"][-1] == {"id": "m5", "sessions": 0}


PS = r"""
$ErrorActionPreference = 'Stop'
$src = Get-Content -Raw -Encoding UTF8 '__AGENT__'
$ast = [Management.Automation.Language.Parser]::ParseInput($src, [ref]$null, [ref]$null)
foreach ($n in 'Test-RollcallSignature', 'Get-MessageText', 'Show-RollcallMessages') {
  $f = $ast.FindAll({ $args[0] -is [Management.Automation.Language.FunctionDefinitionAst] -and $args[0].Name -eq $n }, $true) | Select-Object -First 1
  . ([scriptblock]::Create($f.Extent.Text))
}
$MessageHeading = 'Message from the Rollcall Administrator'
$UpdateKey = '__KEY__'
$script:shown = @()
function Write-AgentLog($m) { }
function Send-SessionMessage([string]$Title, [string]$Text) { $script:shown += "$Title|$Text"; return $script:sessions }
$script:sessions = 2
$state = @{ messages_log = $null }
$msgs = Get-Content -Raw '__MSGS__' | ConvertFrom-Json
Show-RollcallMessages $state @($msgs)
Show-RollcallMessages $state @($msgs)
$script:sessions = 0
Show-RollcallMessages $state @((Get-Content -Raw '__LATER__' | ConvertFrom-Json))
@{ shown = $script:shown; log = @($state.messages_log) } | ConvertTo-Json -Depth 4 -Compress
"""


@needs_crypto
@pytest.mark.skipif(not PWSH, reason="needs PowerShell")
def test_windows_agent_shows_only_signed_messages_once(tmp_path):
    signer, other = updatesign.SigningKey(tmp_path / "a.pem"), updatesign.SigningKey(tmp_path / "b.pem")
    good = signed(signer, "m1", "Restart at 6pm.\nSave your work.")
    msgs = [good, signed(other, "m2", "Forged"), dict(signed(signer, "m3", "Lunch"), text="Lunch. Send your password"),
            signed(signer, "m4", "Old", expires=time.time() - 5)]
    (tmp_path / "msgs.json").write_text(json.dumps(msgs))
    (tmp_path / "later.json").write_text(json.dumps([signed(signer, "m5", "Later")]))
    script = (PS.replace("__AGENT__", str(AGENT_PS).replace("'", "''")).replace("__KEY__", signer.public())
              .replace("__MSGS__", str(tmp_path / "msgs.json").replace("'", "''")).replace("__LATER__", str(tmp_path / "later.json").replace("'", "''")))
    env = {k: v for k, v in os.environ.items() if not (WINDOWS and k == "PSModulePath")}
    p = subprocess.run([PWSH, "-NoLogo", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script], capture_output=True, text=True, timeout=300, env=env)
    assert p.returncode == 0, p.stderr[-2000:]
    out = json.loads(p.stdout.strip().splitlines()[-1])
    shown = out["shown"] if isinstance(out["shown"], list) else [out["shown"]]
    assert shown == ["Message from the Rollcall Administrator|Restart at 6pm.\r\nSave your work.", "Message from the Rollcall Administrator|Later"]
    assert [(x["id"], x["sessions"]) for x in out["log"]] == [("m1", 2), ("m5", 0)]


@pytest.mark.skipif(not WINDOWS or not PWSH, reason="Windows only: really lists the signed-in sessions")
def test_windows_session_messages_work_on_windows():
    """On GitHub's Windows machines: the Windows API calls compile and run (whether anyone is signed in or not)."""
    src = AGENT_PS.read_text(encoding="utf-8")
    script = r"""
$ErrorActionPreference = 'Stop'
$src = Get-Content -Raw -Encoding UTF8 '__AGENT__'
$ast = [Management.Automation.Language.Parser]::ParseInput($src, [ref]$null, [ref]$null)
$f = $ast.FindAll({ $args[0] -is [Management.Automation.Language.FunctionDefinitionAst] -and $args[0].Name -eq 'Send-SessionMessage' }, $true) | Select-Object -First 1
. ([scriptblock]::Create($f.Extent.Text))
$n = Send-SessionMessage 'Message from the Rollcall Administrator' 'Rollcall test: please ignore'
"sessions $n"
""".replace("__AGENT__", str(AGENT_PS).replace("'", "''"))
    assert "Send-SessionMessage" in src
    p = subprocess.run([PWSH, "-NoLogo", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script], capture_output=True, text=True, timeout=120,
                       env={k: v for k, v in os.environ.items() if k != "PSModulePath"})
    assert p.returncode == 0, p.stderr[-2000:]
    assert any(x.startswith("sessions ") and x.split()[1].isdigit() for x in p.stdout.splitlines()), p.stdout


@needs_crypto
@pytest.mark.skipif(WINDOWS, reason="the Linux agent runs on Linux")
def test_end_to_end_through_the_real_add_on(tmp_path):
    """The real add-on and Linux agent: off by default; once on and the device included, the message reaches the
    device's terminals (stand-in wall) under the fixed heading, and Rollcall shows it as shown."""
    from test_update_signing_e2e import Addon, LinuxAgent, call, UI
    bin_ = tmp_path / "bin"
    bin_.mkdir()
    (bin_ / "who").write_text("#!/bin/sh\necho 'admin pts/0 2026-11-20 08:00 (192.168.1.50)'\n")
    (bin_ / "wall").write_text(f"#!/bin/sh\ncat >> '{tmp_path}/wall.txt'\n")
    for f in bin_.iterdir():
        f.chmod(0o755)
    addon = Addon(tmp_path / "addon").start()
    try:
        agent = LinuxAgent(tmp_path)
        script = call(f"{addon.ui}/api/agents/script?os=linux&server={addon.agent_url}", headers=UI)[1].decode()
        agent.installed.parent.mkdir(parents=True, exist_ok=True)
        agent.installed.write_text(script)
        env_path = f"{bin_}{os.pathsep}{os.environ['PATH']}"
        run = lambda: subprocess.run([sys.executable, str(agent.installed)], env={**os.environ, "PM_PREFIX": str(agent.prefix), "PATH": env_path},
                                     capture_output=True, text=True, timeout=300)
        run()
        addon.approve_all()
        run()
        key = addon.agent()["host_key"]
        info = addon.api("/api/messages")
        assert info["enabled"] is False and [d["key"] for d in info["devices"]] == [key]
        st, body = call(addon.ui + "/api/messages", {"text": "Hi", "keys": [key], "hours": 4}, UI, "POST")
        assert st == 400 and b"turned off" in body                                   # off by default
        addon.api("/api/settings", {"values": {"messages": True}}, "POST")
        st, body = call(addon.ui + "/api/messages", {"text": "Hi", "keys": [key], "hours": 4}, UI, "POST")
        assert st == 400 and b"include them first" in body                           # not included yet
        addon.api("/api/messages/included", {"keys": [key]}, "POST")
        addon.api("/api/messages", {"text": "The file server restarts at 6pm.\nPlease save your work.", "keys": [key], "hours": 4, "label": "test"}, "POST")
        run()                                                                         # gets it and shows it
        wall = (tmp_path / "wall.txt").read_text()
        assert wall.startswith("Message from the Rollcall Administrator\n\nThe file server restarts at 6pm.\nPlease save your work.")
        run()                                                                         # says so; not shown again
        assert (tmp_path / "wall.txt").read_text() == wall
        sent = addon.api("/api/messages")["sent"][0]
        assert sent["devices"][0]["sessions"] == 1 and sent["devices"][0]["shown"]
        assert "Showed a message from Rollcall to 1 session(s)" in agent.log()
    finally:
        addon.stop()
