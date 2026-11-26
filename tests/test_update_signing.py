"""Rollcall's own signing key (1.92.1): the add-on, the Linux agent and the Windows agent must agree exactly on what
a good signature is and on the text that's signed, and refuse everything else. Also: dashboard editing fails closed
when Home Assistant's user list can't be read, and the key is kept in exports.

The PowerShell parts run on Windows PowerShell 5.1 on Windows (.NET Framework's BigInteger), else PowerShell 7.

Run from the repository root:  python3 -m pytest tests/test_update_signing.py
"""
import asyncio
import base64
import importlib.util
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "rollcall" / "app"
sys.path.insert(0, str(APP))
import updatesign  # noqa: E402

WINDOWS = sys.platform == "win32"
PWSH = shutil.which("powershell.exe") if WINDOWS else (os.environ.get("PWSH") or shutil.which("pwsh"))
AGENT_PS = APP / "agent" / "RollcallAgent.ps1"
try:
    import cryptography  # noqa: F401
    HAVE_CRYPTO = True
except ImportError:
    HAVE_CRYPTO = False
needs_crypto = pytest.mark.skipif(not HAVE_CRYPTO, reason="needs cryptography (the add-on has it)")


def linux_agent(update_key):
    spec = importlib.util.spec_from_file_location("lx_agent", APP / "agent" / "rollcall-agent.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.UPDATE_KEY = update_key
    return mod


@pytest.fixture(scope="module")
def keys(tmp_path_factory):
    d = tmp_path_factory.mktemp("keys")
    return updatesign.SigningKey(d / "a.pem"), updatesign.SigningKey(d / "b.pem")


def cases(keys):
    """(data, signature, should it pass) with key a's public half."""
    a, b = keys
    data = b"$AgentVersion = '1.0.99'\r\nWrite-Output 'hello'\r\n"
    good = a.sign(data)
    raw = bytearray(base64.b64decode(good))
    raw[-1] ^= 1
    n = int.from_bytes(base64.b64decode(a.public()), "big")
    return [
        (data, good, True),
        (data + b" ", good, False),                                     # the script changed after signing
        (data, base64.b64encode(bytes(raw)).decode(), False),            # the signature changed
        (data, b.sign(data), False),                                     # another key
        (data, "", False), (data, "not base64!", False),
        (data, base64.b64encode(b"\x00" * 10).decode(), False),          # wrong length
        (data, base64.b64encode(n.to_bytes(384, "big")).decode(), False),  # s >= n
        (data, base64.b64encode(b"\x00" * 383 + b"\x01").decode(), False),  # s = 1
    ]


@needs_crypto
def test_the_add_on_and_the_linux_agent_agree(keys):
    a, _ = keys
    ag = linux_agent(a.public())
    for data, sig, ok in cases(keys):
        assert updatesign.verify(a.public(), data, sig) is ok, (data[:20], sig[:20])
        assert ag.rollcall_signed(data, sig) is ok, (data[:20], sig[:20])
    assert linux_agent("__PM_UPDATE_KEY__").rollcall_signed(cases(keys)[0][0], cases(keys)[0][1]) is False  # no key built in
    assert not updatesign.verify(base64.b64encode(b"\x01" * 64).decode(), b"x", base64.b64encode(b"\x00" * 64).decode())  # tiny keys refused


@needs_crypto
def test_the_signed_address_text_is_built_the_same_way(keys):
    ag = linux_agent(keys[0].public())
    for servers, route in ((["http://10.0.1.5:8100", "https://rollcall.example.local:8100"],
                            {"inside": "http://10.0.1.5:8100", "outside": "https://rollcall.example.local:8100", "networks": ["10.0.1.0/24", "10.0.2.0/24"]}),
                           ([], None), (["http://192.168.1.5:8100"], None)):
        body = json.loads(json.dumps({"servers": servers, "route": route}))
        assert ag.config_text(body) == updatesign.config_text(servers, route)
    assert updatesign.config_text([], None) == b"rollcall-agent-config/1\nservers=\nroute=\n"


PS = r"""
$ErrorActionPreference = 'Stop'
$src = Get-Content -Raw -Encoding UTF8 '__AGENT__'
$ast = [Management.Automation.Language.Parser]::ParseInput($src, [ref]$null, [ref]$null)
foreach ($n in 'Test-RollcallSignature', 'Get-ConfigText') {
  $f = $ast.FindAll({ $args[0] -is [Management.Automation.Language.FunctionDefinitionAst] -and $args[0].Name -eq $n }, $true) | Select-Object -First 1
  . ([scriptblock]::Create($f.Extent.Text))
}
$UpdateKey = '__KEY__'
$cases = Get-Content -Raw '__CASES__' | ConvertFrom-Json
foreach ($c in $cases) {
  $ok = Test-RollcallSignature ([Convert]::FromBase64String($c.data)) ([string]$c.sig)
  "case $($c.i) $ok"
}
$UpdateKey = '__PM_UPDATE_KEY__'
"nokey $(Test-RollcallSignature ([Convert]::FromBase64String($cases[0].data)) ([string]$cases[0].sig))"
foreach ($b in (Get-Content -Raw '__BODIES__' | ConvertFrom-Json)) {
  "text " + [Convert]::ToBase64String((Get-ConfigText $b))
}
"""


@needs_crypto
@pytest.mark.skipif(not PWSH, reason="needs PowerShell")
def test_the_windows_agent_agrees(keys, tmp_path):
    a, _ = keys
    cs = cases(keys)
    (tmp_path / "cases.json").write_text(json.dumps([{"i": i, "data": base64.b64encode(d).decode(), "sig": s} for i, (d, s, _) in enumerate(cs)]))
    bodies = [{"servers": ["http://10.0.1.5:8100", "https://rollcall.example.local:8100"],
               "route": {"inside": "http://10.0.1.5:8100", "outside": "https://rollcall.example.local:8100", "networks": ["10.0.1.0/24"]}},
              {"servers": ["http://192.168.1.5:8100"], "route": None}, {"servers": [], "route": None}]
    (tmp_path / "bodies.json").write_text(json.dumps(bodies))
    script = (PS.replace("__AGENT__", str(AGENT_PS).replace("'", "''")).replace("__KEY__", a.public())
              .replace("__CASES__", str(tmp_path / "cases.json").replace("'", "''")).replace("__BODIES__", str(tmp_path / "bodies.json").replace("'", "''")))
    env = {k: v for k, v in os.environ.items() if not (WINDOWS and k == "PSModulePath")}
    p = subprocess.run([PWSH, "-NoLogo", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script], capture_output=True, text=True, timeout=300, env=env)
    assert p.returncode == 0, p.stderr[-2000:]
    out = p.stdout.split("\n")
    got = {int(x.split()[1]): x.split()[2] == "True" for x in out if x.startswith("case ")}
    assert got == {i: ok for i, (_, _, ok) in enumerate(cs)}, out
    assert "nokey False" in [x.strip() for x in out]
    texts = [base64.b64decode(x.split()[1]) for x in out if x.startswith("text ")]
    assert texts == [updatesign.config_text(b["servers"], b["route"]) for b in bodies]


@needs_crypto
def test_the_key_is_made_once_kept_private_and_built_into_scripts(tmp_path, monkeypatch):
    k = updatesign.SigningKey(tmp_path / "update_key.pem")
    pub = k.public()
    assert (tmp_path / "update_key.pem").exists() and updatesign.SigningKey(tmp_path / "update_key.pem").public() == pub
    if not WINDOWS:
        assert oct((tmp_path / "update_key.pem").stat().st_mode & 0o777) == "0o600"
    import main
    monkeypatch.setattr(main, "SIGNER", k)
    for os_name, marker in (("windows", f"$UpdateKey = '{pub}'"), ("linux", f'UPDATE_KEY = "{pub}"')):
        text = main.build_agent_script(os_name, "http://192.168.1.5:8100", "k" * 32, False).decode("utf-8-sig")
        assert marker in text and "__PM_UPDATE_KEY__" not in text
    assert "update_key.pem" in main.backup_files()           # exported and restored with everything else


def test_editing_fails_closed_without_home_assistants_user_list(monkeypatch):
    import main
    monkeypatch.setattr(main, "SUPERVISOR_TOKEN", "x")

    class HA:
        async def list_users(self):
            return None  # can't be read

    def can(opts, name):
        acc = main.Access(opts, HA())
        return asyncio.run(acc._can_edit("u-1", name, name)), acc
    ok, acc = can({}, "someone")
    assert ok is False and acc.blocked()                    # before 1.92.1: True (everyone could)
    assert can({"editors": ["helper"]}, "helper")[0] is True       # names in editors still can
    assert can({"editors": ["helper"]}, "someone")[0] is False
    assert can({"admin_only_changes": False}, "someone")[0] is True   # the owner's own choice to let everyone
