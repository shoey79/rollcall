"""Fixes from the security and code review of 1.97.1 (F1-F14), each checked against what the review described."""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "rollcall" / "app"))
import agents as agentlib  # noqa: E402
from test_update_signing_e2e import HAVE_ADDON_DEPS, UI, Addon, call  # noqa: E402


def test_f10_non_ascii_enrolment_key_is_just_wrong(tmp_path):
    st = agentlib.AgentStore(tmp_path / "agents.json", tmp_path / "reports")
    st.rotate_key()
    assert st.check_key("clé") is False and st.check_key(None) is False and st.check_key(st.enrol_key) is True


def test_f13_patterns_refuse_a_trailing_newline():
    import main
    assert agentlib.TOKEN_RE.match("a" * 64) and not agentlib.TOKEN_RE.match("a" * 64 + "\n")
    assert agentlib.HOSTNAME_RE.match("PC01") and not agentlib.HOSTNAME_RE.match("PC01\n")
    assert main.ICON_FILE.match("abcdef123456.png") and not main.ICON_FILE.match("abcdef123456.png\n")
    assert not main.REPORT_NAME.match("agent_reports/abcdef.json\n")


@pytest.mark.skipif(not HAVE_ADDON_DEPS, reason="needs the add-on's packages")
def test_f10_and_f3_through_the_add_on(tmp_path):
    addon = Addon(tmp_path / "addon").start()
    try:
        key = addon.enrol_key("windows", addon.agent_url)

        def enrol(host, token, k=key):
            return call(addon.agent_url + "/agent/enrol", {"enrol_key": k, "token": token, "hostname": host, "os": "Test",
                                                          "os_family": "windows", "agent_version": "1.0.57"})
        # F10: a wrong key with non-ASCII characters is refused, not a crash
        st, _ = enrol("PC09", "f" * 64, "clé-ünïcode")
        assert st == 403
        # An existing approved agent, then a request that would replace it and two new ones
        assert enrol("SRV01", "1" * 64)[0] == 202
        addon.approve_all()
        assert enrol("SRV01", "2" * 64)[0] == 202                   # claims to be SRV01 again
        assert enrol("PC01", "3" * 64)[0] == 202
        shown = [p for p in addon.api("/api/agents")["pending"]]
        repl = next(p for p in shown if p["hostname"] == "SRV01")
        assert repl["replaces"] is True and repl["replaces_from"] == "127.0.0.1"
        assert enrol("PC02", "4" * 64)[0] == 202                    # arrives after the page loaded
        # F3: without the ids the admin saw: refused
        st, _ = call(addon.ui + "/api/agents/approve-all", {}, UI, "POST")
        assert st == 400
        # with them: only the new server shown is approved; the replacement and the late one wait
        st, body = call(addon.ui + "/api/agents/approve-all", {"ids": [p["id"] for p in shown]}, UI, "POST")
        assert st == 200 and json.loads(body) == {"approved": 1, "skipped": 1}, body
        left = {p["hostname"] for p in addon.api("/api/agents")["pending"]}
        assert left == {"SRV01", "PC02"}
        assert {a["hostname"] for a in addon.api("/api/agents")["agents"]} == {"SRV01", "PC01"}
    finally:
        addon.stop()


PWSH = __import__("os").environ.get("PWSH") or __import__("shutil").which("pwsh")


@pytest.mark.skipif(not PWSH, reason="needs PowerShell")
def test_f9_folder_writers_are_found():
    """The read-back after locking the folder: anyone but SYSTEM and Administrators with write access is named.
    (Windows permissions are stood in for: Get-Acl returns a made-up ACL.)"""
    import subprocess
    agent = Path(__file__).resolve().parents[1] / "rollcall" / "app" / "agent" / "RollcallAgent.ps1"
    script = r"""
$ast = [Management.Automation.Language.Parser]::ParseFile('__A__', [ref]$null, [ref]$null)
$f = $ast.Find({ param($x) $x -is [Management.Automation.Language.FunctionDefinitionAst] -and $x.Name -eq 'Get-DataFolderWriters' }, $true)
$text = $f.Extent.Text -replace 'if \(\$PSVersionTable.PSVersion.Major -ge 6 -and -not \$IsWindows\) \{ return @\(\) \}', ''
. ([scriptblock]::Create($text))
function rule($sid, $rights, $type = 'Allow') {
  $id = [pscustomobject]@{ Value = $sid }
  $id | Add-Member ScriptMethod Translate { param($t) [pscustomobject]@{ Value = $this.Value } }
  $id | Add-Member ScriptMethod ToString { $this.Value } -Force
  [pscustomobject]@{ AccessControlType = $type; FileSystemRights = $rights; IdentityReference = $id }
}
$script:rules = @()
function Get-Acl { param($LiteralPath, $ErrorAction) [pscustomobject]@{ Access = $script:rules } }
$out = @{}
$script:rules = @((rule 'S-1-5-18' 2032127), (rule 'S-1-5-32-544' 2032127))
$out.locked = @(Get-DataFolderWriters 'x')
$script:rules += @((rule 'S-1-5-32-545' 1179817))                 # Users: read and execute only
$out.read_only = @(Get-DataFolderWriters 'x')
$script:rules += @((rule 'S-1-5-11' 1245631), (rule 'S-1-1-0' 278 'Deny'))   # Authenticated Users: modify; a deny
$out.open = @(Get-DataFolderWriters 'x')
$out | ConvertTo-Json -Compress
""".replace("__A__", str(agent))
    p = subprocess.run([PWSH, "-NoProfile", "-NonInteractive", "-Command", script], capture_output=True, text=True, timeout=60)
    assert p.returncode == 0, p.stderr
    out = json.loads(p.stdout.strip().splitlines()[-1])
    assert out["locked"] == [] and out["read_only"] == [] and out["open"] == ["S-1-5-11"], out


@pytest.mark.skipif(not HAVE_ADDON_DEPS, reason="needs the add-on's packages")
def test_f4_only_ingress_may_use_the_dashboard(tmp_path):
    """In Home Assistant (SUPERVISOR_TOKEN set), a caller other than the ingress gateway is refused, whatever
    headers it sends; the agent port is unaffected. 127.0.0.1 stands in for "someone else" here."""
    addon = Addon(tmp_path / "addon").start(extra_env={"SUPERVISOR_TOKEN": "test-token", "PM_INGRESS_FROM": "172.30.32.2"}, ready=403)
    try:
        st, body = call(addon.ui + "/api/status", headers=UI)
        assert st == 403 and b"Home Assistant" in body
        st, _ = call(addon.agent_url + "/agent/enrol", {"enrol_key": "x", "token": "a" * 64, "hostname": "PC01"})
        assert st == 403  # the agent port answers as usual (wrong key), it isn't blocked
    finally:
        addon.stop()


@pytest.mark.skipif(not HAVE_ADDON_DEPS, reason="needs the add-on's packages")
def test_f12_unknown_body_token_reports_are_kept_small(tmp_path):
    addon = Addon(tmp_path / "addon").start()
    try:
        big = {"agent_token": "a" * 64, "pad": "x" * (600 * 1024)}
        st, _ = call(addon.agent_url + "/agent/report", big)
        assert st == 413
        st, _ = call(addon.agent_url + "/agent/report", {"agent_token": "a" * 64, "pad": "x" * 1000})
        assert st == 401          # small: read, then refused as unknown
    finally:
        addon.stop()


@pytest.mark.skipif(not PWSH, reason="needs PowerShell")
def test_windows_agent_keeps_its_state_between_runs(tmp_path):
    """Found while fixing F7: Read-State only keeps fields it names, so the agent policy cache (read hourly) and the
    NetBackup / Data Protector history from 1.98.0 were lost at every run. Saved, then read back."""
    import subprocess
    agent = Path(__file__).resolve().parents[1] / "rollcall" / "app" / "agent" / "RollcallAgent.ps1"
    script = r"""
$ast = [Management.Automation.Language.Parser]::ParseFile('__A__', [ref]$null, [ref]$null)
foreach ($n in 'Read-State', 'Save-State') { $f = $ast.Find({ param($x) $x -is [Management.Automation.Language.FunctionDefinitionAst] -and $x.Name -eq $n }.GetNewClosure(), $true); . ([scriptblock]::Create($f.Extent.Text)) }
$DataPath = '__D__'; $StatePath = Join-Path $DataPath 'state.json'
$st = Read-State
$st.veeam_policy = '[{"policy":"Laptops"}]'; $st.veeam_policy_key = 'Laptops'; $st.veeam_policy_checked = 1795000000
$st.bp_nbu = '{"nbu:x|y":{}}'; $st.bp_dp = '{}'; $st.sig_serial = 1795000123
Save-State $st
$back = Read-State
@{ vp = $back.veeam_policy; vk = $back.veeam_policy_key; vc = $back.veeam_policy_checked; nbu = $back.bp_nbu; dp = $back.bp_dp; ser = $back.sig_serial } | ConvertTo-Json -Compress
""".replace("__A__", str(agent)).replace("__D__", str(tmp_path))
    p = subprocess.run([PWSH, "-NoProfile", "-NonInteractive", "-Command", script], capture_output=True, text=True, timeout=60)
    assert p.returncode == 0, p.stderr
    out = json.loads(p.stdout.strip().splitlines()[-1])
    assert out == {"vp": '[{"policy":"Laptops"}]', "vk": "Laptops", "vc": 1795000000, "nbu": '{"nbu:x|y":{}}', "dp": "{}", "ser": 1795000123}, out


@pytest.mark.skipif(not HAVE_ADDON_DEPS, reason="needs the add-on's packages")
def test_f11_import_is_unpacked_from_a_file(tmp_path):
    """An export imported directly and in pieces is staged for the next start; a zip whose files are bigger than
    they claim is refused by what's really unpacked (the restore limit is lowered for the test)."""
    import urllib.request
    import zipfile
    addon = Addon(tmp_path / "addon").start()
    try:
        call(addon.ui + "/api/hosts", {"name": "PC01", "host": "192.168.1.10", "checks": ["ping"]}, UI, "POST")
        with urllib.request.urlopen(urllib.request.Request(addon.ui + "/api/export", headers=UI), timeout=30) as r:
            export = r.read()
        assert zipfile.ZipFile(__import__("io").BytesIO(export)).read("manifest.json")

        def post(url, data):
            req = urllib.request.Request(url, data=data, headers={**UI, "Content-Type": "application/octet-stream"}, method="POST")
            try:
                with urllib.request.urlopen(req, timeout=60) as r:
                    return r.status, json.loads(r.read())
            except urllib.error.HTTPError as e:
                return e.code, json.loads(e.read() or b"{}")
        st, out = post(addon.ui + "/api/import", export)
        assert st == 200 and out["ok"] and "hosts" in out["manifest"], out
        staged = tmp_path / "addon" / "restore_pending"
        assert (staged / "ready").exists() and (staged / "hosts.json").exists()
        # in pieces
        up, off = "abcdef0123456789abcdef0123456789", 0
        for i in range(0, len(export), 4096):
            st, out = post(addon.ui + f"/api/import/chunk?upload={up}&offset={off}", export[i:i + 4096])
            assert st == 200, out
            off = out["size"]
        st, out = post(addon.ui + f"/api/import?upload={up}", b"")
        assert st == 200 and out["ok"], out
        assert not any((tmp_path / "addon").rglob(f"{up}*.zip"))           # the upload is removed afterwards
        st, out = post(addon.ui + "/api/import", b"not a zip")
        assert st == 400 and "not a zip" in out["error"]
    finally:
        addon.stop()


def test_f11_limit_counts_bytes_really_unpacked(tmp_path, monkeypatch):
    import io
    import zipfile
    import main
    monkeypatch.setattr(main, "RESTORE_DIR", tmp_path / "restore")
    monkeypatch.setattr(main, "RESTORE_MAX", 1000)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("manifest.json", json.dumps({"format": main.BACKUP_FORMAT}))
        z.writestr("hosts.json", json.dumps({"hosts": [{"pad": "x" * 5000}]}))
    with pytest.raises(ValueError, match="too large"):
        main.stage_restore(buf.getvalue())
    assert not (tmp_path / "restore").exists()
