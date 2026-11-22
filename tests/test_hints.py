"""Hints for errors: the built-in table, and hints from Claude (off by default; names and addresses replaced before
anything is sent; cached; a daily limit; security checks never sent). Issue 16.

Run from the repository root:  python3 -m pytest tests/test_hints.py
"""
import asyncio
import json
import socket
import sys
import threading
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "rollcall" / "app"))
sys.path.insert(0, str(ROOT / "tests"))
import hints  # noqa: E402

aiohttp = pytest.importorskip("aiohttp")
from aiohttp import web  # noqa: E402

KEY = "sk-ant-test-made-up-key"


# ---- a stand-in for Anthropic's Messages API --------------------------------------------------------------------
class FakeAnthropic:
    def __init__(self):
        self.asked, self.status = [], 200
        self.loop = asyncio.new_event_loop()
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        self.port = s.getsockname()[1]
        s.close()
        app = web.Application()
        app.router.add_post("/v1/messages", self.messages)
        app.router.add_post("/v1/chat/completions", self.openai)
        app.router.add_post("/v1beta/models/{model}:generateContent", self.gemini)
        self.runner = web.AppRunner(app)
        ready = threading.Event()

        def run():
            asyncio.set_event_loop(self.loop)
            self.loop.run_until_complete(self.runner.setup())
            self.loop.run_until_complete(web.TCPSite(self.runner, "127.0.0.1", self.port).start())
            ready.set()
            self.loop.run_forever()
        threading.Thread(target=run, daemon=True).start()
        ready.wait(5)

    @property
    def base(self):
        return f"http://127.0.0.1:{self.port}"

    async def messages(self, req):
        body = await req.json()
        self.asked.append({"headers": dict(req.headers), "body": body})
        if req.headers.get("x-api-key") != KEY:
            return web.json_response({"type": "error", "error": {"type": "authentication_error", "message": "invalid x-api-key"}}, status=401)
        if self.status != 200:
            return web.json_response({"type": "error", "error": {"type": "overloaded_error", "message": "Overloaded"}}, status=self.status)
        return web.json_response({"id": "msg_1", "type": "message", "role": "assistant", "model": body["model"],
                                  "content": [{"type": "text", "text": "The device can't reach a domain controller. Check its DNS."}],
                                  "stop_reason": "end_turn", "usage": {"input_tokens": 120, "output_tokens": 30}})


    async def openai(self, req):
        body = await req.json()
        self.asked.append({"provider": "openai", "headers": dict(req.headers), "body": body})
        if req.headers.get("Authorization") != f"Bearer {OKEY}":
            return web.json_response({"error": {"message": "Incorrect API key provided", "type": "invalid_request_error"}}, status=401)
        return web.json_response({"id": "chatcmpl-1", "object": "chat.completion", "model": body["model"] + "-2026",
                                  "choices": [{"index": 0, "message": {"role": "assistant", "content": "ChatGPT says: check DNS."},
                                               "finish_reason": "stop"}]})

    async def gemini(self, req):
        body = await req.json()
        self.asked.append({"provider": "gemini", "path": req.path, "query": req.query_string, "headers": dict(req.headers), "body": body})
        if req.headers.get("x-goog-api-key") != GKEY:
            return web.json_response({"error": {"code": 400, "message": "API key not valid. Please pass a valid API key.",
                                                "status": "INVALID_ARGUMENT"}}, status=400)
        return web.json_response({"candidates": [{"content": {"role": "model", "parts": [
            {"text": "thinking...", "thought": True}, {"text": "Gemini says: check DNS."}]}, "finishReason": "STOP"}],
            "modelVersion": req.match_info["model"]})


OKEY, GKEY = "sk-openai-made-up", "AIza-made-up"


@pytest.fixture
def api(monkeypatch):
    f = FakeAnthropic()
    monkeypatch.setattr(hints, "TEST_BASE", f.base)
    return f


# ---- the built-in table -------------------------------------------------------------------------------------------
@pytest.mark.parametrize("check,text,words", [
    ("laps", "Last LAPS run failed: Failed to find a domain controller (0x8007054B)", "couldn't find or reach a domain controller"),
    ("tasks", "Nightly copy: last run failed (access denied)", "Access denied"),
    ("gpo", "Failing: couldn't read a policy from SYSVOL (gpt.ini); not applied for 5 h", "gpt.ini from SYSVOL"),
    ("time", "6 min 10 s ahead of DC01; Kerberos sign-ins fail at 5 minutes", "w32tm"),
    ("laps", "No LAPS password in Active Directory yet (not backed up, or the device can't write it)", "Set-LapsADComputerSelfPermission"),
    ("updates", "Windows Update failed: 0x80244022", "WsusPool"),
    ("sysvol", "Stopped replicating: offline too long (4012)", "MaxOfflineTimeInDays"),
])
def test_well_known_errors(check, text, words):
    h = hints.known(check, text)
    assert h and words in h[0]["means"] + h[0]["try"], h


def test_codes_match_whole_and_checks_are_respected():
    assert hints.known("x", "error 0x8007054B")[0]["code"] == "0x8007054B"
    assert hints.known("x", "error 0x8007054B2") == []          # not part of a longer code
    assert hints.known("backups", "Kerberos sign-ins fail at 5 minutes") == []  # a time hint, not for backups
    assert hints.known("x", "") == [] and hints.known("x", "All fine") == []


# ---- replacing names and addresses ----------------------------------------------------------------------------------
def test_names_and_addresses_are_replaced():
    r = hints.Redactor(names=["PC-ACCT07", "fileserver"], domains=["CONTOSOX", "contosox.local"], users=["jbloggs"])
    text = (r"Couldn't copy to \\fileserver\backup as CONTOSOX\svc_bk (S-1-5-21-111-222-333-1104) from 10.20.30.40 "
            r"and fe80::1:2:3 (MAC 00-1A-2B-3C-4D-5E); dc1.contosox.local; mail jbloggs@contosox.local; pc-acct07 said "
            r"C:\Users\jbloggs\run.ps1 failed; jbloggs signed in; at C:\Windows\System32\GroupPolicy\Machine\registry.pol "
            r"as NT AUTHORITY\SYSTEM; System.Net.WebException; build 10.0.19045.1; 0x8007054B; see www.microsoft.com")
    out = r(text)
    for real in ("fileserver", "CONTOSOX", "contosox", "svc_bk", "111-222-333", "10.20.30.40", "fe80::1:2:3", "00-1A-2B",
                 "dc1.", "jbloggs", "PC-ACCT07", "pc-acct07"):
        assert real.lower() not in out.lower(), (real, out)
    for kept in (r"C:\Windows\System32\GroupPolicy\Machine\registry.pol", r"NT AUTHORITY\SYSTEM", "System.Net.WebException",
                 "10.0.19045.1", "0x8007054B", "www.microsoft.com", "run.ps1", "CONTOSO\\user1", "PC01"):
        assert kept in out, (kept, out)


# ---- asking Claude ---------------------------------------------------------------------------------------------------
def ask(c, sent="Check: LAPS\nError: x", key=KEY, limit=5, day="2026-11-21", now=None):
    async def go():
        async with aiohttp.ClientSession() as s:
            return await c.ask(s, key, "claude-haiku-5-5", "LAPS", sent, day, limit, now or time.time())
    return asyncio.run(go())


def test_asks_once_per_error_and_keeps_the_answer(tmp_path, api):
    c = hints.ClaudeHints(tmp_path / "claude_hints.json")
    a = ask(c)
    assert a["text"].startswith("The device") and a["cached"] is False
    sent = api.asked[0]
    assert sent["headers"]["x-api-key"] == KEY and sent["headers"]["anthropic-version"] == "2023-06-01"
    assert sent["body"]["model"] == "claude-haiku-5-5" and sent["body"]["messages"] == [{"role": "user", "content": "Check: LAPS\nError: x"}]
    assert ask(c)["cached"] is True and len(api.asked) == 1                 # the same error again: not asked twice
    saved = (tmp_path / "claude_hints.json").read_text()
    assert KEY not in saved and "The device" in saved                        # the answer is kept, the key never is
    assert hints.ClaudeHints(tmp_path / "claude_hints.json").cached(c.key("LAPS", "Check: LAPS\nError: x"), time.time())
    assert c.key("LAPS", "Error: x\nLast agent report: 5 minutes ago") == c.key("LAPS", "Error: x\nLast agent report: 9 minutes ago")


def test_daily_limit(tmp_path, api):
    c = hints.ClaudeHints(tmp_path / "claude_hints.json")
    for i in range(2):
        ask(c, f"error {i}", limit=2)
    with pytest.raises(ValueError, match="limit of 2"):
        ask(c, "error 3", limit=2)
    assert len(api.asked) == 2
    assert ask(c, "error 3", limit=2, day="2026-11-22")["text"]           # a new day


def test_refused_key_and_errors_are_explained(tmp_path, api):
    c = hints.ClaudeHints(tmp_path / "claude_hints.json")
    with pytest.raises(ValueError, match="key was refused"):
        ask(c, key="sk-ant-wrong")
    api.status = 529
    with pytest.raises(ValueError, match="Overloaded"):
        ask(c, "another")
    with pytest.raises(ValueError, match="No Anthropic API key"):
        ask(c, "more", key="")


def test_each_key_only_goes_to_its_own_provider():
    import os
    assert hints.PROVIDERS["anthropic"]["url"] == "https://api.anthropic.com/v1/messages"
    assert hints.PROVIDERS["openai"]["url"] == "https://api.openai.com/v1/chat/completions"
    assert hints.PROVIDERS["gemini"]["url"].startswith("https://generativelanguage.googleapis.com/v1beta/models/")
    assert not os.environ.get("PM_AI_TEST_BASE")


@pytest.mark.parametrize("provider, key, model, says", [
    ("openai", OKEY, "gpt-5.4-mini", "ChatGPT says"), ("gemini", GKEY, "gemini-3.5-flash-lite", "Gemini says")])
def test_other_providers(tmp_path, api, provider, key, model, says):
    c = hints.ClaudeHints(tmp_path / "claude_hints.json")

    async def go(k):
        async with aiohttp.ClientSession() as s:
            return await c.ask(s, k, model, "LAPS", "Check: LAPS\nError: x", "2026-11-22", 5, time.time(), provider)
    a = asyncio.run(go(key))
    assert a["text"].startswith(says) and a["provider"] == hints.PROVIDERS[provider]["name"] and a["cached"] is False
    sent = api.asked[-1]
    if provider == "openai":
        assert sent["body"]["messages"][0]["role"] == "system" and sent["body"]["messages"][1] == {"role": "user", "content": "Check: LAPS\nError: x"}
        assert sent["body"]["model"] == model and "x-api-key" not in {h.lower() for h in sent["headers"]}
    else:
        assert sent["path"] == f"/v1beta/models/{model}:generateContent" and key not in sent["query"]   # the key isn't in the address
        assert sent["body"]["contents"][0]["parts"][0]["text"] == "Check: LAPS\nError: x" and "systemInstruction" in sent["body"]
        assert "thinking" not in a["text"]                                  # Gemini's thoughts left out
    assert asyncio.run(go(key))["cached"] is True
    c2 = hints.ClaudeHints(tmp_path / "other.json")

    async def bad():
        async with aiohttp.ClientSession() as s:
            return await c2.ask(s, "wrong", model, "LAPS", "other", "2026-11-22", 5, time.time(), provider)
    with pytest.raises(ValueError, match="key was refused"):
        asyncio.run(bad())
    assert key not in (tmp_path / "claude_hints.json").read_text()


def test_switching_provider_asks_again(tmp_path):
    c = hints.ClaudeHints(tmp_path / "claude_hints.json")
    assert c.key("LAPS", "x", "anthropic") != c.key("LAPS", "x", "openai")


# ---- what Rollcall sends, from a real check ----------------------------------------------------------------------
@pytest.fixture
def mon(tmp_path, monkeypatch):
    main = pytest.importorskip("main")
    from test_upstream import FakeHA
    for name, fn in (("HOSTS_PATH", "hosts.json"), ("IMPORT_MARK", "imported.json"), ("MAINT_PATH", "maint.json"),
                     ("AGENT_SETTINGS", "agent_settings.json"), ("DISCOVERY_PATH", "discovery.json"),
                     ("DB_HEALTH_PATH", "db_health.json"), ("CLAUDE_HINTS_PATH", "claude_hints.json")):
        monkeypatch.setattr(main, name, tmp_path / fn)
    monkeypatch.setattr(main, "VULN_DIR", tmp_path / "vulns")
    (tmp_path / "hosts.json").write_text(json.dumps([
        {"id": "lap", "name": "LAPTOP-ACCT07", "host": "10.0.1.57", "checks": []},
        {"id": "fs", "name": "FILESRV02", "host": "fs02.contosox.local", "checks": []}]))
    m = main.Monitor(dict(main.DEFAULTS), main.Store(tmp_path / "db.sqlite"), FakeHA())
    h = m.hosts["lap"]
    h.agent_report = {"hostname": "LAPTOP-ACCT07", "fqdn": "laptop-acct07.contosox.local", "os": "Microsoft Windows 11 Pro",
                      "roles": [], "sessions": [{"user": "CONTOSOX\\jbloggs", "state": "active", "session": "console"}]}
    h.agent_seen = time.time() - 300
    mk = lambda key, label, status, detail: main.Service(key=key, label=label, kind="agent", port=None, url=None, desc="",  # noqa: E731
                                                         status=status, detail=detail)
    h.agent_checks = [
        mk("agent_laps", "LAPS", main.AMBER, "Last LAPS run failed: couldn't write to laptop-acct07.contosox.local from 10.0.1.57 "
                                             "via FILESRV02 as CONTOSOX\\jbloggs (0x80070005)"),
        mk("agent_security", "Security", main.RED, "3 failed sign-ins for CONTOSOX\\admin"),
        mk("agent_disk", "Disk", main.GREEN, "All fine")]
    return main, m, h


def test_what_is_sent_has_no_names(mon):
    main, m, h = mon
    check, sent = m.claude_question(h, "agent_laps")
    for real in ("LAPTOP-ACCT07", "laptop-acct07", "contosox", "CONTOSOX", "10.0.1.57", "FILESRV02", "jbloggs"):
        assert real.lower() not in sent.lower(), (real, sent)
    assert "0x80070005" in sent and "Windows 11 Pro (workstation)" in sent and "State: amber" in sent
    assert "Last agent report: 5 minutes ago" in sent
    with pytest.raises(ValueError, match="never sent"):
        m.claude_question(h, "agent_security")
    with pytest.raises(ValueError, match="amber and red"):
        m.claude_question(h, "agent_disk")


def test_hints_show_on_the_dashboard(mon):
    main, m, h = mon
    snap = m.snapshot()
    assert snap["claude_hints"] is False                                     # off by default
    svc = {s["key"]: s for s in next(x for x in snap["hosts"] if x["key"] == "lap")["services"]}
    assert "Access denied" in svc["agent_laps"]["hint"][0]["means"] and "hint" not in svc["agent_disk"]
    m.opts.update(claude_hints=True, claude_api_key=KEY)
    assert m.snapshot()["claude_hints"] is True


# ---- end to end through the add-on --------------------------------------------------------------------------------
from test_update_signing_e2e import HAVE_ADDON_DEPS, UI, Addon, call  # noqa: E402


@pytest.mark.skipif(not HAVE_ADDON_DEPS, reason="needs the add-on's packages")
def test_end_to_end(tmp_path, monkeypatch, api):
    monkeypatch.setenv("PM_AI_TEST_BASE", api.base)
    addon = Addon(tmp_path / "addon")
    addon.start()
    try:
        st, body = call(addon.ui + "/api/hosts", {"name": "PC-HINT01", "host": "127.0.0.1", "checks": ["Web=tcp:127.0.0.1:9"]}, UI, "POST")
        assert st == 201, body[:300]
        for _ in range(60):
            hh = next(x for x in addon.api("/api/status")["hosts"] if x["name"] == "PC-HINT01")
            svc = next((s for s in hh["services"] if s["kind"] == "tcp"), None)
            if svc and svc["status"] == "red":
                break
            addon.api(f"/api/check/{hh['key']}", {}, "POST")
            time.sleep(0.5)
        assert svc["status"] == "red", svc
        ask_ = {"host": hh["key"], "check": svc["key"]}
        # Off by default: what would be sent can be seen, but nothing is asked
        prev = addon.api("/api/hints/ask", {**ask_, "preview": True}, "POST")
        assert "127.0.0.1" not in prev["sent"] and "PC-HINT01" not in prev["sent"] and "Error:" in prev["sent"]
        st, body = call(addon.ui + "/api/hints/ask", ask_, UI, "POST")
        assert st == 409 and b"off" in body and not api.asked
        # An admin turns it on with a key
        addon.api("/api/settings", {"values": {"claude_hints": True, "claude_api_key": KEY, "claude_hints_per_day": 3}}, "POST")
        settings = json.dumps(addon.api("/api/settings"))
        assert KEY not in settings                                           # never shown again
        out = addon.api("/api/hints/ask", ask_, "POST")
        assert out["text"].startswith("The device") and out["cached"] is False and out["left"] == 2
        assert api.asked[-1]["body"]["messages"][0]["content"] == out["sent"] and "127.0.0.1" not in out["sent"]
        again = addon.api("/api/hints/ask", ask_, "POST")
        assert again["cached"] is True and len(api.asked) == 1
        assert KEY not in json.dumps(addon.api("/api/status")) and KEY not in (tmp_path / "addon" / "addon.log").read_text()
        assert "asked Claude about" in (tmp_path / "addon" / "addon.log").read_text()
        # Test the saved key and model (admins only), then switch to Gemini with its own key: asked again, by Gemini
        assert addon.api("/api/hints/test", {}, "POST")["ok"] is True
        addon.api("/api/settings", {"values": {"ai_provider": "gemini", "gemini_api_key": GKEY}}, "POST")
        assert addon.api("/api/status")["ai_name"] == "Gemini"
        g = addon.api("/api/hints/ask", ask_, "POST")
        assert g["provider"] == "Gemini" and g["cached"] is False and api.asked[-1]["provider"] == "gemini"
        assert GKEY not in json.dumps(addon.api("/api/settings")) and GKEY not in (tmp_path / "addon" / "addon.log").read_text()
        addon.api("/api/settings", {"values": {"gemini_api_key": "wrong"}}, "POST")
        st, body = call(addon.ui + "/api/hints/test", {}, UI, "POST")
        assert st == 502 and b"key was refused" in body
    finally:
        addon.stop()


def test_veeam_cbt_warning_is_explained():
    text = ("Cannot use CBT: There is no change tracking data available associated with the specified change tracking "
            "identifier. Failed to query changes for disk 'D:\\VMs\\VM01\\disk0.vhd'.")
    h = hints.known("backups", text)
    assert h and "changed block tracking" in h[0]["means"] and "backup is fine" in h[0]["means"]


def test_veeam_reasons_get_their_hint_in_details(mon):
    main, m, h = mon
    h.agent_report = {**h.agent_report, "checks": {"backups": {"jobs": [
        {"source": "Veeam", "id": "j1", "name": "Daily VMs", "result": "Warning", "issue": {"session": "s", "source": "Veeam PowerShell",
         "objects": [{"name": "VM01", "status": "Warning", "reason": "", "details": ["Cannot use CBT: no change tracking data available"]},
                     {"name": "VM02", "status": "Success", "reason": "", "details": []}], "log": []}}]}}}
    import types
    m.agents = m.agents or types.SimpleNamespace(agents={})
    m.secret_scan_config = lambda _a: {"on": False}
    r = m.details(h, include_security=False)["report"]
    objs = r["checks"]["backups"]["jobs"][0]["issue"]["objects"]
    assert "_hint" in objs[0] and "_hint" not in objs[1]


def test_a_reading_says_what_it_is(mon):
    """A bare "1.5% (above 1)" means nothing on its own: the question says what was measured, the limit and the
    related check."""
    main, m, h = mon
    h.services = [main.Service(key="starlink", label="Starlink", kind="starlink", port=None, url=None, desc="Starlink",
                               status=main.AMBER, detail="Starlink online, 31 ms, obstructed 1.5% of the time"),
                  main.Service(key="obstructed", label="Obstructed", kind="reading", port=None, url=None, desc="Starlink obstructed > 1",
                               entity="starlink.obstructed", op=">", value="1", status=main.RED, detail="1.5% (above 1)")]
    h.sl_data = {"obstructed_fraction": 0.015, "latency_ms": 31}
    _check, sent = m.claude_question(h, "obstructed")
    assert "What it checks: a reading from a Starlink satellite dish: Obstructed (share of the time something" in sent
    assert "Problem when: the value is above 1 (a limit set in Rollcall)" in sent
    assert "Related check: Starlink: Starlink online, 31 ms, obstructed 1.5% of the time" in sent
    assert "Error: 1.5% (above 1)" in sent


def test_other_checks_say_what_they_look_at(mon):
    main, m, h = mon
    h.services = [main.Service(key="web", label="Web", kind="tcp", port=8443, url=None, desc="tcp/8443", status=main.RED,
                               detail="connection refused")]
    assert "What it checks: whether a TCP port answers (tcp/8443)" in m.claude_question(h, "web")[1]
    assert "What it checks: a check run by Rollcall's agent on the computer" in m.claude_question(h, "agent_laps")[1]
