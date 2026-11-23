"""Fire TV / Android TV over network ADB (firetv.py), against a stand-in stick (adb_fake.py): Rollcall's own key, the
TV's "Allow USB debugging?" once, then read-only commands only. Everything here is made up."""
import asyncio
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "rollcall" / "app"))
pytest.importorskip("cryptography")
import adb_fake as fk  # noqa: E402
import firetv as ft  # noqa: E402


def read(stick, key, **kw):
    return asyncio.run(ft.read("127.0.0.1", stick.port, key, **kw))


def test_first_time_the_tv_asks_then_remembers(tmp_path):
    stick, key = fk.FakeStick(), ft.Key(tmp_path / "adbkey")
    d = read(stick, key)
    assert stick.prompts == 1                              # the TV asked once
    assert d["model"] == "AFTMM" and d["fire_os"] == "6.7.1.1" and d["android"] == "7.1.2"   # not the generation "6.0"
    assert d["cpu_pct"] == 12.9 and d["cores"] == 4
    assert d["mem_free_mb"] == 451 and d["storage_free_mb"] == 2211
    assert d["wifi"] == {"rssi_dbm": -64, "link_mbps": 650, "freq_mhz": 5240, "band": "5 GHz"}
    assert d["temps"] == [] and d["temp_note"] == "not readable over ADB on this model"
    assert d["screen"] == "on" and d["app_in_front"] == "com.example.tvplayer"
    assert [(a["package"], a["from"], a["version"]) for a in d["apps"]] == [
        ("com.example.news", "Appstore", "10.0"), ("com.example.tvplayer", "Appstore", "4.2.1"), ("local.example.launcher", "sideloaded", "1.3")]
    assert d["sideloaded_running"] == {"local.example.launcher": {"running": True, "services": 1}}
    assert d["disabled"] == 27 and d["boot_count"] == 1543 and d["uptime_s"] == 3418
    assert "ssid" not in repr(d).lower() or "TestNet" not in repr(d)       # the Wi-Fi name isn't kept
    read(stick, key)
    assert stick.prompts == 1                              # allowed: not asked again
    assert (tmp_path / "adbkey").stat().st_mode & 0o077 == 0


def test_waiting_for_allow_on_the_tv(tmp_path):
    stick = fk.FakeStick(allow=False)
    with pytest.raises(ft.FireTVError) as e:
        asyncio.run(ft.read("127.0.0.1", stick.port, ft.Key(tmp_path / "k"), timeout=3, auth_wait=2))
    assert e.value.level == "warn" and "Allow" in str(e.value)


def test_nothing_listening():
    with pytest.raises(ft.FireTVError) as e:
        asyncio.run(ft.read("127.0.0.1", 9, ft.Key(Path("/nonexistent/k")), timeout=2))
    assert "network debugging" in str(e.value) and e.value.level is None


def test_only_reading_commands():
    """Every command is one of a fixed few that only read; nothing that types, installs or changes settings."""
    text = ft.script()
    for bad in ("input ", "am ", "pm install", "pm uninstall", "pm disable", "pm enable", "settings put", "reboot", "rm ",
                "svc ", "setprop", ">", "monkey"):
        assert bad not in text.replace("2>&1", "").replace("2>/dev/null", ""), bad


def test_what_it_means():
    base = ft.parse(fk.outputs())
    base["sideloaded_running"] = {"local.example.launcher": {"running": True, "services": 1}}
    ok, _, detail, level, mem = ft.evaluate(base)
    assert ok and "Fire OS 6.7.1.1" in detail and "CPU 13%" in detail
    # CPU busy only counts when it stays busy: one busy check (a video) isn't a problem
    busy = {**ft.parse(fk.outputs(cpu_busy=True)), "sideloaded_running": base["sideloaded_running"]}
    assert busy["cpu_pct"] >= 90
    ok, _, _, _, mem1 = ft.evaluate(busy, mem)
    assert ok
    ok, _, _, _, mem2 = ft.evaluate(busy, mem1)
    ok, _, detail, level, mem3 = ft.evaluate(busy, mem2)
    assert not ok and level == "warn" and "CPU busy" in detail
    # A Fire OS update turned debloated apps back on; the launcher's helper stopped; storage low
    worse = {**ft.parse(fk.outputs(disabled=20, free_kb=300 * 1024)), "sideloaded_running": {"local.example.launcher": {"running": False, "services": 0}}}
    ok, _, detail, level, _ = ft.evaluate(worse, mem)
    assert not ok and level == "warn"
    assert "7 disabled app(s) back on" in detail and "local.example.launcher stopped running" in detail and "storage low" in detail


def test_end_to_end(tmp_path, monkeypatch):
    """The real add-on: the Fire TV preset's check, the tab's data, readings as chips, the key's fingerprint."""
    import json
    import time
    from test_update_signing_e2e import HAVE_ADDON_DEPS, UI, Addon, call
    if not HAVE_ADDON_DEPS:
        pytest.skip("needs the add-on's packages")
    stick, shy = fk.FakeStick(), fk.FakeStick(allow=False)
    monkeypatch.setenv("PM_FIRETV_AUTH_WAIT", "3")
    addon = Addon(tmp_path / "addon").start()
    try:
        def host(name):
            return next(h for h in addon.api("/api/status")["hosts"] if h["name"] == name)

        def check(name, want):
            for _ in range(6):
                before = host(name).get("last_check") or 0
                addon.api(f"/api/check/{host(name)['key']}", {}, "POST")
                for _ in range(120):
                    h = host(name)
                    if (h.get("last_check") or 0) > before:
                        break
                    time.sleep(0.25)
                s = next(x for x in h["services"] if x["kind"] == "firetv")
                if s["status"] == want:
                    return h, s
            raise AssertionError((want, s))

        for name, st in (("Lounge TV", stick), ("Bedroom TV", shy)):
            code, body = call(addon.ui + "/api/hosts", {"name": name, "host": "127.0.0.1", "checks": [f"firetv:{st.port}"]}, UI, "POST")
            assert code == 201, body[:300]
        h, s = check("Lounge TV", "green")
        assert "Fire OS 6.7.1.1" in s["detail"] and stick.prompts == 1
        f = h["firetv"]
        assert f["storage_free_mb"] == 2211 and f["apps"][2]["from"] == "sideloaded"
        status = addon.api("/api/status")
        assert len(status["firetv_key"].split(":")) == 16
        assert (tmp_path / "addon" / "firetv" / "adbkey").exists()
        # Readings as chips
        rd = {r["id"]: r for r in addon.api(f"/api/hosts/{h['key']}/readings/available")["readings"] if r["source"] == "firetv"}
        assert rd["storage_free"]["value"] == 2211 and rd["disabled_apps"]["value"] == 27 and rd["wifi_signal"]["value"] == -64
        addon.api(f"/api/hosts/{h['key']}", {"name": "Lounge TV", "host": "127.0.0.1",
                  "checks": [f"firetv:{stick.port}", "Storage=reading:firetv.storage_free<5000"]}, "PUT")
        for _ in range(3):
            h, _ = check("Lounge TV", "green")
            chip = next(x for x in h["services"] if x["kind"] == "reading")
            if chip["status"] == "red":
                break
        assert chip["status"] == "red" and "below 5000" in chip["detail"], chip
        # Not allowed on the TV yet: amber, saying what to do
        h, s = check("Bedroom TV", "amber")
        assert "Allow" in s["detail"] and h.get("firetv") is None
        assert not any("input " in c or "install" in c for c in stick.commands)
    finally:
        addon.stop()
