"""Readings as chips: an integration's readings as their own checks, with conditions that alert. Starlink end to end
(a dish knocked out of alignment), and every source's catalogue from its data.

Run from the repository root:  python3 -m pytest tests/test_readings.py
"""
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "rollcall" / "app"))
sys.path.insert(0, str(ROOT / "tests"))
import readings  # noqa: E402

STARLINK = {"latency_ms": 32.5, "drop_rate": 0.012, "down_bps": 48_200_000, "up_bps": 5_100_000, "obstructed_fraction": 0.0021,
            "uptime_s": 7200, "eth_mbps": 1000, "snr_ok": True, "snr_low": False, "update_ready": False,
            "alignment": {"tilt": 24.0, "az": 320.0, "el": 65.0, "want_az": 300.0, "want_el": 66.0}}


def ids(src, d, extra=None):
    return {r["id"]: r["value"] for r in readings.catalog(src, d, extra)}


def test_starlink_catalogue():
    v = ids("starlink", STARLINK, {"map": {"summary": {"blocked_pct": 2.9}}})
    assert v["latency"] == 32.5 and v["drops"] == 1.2 and v["download"] == 48.2 and v["upload"] == 5.1
    assert v["obstructed"] == 0.21 and v["sky_blocked"] == 2.9 and v["uptime"] == 2.0 and v["ethernet"] == 1000
    assert v["rotation_off"] == 20.0 and v["elevation_off"] == 1.0 and v["signal"] == "ok" and v["update"] == "none"
    across = {**STARLINK, "alignment": {**STARLINK["alignment"], "az": 10.0, "want_az": 350.0}}
    assert ids("starlink", across)["rotation_off"] == 20.0          # across north
    assert ids("starlink", {**STARLINK, "alignment": None})["rotation_off"] is None


def test_other_catalogues():
    assert ids("jellyfin", {"streams": 2, "transcodes": 1, "users": 2, "failed_tasks": [{"name": "Scan"}], "update": True}) == \
        {"streams": 2, "transcodes": 1, "users": 2, "failed_tasks": 1, "update": "available"}
    assert ids("plex", {"streams": 0, "transcodes": 0, "users": 0, "update": ""})["update"] == "none"
    ilo = ids("ilo", {"power_summary": {"reading": "142 Watts"}, "temps": [{"label": "01-Inlet Ambient", "reading": 21}],
                      "fans": [{"label": "Fan 1", "speed": "23", "unit": "Percentage"}]})
    assert ilo == {"power": 142.0, "temp_01_inlet_ambient": 21, "fan_fan_1": 23.0}
    ups = ids("ups", {"ups": {"charge_pct": 100, "runtime_min": 42, "load_pct": 31, "battery_temp_c": 28, "input_v": 238, "on_battery": False}})
    assert ups == {"charge": 100, "runtime": 42, "load": 31, "battery_temp": 28, "input_v": 238, "on_battery": "no"}
    assert readings.catalog("ups", {"interfaces": []}) == [] and readings.catalog("starlink", None) == []


@pytest.mark.parametrize("op, value, ok, text", [
    (None, None, True, "20°"), (">", "15", False, "20° (above 15)"), ("<", "15", True, "20°"),
    (">=", "20", False, "20° (at or above 20)"), ("=", "20", False, "20° (is 20)")])
def test_conditions(op, value, ok, text):
    assert readings.judge({"value": 20.0, "unit": "°"}, op, value) == (ok, text)


def test_words_and_missing_readings():
    assert readings.judge({"value": "weak", "unit": ""}, "=", "weak") == (False, "weak (is weak)")
    assert readings.judge({"value": "ok", "unit": ""}, "=", "weak") == (True, "ok")
    assert readings.judge({"value": "ok", "unit": "ms"}, ">", "5") == (False, "ok ms (not a number)")
    assert readings.judge(None, ">", "5") == (True, "not read yet")                    # the source's own check says why
    assert readings.judge({"value": None, "unit": "ms"}, ">", "5") == (True, "no reading")


def test_available_only_from_the_devices_own_integrations():
    h = SimpleNamespace(services=[SimpleNamespace(kind="starlink")], sl_data=STARLINK, sl_map=None, jf_data={"streams": 1},
                        px_data=None, ilo_data=None, snmp_data={"ups": {"charge_pct": 90}})
    srcs = {r["source"] for r in readings.available(h)}
    assert srcs == {"starlink"}                                        # no Jellyfin or SNMP check on this one
    assert readings.lookup(h, "starlink", "latency")["value"] == 32.5 and readings.lookup(h, "starlink", "nope") is None


def test_check_entries():
    main = pytest.importorskip("main")
    d = main.parse_check("Rotation=reading:starlink.rotation_off>15")[0]
    assert d["kind"] == "reading" and d["entity"] == "starlink.rotation_off" and d["op"] == ">" and d["value"] == "15"
    assert d["label"] == "Rotation" and d["desc"] == "Starlink rotation off > 15"
    assert main.parse_check("reading:ups.charge")[0]["label"] == "Charge"
    with pytest.raises(ValueError, match="needs a number"):
        main.parse_check("reading:starlink.latency>fast")
    with pytest.raises(ValueError, match="unknown source"):
        main.parse_check("reading:nas.disks>1")


# ---- end to end: a Starlink dish knocked out of alignment ----------------------------------------------------------
from test_update_signing_e2e import HAVE_ADDON_DEPS, UI, Addon, call  # noqa: E402

grpc = pytest.importorskip("grpc") if HAVE_ADDON_DEPS else None


@pytest.mark.skipif(not HAVE_ADDON_DEPS, reason="needs the add-on's packages")
def test_end_to_end_starlink_alignment_alarm(tmp_path):
    import starlink_fake as fk
    dish = fk.FakeDish()
    addon = Addon(tmp_path / "addon").start()
    try:
        st, body = call(addon.ui + "/api/hosts", {"name": "Dish", "host": "127.0.0.1", "starlink_source": "local", "starlink_addr": dish.addr,
                        "checks": ["starlink", "Rotation=reading:starlink.rotation_off>15", "Latency=reading:starlink.latency>80"]}, UI, "POST")
        assert st == 201, body[:300]

        def svc(name, want, tries=10):
            for _ in range(tries):
                h = next(x for x in addon.api("/api/status")["hosts"] if x["name"] == "Dish")
                before = h.get("last_check") or 0
                addon.api(f"/api/check/{h['key']}", {}, "POST")
                for _ in range(40):
                    h = next(x for x in addon.api("/api/status")["hosts"] if x["name"] == "Dish")
                    if (h.get("last_check") or 0) > before:
                        break
                    time.sleep(0.25)
                s = next(x for x in h["services"] if x["label"] == name)
                if s["status"] == want:
                    return h, s
            raise AssertionError((name, want, s))

        _h, s = svc("Rotation", "green")
        assert s["detail"] == "5.4°" and s["kind"] == "reading"      # 291.6 against 297: fine
        _h, s = svc("Latency", "green")
        assert s["detail"].endswith(" ms")
        # The picker offers everything the dish reads, with values
        avail = addon.api(f"/api/hosts/{_h['key']}/readings/available")["readings"]
        assert {"latency", "rotation_off", "elevation_off", "download"} <= {r["id"] for r in avail}
        # Knocked: 50° off where it wants to face
        dish.status = {**fk.healthy(), "alignment_stats": {**fk.healthy()["alignment_stats"], "boresight_azimuth_deg": 247.0}}
        _h, s = svc("Rotation", "red")
        assert s["detail"] == "50° (above 15)"
        log = (tmp_path / "addon" / "addon.log").read_text()
        assert "Dish Rotation (Starlink rotation off > 15): amber -> red [50° (above 15)]" in log   # confirmed, then alerts
        # Put right: green again
        dish.status = fk.healthy()
        svc("Rotation", "green")
    finally:
        addon.stop()
