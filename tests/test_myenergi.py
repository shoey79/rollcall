"""Several Home Assistant devices on one Rollcall device, and the myenergi view (1.93.0).

A made-up myenergi system as the HACS integration shows it in Home Assistant: a Zappi, the hub and a Harvi, each its
own device (serials invented). The hub is named "Garage" here; entity ids follow the device names, as they do in
Home Assistant, so the profile has to find readings by what they measure.

Run from the repository root:  python3 -m pytest tests/test_myenergi.py
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "rollcall" / "app"))
import hadevice  # noqa: E402

DIAG = "diagnostic"


def device(dev_id, name, model):
    return {"id": dev_id, "name": name, "manufacturer": "myenergi", "model": model}


def ent(eid, state, unit="", category=None, device_class=""):
    return eid, state, unit, category, device_class


ZAPPI = ("zap1", device("zap1", "Zappi", "myenergi Zappi"), [
    ent("sensor.myenergi_zappi_charge_added_session", "10.74", "kWh"),
    ent("sensor.myenergi_zappi_plug_status", "EV Connected"),
    ent("sensor.myenergi_zappi_status", "Paused"),
    ent("sensor.myenergi_zappi_serial_number", "11111111"),
    ent("select.myenergi_zappi_charge_mode", "Eco+"),
    ent("binary_sensor.myenergi_zappi_locked", "on"),
    ent("binary_sensor.myenergi_zappi_update_available", "off"),
    ent("sensor.myenergi_zappi_energy_used_today", "23.32", "kWh", DIAG),
    ent("sensor.myenergi_zappi_green_energy_today", "0.02", "kWh", DIAG),
    ent("sensor.myenergi_zappi_power_ct_internal_load", "7200", "W", DIAG),
    ent("sensor.myenergi_zappi_power_ct_grid", "-1", "W", DIAG),
    ent("sensor.myenergi_zappi_power_ct_generation", "0", "W", DIAG),
])
HUB = ("hub1", device("hub1", "Garage", "myenergi Hub"), [
    ent("sensor.myenergi_garage_generated_today", "9.54", "kWh"),
    ent("sensor.myenergi_garage_grid_import_today", "104.29", "kWh"),
    ent("sensor.myenergi_garage_grid_export_today", "0.22", "kWh"),
    ent("sensor.myenergi_garage_hub_serial_number", "22222222"),
    ent("sensor.myenergi_garage_voltage_grid", "238.9", "V", DIAG),
    ent("sensor.myenergi_garage_frequency_grid", "49.87", "Hz", DIAG),
    ent("sensor.myenergi_garage_home_consumption", "407", "W", DIAG),
    ent("sensor.myenergi_garage_power_grid", "23", "W", DIAG),
    ent("sensor.myenergi_garage_power_generation", "384", "W", DIAG),
])
HARVI = ("harvi1", device("harvi1", "harvi-3333333", "myenergi Harvi"), [
    ent("sensor.myenergi_harvi_3333333_power_ct_generation", "428", "W"),
    ent("sensor.myenergi_harvi_3333333_generation_ct1", "428", "W", DIAG),
    ent("sensor.myenergi_harvi_3333333_none_ct2", "0", "W", DIAG),
])


def build(*devs, changes=None):
    changes = changes or {}
    parts, states = [], {}
    for dev_id, dev, rows in devs:
        regs = []
        for eid, state, unit, cat, dc in rows:
            regs.append({"entity_id": eid, "platform": "myenergi", "entity_category": cat, "device_id": dev_id})
            states[eid] = {"state": changes.get(eid, state), "attributes": {"unit_of_measurement": unit, "device_class": dc,
                                                                          "friendly_name": eid.split(".", 1)[1].replace("_", " ")}}
        parts.append((dev, regs))
    return parts, states


def tiles(d):
    return {t["label"]: (t["value"], t.get("unit", ""), t.get("sub", ""), t["level"]) for t in d["tiles"]}


def test_zappi_hub_and_harvi_together():
    parts, states = build(ZAPPI, HUB, HARVI)
    d = hadevice.read_many(parts, states)
    assert [p["device"]["name"] for p in d["devices"]] == ["Zappi", "Garage", "harvi-3333333"]
    assert d["device"]["integration"] == "myenergi"
    t = tiles(d)
    assert t["Zappi"] == ("Paused", "", "EV Connected", "")
    assert t["Mode"][0] == "Eco+" and t["Charger"][0] == "Locked"
    assert t["Charging now"][0] == "7.20 kW"
    assert t["Added this session"][0] == "10.74 kWh" and t["Charged today"][:3:2] == ("23.32 kWh", "0.02 kWh green")
    assert t["Grid now"] == ("23 W", "", "importing", "")
    assert t["Home using"][0] == "407 W"
    # The hub's total, not the Harvi's clamp added on top (which can also see a home battery)
    assert t["Generation"] == ("384 W", "", "as myenergi measures it", "")
    assert t["Supply"] == ("238.9 V", "", "49.87 Hz", "")
    assert t["Grid today"] == ("104.29 kWh in", "", "0.22 kWh out · 9.54 kWh generated", "")
    assert not [i for i in d["items"] if i["level"] in ("warn", "crit")]
    assert d["summary"] == "myenergi: Zappi paused (EV Connected), Eco+; grid 238.9 V"
    assert len(d["entities"]) == 12 + 9 + 3          # every linked device's entities (controls use them)


def test_a_fault_is_red_an_update_or_odd_supply_amber():
    parts, states = build(ZAPPI, HUB, changes={"sensor.myenergi_zappi_plug_status": "Fault/Restart",
                                               "binary_sensor.myenergi_zappi_update_available": "on",
                                               "sensor.myenergi_garage_voltage_grid": "254.1",
                                               "sensor.myenergi_garage_frequency_grid": "49.4"})
    d = hadevice.read_many(parts, states)
    lv = {(i["what"], i["level"]) for i in d["items"]}
    assert ("Zappi", "crit") in lv and ("Zappi", "warn") in lv and ("Grid supply", "warn") in lv
    assert tiles(d)["Zappi"][3] == "crit" and tiles(d)["Supply"][3] == "warn"
    assert any("254.1 V, outside the UK supply range (216-253 V)" in i["detail"] for i in d["items"])
    assert any("49.4 Hz" in i["detail"] for i in d["items"])


def test_without_the_hub_generation_comes_from_the_clamps_and_renamed_devices_still_work():
    zid, zdev, zrows = ZAPPI
    renamed = [(e.replace("myenergi_zappi", "car_charger"), *rest) for e, *rest in zrows]
    parts, states = build((zid, {**zdev, "name": "Car charger"}, renamed), HARVI)
    d = hadevice.read_many(parts, states)
    t = tiles(d)
    assert t["Zappi"][0] == "Paused" and t["Mode"][0] == "Eco+"
    assert t["Generation"][0] == "428 W"              # Zappi's clamp (0) + the Harvi's (428)
    assert t["Grid now"] == ("1 W", "", "exporting", "")
    assert "Supply" not in t and "Grid today" not in t


def test_myenergis_cloud_is_mentioned_when_home_assistant_loses_touch():
    parts, states = build(ZAPPI, HUB, changes={e[0]: "unavailable" for e in HUB[2]})
    d = hadevice.read_many(parts, states)
    lost = [i for i in d["items"] if i["level"] == "crit"]
    assert len(lost) == 1 and lost[0]["what"] == "Garage" and "myenergi's servers" in lost[0]["detail"]


def test_a_linked_device_gone_from_home_assistant_and_one_device_as_before():
    parts, states = build(ZAPPI)
    d = hadevice.read_many(parts, states, missing=["Garage"])
    assert {"level": "warn", "what": "Garage", "detail": "is no longer in Home Assistant (Edit to link it again)"} in d["items"]
    one = hadevice.read(parts[0][0], parts[0][1], states)        # the old single-device call still works
    assert one["device"]["name"] == "Zappi" and len(one["devices"]) == 1


def test_the_form_keeps_extra_devices_and_drops_bad_ones():
    import pytest
    import main
    e = main.validate_entry({"name": "Car charger", "host": "192.168.1.70", "ha_device": "zap1", "ha_device_name": "Zappi",
                            "ha_more": [{"id": "hub1", "name": "Garage"}, {"id": "zap1"}, {"id": "harvi1", "name": "harvi"}]})
    assert e["ha_more"] == [{"id": "hub1", "name": "Garage"}, {"id": "harvi1", "name": "harvi"}]   # no repeats of the main one
    assert main.validate_entry({"name": "x", "host": "192.168.1.71", "ha_device": "", "ha_more": [{"id": "hub1"}]})["ha_more"] == []
    with pytest.raises(ValueError):
        main.validate_entry({"name": "x", "host": "192.168.1.72", "ha_device": "zap1", "ha_more": [{"id": "bad id!"}]})
