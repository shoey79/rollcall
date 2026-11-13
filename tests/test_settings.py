"""Checks the dashboard's Settings dialog matches the Configuration tab.

Run from the repository root:  python3 tests/test_settings.py   (needs PyYAML)
"""
import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "rollcall" / "app"))
import settingslib  # noqa: E402

config = yaml.safe_load((ROOT / "rollcall" / "config.yaml").read_text())
names = yaml.safe_load((ROOT / "rollcall" / "translations" / "en.yaml").read_text())["configuration"]
schema = {k: v for k, v in config["schema"].items() if k != "hosts"}
fields = {f["key"]: f for f in settingslib.fields()}


def test_same_settings():
    assert set(fields) == set(schema), set(fields) ^ set(schema)
    assert set(settingslib.LABELS) == set(fields)


def test_types_and_ranges():
    for key, rule in schema.items():
        f = fields[key]
        if isinstance(rule, list):
            assert f["type"] in ("strs", "ints"), key
            assert (rule[0] == "int") == (f["type"] == "ints"), key
            continue
        rule = rule.rstrip("?")
        if m := re.fullmatch(r"int\((\d+),(\d+)\)", rule):
            assert f["type"] == "int" and (f["min"], f["max"]) == (int(m[1]), int(m[2])), key
        elif m := re.fullmatch(r"list\((.+)\)", rule):
            assert f["type"] == "choice" and f["options"] == m[1].split("|"), key
        elif rule == "bool":
            assert f["type"] == "bool", key
        elif rule == "str":
            assert f["type"] in ("str", "file"), key
        else:
            raise AssertionError(f"{key}: unexpected rule {rule}")


def test_labels_match_configuration_tab():
    for key, (name, desc) in settingslib.LABELS.items():
        assert names[key]["name"] == name, key
        assert names[key]["description"] == desc, key


def test_defaults_are_valid():
    opts = {k: v for k, v in config["options"].items() if k != "hosts"}
    clean, errors = settingslib.clean(opts)
    assert not errors, errors
    assert clean == opts


def test_rejects_bad_values():
    _, errors = settingslib.clean({"interval": 5, "ping_count": "3.5", "log_level": "loud", "persistent_notification": "yes",
                                   "agent_certfile": "../../etc/shadow", "agent_security_alert_ids": [4740, "x"], "nope": 1})
    assert set(errors) == {"interval", "ping_count", "log_level", "persistent_notification", "agent_certfile",
                           "agent_security_alert_ids", "nope"}, errors


def test_tidies_lists():
    clean, errors = settingslib.clean({"notify_services": ["notify.mobile_app_a", "mobile_app_a", " ", "mobile_app_b"],
                                       "agent_security_alert_ids": ["4740", 4740, 1102], "interval": "60"})
    assert not errors
    assert clean == {"notify_services": ["mobile_app_a", "mobile_app_b"], "agent_security_alert_ids": [4740, 1102], "interval": 60}


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
        print("ok", t.__name__)
