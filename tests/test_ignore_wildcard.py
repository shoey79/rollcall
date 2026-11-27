"""Ignore entries with * (a service that has its version in its name comes back renamed after each update)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "rollcall" / "app"))

import agents  # noqa: E402


def test_wildcard_service_ignore_covers_every_version():
    ig = agents.Ignore(["service:GoogleUpdaterService*", "Spooler"])
    assert ig.has("service", "GoogleUpdaterService159.0.8140.0")
    assert ig.has("service", "googleupdaterservice160.1.2.3")
    assert not ig.has("service", "GoogleUpdaterInternalService159.0.8140.0")
    assert ig.has("service", "spooler") and not ig.has("service", "Spool")
    assert not ig.has("task", "GoogleUpdaterService159")  # only the kind it was set for


def test_wildcard_is_literal_otherwise():
    ig = agents.Ignore(["service:App.Svc*"])
    assert ig.has("service", "App.Svc2.0") and not ig.has("service", "AppXSvc2.0")


def test_all_versions_name():
    assert agents.all_versions("GoogleUpdaterService159.0.8140.0") == "GoogleUpdaterService*"
    assert agents.all_versions("GoogleUpdaterInternalService159.0.8140.0") == "GoogleUpdaterInternalService*"
    assert agents.all_versions("Some Service 2.1") == "Some Service*"
    assert agents.all_versions("MyApp_v3.4.1") == "MyApp*"
    assert agents.all_versions("Spooler") is None
    assert agents.all_versions("W3SVC") is None
    assert agents.all_versions("ab1.2") is None  # too short to be worth a wildcard
