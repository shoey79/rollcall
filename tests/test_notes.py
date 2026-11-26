"""Notes on each device: the admins' own free text (where it lives, who to call, quirks). Saved with the device, so
they're in hosts.json and therefore exports and backups; kept when the device is edited; editors change them, anyone
can read them (who may call the route is covered by test_roles).

Run from the repository root:  python3 -m pytest tests/test_notes.py
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "rollcall" / "app"))
sys.path.insert(0, str(ROOT / "tests"))
import main  # noqa: E402
from test_ip_change_and_acks import monitor  # noqa: E402
from test_update_signing_e2e import UI, Addon, call  # noqa: E402


def test_clean_notes():
    assert main.clean_notes(None) == "" and main.clean_notes("   ") == ""
    assert main.clean_notes("Rack 2, top shelf\r\nCall the landlord\x07 first\t!") == "Rack 2, top shelf\nCall the landlord first\t!"
    assert len(main.clean_notes("x" * 9000)) == main.NOTES_MAX


def test_saved_with_the_device_and_kept_on_edit(tmp_path, monkeypatch):
    m, _ = monitor(tmp_path, monkeypatch, [{"id": "p1", "name": "PC01", "host": "10.0.1.20", "checks": []}])
    h = m.hosts["p1"]
    h.notes, h.notes_by, h.notes_at = "Under the reception desk", "admin", 1700000000.0
    m._save_hosts()
    saved = json.loads(Path(main.HOSTS_PATH).read_text())
    saved = saved["hosts"] if isinstance(saved, dict) else saved
    e = next(x for x in saved if x["id"] == "p1")
    assert (e["notes"], e["notes_by"], e["notes_at"]) == ("Under the reception desk", "admin", 1700000000.0)
    again = m._make_host(e, 0)
    assert (again.notes, again.notes_by, again.notes_at) == ("Under the reception desk", "admin", 1700000000.0)
    assert "notes" not in m._entry(m._make_host({"id": "p2", "name": "PC02", "host": "10.0.1.21", "checks": []}, 0))  # none: nothing saved


def test_route_saves_shows_and_clears(tmp_path):
    addon = Addon(tmp_path / "addon").start()
    try:
        st, b = call(addon.ui + "/api/hosts", {"name": "PRINTER01", "host": "192.168.1.90", "checks": []}, UI)
        assert st == 201, b
        key = next(h["key"] for h in addon.api("/api/status")["hosts"] if h["name"] == "PRINTER01")
        st, b = call(addon.ui + f"/api/hosts/{key}/notes", {"notes": "Toner in the cupboard\nCall sip.provider.example support"}, UI)
        assert st == 200, b
        r = json.loads(b)
        assert r["notes"] == "Toner in the cupboard\nCall sip.provider.example support" and r["notes_by"] == "admin" and r["notes_at"]
        h = next(h for h in addon.api("/api/status")["hosts"] if h["key"] == key)
        assert h["notes"] == r["notes"] and h["notes_by"] == "admin"
        # Editing the device doesn't touch them
        st, b = call(addon.ui + f"/api/hosts/{key}", {"name": "PRINTER02", "host": "192.168.1.90", "checks": []}, UI, "PUT")
        assert st == 200, b
        assert next(h for h in addon.api("/api/status")["hosts"] if h["key"] == key)["notes"] == r["notes"]
        st, b = call(addon.ui + f"/api/hosts/{key}/notes", {"notes": "x" * (main.NOTES_MAX + 1)}, UI)
        assert st == 400 and b"4000" in b
        st, b = call(addon.ui + f"/api/hosts/{key}/notes", {"nope": 1}, UI)
        assert st == 400
        st, b = call(addon.ui + f"/api/hosts/{key}/notes", {"notes": "  "}, UI)   # cleared
        assert st == 200 and json.loads(b) == {"ok": True, "notes": "", "notes_by": "", "notes_at": None}
        st, _ = call(addon.ui + "/api/hosts/nosuch/notes", {"notes": "x"}, UI)
        assert st == 404
    finally:
        addon.stop()
