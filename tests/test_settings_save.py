"""Saving settings from the dashboard, with a Supervisor that behaves like the real one: options saved through its
API are stored at once but only written to /data/options.json when the add-on starts.

Before 1.100.1 the save compared against that file, so changing a setting back to how it was at start-up "saved"
but stayed as it was in use (the dialog showed the old value again until a restart), and each save wrote the stale
file back, quietly undoing settings changed earlier in the same session.

Run from the repository root:  python3 -m pytest tests/test_settings_save.py
"""
import asyncio
import json
import sys
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "rollcall" / "app"))
sys.path.insert(0, str(ROOT / "tests"))
import main  # noqa: E402
from test_ip_change_and_acks import monitor  # noqa: E402


class Supervisor:
    """Stores options when they're saved; writes options.json only at start (as the real Supervisor does)."""
    enabled = True

    def __init__(self, options: dict):
        self.options = dict(options)
        self.writes = 0

    async def write_options(self, options: dict):
        self.options = json.loads(json.dumps(options))
        self.writes += 1
        return None

    async def read_options(self):
        return json.loads(json.dumps(self.options))


def setup(tmp_path, monkeypatch):
    opts_file = tmp_path / "options.json"
    monkeypatch.setattr(main, "OPTIONS_PATH", opts_file)
    m, _ = monitor(tmp_path, monkeypatch, [])
    start = {**main.DEFAULTS, "vuln_skip_os": [], "interval": 300}
    opts_file.write_text(json.dumps(start))       # what the add-on started with
    m.opts.update(start)
    sup = Supervisor(start)
    m.ha = SimpleNamespace(enabled=True, write_options=sup.write_options, read_options=sup.read_options)
    live = main.LiveSettings(m, SimpleNamespace(update=lambda o: None, enabled=False, editors=set()), None)
    return m, sup, live, opts_file


def test_changing_back_to_the_start_up_value_takes_effect(tmp_path, monkeypatch):
    m, sup, live, opts_file = setup(tmp_path, monkeypatch)
    r = asyncio.run(live.save({"vuln_skip_os": ["Windows 10"]}, "admin"))
    assert r["changed"] == ["vuln_skip_os"] and m.opts["vuln_skip_os"] == ["Windows 10"]
    # Back to how it was at start-up (the owner's report): it must change, not "save" and stay
    r = asyncio.run(live.save({"vuln_skip_os": []}, "admin"))
    assert r["changed"] == ["vuln_skip_os"] and m.opts["vuln_skip_os"] == []
    assert sup.options["vuln_skip_os"] == [] and json.loads(opts_file.read_text())["vuln_skip_os"] == []
    assert main.settingslib.values(m.opts)["vuln_skip_os"] == []   # what the dialog shows after saving


def test_a_save_doesnt_undo_an_earlier_one(tmp_path, monkeypatch):
    m, sup, live, opts_file = setup(tmp_path, monkeypatch)
    asyncio.run(live.save({"interval": 120}, "admin"))
    asyncio.run(live.save({"vuln_skip_os": ["Windows 10"]}, "admin"))
    assert sup.options["interval"] == 120 and sup.options["vuln_skip_os"] == ["Windows 10"]   # both kept
    assert json.loads(opts_file.read_text())["interval"] == 120     # and exports read the current settings
    n = sup.writes
    r = asyncio.run(live.save({"interval": 120}, "admin"))          # nothing new: nothing written
    assert r["changed"] == [] and sup.writes == n


def test_configuration_tab_changes_are_picked_up(tmp_path, monkeypatch):
    m, sup, live, opts_file = setup(tmp_path, monkeypatch)
    live.WATCH_SECONDS = 0

    async def go():
        task = asyncio.create_task(live.watch())
        await asyncio.sleep(0.05)                                    # sees what it started with
        sup.options["interval"] = 90                                 # saved in the Configuration tab
        for _ in range(50):
            await asyncio.sleep(0.02)
            if m.opts.get("interval") == 90:
                break
        task.cancel()
    asyncio.run(go())
    assert m.opts["interval"] == 90 and json.loads(opts_file.read_text())["interval"] == 90
