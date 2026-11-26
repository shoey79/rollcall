"""What's new: each admin sees the headlines of the versions since they last looked, once; a new install starts
at its own version, an upgraded one at the release before What's new.

Run from the repository root:  python3 -m pytest tests/test_whats_new.py
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "rollcall" / "app"))
import whatsnew as wn  # noqa: E402

CL = """# Changelog

## Unreleased

- **Not out yet.** Shouldn't show.

## 1.99.0 - 2026-11-27

- **Address changes on agent devices: Rollcall asks.** When a device ...
  - **A sub-bullet** isn't a headline.

- **Backups: `Acknowledge` a job's [warning](https://example.com/x).** Text.

## 1.98.1 - 2026-11-23

- **Router agents without HTTPS keep reporting.** Text.

## 1.98.0 - 2026-11-23

- **Fire TV.** Text.
"""


def make(tmp_path, version, existing):
    cl = tmp_path / "CHANGELOG.md"
    cl.write_text(CL)
    return wn.WhatsNew(tmp_path / "wn.json", cl, version, existing)


def test_parse_headlines():
    e = wn.parse(CL)
    assert [x["version"] for x in e] == ["1.99.0", "1.98.1", "1.98.0"]   # Unreleased left out
    assert e[0]["date"] == "2026-11-27"
    assert e[0]["lines"] == ["Address changes on agent devices: Rollcall asks", "Backups: Acknowledge a job's warning"]


def test_upgraded_install_shows_since_1_98_1_once_per_admin(tmp_path):
    w = make(tmp_path, "1.99.0", existing=True)
    assert [x["version"] for x in w.unseen("admin1")] == ["1.99.0"]
    w.mark_seen("admin1")
    assert w.unseen("admin1") == []
    assert [x["version"] for x in w.unseen("admin2")] == ["1.99.0"]      # each admin, not each browser
    # Kept across restarts; the next version shows only itself
    w2 = make(tmp_path, "1.99.0", existing=True)
    assert w2.unseen("admin1") == [] and w2.state["baseline"] == "1.98.1"


def test_new_install_shows_nothing_and_skipped_versions_come_together(tmp_path):
    w = make(tmp_path, "1.98.0", existing=False)
    assert w.unseen("admin1") == []
    w3 = wn.WhatsNew(tmp_path / "wn.json", tmp_path / "CHANGELOG.md", "1.99.0", True)  # updated twice since
    assert [x["version"] for x in w3.unseen("admin1")] == ["1.99.0", "1.98.1"]       # newest first, one pop-up
    assert w3.unseen("") == []


def test_development_build_never_pops_up(tmp_path):
    assert make(tmp_path, None, existing=True).unseen("admin1") == []


def test_image_includes_the_changelog():
    assert "COPY CHANGELOG.md /app/CHANGELOG.md" in (ROOT / "rollcall" / "Dockerfile").read_text()
    assert wn.parse((ROOT / "rollcall" / "CHANGELOG.md").read_text())[0]["lines"]
