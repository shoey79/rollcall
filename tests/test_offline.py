"""Offline mode (owner's request, 21 Nov): no downloads, imported data instead; a bundle of only the reference
data; and the winget catalogue already on disk used when the download fails.

Run from the repository root:  python3 -m pytest tests/test_offline.py
"""
import asyncio
import json
import sys
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "rollcall" / "app"))
sys.path.insert(0, str(ROOT / "tests"))
import main  # noqa: E402
import offline as off  # noqa: E402


def vuln_data(d: Path, kev):
    (d / "msrc").mkdir(parents=True)
    (d / "osv").mkdir()
    (d / "meta.json").write_text(json.dumps({"msrc_at": 1764000000, "kev_at": 1764000100, "osv_mode": "local", "msrc_ids": ["2026-Nov"]}))
    (d / "kev.json").write_text(json.dumps(kev))
    (d / "msrc" / "2026-Nov.json").write_text("{}")
    (d / "osv" / "debian-index.json").write_text('{"idx": {}}')
    (d / "osv" / "debian.zip").write_bytes(b"PK raw download, stays behind")


def test_bundle_round_trip_has_only_reference_data(tmp_path):
    src, dst = tmp_path / "a" / "vulns", tmp_path / "b" / "vulns"
    vuln_data(src, ["CVE-2026-0001"])
    vuln_data(dst, ["CVE-OLD"])
    wg = tmp_path / "a" / "winget.msix"
    wg.write_bytes(b"msix bytes")
    bundle = tmp_path / "bundle.zip"
    m = off.export_bundle(bundle, src, wg, {"fetched": 1764000200}, "1.99.0")
    names = set(zipfile.ZipFile(bundle).namelist())
    assert names == {"manifest.json", "vulns/meta.json", "vulns/kev.json", "vulns/msrc/2026-Nov.json", "vulns/osv/debian-index.json", "winget/source2.msix"}
    assert m["vulns"]["kev_at"] == 1764000100 and m["winget"]["fetched"] == 1764000200

    wg2, wm2 = tmp_path / "b" / "winget.msix", tmp_path / "b" / "winget.json"
    info = off.import_bundle(bundle, dst, wg2, wm2)
    assert json.loads((dst / "kev.json").read_text()) == ["CVE-2026-0001"]
    assert wg2.read_bytes() == b"msix bytes" and json.loads(wm2.read_text())["fetched"] == 1764000200
    assert info["imported"]["vulns"] and info["imported"]["winget"]
    assert not (tmp_path / "b" / "vulns.import").exists() and not (tmp_path / "b" / "vulns.old").exists()


@pytest.mark.parametrize("name", ["../../etc/passwd", "vulns/../../x.json", "vulns/msrc/../../evil.json", "hosts.json", "vulns/agents.json"])
def test_import_refuses_anything_else_and_changes_nothing(tmp_path, name):
    dst = tmp_path / "vulns"
    vuln_data(dst, ["CVE-KEEP"])
    bad = tmp_path / "bad.zip"
    with zipfile.ZipFile(bad, "w") as z:
        z.writestr("manifest.json", json.dumps({"kind": "rollcall-offline-data", "format": 1, "made": 1}))
        z.writestr("vulns/meta.json", "{}")
        z.writestr(name, "x")
    with pytest.raises(ValueError):
        off.import_bundle(bad, dst, tmp_path / "w.msix", tmp_path / "w.json")
    assert json.loads((dst / "kev.json").read_text()) == ["CVE-KEEP"]


def test_import_refuses_other_zips(tmp_path):
    z = tmp_path / "export.zip"
    with zipfile.ZipFile(z, "w") as f:
        f.writestr("manifest.json", json.dumps({"format": 1, "version": 1}))   # a full Rollcall export, not this
    with pytest.raises(ValueError, match="offline data"):
        off.import_bundle(z, tmp_path / "vulns", tmp_path / "w.msix", tmp_path / "w.json")
    (tmp_path / "notzip.zip").write_text("hello")
    with pytest.raises(ValueError):
        off.import_bundle(tmp_path / "notzip.zip", tmp_path / "vulns", tmp_path / "w.msix", tmp_path / "w.json")


def _monitor(tmp_path, monkeypatch, opts):
    from test_ip_change_and_acks import monitor
    wg = tmp_path / "winget-source2.msix"
    monkeypatch.setattr(main, "WINGET_PATH", wg)
    m, _ = monitor(tmp_path, monkeypatch, [])
    m.opts.update(opts)
    return m, wg


def _one_pass(m, monkeypatch):
    sleeps = []

    async def sleep(n):
        sleeps.append(n)
        if len(sleeps) > 1:
            raise asyncio.CancelledError
    monkeypatch.setattr(main.asyncio, "sleep", sleep)
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(m.winget_loop())
    return sleeps


class FakeIndex:
    def __init__(self, n):
        self.packages = {f"p{i}": {} for i in range(n)}


def test_winget_on_disk_is_used_when_the_download_fails(tmp_path, monkeypatch):
    m, wg = _monitor(tmp_path, monkeypatch, {"software_updates": True})
    wg.write_bytes(b"old catalogue")
    wg.with_suffix(".json").write_text(json.dumps({"fetched": 1}))   # stale: it'll try to download
    monkeypatch.setattr(main.wingetidx.Index, "from_msix", staticmethod(lambda b: FakeIndex(3)))

    def no_internet(*a, **k):
        raise OSError("no route to host")
    monkeypatch.setattr(main, "ClientSession", no_internet)
    _one_pass(m, monkeypatch)
    assert m.winget is not None and len(m.winget.packages) == 3        # before 1.99 this stayed empty
    assert "no route to host" in m.winget_info.get("error", "")


def test_offline_downloads_nothing(tmp_path, monkeypatch):
    m, wg = _monitor(tmp_path, monkeypatch, {"software_updates": True, "offline": True})
    wg.write_bytes(b"imported catalogue")
    wg.with_suffix(".json").write_text(json.dumps({"fetched": 1764000200, "imported": 1764100000}))
    monkeypatch.setattr(main.wingetidx.Index, "from_msix", staticmethod(lambda b: FakeIndex(5)))

    def must_not(*a, **k):
        raise AssertionError("downloaded while offline")
    monkeypatch.setattr(main, "ClientSession", must_not)
    monkeypatch.setattr(main.jflib, "latest_release", must_not)
    sleeps = _one_pass(m, monkeypatch)
    assert m.winget_info == {"offline": True, "fetched": 1764000200, "imported": 1764100000, "packages": 5}
    assert sleeps[-1] == 300

    # The vulnerability loop does nothing online either, and the Jellyfin check skips the release lookup
    calls = []

    async def sleep2(n):
        calls.append(n)
        if len(calls) > 1:
            raise asyncio.CancelledError
    monkeypatch.setattr(main.asyncio, "sleep", sleep2)
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(m.vulns_loop(first_wait=0))
    assert m.offline()
