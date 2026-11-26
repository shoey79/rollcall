"""Offline data: the downloaded reference data (vulnerability lists and the winget catalogue) as one bundle, made on
a Rollcall that has the internet and imported on one that hasn't (an airgapped network).

Only that data is in a bundle: no devices, settings, keys or anything about the network it came from.
"""
from __future__ import annotations

import json
import re
import shutil
import time
import zipfile
from pathlib import Path

FORMAT = 1
MAX_BYTES = 1536 * 1024 ** 2   # unpacked; Microsoft's months and OSV's indexes are the big parts
# The files a bundle may hold, relative to the vulnerability folder (the raw OSV downloads stay behind: Rollcall
# only reads the indexes made from them)
VULN_FILES = re.compile(r"\A(meta\.json|kev\.json|msrc/[A-Za-z0-9-]{1,40}\.json|osv/[a-z0-9_-]{1,40}-index\.json)\Z")
WINGET_NAME = "winget/source2.msix"


def export_bundle(dest: Path, vuln_dir: Path, winget: Path, winget_meta: dict, made_by: str = "") -> dict:
    """Write the bundle to dest. Returns what's in it."""
    files = sorted(p for p in vuln_dir.rglob("*") if p.is_file() and VULN_FILES.match(p.relative_to(vuln_dir).as_posix())) if vuln_dir.exists() else []
    meta = {}
    try:
        meta = json.loads((vuln_dir / "meta.json").read_text())
    except (OSError, ValueError):
        pass
    manifest = {"format": FORMAT, "kind": "rollcall-offline-data", "made": int(time.time()), "made_by": made_by[:80],
                "vulns": {"msrc_at": meta.get("msrc_at"), "kev_at": meta.get("kev_at"), "osv_at": meta.get("osv_at"),
                          "osv_mode": meta.get("osv_mode"), "files": len(files)},
                "winget": {"fetched": winget_meta.get("fetched"), "size": winget.stat().st_size} if winget.exists() else None}
    tmp = dest.with_suffix(".tmp")
    with zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("manifest.json", json.dumps(manifest, indent=1))
        for p in files:
            z.write(p, "vulns/" + p.relative_to(vuln_dir).as_posix())
        if winget.exists():
            z.write(winget, WINGET_NAME, compress_type=zipfile.ZIP_STORED)  # an msix is a zip already
    tmp.replace(dest)
    return manifest


def import_bundle(src: Path, vuln_dir: Path, winget: Path, winget_meta_path: Path) -> dict:
    """Check a bundle and put its data in place. Raises ValueError for anything that isn't a bundle (nothing is
    changed then). Returns the manifest, with what was imported."""
    try:
        z = zipfile.ZipFile(src)
    except (zipfile.BadZipFile, OSError) as err:
        raise ValueError("That isn't a Rollcall offline data file") from err
    with z:
        try:
            manifest = json.loads(z.read("manifest.json"))
        except (KeyError, ValueError) as err:
            raise ValueError("That isn't a Rollcall offline data file (no manifest)") from err
        if not isinstance(manifest, dict) or manifest.get("kind") != "rollcall-offline-data":
            raise ValueError("That isn't a Rollcall offline data file")
        if int(manifest.get("format") or 0) > FORMAT:
            raise ValueError("That file was made by a newer Rollcall: update this one first")
        names, total = [], 0
        for i in z.infolist():
            if i.is_dir() or i.filename == "manifest.json":
                continue
            rel = i.filename[len("vulns/"):] if i.filename.startswith("vulns/") else None
            if not ((rel and VULN_FILES.match(rel)) or i.filename == WINGET_NAME):
                raise ValueError(f"Unexpected file in the bundle: {i.filename[:80]}")
            names.append(i)
        stage = vuln_dir.parent / (vuln_dir.name + ".import")
        shutil.rmtree(stage, ignore_errors=True)
        try:
            for i in names:
                out = stage / i.filename
                out.parent.mkdir(parents=True, exist_ok=True)
                with z.open(i) as r, open(out, "wb") as w:  # counted as unpacked, whatever the zip claims
                    while chunk := r.read(1 << 20):
                        total += len(chunk)
                        if total > MAX_BYTES:
                            raise ValueError("The bundle is too big to be a Rollcall offline data file")
                        w.write(chunk)
            got_vulns = (stage / "vulns" / "meta.json").exists()
            if got_vulns:
                old = vuln_dir.parent / (vuln_dir.name + ".old")
                shutil.rmtree(old, ignore_errors=True)
                if vuln_dir.exists():
                    vuln_dir.replace(old)
                (stage / "vulns").replace(vuln_dir)
                shutil.rmtree(old, ignore_errors=True)
            got_winget = (stage / WINGET_NAME).exists()
            if got_winget:
                (stage / WINGET_NAME).replace(winget)
                wm = manifest.get("winget") or {}
                winget_meta_path.write_text(json.dumps({"fetched": wm.get("fetched") or manifest.get("made"), "size": winget.stat().st_size,
                                                        "imported": int(time.time())}))
        finally:
            shutil.rmtree(stage, ignore_errors=True)
    manifest["imported"] = {"at": int(time.time()), "vulns": got_vulns, "winget": got_winget}
    return manifest
