"""WordPress on an IIS server, as the Windows agent finds it (owner's request, 26 Nov): every install under IIS's
sites and virtual directories, its version, and each plugin's and theme's name and version, read from files only.
IIS is stood in; the sites and paths are made up."""
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

AGENT = Path(__file__).resolve().parents[1] / "rollcall" / "app" / "agent" / "RollcallAgent.ps1"
PWSH = os.environ.get("PWSH") or shutil.which("pwsh")


def make_wp(root: Path, version: str, plugins: dict, themes: dict, mu: dict | None = None):
    (root / "wp-includes").mkdir(parents=True)
    (root / "wp-includes" / "version.php").write_text(f"<?php\n$wp_db_version = 57155;\n$wp_version = '{version}';\n")
    (root / "wp-config.php").write_text("<?php define('DB_PASSWORD', 'never-read');\n")
    for slug, (name, ver) in plugins.items():
        if slug.endswith(".php"):
            (root / "wp-content" / "plugins").mkdir(parents=True, exist_ok=True)
            (root / "wp-content" / "plugins" / slug).write_text(f"<?php\n/*\nPlugin Name: {name}\nVersion: {ver}\n*/\n")
            continue
        d = root / "wp-content" / "plugins" / slug
        d.mkdir(parents=True)
        (d / "uninstall.php").write_text("<?php // nothing here\n")
        (d / f"{slug}.php").write_text(f"<?php\n/**\n * Plugin Name:       {name}\n * Description: x\n * Version:           {ver}\n */\n")
    for slug, (name, ver) in (mu or {}).items():
        (root / "wp-content" / "mu-plugins").mkdir(parents=True, exist_ok=True)
        (root / "wp-content" / "mu-plugins" / f"{slug}.php").write_text(f"<?php\n/* Plugin Name: {name}\n   Version: {ver} */\n")
    for slug, (name, ver, parent) in themes.items():
        d = root / "wp-content" / "themes" / slug
        d.mkdir(parents=True)
        (d / "style.css").write_text(f"/*\nTheme Name: {name}\nVersion: {ver}\n" + (f"Template: {parent}\n" if parent else "") + "*/\n")


@pytest.mark.skipif(not PWSH, reason="needs PowerShell")
def test_agent_finds_sites_plugins_and_themes(tmp_path):
    shop, blog, other = tmp_path / "sites" / "shop", tmp_path / "sites" / "corp" / "blog", tmp_path / "sites" / "plain"
    make_wp(shop, "6.6.2", {"woocommerce": ("WooCommerce", "9.3.3"), "akismet": ("Akismet Anti-spam", "5.3.3"),
                            "hello.php": ("Hello Dolly", "1.7.2")},
            {"twentytwentyfour": ("Twenty Twenty-Four", "1.2", None), "shop-child": ("Shop Child", "1.0", "twentytwentyfour")},
            mu={"site-tweaks": ("Site tweaks", "")})
    make_wp(blog, "6.7.1", {"wordfence": ("Wordfence Security", "8.0.1")}, {"twentytwentyfive": ("Twenty Twenty-Five", "1.0", None)})
    other.mkdir(parents=True)
    (other / "index.html").write_text("hi")
    xml = ("<?xml version=\"1.0\" encoding=\"UTF-8\"?><appcmd>"
           f"<VDIR VDIR.NAME=\"Shop/\" APP.NAME=\"Shop/\" physicalPath=\"{shop}\" />"
           f"<VDIR VDIR.NAME=\"Corp/\" APP.NAME=\"Corp/\" physicalPath=\"{tmp_path / 'sites' / 'corp'}\" />"
           f"<VDIR VDIR.NAME=\"Default Web Site/\" APP.NAME=\"Default Web Site/\" physicalPath=\"{other}\" />"
           "<VDIR VDIR.NAME=\"Files/\" APP.NAME=\"Files/\" physicalPath=\"\\\\nas01\\share\" /></appcmd>")
    src = AGENT.read_text(encoding="utf-8-sig")
    funcs = re.search(r"(function Read-FileHead.*?)\nfunction Get-NetworkReport", src, re.S).group(1)
    script = r"""
$ErrorActionPreference = 'Stop'
function Limit-Text([string]$T, [int]$N) { $t = ($T -replace '\s+', ' ').Trim(); if ($t.Length -gt $N) { $t.Substring(0, $N) } else { $t } }
function Invoke-AppCmd([string[]]$a) { if ($a[1] -eq 'vdir') { return $env:FAKE_VDIRS } }
""" + funcs + r"""
$state = @{}
$a = @(Get-WordPressSites $state)
$b = @(Get-WordPressSites $state)   # within the hour: the saved result
[pscustomobject]@{ a = $a; same = ((ConvertTo-Json $a -Depth 5 -Compress) -eq (ConvertTo-Json $b -Depth 5 -Compress)); cached = [bool]$state.wp_cache } | ConvertTo-Json -Depth 6 -Compress
"""
    p = subprocess.run([PWSH, "-NoProfile", "-NonInteractive", "-Command", script], capture_output=True, text=True, timeout=120,
                       env={**os.environ, "FAKE_VDIRS": xml})
    assert p.returncode == 0, p.stderr
    out = json.loads(p.stdout.strip().splitlines()[-1])
    assert out["same"] and out["cached"]
    sites = {(s["site"], s["path"]): s for s in out["a"]}
    assert set(sites) == {("Shop", "/"), ("Corp", "/blog")}
    s = sites[("Shop", "/")]
    assert s["version"] == "6.6.2" and "wp-config" not in json.dumps(s)
    plugins = {x["slug"]: x for x in s["plugins"]}
    assert plugins["woocommerce"] == {"slug": "woocommerce", "name": "WooCommerce", "version": "9.3.3"}
    assert plugins["hello"]["name"] == "Hello Dolly" and plugins["site-tweaks"]["mu"] is True
    themes = {x["slug"]: x for x in s["themes"]}
    assert themes["twentytwentyfour"]["version"] == "1.2" and themes["shop-child"]["parent"] == "twentytwentyfour"
    b = sites[("Corp", "/blog")]
    assert b["version"] == "6.7.1" and b["plugins"] == [{"slug": "wordfence", "name": "Wordfence Security", "version": "8.0.1"}]
