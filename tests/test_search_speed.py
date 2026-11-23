"""Searching with many devices (owner's request, 22 Nov: 127 devices, typing in the search box was slow).

Each keystroke redrew every row, and the 24-hour bars made a new time format for every bar: about a second per
keystroke with 150 devices. Now the bars' times are worked out once, each row's HTML is kept until its device
changes, and the search waits for a pause in typing. Measured here against the real add-on and dashboard."""
import json
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_update_signing_e2e import HAVE_ADDON_DEPS, UI, Addon, call  # noqa: E402

playwright = pytest.importorskip("playwright.sync_api")
N = 150


@pytest.mark.skipif(not HAVE_ADDON_DEPS, reason="needs the add-on's packages (aiohttp, cryptography)")
def test_search_stays_fast_with_150_devices(tmp_path):
    addon = Addon(tmp_path / "addon").start()
    try:
        for i in range(N):
            st, body = call(addon.ui + "/api/hosts", {"name": f"PC{i:03d}", "host": f"127.0.{i // 250}.{i % 250 + 1}",
                            "checks": ["tcp:9", "http:80/"] if i % 3 == 0 else ["tcp:22"]}, UI, "POST")
            assert st == 201, body[:200]
        with playwright.sync_playwright() as p:
            b = p.chromium.launch()
            pg = b.new_page(viewport={"width": 1400, "height": 900}, extra_http_headers=UI)
            pg.goto(addon.ui + "/")
            pg.wait_for_function(f"typeof data !== 'undefined' && data && data.hosts.length >= {N}", timeout=30000)
            pg.click("[data-tab='all']")
            r = pg.evaluate("""async () => {
              const f = document.getElementById('filter'), rows = () => document.querySelectorAll('#rows tr').length;
              const time = fn => { const a = performance.now(); fn(); return performance.now() - a; };
              rowCache.clear(); lastRowsHtml = null;
              const cold = time(render);                                   // every row built from scratch
              const all = rows();
              const keys = [];
              for (const q of ['p', 'pc', 'pc0', 'pc01', 'pc0', 'pc', 'p', '']) { f.value = q; keys.push(time(render)); }
              // typing: nothing is redrawn until a pause, then once
              let redraws = 0; const orig = window.render; window.render = () => { redraws++; orig(); };
              for (const q of ['p', 'pc', 'pc0', 'pc04']) { f.value = q; f.dispatchEvent(new Event('input')); }
              await new Promise(res => setTimeout(res, 300));
              window.render = orig;
              return {cold, all, keys, redraws, shown: rows()};
            }""")
            b.close()
        print(json.dumps({k: (round(v, 1) if isinstance(v, float) else v) for k, v in r.items() if k != "keys"},),
              "keystrokes (ms):", [round(x, 1) for x in r["keys"]])
        assert r["all"] == N and r["shown"] == 10                         # PC040-PC049
        assert r["redraws"] == 1
        assert r["cold"] < 600, r                                          # was ~1000 ms
        assert max(r["keys"]) < 250, r                                     # was ~1000 ms each
    finally:
        addon.stop()
