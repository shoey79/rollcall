"""WordPress sites (rollcall/app/wordpress.py): what the agent sends, updates from wordpress.org, closed plugins, and
known vulnerabilities from the Wordfence feed (read a record at a time). The sample answers follow the published
formats with made-up values; sites and folders are made up.

Run from the repository root:  python3 -m pytest tests/test_wordpress.py
"""
import asyncio
import json
import logging
import sys
import time
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "rollcall" / "app"))
sys.path.insert(0, str(ROOT / "tests"))
import main  # noqa: E402
import wordpress as wp  # noqa: E402
from test_ip_change_and_acks import monitor  # noqa: E402

SITES = [{"site": "Shop", "path": "/", "dir": "D:\\Sites\\shop", "version": "6.6.2",
          "plugins": [{"slug": "woocommerce", "name": "WooCommerce", "version": "9.3.3"},
                      {"slug": "old-gallery", "name": "Old Gallery", "version": "1.0"},
                      {"slug": "in-house", "name": "In-house tweaks", "version": "2.1"},
                      {"slug": "site-tweaks", "name": "Site tweaks", "version": "", "mu": True}],
          "themes": [{"slug": "twentytwentyfour", "name": "Twenty Twenty-Four", "version": "1.2"}]},
         {"site": "Corp", "path": "/blog", "dir": "D:\\Sites\\corp\\blog", "version": "6.7.1",
          "plugins": [{"slug": "woocommerce", "name": "WooCommerce", "version": "9.4.2"}], "themes": []}]

FEED = {
    "11111111-aaaa": {"id": "11111111-aaaa", "title": "WooCommerce <= 9.3.3 - Stored XSS", "cve": "CVE-2026-1111",
                      "cvss": {"vector": "x", "score": 6.4, "rating": "Medium"}, "references": [], "published": "2026-10-01",
                      "software": [{"type": "plugin", "name": "WooCommerce", "slug": "woocommerce", "patched": True, "patched_versions": ["9.3.4"],
                                    "affected_versions": {"* - 9.3.3": {"from_version": "*", "from_inclusive": True, "to_version": "9.3.3", "to_inclusive": True}}}]},
    "22222222-bbbb": {"id": "22222222-bbbb", "title": "Old Gallery - Unauthenticated file upload", "cve": "CVE-2026-2222",
                      "cvss": {"vector": "x", "score": 9.8, "rating": "Critical"}, "references": [], "published": "2026-09-01",
                      "software": [{"type": "plugin", "name": "Old Gallery", "slug": "old-gallery", "patched": False, "patched_versions": [],
                                    "affected_versions": {"*": {"from_version": "*", "from_inclusive": True, "to_version": "*", "to_inclusive": True}}}]},
    "33333333-cccc": {"id": "33333333-cccc", "title": "WordPress Core < 6.6.3 - something", "cve": None, "cvss": {"vector": "x", "score": 5.3, "rating": "Medium"},
                      "references": [], "published": "2026-08-01",
                      "software": [{"type": "core", "name": "WordPress", "slug": "wordpress", "patched": True, "patched_versions": ["6.6.3", "6.7.1"],
                                    "affected_versions": {"6.6 - 6.6.2": {"from_version": "6.6", "from_inclusive": True, "to_version": "6.6.2", "to_inclusive": True}}}]},
    "44444444-dddd": {"id": "44444444-dddd", "title": "Informational only", "informational": True, "references": [], "published": "2026-08-01",
                      "software": [{"type": "plugin", "name": "WooCommerce", "slug": "woocommerce", "patched": True, "patched_versions": [],
                                    "affected_versions": {"*": {"from_version": "*", "from_inclusive": True, "to_version": "*", "to_inclusive": True}}}]},
}


def test_versions_compare_like_php():
    c = wp.php_cmp
    assert c("6.7.1", "6.7") > 0 and c("6.7", "6.7.0") == 0 and c("1.0-beta", "1.0") < 0 and c("1.0RC1", "1.0beta") > 0
    assert c("10.2", "9.9") > 0 and c("1.0pl1", "1.0") > 0
    assert wp.in_range("9.3.3", ["*", True, "9.3.3", True]) and not wp.in_range("9.3.4", ["*", True, "9.3.3", True])
    assert not wp.in_range("6.6", ["6.6", False, "6.7", False]) and wp.in_range("6.6.1", ["6.6", False, "6.7", False])


def test_clean_keeps_what_matters():
    raw = [{"site": "Shop", "path": "/", "dir": "D:\\x", "version": "6.6.2", "plugins": [{"slug": "a", "name": "A", "version": "1", "mu": True}, "junk", {"name": "no slug"}],
            "themes": [{"slug": "t", "name": "T", "version": "1", "parent": "p"}], "dbpass": "nope"}, {"site": "x"}, "junk"]
    c = wp.clean(raw)
    assert len(c) == 1 and c[0]["plugins"] == [{"slug": "a", "name": "A", "version": "1", "mu": True}]
    assert c[0]["themes"][0]["parent"] == "p" and "dbpass" not in c[0]


def test_feed_is_read_a_record_at_a_time(tmp_path):
    f = tmp_path / "feed.json"
    f.write_text(json.dumps(FEED, indent=1))
    recs = list(wp._iter_feed(f, chunk=64))          # tiny pieces: every record spans several
    assert [k for k, _ in recs] == list(FEED) and recs[1][1]["title"] == FEED["22222222-bbbb"]["title"]
    idx = wp.index_feed(f)
    assert set(idx) == {"plugin:woocommerce", "plugin:old-gallery", "core:wordpress"}   # the informational one is left out
    assert idx["plugin:woocommerce"][0][1] == "CVE-2026-1111" and idx["plugin:woocommerce"][0][2] == 6.4
    (tmp_path / "bad.json").write_text(json.dumps(FEED)[:500])
    try:
        list(wp._iter_feed(tmp_path / "bad.json", chunk=64))
        assert False, "a cut-off feed must fail"
    except ValueError:
        pass


def test_findings(tmp_path):
    f = tmp_path / "feed.json"
    f.write_text(json.dumps(FEED))
    found = wp.findings(SITES, wp.index_feed(f), {"CVE-2026-2222"})
    by = {(x["what"], x["cve"]) for x in found}
    assert ("WooCommerce (plugin) on Shop", "CVE-2026-1111") in by              # 9.3.3 is affected
    assert not any(x["what"] == "WooCommerce (plugin) on Corp/blog" for x in found)   # 9.4.2 isn't
    og = next(x for x in found if x["cve"] == "CVE-2026-2222")
    assert og["exploited"] and og["fixed"] == "no fix yet" and og["score"] == 9.8
    core = next(x for x in found if x["what"] == "WordPress on Shop")
    assert core["cve"].startswith("WF-") and core["fixed"] == "6.6.3" and core["ref"].endswith("33333333-cccc")


class FakeResp:
    def __init__(self, status, body):
        self.status, self._body = status, body if isinstance(body, bytes) else json.dumps(body).encode()
        self.content = SimpleNamespace(iter_chunked=self._chunks)

    async def _chunks(self, n):
        for i in range(0, len(self._body), n):
            yield self._body[i:i + n]

    async def read(self):
        return self._body

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False


class FakeSession:
    def __init__(self, answers):
        self.answers, self.asked = answers, []

    def get(self, url, headers=None, **kw):
        self.asked.append((url, headers or {}))
        for key, ans in self.answers.items():
            if key in url:
                return FakeResp(*ans)
        return FakeResp(404, {"error": "Plugin not found."})


def wp_answers():
    return {"core/version-check": (200, {"offers": [{"response": "upgrade", "version": "6.7.1"}]}),
            "slug]=woocommerce": (200, {"version": "9.4.2", "last_updated": "2026-11-20"}),
            "slug]=old-gallery": (404, {"error": "closed", "closed": True, "closed_date": "2026-06-01", "reason_text": "Security Issue"}),
            "slug]=twentytwentyfour": (200, {"version": "1.2"}),
            "wordfence.com": (200, json.dumps(FEED).encode())}


def test_refresh_updates_and_check(tmp_path):
    d = wp.Data(tmp_path / "wp", logging.getLogger("t"))
    s = FakeSession(wp_answers())
    now = time.time()
    assert asyncio.run(d.refresh(s, now, wp.wanted(SITES), "")) is True
    assert d.core["latest"] == "6.7.1" and d.info["plugin:woocommerce"]["latest"] == "9.4.2"
    assert d.info["plugin:old-gallery"]["closed"] and d.info["plugin:in-house"]["missing"]
    assert "plugin:site-tweaks" not in d.info                                # must-use plugins aren't on wordpress.org
    assert not any("wordfence" in u for u, _ in s.asked) and not d.wf        # no key: no feed
    assert all("Shop" not in u and "Corp" not in u for u, _ in s.asked)      # only slugs leave, never sites
    u = wp.updates(SITES, d)
    assert u["sites"][0]["core"] == "6.7.1" and u["sites"][1]["core"] is None
    assert u["sites"][0]["items"]["plugin:woocommerce"] == {"latest": "9.4.2"} and u["closed"] == 1
    assert wp.check(SITES, u) == ("warn", "2 updates waiting on 1 of 2 sites; 1 plugin closed on wordpress.org")
    # with a key, the feed: then nothing is asked again until it's due
    s2 = FakeSession(wp_answers())
    assert asyncio.run(d.refresh(s2, now + 60, wp.wanted(SITES), "k123")) is True
    assert d.wf and any(h.get("Authorization") == "Bearer k123" for u_, h in s2.asked if "wordfence" in u_)
    assert not any("api.wordpress.org" in u_ for u_, _ in s2.asked)
    d2 = wp.Data(tmp_path / "wp", logging.getLogger("t"))
    d2.load()
    assert d2.wf.keys() == d.wf.keys() and d2.core["latest"] == "6.7.1"     # kept for after a restart
    # the key removed: its data goes too
    assert asyncio.run(d.refresh(FakeSession(wp_answers()), now + 120, set(), "")) is True and not d.wf
    s3 = FakeSession({"wordfence.com": (401, b"{}")})
    d3 = wp.Data(tmp_path / "wp3", logging.getLogger("t"))
    asyncio.run(d3.refresh(s3, now, set(), "bad"))
    assert "turned down" in d3.status()["errors"]["Wordfence"]


def test_monitor_stores_checks_and_shows(tmp_path, monkeypatch):
    monkeypatch.setattr(main, "SOFTWARE_DIR", tmp_path / "software")
    m, _ = monitor(tmp_path, monkeypatch, [{"id": "web", "name": "SRV01", "host": "10.0.1.10", "checks": []}])
    h = m.hosts["web"]
    h.agent_id, h.agent_report = "a1", {"os_family": "windows", "os": "Microsoft Windows Server 2022 Standard"}
    m._store_wordpress({"id": "a1", "hostname": "SRV01"}, SITES, "h1", time.time())
    assert m.wordpress("a1")["hash"] == "h1" and len(m.wordpress("a1")["sites"]) == 2
    m._wp.clear()
    assert m.wordpress("a1")["sites"][1]["path"] == "/blog"                   # read back from disk
    assert "checking wordpress.org" in m.wordpress_check(h)["detail"]
    asyncio.run(m.wpdata.refresh(FakeSession(wp_answers()), time.time(), wp.wanted(SITES), "k"))
    c = m.wordpress_check(h)
    assert c["level"] == main.agentlib.WARN and "closed" in c["detail"]
    v = m.wordpress_view(h)
    assert v["vulns"]["WooCommerce (plugin) on Shop"][0]["cve"] == "CVE-2026-1111" and v["wordfence"] is False
    # the Vulnerabilities check: only what scores at or above the setting (9), or is exploited
    m.vulnfeeds.kev = set()
    extra = m.extra_findings(h)
    assert [x["cve"] for x in extra] == ["CVE-2026-2222"]
    m.opts["vuln_min_score"] = 5
    assert {x["cve"] for x in m.extra_findings(h)} == {"CVE-2026-1111", "CVE-2026-2222"} | {x["cve"] for x in m.extra_findings(h) if x["cve"].startswith("WF-")}
    vc = m.vuln_check(h)
    assert vc["level"] == main.agentlib.WARN and "CVE-2026-2222" in vc["ids"]
    m.opts["wordpress_checks"] = False
    assert m.wordpress_check(h) is None and m.extra_findings(h) == []
