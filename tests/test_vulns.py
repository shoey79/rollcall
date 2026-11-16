"""Vulnerability alerts (rollcall/app/vulns.py): CVSS scores, version comparison, matching Windows
builds against Microsoft's data and Linux packages against OSV's, and the online OSV path.
The sample records follow the published formats with made-up values."""
import asyncio
import io
import json
import logging
import sys
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "rollcall" / "app"))

import vulns  # noqa: E402


def test_cvss3():
    assert vulns.cvss3_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8
    assert vulns.cvss3_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H") == 10.0
    assert vulns.cvss3_score("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H") == 5.5
    assert vulns.cvss3_score("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H") == 5.9
    assert vulns.cvss3_score("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N") == 6.4
    assert vulns.cvss3_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N") == 0.0
    assert vulns.cvss3_score("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N") is None
    assert vulns.cvss3_score("rubbish") is None


def test_dpkg_cmp():
    c = vulns.dpkg_cmp
    assert c("1.0~rc1", "1.0") < 0 and c("1:1.0", "2.0") > 0 and c("1.2.3", "1.2.3") == 0
    assert c("3.0.15-1~deb12u1", "3.0.14-1~deb12u2") > 0
    assert c("2.36-9+deb12u7", "2.36-9+deb12u10") < 0
    assert c("1.0-1", "1.0-1+b1") < 0 and c("1.0a", "1.0") > 0 and c("1.0", "1.0.0") < 0
    assert c("7.88.1-10+deb12u5", "7.88.1-10+deb12u5") == 0 and c("0", "0.1") < 0


def test_rpm_cmp():
    c = vulns.rpm_cmp
    assert c("1.0~rc1-1", "1.0-1") < 0 and c("1.0^git1-1", "1.0-1") > 0
    assert c("2:1.0-1", "1:9.0-1") > 0 and c("1.10-1", "1.9-1") > 0
    assert c("1.0.1-1", "1.0a-1") > 0 and c("3.0.7-27.el9", "3.0.7-27.el9") == 0
    assert c("1:16.13.1-3.module_el8.5.0+2605+45d748af", "1:16.13.1-2.module_el8.5.0") > 0
    assert c("3.0.7-25.el9_3", "3.0.7-27.el9") < 0


def msrc_doc():
    return {"ProductTree": {"FullProductName": [{"ProductID": "1", "Value": "Windows Server 2019"},
                                                {"ProductID": "2", "Value": "Windows Server 2022"},
                                                {"ProductID": "3", "Value": "Microsoft Office 2019"},
                                                {"ProductID": "4", "Value": "Windows Server 2019 Datacenter: Azure Edition (Hotpatch)"},
                                                {"ProductID": "5", "Value": "Windows SDK"}]},
            "Vulnerability": [
                {"CVE": "CVE-2026-0001", "Threats": [{"Type": 1, "Description": {"Value": "Publicly Disclosed:No;Exploited:Yes;Latest Software Release:Exploitation Detected"}}],
                 "CVSSScoreSets": [{"BaseScore": 8.8, "ProductID": ["1", "2"]}],
                 "Remediations": [{"Type": 2, "Description": {"Value": "5044277"}, "ProductID": ["1"], "FixedBuild": "10.0.17763.6414"},
                                  {"Type": 2, "Description": {"Value": "5044281"}, "ProductID": ["2"], "FixedBuild": "10.0.20348.2762"},
                                  {"Type": 2, "Description": {"Value": "5044999"}, "ProductID": ["4"], "FixedBuild": "10.0.17763.6400"},  # a hotpatch
                                  {"Type": 2, "Description": {"Value": "5045000"}, "ProductID": ["5"], "FixedBuild": "10.0.22621.4000"}]},  # not Windows itself
                {"CVE": "CVE-2026-0002", "Threats": [], "CVSSScoreSets": [{"BaseScore": 9.8, "ProductID": ["1"]}],
                 "Remediations": [{"Type": 2, "Description": {"Value": "5044277"}, "ProductID": ["1"], "FixedBuild": "10.0.17763.6414"},
                                  {"Type": 0, "Description": {"Value": "Workaround"}, "ProductID": ["1"]}]},
                {"CVE": "CVE-2026-0003", "Threats": [], "CVSSScoreSets": [{"BaseScore": 9.1, "ProductID": ["3"]}],
                 "Remediations": [{"Type": 2, "Description": {"Value": "5002600"}, "ProductID": ["3"], "FixedBuild": "16.0.10414.20002"}]},
                {"CVE": "CVE-2026-0004", "Threats": [], "CVSSScoreSets": [{"BaseScore": 5.5, "ProductID": ["1"]}],
                 "Remediations": [{"Type": 2, "Description": {"Value": "5044277"}, "ProductID": ["1"], "FixedBuild": "10.0.17763.6414"}]},
            ]}


def test_msrc_windows():
    idx = vulns.msrc_merge([vulns.msrc_compact(msrc_doc())])
    assert set(idx) == {"10.0.17763", "10.0.20348"}                       # Office and the SDK aren't Windows itself
    assert idx["10.0.17763"]["CVE-2026-0001"] == [6414, 8.8, True, "KB5044277"]  # the monthly update, not the hotpatch
    assert vulns.msrc_compact({"Vulnerability": ["odd", {"CVE": "CVE-2026-1", "Remediations": ["x", None]}]}) == {}
    f = {x["cve"]: x for x in vulns.windows_findings("10.0.17763.6293", idx, set(), 9.0)}
    assert set(f) == {"CVE-2026-0001", "CVE-2026-0002"}                     # 0001: exploited despite 8.8; 0004: 5.5
    assert f["CVE-2026-0002"]["fixed"] == "10.0.17763.6414" and not f["CVE-2026-0002"]["exploited"]
    assert vulns.windows_findings("10.0.17763.6414", idx, set(), 9.0) == []  # up to date
    assert vulns.windows_findings("10.0.26100.100", idx, set(), 9.0) == []   # another Windows version
    assert vulns.windows_findings("10.0.17763", idx, set(), 9.0) == []       # no revision: can't tell
    # A later month revises the fix to a later build
    later = vulns.msrc_compact({"ProductTree": msrc_doc()["ProductTree"], "Vulnerability": [
        {"CVE": "CVE-2026-0002", "CVSSScoreSets": [{"BaseScore": 9.8, "ProductID": ["1"]}],
         "Remediations": [{"Type": 2, "Description": {"Value": "5046615"}, "ProductID": ["1"], "FixedBuild": "10.0.17763.6532"}]}]})
    idx2 = vulns.msrc_merge([vulns.msrc_compact(msrc_doc()), later])
    assert idx2["10.0.17763"]["CVE-2026-0002"][0] == 6532


def osv_rec(rid, eco, name, fixed, vector=None, introduced="0", upstream=None):
    r = {"id": rid, "modified": "2026-11-01T00:00:00Z", "affected": [{"package": {"ecosystem": eco, "name": name},
         "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": introduced}] + ([{"fixed": fixed}] if fixed else [])}]}]}
    if vector:
        r["severity"] = [{"type": "CVSS_V3", "score": vector}]
    if upstream:
        r["upstream"] = upstream
    return r


CRIT = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
LOW = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H"


def test_keys():
    assert vulns.os_key("debian", "12") == "debian:12" and vulns.os_key("raspbian", "12") == "debian:12"
    assert vulns.os_key("ubuntu", "22.04") == "ubuntu:22.04" and vulns.os_key("almalinux", "9.4") == "almalinux:9"
    assert vulns.os_key("arch", "") is None and vulns.os_key("fedora", "40") is None
    assert vulns.eco_key("Ubuntu:22.04:LTS") == "ubuntu:22.04" and vulns.eco_key("Ubuntu:Pro:18.04:LTS") is None
    assert vulns.eco_key("Rocky Linux:9") == "rocky:9" and vulns.eco_key("Debian:12") == "debian:12"
    assert vulns.osv_ecosystem("ubuntu:22.04") == "Ubuntu:22.04:LTS" and vulns.osv_ecosystem("ubuntu:24.10") == "Ubuntu:24.10"
    assert vulns.osv_ecosystem("rocky:9") == "Rocky Linux:9"


def test_linux_matching():
    recs = [osv_rec("DEBIAN-CVE-2026-1000", "Debian:12", "openssl", "3.0.15-1~deb12u1", CRIT, upstream=["CVE-2026-1000"]),
            osv_rec("DEBIAN-CVE-2026-1001", "Debian:12", "openssl", "3.0.15-1~deb12u1", LOW),
            osv_rec("DEBIAN-CVE-2026-1002", "Debian:12", "openssl", None, CRIT),                 # no fix yet: not counted
            osv_rec("DEBIAN-CVE-2026-1003", "Debian:11", "openssl", "1.1.1w-0+deb11u2", CRIT),   # another release
            osv_rec("DEBIAN-CVE-2026-1004", "Debian:12", "linux", "6.1.115-1", CRIT),
            osv_rec("DEBIAN-CVE-2026-1005", "Debian:12", "curl", "7.88.1-10+deb12u8", None),     # no score: only if exploited
            osv_rec("DSA-5800-1", "Debian:12", "curl", "7.88.1-10+deb12u8", CRIT)]               # not the record type used
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for r in recs:
            z.writestr(r["id"] + ".json", json.dumps(r))
    idx = vulns.osv_index_zip(buf.getvalue(), "debian", {"debian:12"})
    assert set(idx["debian:12"]) == {"openssl", "linux", "curl"} and "debian:11" not in idx
    apps = [{"name": "libssl3", "version": "3.0.14-1~deb12u2", "src": "openssl", "srcver": "3.0.14-1~deb12u2"},
            {"name": "openssl", "version": "3.0.14-1~deb12u2", "src": "openssl", "srcver": "3.0.14-1~deb12u2"},
            {"name": "linux-image-6.1.0-25-amd64", "version": "6.1.106-3", "src": "linux", "srcver": "6.1.106-3"},
            {"name": "linux-image-6.1.0-27-amd64", "version": "6.1.115-1", "src": "linux", "srcver": "6.1.115-1"},  # the newer kernel
            {"name": "curl", "version": "7.88.1-10+deb12u5", "src": "curl", "srcver": "7.88.1-10+deb12u5"}]
    f = vulns.linux_findings(apps, "debian:12", idx, set(), 9.0)
    assert [x["cve"] for x in f] == ["CVE-2026-1000"] and f[0]["fixed"] == "3.0.15-1~deb12u1" and f[0]["what"] == "openssl"
    f = vulns.linux_findings(apps, "debian:12", idx, {"CVE-2026-1005"}, 9.0)
    assert {x["cve"] for x in f} == {"CVE-2026-1000", "CVE-2026-1005"} and next(x for x in f if x["cve"] == "CVE-2026-1005")["exploited"]
    assert {x["cve"] for x in vulns.linux_findings(apps, "debian:12", idx, set(), 5.0)} == {"CVE-2026-1000", "CVE-2026-1001"}
    level, detail = vulns.summarise(f, 9.0)
    assert level == "crit" and detail.startswith("1 known-exploited, 2 CVEs: curl CVE-2026-1005 (exploited), fixed in 7.88.1-10+deb12u8")
    assert vulns.summarise([], 9.0) == ("ok", "No known vulnerabilities scoring 9 or more")


def test_linux_rpm_epoch():
    idx = {"almalinux:9": {"nodejs": [["CVE-2026-2000", "0", "1:16.20.2-1.el9", 9.8]]}}
    apps = [{"name": "nodejs", "version": "16.19.1-1.el9", "src": "nodejs", "srcver": "1:16.19.1-1.el9"}]
    assert [x["cve"] for x in vulns.linux_findings(apps, "almalinux:9", idx, set(), 9.0)] == ["CVE-2026-2000"]
    apps[0]["srcver"] = "1:16.20.2-1.el9"
    assert vulns.linux_findings(apps, "almalinux:9", idx, set(), 9.0) == []


class FakeResp:
    def __init__(self, status, body):
        self.status, self.body, self.headers = status, body, {}

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def json(self, content_type=None):
        return self.body

    async def read(self):
        return json.dumps(self.body).encode()


class FakeSession:
    def __init__(self, routes):
        self.routes, self.posts, self.gets = routes, [], []

    def get(self, url, headers=None):
        self.gets.append(url)
        return FakeResp(200, self.routes[url]) if url in self.routes else FakeResp(404, {})

    def post(self, url, json=None):
        self.posts.append(json)
        return FakeResp(200, self.routes[url](json))


def test_online_and_feeds(tmp_path):
    rec = osv_rec("UBUNTU-CVE-2026-3000", "Ubuntu:22.04:LTS", "openssl", "3.0.2-0ubuntu1.18", CRIT)
    routes = {
        vulns.MSRC_LIST: {"value": [{"ID": "2026-Nov", "InitialReleaseDate": "2026-11-11T08:00:00Z", "CurrentReleaseDate": "2026-11-11T08:00:00Z",
                                     "CvrfUrl": "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/2026-Nov"}]},
        "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/2026-Nov": msrc_doc(),
        vulns.KEV_URL: {"vulnerabilities": [{"cveID": "CVE-2026-0002"}]},
        vulns.OSV_BATCH: lambda body: {"results": [{"vulns": [{"id": "UBUNTU-CVE-2026-3000", "modified": "x"}, {"id": "USN-7000-1", "modified": "x"}]}
                                                   for _ in body["queries"]]},
        vulns.OSV_VULN.format(id="UBUNTU-CVE-2026-3000"): rec,
    }
    s = FakeSession(routes)
    f = vulns.Feeds(tmp_path, logging.getLogger("t"))
    q = [("ubuntu:22.04", "openssl", "3.0.2-0ubuntu1.15")]
    assert asyncio.run(f.refresh(s, 1e9, "online", {"ubuntu:22.04"}, q)) is True
    assert s.posts[0] == {"queries": [{"package": {"name": "openssl", "ecosystem": "Ubuntu:22.04:LTS"}, "version": "3.0.2-0ubuntu1.15"}]}
    assert vulns.OSV_VULN.format(id="USN-7000-1") not in s.gets      # only the per-CVE records are fetched
    assert "CVE-2026-0002" in f.kev and f.msrc["10.0.17763"]["CVE-2026-0002"][0] == 6414
    apps = [{"name": "libssl3", "src": "openssl", "srcver": "3.0.2-0ubuntu1.15", "version": "3.0.2-0ubuntu1.15"}]
    assert [x["cve"] for x in vulns.linux_findings(apps, "ubuntu:22.04", f.osv, f.kev, 9.0)] == ["CVE-2026-3000"]
    # Nothing changed: nothing fetched again; and it all comes back after a restart
    n = len(s.gets)
    assert asyncio.run(f.refresh(s, 1e9 + 60, "online", {"ubuntu:22.04"}, q)) is False and len(s.gets) == n
    g = vulns.Feeds(tmp_path, logging.getLogger("t"))
    g.load()
    assert g.osv == f.osv and g.kev == f.kev and g.msrc == f.msrc
    # An error is recorded for the dashboard, and the rest still works
    bad = FakeSession({})
    asyncio.run(g.refresh(bad, 1e9 + 2 * vulns.Feeds.DAY, "online", {"ubuntu:22.04"}, q + [("ubuntu:22.04", "curl", "1")]))
    assert "Microsoft" in g.info["errors"] and g.msrc  # keeps what it had


# -- the add-on side: the Vulnerabilities check on a computer -----------------------------------
def _mon(tmp_path, apps=None, opts=None):
    import types
    import main
    M = main.Monitor
    m = types.SimpleNamespace(opts={"vuln_checks": True, "vuln_min_score": 9, "vuln_linux_source": "local", **(opts or {})},
                              vulnfeeds=vulns.Feeds(tmp_path, logging.getLogger("t")), _vf={})
    m.software = lambda aid: {"hash": "h1", "updated": 1, "apps": apps or []}
    for name in ("vuln_findings", "vuln_check", "_vuln_why_not", "_vuln_key", "vulns_by_app", "vulns_view", "_vuln_wanted"):
        setattr(m, name, types.MethodType(getattr(M, name), m))
    return m, main


def test_windows_check(tmp_path):
    m, main = _mon(tmp_path)
    h = main.Host(key="srv01", name="SRV01", host="192.168.1.10", agent_id="a1",
                  agent_report={"os_build": "10.0.17763.6293", "os": "Windows Server 2019"})
    assert m.vuln_check(h)["detail"] == "Waiting for Microsoft's update data to download"
    m.vulnfeeds.msrc = vulns.msrc_merge([vulns.msrc_compact(msrc_doc())])
    m.vulnfeeds.version += 1
    c = m.vuln_check(h)
    assert c["level"] == main.agentlib.CRIT and c["ids"] == ["CVE-2026-0001", "CVE-2026-0002"]  # 0001 is exploited: red
    assert c["detail"].startswith("1 known-exploited, 2 CVEs: Windows CVE-2026-0001 (8.8, exploited)") and c["detail"].endswith("fixed in build 10.0.17763.6414")
    h.agent_report = {"os_build": "10.0.14393.7000"}
    assert "probably out of support" in m.vuln_check(h)["detail"]
    m.opts["vuln_checks"] = False
    assert m.vuln_check(h) is None


def test_linux_check(tmp_path):
    apps = [{"name": "libssl3", "version": "3.0.14-1~deb12u2", "src": "openssl", "srcver": "3.0.14-1~deb12u2"},
            {"name": "openssl", "version": "3.0.14-1~deb12u2", "src": "openssl", "srcver": "3.0.14-1~deb12u2"},
            {"name": "bash", "version": "5.2.15-2+b7", "src": "bash", "srcver": "5.2.15-2"}]
    m, main = _mon(tmp_path, apps)
    h = main.Host(key="pc01", name="PC01", host="192.168.1.11", agent_id="a2",
                  agent_report={"os_family": "linux", "os_id": "debian", "os_version_id": "12"})
    assert m.vuln_check(h)["detail"].startswith("Waiting for the Linux vulnerability data")
    m.vulnfeeds.osv = {"debian:12": {"openssl": [["CVE-2026-1000", "0", "3.0.15-1~deb12u1", 9.8]]}}
    m.vulnfeeds.version += 1
    c = m.vuln_check(h)
    assert c["level"] == main.agentlib.WARN and c["ids"] == ["CVE-2026-1000"]                 # not exploited: amber
    assert sorted(m.vulns_by_app(h)) == [0, 1]                                                # both openssl packages marked
    m.hosts = {"pc01": h}
    assert m._vuln_wanted("online") == ({"debian:12"}, [("debian:12", "bash", "5.2.15-2"), ("debian:12", "openssl", "3.0.14-1~deb12u2")])
    h.agent_report = {"os_family": "linux"}                                                   # an older agent
    assert m.vuln_check(h)["detail"] == "Not checked yet: needs Linux agent 1.0.20 or later"
    m.opts["vuln_linux_source"] = "off"
    assert m.vuln_check(h) is None


def test_online_retries_and_covered(tmp_path):
    """A release with nothing to fix still counts as checked; a failed fetch is tried again next time."""
    routes = {vulns.MSRC_LIST: {"value": []}, vulns.KEV_URL: {"vulnerabilities": [{"cveID": "CVE-2026-0002"}]},
              vulns.OSV_BATCH: lambda body: {"results": [{"vulns": [{"id": "UBUNTU-CVE-2026-3001", "modified": "y"}]} for _ in body["queries"]]}}
    s = FakeSession(routes)
    f = vulns.Feeds(tmp_path, logging.getLogger("t"))
    q = [("ubuntu:24.04", "bash", "5.2.21-2ubuntu4")]
    asyncio.run(f.refresh(s, 1e9, "online", set(), q))
    assert "osv_online_at" not in f.meta and not f.covered               # the record couldn't be fetched: not done
    routes[vulns.OSV_VULN.format(id="UBUNTU-CVE-2026-3001")] = osv_rec("UBUNTU-CVE-2026-3001", "Ubuntu:24.04:LTS", "bash", None, CRIT)
    asyncio.run(f.refresh(s, 1e9 + 3600, "online", set(), q))           # an hour later it's fetched
    assert f.covered == {"ubuntu:24.04"} and "ubuntu:24.04" not in f.osv  # nothing to fix, but checked


def test_rpm_online_queries_binary_names(tmp_path):
    apps = [{"name": "python3-libs", "version": "3.9.18-3.el9", "src": "python3.9", "srcver": "3.9.18-3.el9"}]
    m, main = _mon(tmp_path, apps, {"vuln_linux_source": "online"})
    h = main.Host(key="pc02", name="PC02", host="192.168.1.12", agent_id="a3",
                  agent_report={"os_family": "linux", "os_id": "rocky", "os_version_id": "9.4"})
    m.hosts = {"pc02": h}
    assert m._vuln_wanted("online")[1] == [("rocky:9", "python3-libs", "3.9.18-3.el9"), ("rocky:9", "python3.9", "3.9.18-3.el9")]


def test_same_cve_in_two_packages():
    idx = {"debian:12": {"firefox-esr": [["CVE-2026-4000", "0", "128.5.0esr-1~deb12u1", 9.8]],
                         "thunderbird": [["CVE-2026-4000", "0", "1:128.5.0esr-1~deb12u1", 9.8]]}}
    apps = [{"name": "firefox-esr", "src": "firefox-esr", "srcver": "128.4.0esr-1~deb12u1", "version": ""},
            {"name": "thunderbird", "src": "thunderbird", "srcver": "1:128.4.0esr-1~deb12u1", "version": ""}]
    f = vulns.linux_findings(apps, "debian:12", idx, set(), 9.0)
    assert sorted((x["what"], x["fixed"]) for x in f) == [("firefox-esr", "128.5.0esr-1~deb12u1"), ("thunderbird", "1:128.5.0esr-1~deb12u1")]
