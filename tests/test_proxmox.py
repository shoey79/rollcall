"""Proxmox VE and Proxmox Backup Server through the Linux agent (owner's request, 23 Nov): read-only pvesh and
PBS commands, stood in here by scripts on the PATH. Names and addresses are made up.

Run from the repository root:  python3 -m pytest tests/test_proxmox.py
"""
import importlib.util
import json
import os
import stat
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "rollcall" / "app"))
import agents as A  # noqa: E402

NOW = 1764150000
PVE = {
    "/cluster/status": [{"type": "cluster", "name": "lab", "quorate": 1, "nodes": 3},
                        {"type": "node", "name": "pve01", "online": 1, "local": 1}, {"type": "node", "name": "pve02", "online": 1},
                        {"type": "node", "name": "pve03", "online": 0}],
    "/cluster/resources": [{"vmid": 100, "name": "DC01", "type": "qemu", "node": "pve01", "status": "running", "uptime": 86400 * 3, "cpu": 0.05,
                            "maxcpu": 2, "mem": 2147483648, "maxmem": 4294967296, "hastate": "started"},
                           {"vmid": 101, "name": "web01", "type": "lxc", "node": "pve02", "status": "stopped", "maxcpu": 1, "maxmem": 1073741824},
                           {"vmid": 9000, "name": "tmpl", "type": "qemu", "template": 1}],
    "/nodes/pve01/storage": [{"storage": "local-zfs", "type": "zfspool", "active": 1, "enabled": 1, "total": 1000, "used": 950, "content": "images,rootdir"},
                             {"storage": "nas", "type": "nfs", "active": 0, "enabled": 1, "shared": 1, "total": 0, "used": 0, "content": "backup"}],
    "/nodes/pve01/disks/zfs": [{"name": "rpool", "health": "DEGRADED", "size": 1000, "alloc": 400}],
    "/nodes/pve01/tasks": [
        {"type": "vzdump", "id": "", "starttime": NOW - 2 * 86400, "endtime": NOW - 2 * 86400 + 900, "status": "OK"},
        {"type": "vzdump", "id": "", "starttime": NOW - 86400, "endtime": NOW - 86400 + 900, "status": "WARNINGS: 1"},
        {"type": "vzdump", "id": "100", "starttime": NOW - 3600, "endtime": NOW - 3000, "status": "job errors"},
        {"type": "vzdump", "id": "100", "starttime": NOW - 60, "status": "running"}],
    "/cluster/backup": [{"id": "backup-1a2b", "schedule": "daily 02:00", "enabled": 1, "storage": "nas", "comment": "Nightly"}],
    "/nodes/pve01/replication": [{"id": "100-0", "guest": 100, "target": "pve02", "last_sync": NOW - 600, "fail_count": 2, "error": "no space left"}],
    "/cluster/ha/status/current": [{"type": "quorum", "status": "OK"}, {"type": "service", "sid": "vm:100", "state": "started", "node": "pve01"}],
    "/nodes/pve01/subscription": {"status": "notfound"},
}
PBS_USAGE = [{"store": "store1", "total": 100, "used": 98}]
PBS_TASKS = [{"worker_type": "garbage_collection", "worker_id": "store1", "starttime": NOW - 7200, "endtime": NOW - 7000, "status": "OK"},
             {"worker_type": "verificationjob", "worker_id": "store1:v-1", "starttime": NOW - 3600, "endtime": NOW - 3500, "status": "verification failed - 2 snapshots"},
             {"worker_type": "backup", "worker_id": "store1:vm/100", "starttime": NOW - 3600, "endtime": NOW - 3500, "status": "OK"}]


def fake_bin(tmp_path):
    b = tmp_path / "bin"
    b.mkdir()
    (tmp_path / "pve.json").write_text(json.dumps(PVE))
    (tmp_path / "pbs.json").write_text(json.dumps({"usage": PBS_USAGE, "tasks": PBS_TASKS}))
    calls = tmp_path / "calls.txt"
    scripts = {
        "pvesh": f"""import json, sys
open({str(calls)!r}, "a").write(" ".join(sys.argv[1:]) + "\\n")
if sys.argv[1] != "get": sys.exit(9)   # read only: anything else is a test failure
d = json.load(open({str(tmp_path / 'pve.json')!r}))
p = sys.argv[2]
if p not in d: sys.stderr.write("no such path"); sys.exit(2)
print(json.dumps(d[p]))""",
        "pveversion": 'print("pve-manager/8.2.4/faa83925c9641325 (running kernel: 6.8.8-2-pve)")',
        "proxmox-backup-manager": f"""import json, sys
open({str(calls)!r}, "a").write("pbm " + " ".join(sys.argv[1:]) + "\\n")
if sys.argv[1] == "versions": print("proxmox-backup-server 3.2.7-1 running version: 3.2.7"); sys.exit(0)
if sys.argv[1:3] == ["task", "list"]: print(json.dumps(json.load(open({str(tmp_path / 'pbs.json')!r}))["tasks"])); sys.exit(0)
sys.exit(9)""",
        "proxmox-backup-debug": f"""import json, sys
if sys.argv[1:4] == ["api", "get", "/status/datastore-usage"]: print(json.dumps(json.load(open({str(tmp_path / 'pbs.json')!r}))["usage"])); sys.exit(0)
sys.exit(9)""",
    }
    for name, body in scripts.items():
        p = b / name
        p.write_text(f"#!{sys.executable}\n" + body + "\n")
        p.chmod(p.stat().st_mode | stat.S_IEXEC)
    return b, calls


def load_agent(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location("lx_pve_agent", ROOT / "rollcall" / "app" / "agent" / "rollcall-agent.py")
    mod = importlib.util.module_from_spec(spec)
    monkeypatch.setenv("PM_PREFIX", str(tmp_path / "root"))
    spec.loader.exec_module(mod)
    return mod


def test_agent_reads_proxmox_read_only(tmp_path, monkeypatch):
    b, calls = fake_bin(tmp_path)
    monkeypatch.setenv("PATH", str(b) + os.pathsep + os.environ["PATH"])
    ag = load_agent(tmp_path, monkeypatch)
    monkeypatch.setattr(ag.socket, "gethostname", lambda: "pve01.example.local")
    pv = ag.proxmox_ve({})
    assert pv["version"] == "8.2.4" and pv["cluster"] == {"name": "lab", "quorate": True, "votes": 3}
    assert [n["name"] for n in pv["nodes"] if not n["online"]] == ["pve03"]
    assert [g["vmid"] for g in pv["guests"]] == [100, 101]                      # templates left out, this node first
    assert pv["guests"][0]["cpu_pct"] == 5.0 and pv["guests"][0]["mem_mb"] == 2048 and pv["guests"][1]["kind"] == "CT"
    jobs = {j["id"]: j for j in pv["backup_jobs"]}
    assert jobs["pve:pve01:all"]["result"] == "Warning" and jobs["pve:pve01:all"]["name"] == "All guests on pve01"
    assert len(jobs["pve:pve01:all"]["runs"]) == 2
    g = jobs["pve:pve01:100"]
    assert g["result"] == "Failed" and g["detail"] == "job errors" and g["name"] == "Guest 100 DC01" and g["last_success"] is None
    assert pv["replication"][0]["fail_count"] == 2 and pv["ha"] == [{"sid": "vm:100", "state": "started", "node": "pve01", "status": ""}]
    assert all(line.split()[0] in ("get", "pbm") for line in calls.read_text().splitlines())    # only reads

    pbs = ag.proxmox_backup_server({})
    assert pbs["version"] == "3.2.7-1" and pbs["datastores"][0]["used"] == 98
    kinds = {j["id"]: j for j in pbs["backup_jobs"]}
    assert set(kinds) == {"pbs:Garbage collection:store1", "pbs:Verify:store1:v-1"}      # client backups aren't jobs here
    assert kinds["pbs:Verify:store1:v-1"]["result"] == "Failed"


def test_proxmox_checks(tmp_path, monkeypatch):
    b, _ = fake_bin(tmp_path)
    monkeypatch.setenv("PATH", str(b) + os.pathsep + os.environ["PATH"])
    ag = load_agent(tmp_path, monkeypatch)
    monkeypatch.setattr(ag.socket, "gethostname", lambda: "pve01")
    pv, pbs = ag.proxmox_ve({}), ag.proxmox_backup_server({})
    jobs = pv.pop("backup_jobs") + pbs.pop("backup_jobs")
    report = {"hostname": "pve01", "os_family": "linux", "os": "Debian 12", "roles": ["Proxmox VE", "Proxmox Backup Server"],
              "checks": {"proxmox": pv, "pbs": pbs, "backups": {"jobs": jobs}, "evil": 1}}
    r = A.normalize_report(report)
    out = A.evaluate(r, {}, NOW, {})
    c = {x["key"]: x for x in out["checks"]}
    p = c["proxmox"]
    assert p["level"] == A.WARN   # one node of three offline, storage 95% full and one not active, ZFS degraded, replication failing
    for bit in ("pve03", "local-zfs 95% full", "nas isn't active", "rpool DEGRADED", "replication 100-0 failing"):
        assert bit in p["detail"], bit
    assert c["pbs"]["level"] == A.CRIT and "store1 98% full" in c["pbs"]["detail"]
    assert c["backups"]["level"] == A.CRIT       # guest 100's backup failed

    # Lost quorum is red (after two reports, like ping)
    pv2 = dict(r["checks"]["proxmox"], cluster={"name": "lab", "quorate": False, "votes": 3}, storage=[], zfs=[], replication=[])
    q = A.proxmox_check(pv2, {})
    assert q["level"] == A.CRIT and "lost quorum" in q["detail"] and q["confirm"]
    ok = A.proxmox_check({"guests": [{"status": "running"}, {"status": "stopped"}], "nodes": []}, {})
    assert ok["level"] == A.OK and ok["detail"] == "1 of 2 guests running"
