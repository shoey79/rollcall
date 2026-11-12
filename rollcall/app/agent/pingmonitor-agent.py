#!/usr/bin/env python3
"""Rollcall agent for Linux (formerly Ping Monitor).

Reports server health to the Rollcall Home Assistant add-on. One file,
Python 3.8+ standard library only. Each run (every 5 minutes, from a systemd
timer) it reports:

  - disk space per mounted filesystem, CPU, memory, load, uptime
  - Docker containers (state, health check, restarts), with Immich's stack
    recognised as such, plus key systemd services and any failed units
  - Immich: API reachable, version, and with an admin API key, job queues
    and library statistics
  - serious journal errors since the last run (out-of-memory kills, disk and
    filesystem errors are flagged as critical)
  - security: failed SSH logins, sudo failures, users created or deleted,
    users added to groups
  - updates: pending and security packages, last apt run, reboot required

It only ever sends reports; it never runs anything it's told to.

Install (as root):
    sudo python3 pingmonitor-agent.py --install
    sudo python3 pingmonitor-agent.py --install --immich-api-key KEY
Then approve the server in the Rollcall dashboard (Agents).

Other options: --uninstall, --report (print the report, send nothing).
"""
import argparse
import hashlib
import hmac
import concurrent.futures
import datetime
import glob
import gzip
import json
import os
import re
import secrets
import shutil
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request

AGENT_VERSION = "1.0.16"
SERVER = "__PM_SERVER__"
ENROL_KEY = "__PM_ENROL_KEY__"
IGNORE_CERT = False

PREFIX = os.environ.get("PM_PREFIX", "")          # for testing only
DATA_DIR = PREFIX + "/var/lib/pingmonitor"
CONFIG_PATH = PREFIX + "/etc/pingmonitor/agent.conf"
INSTALL_PATH = PREFIX + "/usr/local/lib/pingmonitor/pingmonitor-agent.py"
UNIT_DIR = PREFIX + "/etc/systemd/system"
STATE_PATH = os.path.join(DATA_DIR, "state.json")
LOG_PATH = os.path.join(DATA_DIR, "agent.log")
UNIT = "pingmonitor-agent"

REAL_FS = {"ext2", "ext3", "ext4", "xfs", "btrfs", "zfs", "f2fs", "nfs", "nfs4", "cifs", "smb3",
           "fuseblk", "ntfs", "ntfs3", "vfat", "exfat", "bcachefs"}
SKIP_MOUNTS = ("/snap/", "/var/lib/docker/", "/var/snap/", "/run/", "/proc", "/sys", "/dev")
WATCH_UNITS = ["docker.service", "containerd.service", "ssh.service", "sshd.service", "cron.service",
               "systemd-timesyncd.service", "chrony.service", "smbd.service", "nfs-server.service"]
CRITICAL_PATTERNS = re.compile(
    r"Out of memory: Killed process|oom-kill|invoked oom-killer|I/O error|EXT4-fs error|XFS .*(error|corrupt)"
    r"|BTRFS (error|critical)|Hardware Error|Buffer I/O error|blk_update_request: (critical|I/O)", re.I)
# Virtual floppy and CD drives (common on VMs) log read errors when empty or probed: not a disk fault.
NOISE_PATTERNS = re.compile(r"\b(dev|device) (fd\d+|sr\d+)\b|\bfloppy\d*:|\bsr\d+: |\[sr\d+\]", re.I)

ERRORS = []
TIMINGS = {}


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
def log(msg):
    line = "%s %s" % (datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), msg)
    print(line, flush=True)
    try:
        if os.path.exists(LOG_PATH) and os.path.getsize(LOG_PATH) > 1024 * 1024:
            os.replace(LOG_PATH, LOG_PATH + ".old")
        with open(LOG_PATH, "a") as f:
            f.write(line + "\n")
    except OSError:
        pass


def collector_error(name, err):
    msg = ("%s: %s" % (name, err)).replace("\n", " ")[:300]
    ERRORS.append(msg)
    log("WARN " + msg)


class step:
    """Time one part of the collection: with step('disks'): ..."""
    def __init__(self, name):
        self.name = name

    def __enter__(self):
        self.t0 = time.monotonic()

    def __exit__(self, exc_type, exc, tb):
        TIMINGS[self.name] = int((time.monotonic() - self.t0) * 1000)
        if exc_type is not None and exc_type is not KeyboardInterrupt:
            collector_error(self.name, exc)
            return True  # a failed collector is reported, not fatal


def run(cmd, timeout=30):
    """Run a command; returns (returncode, stdout, stderr). Never raises for a missing command."""
    if not shutil.which(cmd[0]):
        return 127, "", "%s not found" % cmd[0]
    try:
        # Commands' output is parsed, so read it in the C locale whatever the system's language is
        env = dict(os.environ, LC_ALL="C.UTF-8", LANG="C.UTF-8", LANGUAGE="")
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout,
                           universal_newlines=True, errors="replace", env=env)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return 124, "", "timed out after %ss" % timeout


def utc(ts):
    if ts is None:
        return None
    return datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def limit(text, n=300):
    t = re.sub(r"\s+", " ", str(text or "")).strip()
    return t if len(t) <= n else t[:n - 1] + "\u2026"


def read(path, default=""):
    try:
        with open(path, errors="replace") as f:
            return f.read()
    except OSError:
        return default


def load_json(path, default):
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def save_json(path, data, mode=0o600):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode), "w") as f:
        json.dump(data, f, indent=1)
    os.replace(tmp, path)


def parse_iso(s):
    try:
        return datetime.datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc).timestamp()
    except (TypeError, ValueError):
        return None


# --------------------------------------------------------------------------
# System
# --------------------------------------------------------------------------
def cpu_percent(interval=1.0):
    def snap():
        parts = read("/proc/stat").splitlines()[0].split()[1:]
        vals = [int(x) for x in parts]
        idle = vals[3] + (vals[4] if len(vals) > 4 else 0)
        return idle, sum(vals)
    i1, t1 = snap()
    time.sleep(interval)
    i2, t2 = snap()
    return int(round(100 * (1 - (i2 - i1) / max(1, t2 - t1))))


VIRT_NAMES = {"kvm": "KVM / QEMU", "qemu": "KVM / QEMU", "microsoft": "Hyper-V", "vmware": "VMware", "oracle": "VirtualBox",
              "xen": "Xen", "parallels": "Parallels", "amazon": "AWS", "google": "Google Cloud", "bochs": "KVM / QEMU",
              "lxc": "LXC container", "lxc-libvirt": "LXC container", "openvz": "OpenVZ container", "docker": "Docker container",
              "podman": "Podman container", "wsl": "WSL", "systemd-nspawn": "nspawn container"}


def virtual_kind(vendor: str, model: str) -> str:
    """What the machine runs on ('' for physical): systemd-detect-virt if there is one, else its DMI vendor/model."""
    rc, out, _ = run(["systemd-detect-virt"])
    kind = out.strip().lower()
    if kind and kind != "none":
        return VIRT_NAMES.get(kind, kind)
    if rc == 0 or kind == "none":
        return ""
    t = f"{vendor} {model}"
    for pat, name in ((r"Microsoft.*Virtual", "Hyper-V"), (r"VMware", "VMware"), (r"VirtualBox|innotek", "VirtualBox"),
                      (r"QEMU|KVM|Proxmox|Standard PC \(|oVirt|Red Hat|Bochs", "KVM / QEMU"), (r"Xen", "Xen"),
                      (r"Amazon EC2", "AWS"), (r"Google Compute", "Google Cloud")):
        if re.search(pat, t, re.I):
            return name
    return ""


def system_info():
    info = {}
    osr = dict(re.findall(r'^(\w+)="?([^"\n]*)"?$', read("/etc/os-release"), re.M))
    kernel = os.uname().release
    info["os"] = limit("%s (kernel %s)" % (osr.get("PRETTY_NAME", "Linux"), kernel), 120)
    info["os_build"] = kernel
    btime = re.search(r"^btime (\d+)", read("/proc/stat"), re.M)
    if btime:
        info["boot_time"] = utc(int(btime.group(1)))
    try:
        info["uptime_s"] = int(float(read("/proc/uptime").split()[0]))
    except (IndexError, ValueError):
        pass
    mem = dict((k, int(v)) for k, v in re.findall(r"^(\w+):\s+(\d+) kB", read("/proc/meminfo"), re.M))
    if mem.get("MemTotal"):
        info["mem_total_mb"] = mem["MemTotal"] // 1024
        info["mem_free_mb"] = mem.get("MemAvailable", mem.get("MemFree", 0)) // 1024
    try:
        info["load"] = [round(x, 2) for x in os.getloadavg()]
    except OSError:
        pass
    with step("cpu"):
        info["cpu_pct"] = cpu_percent()
    fqdn = socket.getfqdn()
    info["domain"] = fqdn.split(".", 1)[1] if "." in fqdn else ""
    info["part_of_domain"] = False
    info["workstation"] = False
    dmi = {k: read(f"/sys/class/dmi/id/{k}").strip() for k in ("sys_vendor", "product_name", "product_serial")}
    info["hw_vendor"], info["hw_model"] = dmi["sys_vendor"][:80], dmi["product_name"][:80]
    if dmi["product_serial"] and not re.match(r"^(0+|None|Default string|To be filled by O\.E\.M\.|System Serial Number)$", dmi["product_serial"], re.I):
        info["serial"] = dmi["product_serial"][:60]
    info["virtual"] = virtual_kind(dmi["sys_vendor"], dmi["product_name"])
    ips = []
    rc, out, _ = run(["ip", "-4", "-o", "addr", "show", "scope", "global"])
    for m in re.finditer(r"^\d+:\s+(\S+)\s+inet (\d+\.\d+\.\d+\.\d+)/", out, re.M):
        # Skip Docker's own bridges: the add-on wants the server's LAN address.
        if m.group(2) not in ips and not re.match(r"(docker|br-|veth|virbr|cni|flannel|tailscale)", m.group(1)):
            ips.append(m.group(2))
    if not ips:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("10.255.255.255", 1))
            ips.append(s.getsockname()[0])
            s.close()
        except OSError:
            pass
    info["ips"] = ips[:8]
    info["pending_reboot"] = os.path.exists("/var/run/reboot-required")
    pkgs = read("/var/run/reboot-required.pkgs").split()
    if pkgs:
        info["reboot_packages"] = sorted(set(pkgs))[:20]
    return info


def last_apt_run():
    """Newest apt history entry that installed or upgraded something."""
    best = None
    for path in sorted(glob.glob("/var/log/apt/history.log*")):
        try:
            opener = gzip.open if path.endswith(".gz") else open
            with opener(path, "rt", errors="replace") as f:
                text = f.read()
        except OSError:
            continue
        for block in text.split("\n\n"):
            end = re.search(r"^End-Date: (\d{4}-\d\d-\d\d\s+\d\d:\d\d:\d\d)", block, re.M)
            changed = re.findall(r"^(Upgrade|Install): (.*)$", block, re.M)
            if not end or not changed:
                continue
            ts = time.mktime(time.strptime(re.sub(r"\s+", " ", end.group(1)), "%Y-%m-%d %H:%M:%S"))
            count = sum(len(re.findall(r"\), |\)$", line)) or 1 for _, line in changed)
            if best is None or ts > best[0]:
                best = (ts, count)
    return best


def pending_updates():
    checker = "/usr/lib/update-notifier/apt-check"
    if os.path.exists(checker):
        rc, out, err = run([checker], timeout=120)
        m = re.match(r"\s*(\d+);(\d+)", err or out)
        if m:
            return int(m.group(1)), int(m.group(2))
    rc, out, _ = run(["apt-get", "-s", "-o", "Debug::NoLocking=1", "upgrade"], timeout=120)
    if rc == 0:
        lines = [l for l in out.splitlines() if l.startswith("Inst ")]
        return len(lines), sum(1 for l in lines if "-security" in l)
    return None, None


def patch_info(state, boot_ts):
    """apt history and pending updates, re-checked every 6 hours, after a restart, or as soon
    as packages are installed or the package lists are refreshed (apt upgrade / apt update)."""
    c = state.get("patch") or {}
    checked = parse_iso(c.get("checked"))
    changed = 0.0
    for path in ("/var/lib/dpkg/status", "/var/lib/apt/lists", "/var/log/apt/history.log"):
        try:
            changed = max(changed, os.path.getmtime(path))
        except OSError:
            pass
    if checked and time.time() - checked < 6 * 3600 and not (boot_ts and boot_ts > checked) and changed <= checked:
        c["cached"] = True
        return c
    c = {"checked": utc(time.time()), "cached": False}
    last = last_apt_run()
    if last:
        c["date"] = utc(last[0])
        c["kb"] = "%d package(s)" % last[1]
        c["source"] = "apt history"
    c["pending"], c["security"] = pending_updates()
    state["patch"] = {k: v for k, v in c.items() if k != "cached"}
    return c


# --------------------------------------------------------------------------
# Disks
# --------------------------------------------------------------------------
def disks():
    seen, out, mounts = set(), [], []
    for line in read("/proc/mounts").splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        dev, mnt, fs = parts[0], parts[1].replace("\\040", " "), parts[2]
        if fs not in REAL_FS or any(mnt.startswith(p) for p in SKIP_MOUNTS) or dev in seen:
            continue
        seen.add(dev)
        mounts.append((dev, mnt, fs))

    def stat(m):
        st = os.statvfs(m[1])
        return m, st.f_blocks * st.f_frsize, st.f_bavail * st.f_frsize

    # A hung network mount mustn't stall the whole run.
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
        futures = {ex.submit(stat, m): m for m in mounts}
        for fut, m in futures.items():
            try:
                (dev, mnt, fs), size, free = fut.result(timeout=5)
                if size < 0.5 * 1024 ** 3:
                    continue  # tiny system partitions (e.g. a small /boot/efi) aren't worth alerting on
                out.append({"name": mnt, "label": "%s (%s)" % (dev, fs),
                            "size_gb": round(size / 1024 ** 3, 1), "free_gb": round(free / 1024 ** 3, 1)})
            except Exception as err:  # noqa: BLE001
                collector_error("disk %s" % m[1], err)
    return out


def installed_apps():
    """Installed packages from dpkg (Debian, Ubuntu) or rpm (RHEL, Fedora, SUSE): name, version, publisher, size."""
    out = []
    if shutil.which("dpkg-query"):
        rc, text, _ = run(["dpkg-query", "-W", "-f", "${db:Status-Abbrev}\\t${Package}\\t${Version}\\t${Maintainer}\\t${Installed-Size}\\t${Architecture}\\n"])
        for line in text.splitlines():
            f = line.split("\t")
            if len(f) < 6 or not f[0].startswith("ii"):
                continue
            out.append({"name": f[1][:150], "version": f[2][:60], "publisher": re.sub(r"\s*<[^>]*>", "", f[3])[:100], "installed": "",
                        "size_mb": round(int(f[4]) / 1024, 1) if f[4].isdigit() else 0, "arch": f[5][:12], "scope": "machine"})
    elif shutil.which("rpm"):
        rc, text, _ = run(["rpm", "-qa", "--qf", "%{NAME}\\t%{VERSION}-%{RELEASE}\\t%{VENDOR}\\t%{SIZE}\\t%{ARCH}\\t%{INSTALLTIME}\\n"])
        for line in text.splitlines():
            f = line.split("\t")
            if len(f) < 6 or f[0].startswith("gpg-pubkey"):
                continue
            when = time.strftime("%Y-%m-%d", time.gmtime(int(f[5]))) if f[5].isdigit() else ""
            out.append({"name": f[0][:150], "version": f[1][:60], "publisher": ("" if f[2] == "(none)" else f[2])[:100], "installed": when,
                        "size_mb": round(int(f[3]) / 1048576, 1) if f[3].isdigit() else 0, "arch": f[4][:12], "scope": "machine"})
    else:
        return None
    out.sort(key=lambda a: (a["name"].lower(), a["version"]))
    return out[:5000]


def upgradable(state):
    """Newer package versions the package manager already knows about (its local cache: nothing is
    downloaded here). Re-read at most hourly. {package: version}"""
    c = state.get("upgradable") or {}
    if c.get("at") and time.time() - c["at"] < 3600:
        return c.get("pkgs") or {}
    pkgs = {}
    if shutil.which("apt"):
        rc, out, _ = run(["apt", "list", "--upgradable"], timeout=60)
        for m in re.finditer(r"^([^/\s]+)/\S+\s+(\S+)", out, re.M):
            pkgs[m.group(1)] = m.group(2)
    elif shutil.which("dnf") or shutil.which("yum"):
        rc, out, _ = run([shutil.which("dnf") or shutil.which("yum"), "-C", "-q", "check-update"], timeout=60)
        for m in re.finditer(r"^(\S+?)\.(?:x86_64|aarch64|noarch|i686|armv7hl)\s+(\S+)\s+\S+", out, re.M):
            pkgs[m.group(1)] = m.group(2)
    state["upgradable"] = {"at": time.time(), "pkgs": pkgs}
    return pkgs


def apps_hash(apps):
    text = "\n".join("|".join(str(a.get(k, "")) for k in ("name", "version", "publisher", "arch", "scope", "available")) for a in apps)
    return hashlib.sha256(text.encode()).hexdigest()[:32]


def signed_in_users(text=None):
    """Who is signed in, from `who -u`: user, terminal, sign-in time, idle, and where from (SSH)."""
    if text is None:
        rc, text, _ = run(["who", "-u"])
    out = []
    for line in text.splitlines():
        m = re.match(r"^(\S+)\s+(\S+)\s+(\d{4}-\d\d-\d\d \d\d:\d\d)\s+(\S+)\s+(?:\d+\s*)?(?:\((.*)\))?", line)
        if not m:
            continue
        user, tty, since, idle, frm = m.groups()
        mins = 0
        if re.match(r"^\d+:\d+$", idle):
            h, mm = idle.split(":"); mins = int(h) * 60 + int(mm)
        elif idle == "old":
            mins = 1440
        try:
            since = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.mktime(time.strptime(since, "%Y-%m-%d %H:%M"))))
        except ValueError:
            since = ""
        frm = (frm or "").strip()
        out.append({"user": user[:80], "session": "ssh" if frm and not frm.startswith(":") else "console", "state": "active",
                    "idle_min": mins, "since": since, "from": frm[:80], "tty": tty[:20]})
        if len(out) >= 50:
            break
    return out


def network_report():
    """Every network interface except loopback and container plumbing: state, link speed, addresses, counters."""
    base, out = "/sys/class/net", []
    try:
        names = sorted(os.listdir(base))
    except OSError:
        return None
    addrs = {}
    rc, text, _ = run(["ip", "-o", "addr", "show"])
    for m in re.finditer(r"^\d+:\s+(\S+)\s+inet6? (\S+)", text, re.M):
        if not m.group(2).startswith(("fe80", "127.", "::1")):
            addrs.setdefault(m.group(1).split("@")[0], []).append(m.group(2))
    for n in names:
        if n == "lo" or re.match(r"(veth|ifb\d|dummy\d|docker\d|br-[0-9a-f]{12}|cni|flannel|cali|vxlan\.calico)", n):
            continue
        d = f"{base}/{n}"
        num = lambda f: int(read(f"{d}/{f}").strip() or -1) if read(f"{d}/{f}").strip().lstrip("-").isdigit() else None  # noqa: E731
        flags = read(f"{d}/flags").strip()
        admin_up = bool(int(flags, 16) & 1) if flags.startswith("0x") else True
        oper, carrier = read(f"{d}/operstate").strip(), num("carrier")
        status = "disabled" if not admin_up else "up" if oper == "up" or (oper == "unknown" and carrier == 1) else "down"
        speed = num("speed") if status == "up" else None
        row = {"name": n[:80], "desc": (read(f"{d}/device/uevent").split("DRIVER=")[-1].split("\n")[0] if os.path.exists(f"{d}/device") else "")[:120],
               "status": status, "speed_mbps": speed if speed and speed > 0 else 0, "mac": read(f"{d}/address").strip()[:40],
               "virtual": not os.path.exists(f"{d}/device"), "media": "", "ips": addrs.get(n, [])[:8]}
        for k, f in (("rx_bytes", "rx_bytes"), ("tx_bytes", "tx_bytes"), ("rx_errors", "rx_errors"), ("tx_errors", "tx_errors"),
                     ("rx_drops", "rx_dropped"), ("tx_drops", "tx_dropped")):
            v = num(f"statistics/{f}")
            if v is not None and v >= 0:
                row[k] = v
        out.append(row)
        if len(out) >= 40:
            break
    return {"adapters": out} if out else None


def storage_health():
    """Software RAID (mdadm) arrays and ZFS pools."""
    st = {"physical": [], "virtual": [], "volumes": [], "dyn_disks": [], "drives": []}
    md = read("/proc/mdstat")
    blocks = re.split(r"\n(?=md\d+\s*:)", md)
    for b in blocks:
        m = re.match(r"(md\d+)\s*:\s*(\S+)\s+(?:\(\S+\)\s+)?(raid\d+|linear)?\s*(.*)", b)
        if not m:
            continue
        name, active, level, members = m.group(1), m.group(2), m.group(3) or "", m.group(4).split("\n")[0]
        failed = re.findall(r"(\S+?)\[\d+\]\(F\)", members)
        counts = re.search(r"\[(\d+)/(\d+)\]", b)
        status, health = "OK", "Healthy"
        if active != "active":
            status, health = active.capitalize(), "Unhealthy"
        elif counts and int(counts.group(2)) < int(counts.group(1)):
            status, health = "Degraded (%s of %s disks)" % (counts.group(2), counts.group(1)), "Unhealthy"
        if failed:
            status += "; failed: " + ", ".join(failed)
            health = "Unhealthy"
        prog = re.search(r"(recovery|resync|reshape|check)\s*=\s*([\d.]+%)", b)
        if prog and prog.group(1) in ("recovery", "resync", "reshape"):
            status += "; %s %s" % ("rebuilding" if prog.group(1) == "recovery" else prog.group(1), prog.group(2))
            if health == "Healthy" or (prog.group(1) == "recovery" and not failed):
                health = "Warning"  # redundancy is being restored
        st["virtual"].append({"name": "/dev/" + name, "layout": level, "health": health, "status": status})
    if shutil.which("zpool"):
        rc, out, _ = run(["zpool", "list", "-H", "-o", "name,health"], timeout=30)
        for line in out.splitlines():
            parts = line.split("\t")
            if len(parts) == 2:
                hl = parts[1].strip()
                st["virtual"].append({"name": "zpool " + parts[0], "layout": "zfs",
                                      "health": "Healthy" if hl == "ONLINE" else "Unhealthy",
                                      "status": hl})
    return st


# --------------------------------------------------------------------------
# Docker and systemd
# --------------------------------------------------------------------------
def containers():
    rc, out, err = run(["docker", "ps", "-aq", "--no-trunc"])
    if rc == 127:
        return None
    if rc != 0:
        raise RuntimeError(err.strip() or "docker ps failed")
    ids = out.split()
    if not ids:
        return []
    rc, out, err = run(["docker", "inspect"] + ids, timeout=60)
    if rc != 0:
        raise RuntimeError(err.strip() or "docker inspect failed")
    result = []
    for c in json.loads(out or "[]"):
        st = c.get("State") or {}
        cfg = c.get("Config") or {}
        labels = cfg.get("Labels") or {}
        name = (c.get("Name") or "").lstrip("/")
        image = cfg.get("Image") or ""
        health = (st.get("Health") or {}).get("Status")
        status = st.get("Status") or "unknown"
        if status == "running":
            state = {"unhealthy": "Unhealthy", "starting": "Starting"}.get(health, "Running")
        elif status == "exited":
            state = "Exited (%s)" % st.get("ExitCode")
        else:
            state = status.capitalize()
        policy = ((c.get("HostConfig") or {}).get("RestartPolicy") or {}).get("Name") or "no"
        project = labels.get("com.docker.compose.project", "")
        immich = "immich" in image.lower() or name.lower().startswith("immich") or project.lower() == "immich"
        # Watch containers meant to be up: running now, set to restart, or part of a compose stack.
        # A one-off container that exited cleanly with no restart policy isn't a fault.
        watched = status == "running" or policy in ("always", "unless-stopped", "on-failure") or bool(project)
        if status == "exited" and st.get("ExitCode") == 0 and policy == "no" and not project:
            watched = False
        ports = []
        for cport, binds in ((c.get("NetworkSettings") or {}).get("Ports") or {}).items():
            for b in binds or []:
                ports.append({"container": cport, "host": b.get("HostPort")})
        result.append({"name": name, "image": image, "state": state, "health": health or "",
                       "restarts": int(c.get("RestartCount") or 0), "started": st.get("StartedAt", "")[:19] + "Z",
                       "policy": policy, "project": project, "role": "Immich" if immich else "Docker",
                       "watched": watched, "ports": ports})
    return sorted(result, key=lambda x: (x["role"] != "Immich", x["name"]))


def systemd_units():
    if not shutil.which("systemctl"):
        return [], []
    rc, out, _ = run(["systemctl", "show", "-p", "Id,Description,LoadState,ActiveState,SubState,UnitFileState"] + WATCH_UNITS)
    watched = []
    for block in out.strip().split("\n\n"):
        f = dict(l.split("=", 1) for l in block.splitlines() if "=" in l)
        if f.get("LoadState") != "loaded" or f.get("UnitFileState") not in ("enabled", "static", "enabled-runtime"):
            continue
        state = "Running" if f.get("ActiveState") == "active" else "%s (%s)" % (
            f.get("ActiveState", "?").capitalize(), f.get("SubState", "?"))
        watched.append({"name": f.get("Id"), "display": f.get("Description") or f.get("Id"),
                        "state": state, "start_mode": "Auto", "role": "System"})
    failed = []
    rc, out, _ = run(["systemctl", "list-units", "--state=failed", "--no-legend", "--plain", "--no-pager"])
    for line in out.splitlines():
        parts = line.split(None, 4)
        if parts:
            failed.append({"name": parts[0], "display": parts[4] if len(parts) > 4 else parts[0], "state": "Failed"})
    return watched, failed[:50]


# --------------------------------------------------------------------------
# Journal: errors and security
# --------------------------------------------------------------------------
def journal(state, cursor_name, extra, max_entries):
    """New journal entries since the last run (by cursor)."""
    cmd = ["journalctl", "-o", "json", "--no-pager", "-q", "-n", str(max_entries)] + extra
    cursor = (state.get("cursors") or {}).get(cursor_name)
    if cursor:
        cmd += ["--after-cursor", cursor]
    else:
        cmd += ["--since", "-60min"]
    rc, out, err = run(cmd, timeout=60)
    if rc == 127:
        return None
    if rc != 0 and cursor:  # cursor no longer valid (journal rotated/vacuumed)
        rc, out, err = run(cmd[:-2] + ["--since", "-60min"], timeout=60)
    entries = []
    for line in out.splitlines():
        try:
            entries.append(json.loads(line))
        except ValueError:
            continue
    if entries and entries[-1].get("__CURSOR"):
        state.setdefault("cursors", {})[cursor_name] = entries[-1]["__CURSOR"]
    return entries


def jtext(e):
    m = e.get("MESSAGE", "")
    if isinstance(m, list):  # binary message
        try:
            m = bytes(m).decode("utf-8", "replace")
        except (TypeError, ValueError):
            m = ""
    return str(m)


def jtime(e):
    try:
        return utc(int(e.get("__REALTIME_TIMESTAMP")) / 1e6)
    except (TypeError, ValueError):
        return None


def event_report(state):
    entries = journal(state, "journal", ["-p", "0..3"], 300)
    if entries is None:
        return {"counts": {}, "recent": []}
    counts = {"Journal": {"critical": 0, "error": 0}}
    recent = []
    for e in entries:
        msg = jtext(e)
        if NOISE_PATTERNS.search(msg):
            continue
        try:
            prio = int(e.get("PRIORITY", 3))
        except ValueError:
            prio = 3
        critical = prio <= 2 or bool(CRITICAL_PATTERNS.search(msg))
        counts["Journal"]["critical" if critical else "error"] += 1
        recent.append({"time": jtime(e), "log": "Journal", "level": "Critical" if critical else "Error", "id": 0,
                       "source": e.get("SYSLOG_IDENTIFIER") or e.get("_COMM") or e.get("_SYSTEMD_UNIT") or "?",
                       "message": limit(msg)})
    recent.sort(key=lambda x: x["time"] or "", reverse=True)
    return {"counts": counts, "recent": recent[:30]}


SSH_FAIL = re.compile(r"Failed (?:password|publickey|keyboard-interactive/pam) for (?:invalid user )?(\S+) from (\S+)")
SSH_INVALID = re.compile(r"Invalid user (\S*) from (\S+)")
SSH_OK = re.compile(r"Accepted (\S+) for (\S+) from (\S+)")
SUDO_FAIL = re.compile(r"^\s*(\S+) : (?:\d+ )?incorrect password attempts?")
SUDO_DENIED = re.compile(r"^\s*(\S+) : user NOT in sudoers")
USER_NEW = re.compile(r"new user: name=([^,\s]+)")
USER_DEL = re.compile(r"delete user '([^']+)'")
GROUP_ADD = re.compile(r"(?:add|added) '?([^' ]+)'? to (?:shadow )?group '?([^' ]+?)'?$")
GROUP_ADD2 = re.compile(r"user (\S+) added by \S+ to group (\S+)")


def local_admins():
    """Who can act as root: members of the sudo, wheel and admin groups (including users whose
    main group it is), other accounts with uid 0, and users or %groups given rules in sudoers."""
    import grp
    import pwd
    found = {}

    def add(name, kind, via):
        a = found.setdefault((kind, name), {"account": name, "name": name, "domain": "", "type": kind,
                                            "source": "Local", "via": []})
        if via not in a["via"]:
            a["via"].append(via)

    users = pwd.getpwall()
    for g in ("sudo", "wheel", "admin"):
        try:
            gr = grp.getgrnam(g)
        except KeyError:
            continue
        for u in gr.gr_mem:
            add(u, "user", "group " + g)
        for u in users:
            if u.pw_gid == gr.gr_gid:
                add(u.pw_name, "user", "group " + g)
    for u in users:
        if u.pw_uid == 0 and u.pw_name != "root":
            add(u.pw_name, "user", "uid 0")
    files = ["/etc/sudoers"] + sorted(f for f in glob.glob("/etc/sudoers.d/*")
                                      if not os.path.basename(f).startswith(".") and not f.endswith("~"))
    skip = ("Defaults", "User_Alias", "Runas_Alias", "Host_Alias", "Cmnd_Alias", "@include", "#include")
    for f in files:
        for line in read(f).splitlines():
            line = line.strip()
            if not line or line.startswith(skip) or line.startswith("#") or "=" not in line:
                continue
            who, rule = (line.split(None, 1) + [""])[:2]
            limited = not re.search(r"(^|[:)\s])ALL\s*$", rule.strip())
            via = "sudoers" + (" (some commands)" if limited else "")
            for w in who.split(","):
                w = w.strip()
                if not w or w == "root":
                    continue
                if w.startswith("%"):
                    add(w[1:], "group", via)
                else:
                    add(w, "user", via)
    return sorted(found.values(), key=lambda a: (a["type"], a["name"]))[:200]


def security_report(state):
    report = {"failed_logons": {"count": 0, "top": []}, "items": []}
    entries = journal(state, "auth", ["SYSLOG_FACILITY=4", "SYSLOG_FACILITY=10"], 3000)
    if entries is None:
        return report
    fails, items = {}, []
    for e in entries:
        msg, who, t = jtext(e), e.get("SYSLOG_IDENTIFIER") or "", jtime(e)
        m = SSH_FAIL.search(msg) or (SSH_INVALID.search(msg) if "sshd" in who else None)
        if m and "sshd" in who:
            key = (m.group(1) or "?", m.group(2))
            fails[key] = fails.get(key, 0) + 1
            continue
        m = SUDO_FAIL.search(msg) or SUDO_DENIED.search(msg)
        if m and who == "sudo":
            key = (m.group(1), "sudo")
            fails[key] = fails.get(key, 0) + 1
            if SUDO_DENIED.search(msg):
                items.append({"time": t, "id": 4673, "what": "Not allowed to use sudo", "account": m.group(1), "by": None})
            continue
        m = USER_NEW.search(msg)
        if m:
            items.append({"time": t, "id": 4720, "what": "User account created", "account": m.group(1), "by": who})
            continue
        m = USER_DEL.search(msg)
        if m:
            items.append({"time": t, "id": 4726, "what": "User account deleted", "account": m.group(1), "by": who})
            continue
        m = GROUP_ADD2.search(msg) or (GROUP_ADD.search(msg) if who in ("usermod", "gpasswd", "groupmems", "useradd") else None)
        if m:
            items.append({"time": t, "id": 4732, "what": "Added to local group", "account": m.group(1),
                          "group": m.group(2), "by": who})
            continue
        m = SSH_OK.search(msg)
        if m and "sshd" in who:
            items.append({"time": t, "id": 4624, "what": "Logged on over SSH (%s)" % m.group(1), "account": m.group(2),
                          "source": m.group(3), "by": None})
    report["failed_logons"]["count"] = sum(fails.values())
    report["failed_logons"]["top"] = [{"account": a, "source": s, "count": n}
                                      for (a, s), n in sorted(fails.items(), key=lambda kv: -kv[1])[:5]]
    items.sort(key=lambda x: x["time"] or "", reverse=True)
    report["items"] = items[:50]
    return report


# --------------------------------------------------------------------------
# Immich
# --------------------------------------------------------------------------
def http_json(url, api_key=None, timeout=8):
    req = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "PingMonitorAgent"})
    if api_key:
        req.add_header("x-api-key", api_key)
    ctx = ssl._create_unverified_context() if url.startswith("https") else None  # local health check only
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
        return json.loads(r.read().decode() or "null")


def _version_tuple(v):
    return tuple(int(x) for x in re.findall(r"\d+", str(v or ""))[:3])


def immich_latest(url, key, state):
    """The newest Immich release: from Immich's own version check (admin key, and
    "Version check" on in its settings), otherwise GitHub, at most every 6 hours."""
    if key:
        try:
            vc = http_json(url + "/api/system-metadata/version-check-state", key)
            if vc and vc.get("releaseVersion"):
                return {"latest": str(vc["releaseVersion"]).lstrip("v"), "latest_checked": vc.get("checkedAt"),
                        "latest_source": "Immich version check"}
        except Exception:  # noqa: BLE001  (older Immich, or the key lacks the permission)
            pass
    cache = state.get("immich_latest") or {}
    checked = parse_iso(cache.get("checked"))
    if not (checked and time.time() - checked < 6 * 3600):
        try:
            rel = http_json("https://api.github.com/repos/immich-app/immich/releases/latest", timeout=10)
            cache = {"checked": utc(time.time()), "version": str(rel.get("tag_name") or "").lstrip("v")}
        except Exception as err:  # noqa: BLE001  (no internet access is fine)
            cache = {"checked": utc(time.time()), "version": cache.get("version"), "error": limit(str(err), 100)}
        state["immich_latest"] = cache
    if cache.get("version"):
        return {"latest": cache["version"], "latest_checked": cache.get("checked"), "latest_source": "GitHub releases"}
    return {}


def immich(conts, conf, state=None):
    server = next((c for c in conts or [] if c["role"] == "Immich" and "server" in c["name"].lower()
                   and "machine" not in c["name"].lower()), None)
    url = conf.get("immich_url")
    if not url and not server:
        return None
    if not url:
        port = next((p["host"] for p in server["ports"] if p["container"].startswith("2283") and p["host"]), None)
        url = "http://127.0.0.1:%s" % (port or "2283")
    url = url.rstrip("/")
    out = {"url": url, "ping": False}
    try:
        out["ping"] = (http_json(url + "/api/server/ping") or {}).get("res") == "pong"
    except Exception as err:  # noqa: BLE001
        out["error"] = limit(str(err), 160)
        return out
    try:
        v = http_json(url + "/api/server/version")
        out["version"] = "%s.%s.%s" % (v.get("major"), v.get("minor"), v.get("patch"))
    except Exception:  # noqa: BLE001
        pass
    key = conf.get("immich_api_key")
    try:
        out.update(immich_latest(url, key, state if state is not None else {}))
    except Exception as err:  # noqa: BLE001
        collector_error("immich version check", err)
    if not key:
        return out
    try:
        jobs = http_json(url + "/api/jobs", key)
        queues = []
        for name, q in (jobs or {}).items():
            if not isinstance(q, dict):
                continue
            jc, qs = q.get("jobCounts") or {}, q.get("queueStatus") or {}
            queues.append({"name": name, "active": jc.get("active", 0), "waiting": jc.get("waiting", 0),
                           "delayed": jc.get("delayed", 0), "failed": jc.get("failed", 0),
                           "paused": bool(qs.get("isPaused"))})
        out["queues"] = sorted(queues, key=lambda q: q["name"])
    except urllib.error.HTTPError as err:
        out["api_error"] = "job queues: HTTP %s (the API key needs admin rights)" % err.code
    except Exception as err:  # noqa: BLE001
        out["api_error"] = "job queues: %s" % limit(str(err), 120)
    try:
        s = http_json(url + "/api/server/statistics", key)
        out["stats"] = {"photos": s.get("photos"), "videos": s.get("videos"),
                        "usage_gb": round((s.get("usage") or 0) / 1024 ** 3, 1)}
    except Exception:  # noqa: BLE001
        pass
    try:
        st = http_json(url + "/api/server/storage", key)
        out["storage"] = {"size": st.get("diskSize"), "used": st.get("diskUse"), "free": st.get("diskAvailable"),
                          "used_pct": st.get("diskUsagePercentage")}
    except Exception:  # noqa: BLE001
        pass
    return out


# --------------------------------------------------------------------------
# Report
# --------------------------------------------------------------------------
def build_report(state, conf):
    started = time.monotonic()
    TIMINGS.clear()
    name = socket.gethostname().split(".")[0]
    r = {"agent_version": AGENT_VERSION, "os_family": "linux",
         "ps_version": "Python %s" % sys.version.split()[0], "hostname": name, "collected": utc(time.time())}
    sysinfo = {}
    with step("system info"):
        sysinfo = system_info()
        r.update(sysinfo)
        fqdn = socket.getfqdn().lower()
        r["fqdn"] = fqdn if "." in fqdn else name.lower()
    with step("updates"):
        boot_ts = parse_iso(sysinfo.get("boot_time"))
        p = patch_info(state, boot_ts)
        if p.get("date"):
            r["last_patch"], r["last_patch_kb"], r["last_patch_source"] = p["date"], p.get("kb"), p.get("source")
        r["updates_pending"], r["security_updates"] = p.get("pending"), p.get("security")
        r["last_patch_cached"] = bool(p.get("cached"))
    r["disks"] = []
    with step("disks"):
        r["disks"] = disks()
    conts = None
    with step("containers"):
        conts = containers()
    units, failed = [], []
    with step("systemd"):
        units, failed = systemd_units()
    watched = list(units)
    for c in conts or []:
        if c["watched"]:
            watched.append({"name": c["name"], "display": c["name"],
                            "state": c["state"], "start_mode": "Auto", "role": c["role"]})
    # Extra services asked for in the add-on's settings (agent_watch_services); that list is
    # shared with Windows, so names this server doesn't have are skipped.
    for name_ in conf.get("watch_services") or state.get("watch") or []:
        if not any(w["name"] in (name_, name_ + ".service") for w in watched):
            rc, load, _ = run(["systemctl", "show", "-p", "LoadState", "--value", name_])
            if load.strip() != "loaded":
                continue
            rc, out, _ = run(["systemctl", "is-active", name_])
            watched.append({"name": name_, "display": name_, "state": "Running" if out.strip() == "active" else out.strip().capitalize() or "Unknown",
                            "start_mode": "Auto", "role": "Requested"})
    r["services"] = {"watched": sorted(watched, key=lambda w: (w["role"], w["name"])), "stopped_auto": failed}
    roles = []
    if conts is not None:
        roles.append("Docker")
    if any(c["role"] == "Immich" for c in conts or []):
        roles.append("Immich")
    for u in units:
        if u["name"] in ("smbd.service",):
            roles.append("File server (Samba)")
        if u["name"] in ("nfs-server.service",):
            roles.append("NFS server")
    r["roles"] = roles
    r["events"] = {"counts": {}, "recent": []}
    with step("journal"):
        r["events"] = event_report(state)
    r["security"] = {"failed_logons": {"count": 0, "top": []}, "items": []}
    with step("auth log"):
        r["security"] = security_report(state)
    with step("administrators"):
        r["security"]["admins"] = local_admins()
    r["sessions"] = []
    with step("signed-in users"):
        r["sessions"] = signed_in_users()
    with step("installed software"):
        apps = installed_apps()
        if apps:
            newer = upgradable(state)
            for a in apps:
                if a["name"] in newer:
                    a["available"] = newer[a["name"]][:60]
        if apps is not None:
            r["apps_hash"] = apps_hash(apps)
            if state.get("apps_sent") != r["apps_hash"]:  # only when it changed, or Rollcall asked
                r["apps"] = apps
    r["checks"] = {}
    with step("storage health"):
        sh = storage_health()
        if sh["virtual"]:
            r["checks"]["storage"] = sh
    with step("network"):
        nics = network_report()
        if nics:
            r["checks"]["nics"] = nics
    if conts is not None:
        r["checks"]["containers"] = conts
    with step("immich"):
        im = immich(conts, conf, state)
        if im:
            r["checks"]["immich"] = im
    r["errors"] = list(ERRORS)
    try:
        import resource
        ru = resource.getrusage(resource.RUSAGE_SELF)
        ch = resource.getrusage(resource.RUSAGE_CHILDREN)
        r["cpu_ms"] = int((ru.ru_utime + ru.ru_stime + ch.ru_utime + ch.ru_stime) * 1000)
        r["peak_mem_mb"] = int(ru.ru_maxrss / 1024)
    except Exception:  # noqa: BLE001
        pass
    r["run_ms"] = int((time.monotonic() - started) * 1000)
    r["timings"] = dict(TIMINGS)
    return r


# --------------------------------------------------------------------------
# Talking to the add-on
# --------------------------------------------------------------------------
ACTIVE = {"server": None, "preferred": None, "pushed": []}


def server_list(server):
    """The add-on's addresses: server can list several, e.g. internal then external
    ("http://10.0.0.5:8100,https://rollcall.example.com:8100"). The one that worked last goes first."""
    # Addresses the add-on sent (set under Agents) first; the installed ones stay on the end.
    allx = list(dict.fromkeys(x.strip().rstrip("/") for x in list(ACTIVE["pushed"]) + re.split(r"[,;\s]+", server or SERVER) if x.strip()))
    pref = ACTIVE["preferred"]
    return ([pref] + [x for x in allx if x != pref]) if pref in allx else allx


def reachable(url, timeout=3):
    import urllib.parse
    u = urllib.parse.urlsplit(url)
    try:
        socket.create_connection((u.hostname, u.port or (443 if u.scheme == "https" else 80)), timeout).close()
        return True
    except OSError:
        return False


def send(path, body, token=None, server=None, ignore_cert=False):
    servers = server_list(server)
    last = None
    for srv in servers:
        if len(servers) > 1 and not reachable(srv):
            last = "can't reach " + srv
            continue
        try:
            result = send_to(srv, path, body, token, ignore_cert)
            ACTIVE["server"] = srv
            return result
        except (urllib.error.URLError, OSError) as err:
            last = str(getattr(err, "reason", err))
            if len(servers) > 1:
                log("WARN %s didn't answer (%s); trying the next address" % (srv, last))
    raise SystemExit("Couldn't reach Rollcall at any of its addresses (%s): %s" % (", ".join(servers), last))


def send_to(srv, path, body, token=None, ignore_cert=False):
    url = srv + path
    if isinstance(body, dict):
        body["sent_to"] = srv  # so Rollcall knows which address was used
    req = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST",
                                 headers={"Content-Type": "application/json; charset=utf-8"})
    if token:
        req.add_header("Authorization", "Bearer " + token)
    ctx = ssl._create_unverified_context() if (url.startswith("https") and ignore_cert) else None
    try:
        with urllib.request.urlopen(req, timeout=30, context=ctx) as resp:
            raw = resp.read().decode() or "null"
            try:
                return resp.status, json.loads(raw)
            except ValueError:
                return resp.status, None
    except urllib.error.HTTPError as err:
        return err.code, None


def newer(a, b):
    return _version_tuple(a) > _version_tuple(b)


def self_update(offer, token, server, ignore):
    """Install a newer agent the add-on offers (only when an admin has turned updates on).

    The download must be signed with this server's own token (HMAC-SHA256), be the
    version offered and newer than this one, and compile. The old copy is kept as .old;
    the new one runs from the next report."""
    version = str((offer or {}).get("version") or "")
    if not version or not newer(version, AGENT_VERSION) or not os.path.exists(INSTALL_PATH):
        return
    full = ",".join(x.strip().rstrip("/") for x in re.split(r"[,;\s]+", server) if x.strip())
    url = (ACTIVE["server"] or server_list(server)[0]) + "/agent/update?os=linux&server=" + urllib.request.quote(full, safe="")
    if ignore:
        url += "&ignore_cert=1"
    req = urllib.request.Request(url, headers={"Authorization": "Bearer " + token})
    ctx = ssl._create_unverified_context() if (url.startswith("https") and ignore) else None
    with urllib.request.urlopen(req, timeout=60, context=ctx) as resp:
        body, sig = resp.read(), resp.headers.get("X-Rollcall-Signature", "")
    mac = hmac.new(hashlib.sha256(token.encode()).digest(), body, hashlib.sha256).hexdigest()
    if not sig or not hmac.compare_digest(sig.lower(), mac):
        raise RuntimeError("the update failed its signature check, so it was not installed")
    text = body.decode("utf-8")
    m = re.search(r'^AGENT_VERSION = "([^"]+)"', text, re.M)
    if not m or m.group(1) != version:
        raise RuntimeError("the update is not the version offered, so it was not installed")
    compile(text, INSTALL_PATH, "exec")  # raises SyntaxError if it's broken
    tmp = INSTALL_PATH + ".new"
    with open(os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o700), "w") as f:
        f.write(text)
    shutil.copyfile(INSTALL_PATH, INSTALL_PATH + ".old")
    os.replace(tmp, INSTALL_PATH)
    log("Updated the agent from %s to %s; the new version runs from the next report" % (AGENT_VERSION, version))


def agent_run(conf, report_only=False):
    server = conf.get("server") or SERVER
    key = conf.get("enrol_key") or ENROL_KEY
    if server.startswith("__PM_") or key.startswith("__PM_"):
        raise SystemExit("This copy of the script has no add-on address or enrolment key. Download it from the "
                         "Rollcall dashboard (Agents), or set server/enrol_key in %s." % CONFIG_PATH)
    os.makedirs(DATA_DIR, mode=0o700, exist_ok=True)
    state = load_json(STATE_PATH, {})
    if not state.get("token"):
        state["token"] = secrets.token_hex(32)
        save_json(STATE_PATH, state)
    report = build_report(state, conf)
    if report_only:
        print(json.dumps(report, indent=1))
        return
    ignore = bool(conf.get("ignore_cert", IGNORE_CERT))
    ACTIVE["preferred"] = state.get("last_server")
    ACTIVE["pushed"] = [x for x in state.get("servers") or [] if re.match(r"^https?://[^\s,;]+$", str(x))]
    status, body = send("/agent/report", report, state["token"], server, ignore)
    if status == 401:
        log("Not enrolled yet: asking to join")
        status, body = send("/agent/enrol", {"enrol_key": key, "hostname": report["hostname"], "fqdn": report.get("fqdn"),
                                             "ips": report.get("ips"), "os": report.get("os"),
                                             "agent_version": AGENT_VERSION, "token": state["token"],
                                             "os_family": "linux"},
                            None, server, ignore)
        if status == 403:
            raise SystemExit("The add-on rejected the enrolment key. Download a fresh copy of the script from the dashboard.")
        if status == 410:
            log("This server was rejected or revoked in the dashboard. To ask again, run --uninstall then --install.")
            return
        log("Waiting for an admin to approve this server in the Rollcall dashboard")
        return  # don't advance cursors; events are sent once approved
    if status == 202:
        log("Waiting for approval in the Rollcall dashboard")
        return
    if status != 200:
        raise SystemExit("Report rejected (HTTP %s)" % status)
    state["watch"] = (body or {}).get("watch_services") or []
    if "apps" in report:
        state["apps_sent"] = report["apps_hash"]
    if (body or {}).get("send_apps"):
        state["apps_sent"] = None  # Rollcall hasn't got this list: send it next time
    state["last_run"] = utc(time.time())
    if ACTIVE["server"]:
        state["last_server"] = ACTIVE["server"]
    pushed = [str(x) for x in (body or {}).get("servers") or [] if re.match(r"^https?://[^\s,;]+$", str(x))][:4]
    if pushed:
        if pushed != state.get("servers"):
            log("Rollcall's addresses are now: " + ", ".join(pushed))
        state["servers"] = pushed
    save_json(STATE_PATH, state)
    slow = max(TIMINGS.items(), key=lambda kv: kv[1]) if TIMINGS else None
    log("Report sent to %s: %d role(s), %d error(s); run took %.1f s%s" % (ACTIVE["server"],
        len(report["roles"]), len(report["errors"]), report["run_ms"] / 1000,
        "; slowest: %s %.1f s" % (slow[0], slow[1] / 1000) if slow else ""))
    if (body or {}).get("agent_update"):
        try:
            self_update(body["agent_update"], state["token"], server, ignore)
        except Exception as err:  # noqa: BLE001
            log("WARN Agent update: %s" % err)


# --------------------------------------------------------------------------
# Install / uninstall
# --------------------------------------------------------------------------
SERVICE_UNIT = """[Unit]
Description=Rollcall agent (reports server health to Home Assistant)
Wants=network-online.target
After=network-online.target docker.service

[Service]
Type=oneshot
ExecStart=/usr/bin/env python3 {path}
Nice=10
IOSchedulingClass=idle
TimeoutStartSec=600
"""
TIMER_UNIT = """[Unit]
Description=Run the Rollcall agent every {minutes} minutes

[Timer]
OnBootSec=2min
OnUnitActiveSec={minutes}min
RandomizedDelaySec=20
Persistent=true

[Install]
WantedBy=timers.target
"""


def install(args):
    if os.geteuid() != 0 and not PREFIX:
        raise SystemExit("Run --install as root (sudo).")
    if SERVER.startswith("__PM_") and not args.server:
        raise SystemExit("Download the script from the Rollcall dashboard (Agents) so it includes the "
                         "add-on address and enrolment key, or pass --server and --enrol-key.")
    os.makedirs(os.path.dirname(INSTALL_PATH), mode=0o755, exist_ok=True)
    src = os.path.abspath(__file__)
    installed = re.search(r'^AGENT_VERSION = "([^"]+)"', read(INSTALL_PATH), re.M)
    if installed and newer(installed.group(1), AGENT_VERSION):
        log("Kept the installed agent %s (newer than this copy, %s)" % (installed.group(1), AGENT_VERSION))
    elif src != os.path.abspath(INSTALL_PATH):
        shutil.copyfile(src, INSTALL_PATH)
    os.chmod(INSTALL_PATH, 0o700)
    conf = load_json(CONFIG_PATH, {})
    for k in ("server", "enrol_key", "immich_url", "immich_api_key"):
        v = getattr(args, k)
        if v:
            conf[k] = v
    if args.ignore_cert:
        conf["ignore_cert"] = True
    if conf:
        save_json(CONFIG_PATH, conf, 0o600)  # may hold the Immich API key: root only
    os.makedirs(DATA_DIR, mode=0o700, exist_ok=True)
    os.makedirs(UNIT_DIR, exist_ok=True)
    with open(os.path.join(UNIT_DIR, UNIT + ".service"), "w") as f:
        f.write(SERVICE_UNIT.format(path=INSTALL_PATH.replace(PREFIX, "", 1) if PREFIX else INSTALL_PATH))
    with open(os.path.join(UNIT_DIR, UNIT + ".timer"), "w") as f:
        f.write(TIMER_UNIT.format(minutes=args.interval))
    if not PREFIX:
        for cmd in (["systemctl", "daemon-reload"], ["systemctl", "enable", "--now", UNIT + ".timer"],
                    ["systemctl", "start", "--no-block", UNIT + ".service"]):
            rc, _, err = run(cmd)
            if rc != 0:
                raise SystemExit("%s failed: %s" % (" ".join(cmd), err.strip()))
    log("Installed version %s; reporting to %s every %d min" % (AGENT_VERSION, conf.get("server") or SERVER, args.interval))
    print("Rollcall agent %s installed. It will appear in the dashboard's Agents list for approval within a minute."
          % AGENT_VERSION)


def uninstall():
    if os.geteuid() != 0 and not PREFIX:
        raise SystemExit("Run --uninstall as root (sudo).")
    if not PREFIX:
        run(["systemctl", "disable", "--now", UNIT + ".timer"])
    for p in (os.path.join(UNIT_DIR, UNIT + ".service"), os.path.join(UNIT_DIR, UNIT + ".timer"), INSTALL_PATH, CONFIG_PATH):
        try:
            os.remove(p)
        except FileNotFoundError:
            pass
    shutil.rmtree(DATA_DIR, ignore_errors=True)
    if not PREFIX:
        run(["systemctl", "daemon-reload"])
    print("Rollcall agent removed. Revoke it in the dashboard too if it was approved.")


def main():
    ap = argparse.ArgumentParser(description="Rollcall agent for Linux")
    ap.add_argument("--install", action="store_true", help="install as a systemd timer (root)")
    ap.add_argument("--uninstall", action="store_true", help="remove the agent (root)")
    ap.add_argument("--report", action="store_true", help="print the report without sending it")
    ap.add_argument("--interval", type=int, default=5, help="minutes between reports (default 5)")
    ap.add_argument("--server", help="add-on address, e.g. http://192.168.1.5:8100")
    ap.add_argument("--enrol-key", dest="enrol_key")
    ap.add_argument("--immich-url", dest="immich_url", help="Immich address (default: found from its container)")
    ap.add_argument("--immich-api-key", dest="immich_api_key", help="admin API key for job queues and statistics")
    ap.add_argument("--ignore-cert", dest="ignore_cert", action="store_true", help="accept a self-signed HTTPS certificate")
    args = ap.parse_args()
    try:
        if args.uninstall:
            return uninstall()
        if args.install:
            return install(args)
        conf = load_json(CONFIG_PATH, {})
        for k in ("server", "enrol_key", "immich_url", "immich_api_key"):
            if getattr(args, k):
                conf[k] = getattr(args, k)
        agent_run(conf, report_only=args.report)
    except SystemExit as e:
        if e.code and not isinstance(e.code, int):
            log("ERROR %s" % e.code)
            sys.exit(1)
        raise


if __name__ == "__main__":
    main()
