"""Operating systems by release, and when each stops getting security updates.

group() turns what an agent reports ("Microsoft Windows 10 Enterprise LTSC (10.0.17763.6893)", "Ubuntu 20.04.6 LTS")
into the release it belongs to ("Windows 10 Enterprise LTSC 2019", "Ubuntu 20.04"), so Settings can offer a tick
per release that's actually in use. LTSC/LTSB and IoT editions are their own releases: Windows 10 LTSC 2021 is
supported long after Windows 10 itself, so "Windows 10" never takes them in.

END is when standard security updates end (Microsoft's lifecycle pages, ubuntu.com/about/release-cycle, Debian's
LTS pages). Paid extensions (ESU, Ubuntu Pro) aren't counted: whether a device has one is for the admin to say.
Windows 11 (other than LTSC) is grouped by its feature update (23H2, 24H2...) and edition, as that's what its support
depends on: Enterprise and Education get a year longer than Home and Pro. A build Rollcall doesn't know yet is just
"Windows 11", with no date.
"""
from __future__ import annotations

import re
import time

# Windows LTSC/LTSB releases by build number (the caption often leaves the year out).
LTSC_BUILDS = {10240: "LTSB 2015", 14393: "LTSB 2016", 17763: "LTSC 2019", 19044: "LTSC 2021", 26100: "LTSC 2024"}

# Windows 11 feature updates by build number (learn.microsoft.com/windows/release-health/windows11-release-information)
WIN11_BUILDS = {22000: "21H2", 22621: "22H2", 22631: "23H2", 26100: "24H2", 26200: "25H2", 28000: "26H1", 26300: "26H2"}
WIN11_HOME, WIN11_ENT = "Home/Pro", "Enterprise/Education"

END = {
    "Windows 7": "2020-01-14", "Windows 8.1": "2023-01-10", "Windows 10": "2025-10-14",
    "Windows 10 Enterprise LTSB 2015": "2025-10-14", "Windows 10 Enterprise LTSB 2016": "2026-10-13",
    "Windows 10 Enterprise LTSC 2019": "2029-01-09", "Windows 10 Enterprise LTSC 2021": "2027-01-12",
    "Windows 10 IoT Enterprise LTSB 2016": "2026-10-13", "Windows 10 IoT Enterprise LTSC 2019": "2029-01-09",
    "Windows 10 IoT Enterprise LTSC 2021": "2032-01-13",
    "Windows 11 Enterprise LTSC 2024": "2029-10-09", "Windows 11 IoT Enterprise LTSC 2024": "2034-10-10",
    "Windows Server 2008": "2020-01-14", "Windows Server 2008 R2": "2020-01-14",
    "Windows Server 2012": "2023-10-10", "Windows Server 2012 R2": "2023-10-10",
    "Windows Server 2016": "2027-01-12", "Windows Server 2019": "2029-01-09",
    "Windows Server 2022": "2031-10-14", "Windows Server 2025": "2034-10-10",
    "Ubuntu 16.04": "2021-04-30", "Ubuntu 18.04": "2023-05-31", "Ubuntu 20.04": "2025-05-31",
    "Ubuntu 22.04": "2027-05-31", "Ubuntu 24.04": "2029-05-31",
    "Debian 9": "2022-06-30", "Debian 10": "2024-06-30", "Debian 11": "2026-08-31", "Debian 12": "2028-06-30",
}
# The last day of security updates for each Windows 11 feature update (Microsoft's lifecycle pages for Windows 11
# Home and Pro, and Enterprise and Education; their end times are the morning after, Pacific time)
for _v, _home, _ent in (("21H2", "2023-10-10", "2024-10-08"), ("22H2", "2024-10-08", "2025-10-14"),
                        ("23H2", "2025-11-11", "2026-11-10"), ("24H2", "2026-10-13", "2027-10-12"),
                        ("25H2", "2027-10-12", "2028-10-10"), ("26H1", "2028-03-14", "2029-03-13"),
                        ("26H2", "2028-10-09", "2029-10-08")):
    END[f"Windows 11 {_v} {WIN11_HOME}"], END[f"Windows 11 {_v} {WIN11_ENT}"] = _home, _ent

LINUX_NAMES = {"ubuntu": "Ubuntu", "debian": "Debian", "raspbian": "Raspbian", "rhel": "Red Hat Enterprise Linux",
               "centos": "CentOS", "rocky": "Rocky Linux", "almalinux": "AlmaLinux", "fedora": "Fedora",
               "opensuse-leap": "openSUSE Leap", "sles": "SUSE Linux Enterprise Server", "alpine": "Alpine Linux",
               "freebsd": "FreeBSD", "pfsense": "pfSense", "opnsense": "OPNsense", "linuxmint": "Linux Mint",
               "ol": "Oracle Linux", "amzn": "Amazon Linux", "arch": None, "openwrt": "OpenWrt"}
SPECIAL = re.compile(r"(?<![A-Za-z0-9])(ltsc|ltsb|iot)(?![A-Za-z0-9])", re.I)


def _build(report: dict) -> int | None:
    for text in (report.get("os_build"), report.get("os")):
        m = re.search(r"\b10\.0\.(\d{4,5})\b", str(text or ""))
        if m:
            return int(m.group(1))
    return None


def group(report: dict | None) -> str | None:
    """The release a device's OS belongs to, or None if the agent hasn't said."""
    report = report or {}
    os_name = re.sub(r"\s+", " ", str(report.get("os") or "")).strip()
    if not os_name:
        return None
    if "windows" in os_name.lower() or "hyper-v server" in os_name.lower():
        m = re.search(r"(Windows Server|Hyper-V Server) (\d{4})( R2)?", os_name, re.I)
        if m:
            return f"{'Windows Server' if m.group(1).lower().startswith('windows') else 'Hyper-V Server'} {m.group(2)}{' R2' if m.group(3) else ''}"
        m = re.search(r"Windows (\d+(?:\.\d)?|XP|Vista)(?![\d.])", os_name, re.I)
        if not m:
            return re.sub(r"^Microsoft |\s*\(.*\)$", "", os_name)[:60] or None
        ver = m.group(1)
        kind = re.search(r"(?<![A-Za-z])(LTS[BC])(?![A-Za-z])", os_name, re.I)
        if not kind:
            fu = WIN11_BUILDS.get(_build(report) or 0) if ver == "11" else None
            if fu:
                # Pro Education and Pro for Workstations follow Home and Pro; Enterprise, Education and IoT Enterprise
                # (not LTSC) get the longer support
                ent = re.search(r"\b(Enterprise|Education)\b", os_name, re.I) and not re.search(r"\bPro\b", os_name, re.I)
                return f"Windows 11 {fu} {WIN11_ENT if ent else WIN11_HOME}"
            return f"Windows {ver}"
        iot = "IoT " if re.search(r"(?<![A-Za-z])IoT(?![A-Za-z])", os_name, re.I) else ""
        rel = LTSC_BUILDS.get(_build(report) or 0)
        if not rel:
            year = re.search(r"\b(20\d\d)\b", re.sub(r"\(.*\)", "", os_name))
            rel = kind.group(1).upper() + (f" {year.group(1)}" if year else "")
        return f"Windows {ver} {iot}Enterprise {rel}"
    os_id = str(report.get("os_id") or "").strip().lower()
    vid = str(report.get("os_version_id") or "").strip()
    name = LINUX_NAMES.get(os_id) if os_id in LINUX_NAMES else None
    if name and vid:
        ver = vid if os_id in ("ubuntu", "alpine", "linuxmint", "opensuse-leap", "openwrt", "freebsd") else vid.split(".")[0]
        if os_id in ("alpine", "freebsd", "openwrt"):
            ver = ".".join(vid.split(".")[:2])
        if os_id == "freebsd":
            ver = re.sub(r"-.*", "", ver)
        return f"{name} {ver}"
    # No os-release fields: the name the agent sent, without its patch level, code name and "LTS"
    text = re.sub(r"\s*\(.*?\)|\bGNU/Linux\b|\bLTS\b", "", os_name).strip()
    m = re.match(r"^(.*?[A-Za-z])\s+v?(\d+)(?:\.(\d+))?", text)
    if not m:
        return text[:60] or None
    base = m.group(1).strip()
    ver = f"{m.group(2)}.{m.group(3)}" if m.group(3) and base.lower() == "ubuntu" else m.group(2)
    return f"{base} {ver}"


def matches(pattern: str, report: dict | None) -> bool:
    """Whether a line of vuln_skip_os takes in this device: its release exactly (a tick in Settings), or whole words
    of what the agent reports. A line that doesn't name LTSC/LTSB/IoT never takes in those editions."""
    pattern = str(pattern or "").strip()
    if not pattern:
        return False
    rel = group(report)
    if rel and pattern.lower() == rel.lower():
        return True
    if rel and SPECIAL.search(rel) and not SPECIAL.search(pattern):
        return False
    word = r"(?<![A-Za-z0-9])" + re.escape(pattern) + r"(?![A-Za-z0-9])"
    return any(re.search(word, t, re.I) for t in (str((report or {}).get("os") or ""), rel or ""))


def end(release: str | None) -> str | None:
    return END.get(release or "")


def ended(release: str | None, now: float | None = None) -> bool | None:
    e = end(release)
    if not e:
        return None
    return time.strftime("%Y-%m-%d", time.gmtime(now if now is not None else time.time())) > e
