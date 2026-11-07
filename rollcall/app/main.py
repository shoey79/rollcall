#!/usr/bin/env python3
"""Rollcall (formerly Ping Monitor) - Home Assistant add-on.

Pings a list of hosts on a schedule and tracks status:
  green     last ping succeeded (and all service checks passing)
  amber     one consecutive ping failure
  red       two or more consecutive ping failures (notifies)
  degraded  pings fine, but a service check (TCP port / HTTP) is failing (notifies)

Optional per-host service checks use presets (dc, sql, iis, exchange...) or
custom tcp:/http: checks, each with its own amber -> red count.

Results go to SQLite (/data) for uptime history, are pushed to Home Assistant
as sensor.ping_monitor_<name> (and sensor.ping_monitor_<name>_<service>), and
are shown on an ingress web dashboard.
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import os
import re
import secrets
import hashlib
import hmac
import io
import shutil
import tempfile
import zipfile
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
import socket
import sqlite3
import ssl
import time
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

from aiohttp import ClientSession, ClientTimeout, web

import agents as agentlib
import snmp as snmplib
import syslogrx as sysloglib
from agents import AgentStore, clean_enrol_info, evaluate

OPTIONS_PATH = Path(os.environ.get("PM_OPTIONS", "/data/options.json"))
DB_PATH = Path(os.environ.get("PM_DB", "/data/ping_monitor.db"))
WEB_DIR = Path(__file__).parent / "web"
PORT = int(os.environ.get("PM_PORT", "8099"))
SUPERVISOR_TOKEN = os.environ.get("SUPERVISOR_TOKEN")
HA_API = os.environ.get("PM_HA_API", "http://supervisor/core/api")
SUPERVISOR_API = os.environ.get("PM_SUPERVISOR_API", "http://supervisor")
HA_WS = os.environ.get("PM_HA_WS", "ws://supervisor/core/websocket")

GREEN, AMBER, RED, UNKNOWN, MAINT, DEGRADED = (
    "green", "amber", "red", "unknown", "maintenance", "degraded")
ICONS = {
    GREEN: "mdi:lan-connect",
    AMBER: "mdi:lan-pending",
    RED: "mdi:lan-disconnect",
    UNKNOWN: "mdi:help-network",
    MAINT: "mdi:wrench-clock",
    DEGRADED: "mdi:alert-circle-outline",
}
SVC_ICONS = {
    GREEN: "mdi:check-network",
    AMBER: "mdi:help-network",
    RED: "mdi:close-network",
    UNKNOWN: "mdi:minus-network",
}
MAINT_OK = 2  # value stored in checks.ok for checks made during maintenance
MAINT_PATH = Path(os.environ.get("PM_MAINT", str(DB_PATH.parent / "maintenance.json")))
HOSTS_PATH = Path(os.environ.get("PM_HOSTS", str(DB_PATH.parent / "hosts.json")))
IMPORT_MARK = HOSTS_PATH.with_name("imported_options.json")
AGENTS_PATH = Path(os.environ.get("PM_AGENTS", str(DB_PATH.parent / "agents.json")))
AGENT_REPORTS = Path(os.environ.get("PM_AGENT_REPORTS", str(DB_PATH.parent / "agent_reports")))
ICONS_DIR = Path(os.environ.get("PM_ICONS", str(DB_PATH.parent / "icons")))  # uploaded device pictures
ICON_TYPES = {"png": "image/png", "jpg": "image/jpeg", "webp": "image/webp", "svg": "image/svg+xml"}
ICON_FILE = re.compile(r"^[a-z0-9]{12}\.(png|jpg|webp|svg)$")
ICON_REF = re.compile(r"^(b:[a-z0-9-]{1,24}|u:[a-z0-9]{12}\.(png|jpg|webp|svg))$")
AGENT_PORT = int(os.environ.get("PM_AGENT_PORT", "8100"))
SYSLOG_PORT = int(os.environ.get("PM_SYSLOG_PORT", "5140"))  # inside the container; the host maps 514/udp to it
AGENT_SCRIPT = Path(__file__).parent / "agent" / "PingMonitorAgent.ps1"
LINUX_AGENT_SCRIPT = Path(__file__).parent / "agent" / "pingmonitor-agent.py"
VIEWS_PATH = Path(os.environ.get("PM_VIEWS", str(DB_PATH.parent / "views.json")))
AGENT_SETTINGS = Path(os.environ.get("PM_AGENT_SETTINGS", str(DB_PATH.parent / "agent_settings.json")))
SSL_DIR = Path(os.environ.get("PM_SSL_DIR", "/ssl"))
DAY = 86400
SECURITY_HIDDEN = "Security details are visible to Home Assistant admins"
BUCKETS = 48  # 24h strip on the dashboard, 30 min per bucket

log = logging.getLogger("ping_monitor")

DEFAULTS = {
    "interval": 300,
    "retry_interval": 300,
    "ping_count": 3,
    "ping_timeout": 2,
    "service_timeout": 5,
    "history_days": 7,
    "notify_services": [],
    "persistent_notification": True,
    "notify_recovery": True,
    "log_level": "info",
    "maintenance_minutes": 30,
    "notification_url": "",
    "admin_only_changes": True,
    "editors": [],
    "agent_stale_minutes": 15,
    "agent_slow_seconds": 120,
    "agent_disk_warn": 15,
    "agent_disk_crit": 5,
    "agent_failed_logons": 20,
    "agent_patch_days": 60,
    "agent_security_alerts": True,
    "agent_event_alerts": True,
    "agent_event_watch": list(agentlib.DEFAULT_EVENT_WATCH),
    "agent_security_alert_ids": list(agentlib.DEFAULT_SECURITY_ALERT_IDS),
    "agent_watch_services": [],
    "agent_ignore": [],
    "agent_auto_add": True,
    "agent_ssl": False,
    "agent_certfile": "fullchain.pem",
    "agent_keyfile": "privkey.pem",
    "hosts": [],
}

# --------------------------------------------------------------------------
# Service check presets
# --------------------------------------------------------------------------
# HTTP checks pass on any response below 500: a 401 from Windows auth or a 302
# to a login page still means the app is answering. 5xx (e.g. a stopped IIS
# app pool's 503), timeouts and refused connections fail.
# One row per preset: (name, title shown in the form, group, [(label, check)...]).
# Groups and rows appear in the Add/Edit form in this order. Where an app has
# its own health/status endpoint that's used; otherwise its default port.
# Ports are the defaults - use a custom check if yours differs.
_W, _DB, _MAIL, _REM, _VIRT, _NET, _HOME, _MEDIA, _DL, _MON, _OTHER = (
    "Windows & Microsoft", "Databases", "Mail & files", "Remote access",
    "Virtualisation & storage", "Network & infrastructure", "Home & automation",
    "Media", "Downloads", "Monitoring & development", "Other")
PRESET_TABLE: list[tuple[str, str, str, list[tuple[str, str]]]] = [
    # Windows & Microsoft
    ("dc", "Domain controller", _W, [("DNS", "tcp:53"), ("Kerberos", "tcp:88"), ("LDAP", "tcp:389"),
                                     ("SMB", "tcp:445"), ("GC", "tcp:3268")]),
    ("dns", "DNS server", _W, [("DNS", "tcp:53")]),
    ("ldap", "LDAP", _W, [("LDAP", "tcp:389")]),
    ("ldaps", "LDAPS (secure LDAP)", _W, [("LDAPS", "tcp:636")]),
    ("fileserver", "File server (SMB)", _W, [("SMB", "tcp:445")]),
    ("rds", "Remote Desktop / Terminal Server", _W, [("RDP", "tcp:3389")]),
    ("sql", "SQL Server", _W, [("SQL", "tcp:1433")]),
    ("iis", "IIS (HTTP)", _W, [("HTTP", "http:80/")]),
    ("iis-https", "IIS (HTTPS)", _W, [("HTTPS", "https:443/")]),
    ("sharepoint", "SharePoint", _W, [("SharePoint", "https:443/")]),
    ("exchange", "Exchange", _W, [("OWA", "https:443/owa"), ("SMTP", "tcp:25")]),
    ("wsus", "WSUS", _W, [("WSUS", "tcp:8530")]),
    ("adfs", "AD FS", _W, [("ADFS", "https:443/FederationMetadata/2007-06/FederationMetadata.xml")]),
    ("adcs", "Certificate Services (web enrolment)", _W, [("CertSrv", "http:80/certsrv/")]),
    ("configmgr", "ConfigMgr / SCCM management point", _W, [("MP", "http:80/sms_mp/.sms_aut?mplist")]),
    ("kms", "KMS activation", _W, [("KMS", "tcp:1688")]),
    ("winrm", "WinRM / PowerShell remoting", _W, [("WinRM", "tcp:5985")]),
    ("veeam", "Veeam Backup & Replication", _W, [("Veeam", "tcp:9392")]),
    # Databases
    ("mysql", "MySQL / MariaDB", _DB, [("MySQL", "tcp:3306")]),
    ("postgres", "PostgreSQL", _DB, [("PostgreSQL", "tcp:5432")]),
    ("mongodb", "MongoDB", _DB, [("MongoDB", "tcp:27017")]),
    ("redis", "Redis", _DB, [("Redis", "tcp:6379")]),
    ("oracle", "Oracle", _DB, [("Oracle", "tcp:1521")]),
    ("elasticsearch", "Elasticsearch", _DB, [("Elasticsearch", "http:9200/")]),
    ("influxdb", "InfluxDB", _DB, [("InfluxDB", "http:8086/ping")]),
    # Mail & files
    ("smtp", "SMTP relay / mail server", _MAIL, [("SMTP", "tcp:25")]),
    ("imap", "IMAP (secure)", _MAIL, [("IMAPS", "tcp:993")]),
    ("pop3", "POP3 (secure)", _MAIL, [("POP3S", "tcp:995")]),
    ("ftp", "FTP", _MAIL, [("FTP", "tcp:21")]),
    ("nextcloud", "Nextcloud", _MAIL, [("Nextcloud", "https:443/status.php")]),
    # Remote access
    ("ssh", "SSH / SFTP", _REM, [("SSH", "tcp:22")]),
    ("vnc", "VNC", _REM, [("VNC", "tcp:5900")]),
    ("telnet", "Telnet (switches, old kit)", _REM, [("Telnet", "tcp:23")]),
    # Virtualisation & storage
    ("proxmox", "Proxmox VE", _VIRT, [("Proxmox", "https:8006/")]),
    ("pbs", "Proxmox Backup Server", _VIRT, [("PBS", "https:8007/")]),
    ("esxi", "VMware ESXi", _VIRT, [("ESXi", "https:443/")]),
    ("vcenter", "VMware vCenter", _VIRT, [("vCenter", "https:443/ui/")]),
    ("synology", "Synology DSM", _VIRT, [("DSM", "https:5001/")]),
    ("qnap", "QNAP QTS", _VIRT, [("QTS", "http:8080/")]),
    ("truenas", "TrueNAS", _VIRT, [("TrueNAS", "https:443/")]),
    ("unraid", "Unraid", _VIRT, [("Unraid", "http:80/")]),
    ("portainer", "Portainer", _VIRT, [("Portainer", "https:9443/")]),
    # Network & infrastructure
    ("unifi", "UniFi Network, old controller (8443)", _NET, [("UniFi", "https:8443/"), ("Inform", "tcp:8080")]),
    ("unifi-os", "UniFi OS console, e.g. Cloud Key or UDM (443)", _NET, [("UniFi", "https:443/")]),
    ("unifi-os-server", "UniFi OS Server, self-hosted (11443)", _NET, [("UniFi", "https:11443/"), ("Inform", "tcp:8080")]),
    ("idrac", "Dell iDRAC / server BMC", _NET, [("iDRAC", "https:443/")]),
    ("pihole", "Pi-hole", _NET, [("DNS", "tcp:53"), ("Pi-hole", "http:80/admin/")]),
    ("adguard", "AdGuard Home", _NET, [("DNS", "tcp:53"), ("AdGuard", "http:80/")]),
    ("npm", "Nginx Proxy Manager", _NET, [("NPM", "http:81/")]),
    ("squid", "Squid / web proxy", _NET, [("Proxy", "tcp:3128")]),
    ("printer", "Network printer", _NET, [("Printer", "tcp:9100")]),
    ("snmp", "SNMP: switch ports and PoE, NAS disks and RAID (e.g. Netgear, Buffalo)", _NET, [("SNMP", "snmp:device")]),
    ("syslog", "Syslog: keep this device's log messages and alert on errors", _NET, [("Syslog", "syslog:device")]),
    ("camera", "IP camera / NVR (RTSP)", _NET, [("RTSP", "tcp:554")]),
    # Home & automation
    ("homeassistant", "Home Assistant", _HOME, [("Home Assistant", "http:8123/")]),
    ("nodered", "Node-RED", _HOME, [("Node-RED", "http:1880/")]),
    ("mqtt", "MQTT broker (Mosquitto)", _HOME, [("MQTT", "tcp:1883")]),
    ("frigate", "Frigate NVR", _HOME, [("Frigate", "http:5000/api/version")]),
    ("vaultwarden", "Vaultwarden", _HOME, [("Vaultwarden", "http:80/alive")]),
    ("paperless", "Paperless-ngx", _HOME, [("Paperless", "http:8000/")]),
    ("uptimekuma", "Uptime Kuma", _HOME, [("Uptime Kuma", "http:3001/")]),
    # Media
    ("plex", "Plex", _MEDIA, [("Plex", "http:32400/identity")]),
    ("jellyfin", "Jellyfin", _MEDIA, [("Jellyfin", "http:8096/health")]),
    ("emby", "Emby", _MEDIA, [("Emby", "http:8096/emby/System/Info/Public")]),
    ("immich", "Immich", _MEDIA, [("Immich", "http:2283/api/server/ping")]),
    ("audiobookshelf", "Audiobookshelf", _MEDIA, [("Audiobookshelf", "http:13378/")]),
    ("navidrome", "Navidrome", _MEDIA, [("Navidrome", "http:4533/")]),
    ("tautulli", "Tautulli", _MEDIA, [("Tautulli", "http:8181/")]),
    ("overseerr", "Overseerr / Jellyseerr", _MEDIA, [("Overseerr", "http:5055/api/v1/status")]),
    # Downloads
    ("sonarr", "Sonarr", _DL, [("Sonarr", "http:8989/ping")]),
    ("radarr", "Radarr", _DL, [("Radarr", "http:7878/ping")]),
    ("lidarr", "Lidarr", _DL, [("Lidarr", "http:8686/ping")]),
    ("prowlarr", "Prowlarr", _DL, [("Prowlarr", "http:9696/ping")]),
    ("sabnzbd", "SABnzbd", _DL, [("SABnzbd", "http:8080/")]),
    ("qbittorrent", "qBittorrent", _DL, [("qBittorrent", "http:8080/")]),
    ("transmission", "Transmission", _DL, [("Transmission", "http:9091/transmission/web/")]),
    # Monitoring & development
    ("grafana", "Grafana", _MON, [("Grafana", "http:3000/api/health")]),
    ("prometheus", "Prometheus", _MON, [("Prometheus", "http:9090/-/healthy")]),
    ("gitea", "Gitea / Forgejo", _MON, [("Gitea", "http:3000/api/healthz")]),
    ("jenkins", "Jenkins", _MON, [("Jenkins", "http:8080/login")]),
    # Other
    ("http", "Web server (HTTP)", _OTHER, [("HTTP", "http:80/")]),
    ("https", "Web server (HTTPS)", _OTHER, [("HTTPS", "https:443/")]),
]
PRESETS: dict[str, list[tuple[str, str]]] = {n: checks for n, _t, _g, checks in PRESET_TABLE}
PRESET_INFO = [(n, t, g) for n, t, g, _c in PRESET_TABLE]
ALIASES = {
    "smb": "fileserver", "file": "fileserver", "rdp": "rds", "terminal": "rds",
    "domain": "dc", "mssql": "sql", "owa": "exchange",
    "ilo": "idrac", "bmc": "idrac", "ipmi": "idrac",
    "mariadb": "mysql", "postgresql": "postgres", "pgsql": "postgres", "mongo": "mongodb",
    "elastic": "elasticsearch", "influx": "influxdb", "certsrv": "adcs", "sccm": "configmgr",
    "mecm": "configmgr", "sftp": "ssh", "pve": "proxmox", "vmware": "esxi", "dsm": "synology",
    "nvr": "camera", "rtsp": "camera", "ha": "homeassistant", "node-red": "nodered",
    "mosquitto": "mqtt", "bitwarden": "vaultwarden", "kuma": "uptimekuma",
    "jellyseerr": "overseerr", "forgejo": "gitea", "pi-hole": "pihole",
}


def preset_summary(name: str) -> str:
    """Short description of what a preset checks, e.g. 'TCP 1433' or 'DNS 53 · LDAP 389'."""
    checks = PRESETS[name]
    if len(checks) == 1:
        spec = checks[0][1]
        return f"TCP {spec[4:]}" if spec.startswith("tcp:") else spec
    return " · ".join(f"{label} {spec[4:] if spec.startswith('tcp:') else spec}"
                      for label, spec in checks)


_LABELLED = re.compile(r"^([^=:/]+)=(.+)$")
_TCP = re.compile(r"^tcp:(\d{1,5})$", re.I)
_ADDR = r"(?:[A-Za-z0-9](?:[A-Za-z0-9.\-]{0,251}[A-Za-z0-9])?|\[[0-9A-Fa-f:]+\])"
_PING = re.compile(rf"^ping:({_ADDR})$", re.I)             # another address of the same device
_TCP_AT = re.compile(rf"^tcp:({_ADDR}):(\d{{1,5}})$", re.I)  # a port on another address
_REL_HTTP = re.compile(r"^(https?):(\d{1,5})(/.*)?$", re.I)
# A Home Assistant entity, optionally with a condition: ha:sensor.office_ap_cpu_utilization>90
_HA = re.compile(r"^ha:([a-z_]+\.[a-z0-9_]+)\s*(?:(>=|<=|!=|>|<|=)\s*(\S.{0,60}))?$", re.I)
HA_OPS = {">": "above", ">=": "at or above", "<": "below", "<=": "at or below", "=": "is", "!=": "isn't"}


def ha_label(entity: str) -> str:
    """'sensor.office_ap_cpu_utilization' -> 'CPU'; falls back to the last words of the id."""
    e = entity.split(".", 1)[1]
    for word, label in (("cpu", "CPU"), ("memory", "Memory"), ("mem_", "Memory"), ("temperature", "Temp"),
                        ("uptime", "Uptime"), ("clients", "Clients"), ("state", "State"), ("load", "Load")):
        if word in e:
            return label
    return " ".join(e.split("_")[-2:]).capitalize()


def parse_check(entry: str, label: str | None = None) -> list[dict]:
    """Turn one `checks:` entry into one or more service definitions.

    Accepts a preset (`sql`), `tcp:PORT`, `http:PORT/path`, `https:PORT/path`,
    a full URL, and an optional `Label=` prefix on any of the non-preset forms.
    """
    entry = str(entry).strip()
    low = entry.lower()
    m = _LABELLED.match(entry)
    if m and not low.startswith(("http://", "https://")):
        return parse_check(m.group(2), m.group(1).strip())
    name = ALIASES.get(low, low)
    if name in PRESETS:
        items = PRESETS[name]
        return [d for lab, spec in items
                for d in parse_check(spec, label if label and len(items) == 1 else lab)]
    if m := _PING.match(entry):
        addr = m.group(1).strip("[]")
        return [{"label": label or addr, "kind": "ping", "port": None, "url": None, "desc": f"ping {addr}", "target": addr}]
    if m := _TCP_AT.match(entry):
        addr, port = m.group(1).strip("[]"), int(m.group(2))
        if not 1 <= port <= 65535:
            raise ValueError(f"port out of range in '{entry}'")
        return [{"label": label or f"TCP {port} on {addr}", "kind": "tcp", "port": port, "url": None,
                 "desc": f"tcp/{port} on {addr}", "target": addr}]
    if m := _TCP.match(entry):
        port = int(m.group(1))
        if not 1 <= port <= 65535:
            raise ValueError(f"port out of range in '{entry}'")
        return [{"label": label or f"TCP {port}", "kind": "tcp", "port": port,
                 "url": None, "desc": f"tcp/{port}"}]
    if m := _REL_HTTP.match(entry):
        scheme, port, path = m.group(1).lower(), int(m.group(2)), m.group(3) or "/"
        if not 1 <= port <= 65535:
            raise ValueError(f"port out of range in '{entry}'")
        return [{"label": label or f"{scheme.upper()} {port}", "kind": "http", "port": port,
                 "url": f"{scheme}://{{host}}:{port}{path}", "desc": f"{scheme}:{port}{path}",
                 "fallback": True}]
    if low == "syslog:device":
        return [{"label": label or "Syslog", "kind": "syslog", "port": 514, "url": None, "desc": "syslog"}]
    if low == "snmp:device":
        return [{"label": label or "SNMP", "kind": "snmp", "port": 161, "url": None, "desc": "snmp"}]
    if m := _HA.match(entry):
        entity, op, value = m.group(1).lower(), m.group(2), (m.group(3) or "").strip()
        if op in (">", ">=", "<", "<="):
            try:
                float(value)
            except ValueError:
                raise ValueError(f"'{entry}': {op} needs a number")
        cond = f" {op} {value}" if op else ""
        return [{"label": label or ha_label(entity), "kind": "ha", "port": None, "url": None,
                 "desc": f"ha:{entity}{cond}", "entity": entity, "op": op, "value": value or None}]
    if low.startswith(("http://", "https://")):
        u = urlparse(entry)
        if not u.netloc:
            raise ValueError(f"bad URL '{entry}'")
        return [{"label": label or u.netloc, "kind": "http", "port": u.port,
                 "url": entry, "desc": entry}]
    raise ValueError(f"unknown check '{entry}' (presets: {', '.join(sorted(PRESETS))})")


# --------------------------------------------------------------------------
# Monitoring schedules: some computers are only meant to be on at certain times
# --------------------------------------------------------------------------
DAY_NAMES = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
_HHMM = re.compile(r"^([01]?\d|2[0-3]):([0-5]\d)$|^24:00$")
TZ = None  # Home Assistant's time zone, set at start-up


def _mins(hhmm: str) -> int:
    h, m = hhmm.split(":")
    return int(h) * 60 + int(m)


def clean_schedule(raw) -> dict | None:
    """None means monitored all the time. Otherwise {"windows": [...], "grace": minutes}."""
    if not raw:
        return None
    if not isinstance(raw, dict):
        raise ValueError("Invalid schedule")
    wins = raw.get("windows") or []
    if not isinstance(wins, list) or not 1 <= len(wins) <= 20:
        raise ValueError("A schedule needs between 1 and 20 time windows")
    out = []
    for w in wins:
        if not isinstance(w, dict):
            raise ValueError("Invalid time window")
        days = sorted({int(d) for d in (w.get("days") or []) if str(d).isdigit() and 0 <= int(d) <= 6})
        start, end = str(w.get("start") or "").strip(), str(w.get("end") or "").strip()
        if not days:
            raise ValueError("Pick at least one day for each time window")
        if not _HHMM.match(start) or not _HHMM.match(end) or start == "24:00":
            raise ValueError("Times must be HH:MM, e.g. 07:30")
        if _mins(start) == _mins(end) % 1440:
            raise ValueError(f"A window can't start and end at the same time ({start})")
        out.append({"days": days, "start": f"{_mins(start) // 60:02d}:{_mins(start) % 60:02d}", "end": end if end == "24:00" else f"{_mins(end) // 60:02d}:{_mins(end) % 60:02d}"})
    try:
        grace = int(raw.get("grace", 15))
    except (TypeError, ValueError):
        raise ValueError("The start-up allowance must be a number of minutes")
    if not 0 <= grace <= 240:
        raise ValueError("The start-up allowance must be between 0 and 240 minutes")
    return {"windows": out, "grace": grace}


def schedule_intervals(sched: dict, now: float) -> list[tuple[float, float]]:
    """The schedule's on-periods from yesterday to 8 days ahead, merged, as timestamps."""
    tz = TZ or datetime.now().astimezone().tzinfo
    today = datetime.fromtimestamp(now, tz).replace(hour=0, minute=0, second=0, microsecond=0)
    spans = []
    for offset in range(-1, 9):
        day = (today + timedelta(days=offset))
        midnight = datetime(day.year, day.month, day.day, tzinfo=tz)  # re-localise across DST changes
        for w in sched["windows"]:
            if midnight.weekday() not in w["days"]:
                continue
            a, b = _mins(w["start"]), _mins(w["end"])
            if b <= a:
                b += 1440  # runs past midnight
            st = midnight + timedelta(minutes=a)
            en = midnight + timedelta(minutes=b)
            spans.append((st.timestamp(), en.timestamp()))
    spans.sort()
    merged: list[list[float]] = []
    for a, b in spans:
        if merged and a <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], b)
        else:
            merged.append([a, b])
    return [(a, b) for a, b in merged]


def schedule_state(sched: dict | None, now: float) -> tuple[bool, float | None, float | None]:
    """(on now?, when the current on-period started, when the state next changes)."""
    if not sched:
        return True, None, None
    for a, b in schedule_intervals(sched, now):
        if a <= now < b:
            return True, a, b
        if a > now:
            return False, None, a
    return False, None, None


def describe_schedule(sched: dict | None) -> str:
    if not sched:
        return "All the time"
    parts = []
    for w in sched["windows"]:
        d = w["days"]
        if d == list(range(7)):
            days = "Every day"
        elif d == [0, 1, 2, 3, 4]:
            days = "Mon–Fri"
        elif d == [5, 6]:
            days = "Sat–Sun"
        elif len(d) > 2 and d == list(range(d[0], d[-1] + 1)):
            days = f"{DAY_NAMES[d[0]]}–{DAY_NAMES[d[-1]]}"
        else:
            days = ", ".join(DAY_NAMES[i] for i in d)
        parts.append(f"{days} {w['start']}–{w['end']}")
    return "; ".join(parts)


def validate_entry(raw: dict) -> dict:
    """Check a host entry from the dashboard or the Configuration tab.

    Returns {"name", "host", "checks"} with preset names normalised, or raises
    ValueError with a message suitable to show the user.
    """
    if not isinstance(raw, dict):
        raise ValueError("Expected an object")
    name = str(raw.get("name") or "").strip()
    host = str(raw.get("host") or "").strip()
    if not name:
        raise ValueError("Name is required")
    if len(name) > 64:
        raise ValueError("Name must be 64 characters or fewer")
    if not host or len(host) > 253 or any(c.isspace() for c in host) or "/" in host:
        raise ValueError("Enter a valid IP address or hostname (no spaces, no http://)")
    checks = raw.get("checks") or []
    if isinstance(checks, str):
        checks = re.split(r"[,\s]+", checks)
    if not isinstance(checks, list):
        raise ValueError("Checks must be a list")
    out, seen, errors = [], set(), []
    for c in checks:
        c = str(c).strip()
        if not c:
            continue
        canonical = ALIASES.get(c.lower(), c.lower())
        if canonical in PRESETS:
            c = canonical
        try:
            parse_check(c)
        except ValueError as err:
            if "unknown check" in str(err):
                errors.append(f"'{c}' isn't a valid check. Use tcp:PORT, http:PORT/path, "
                              f"https:PORT/path, a full URL or ha:sensor.entity_id")
            else:
                errors.append(str(err))
            continue
        if c.lower() not in seen:
            seen.add(c.lower())
            out.append(c)
    if errors:
        raise ValueError("; ".join(errors))
    entry = {"name": name, "host": host, "checks": out}
    if raw.get("expect_off"):
        entry["expect_off"] = True  # monitored whenever it's on; a schedule doesn't apply
    else:
        sched = clean_schedule(raw.get("schedule"))
        if sched:
            entry["schedule"] = sched
    if raw.get("no_alerts"):
        entry["no_alerts"] = True
    if "syslog_alert" in raw:
        try:
            lvl = int(raw.get("syslog_alert"))
        except (TypeError, ValueError):
            raise ValueError("Choose which syslog messages alert")
        if not -1 <= lvl <= 4:
            raise ValueError("Choose which syslog messages alert")
        entry["syslog_alert"] = lvl
    for k in ("syslog_keywords", "syslog_ignore"):
        if k in raw:
            v = raw.get(k) or []
            words = [w.strip() for w in (v.split(",") if isinstance(v, str) else v) if str(w).strip()]
            if len(words) > 30 or any(len(str(w)) > 80 for w in words):
                raise ValueError("Up to 30 syslog words, each up to 80 characters")
            entry[k] = [str(w) for w in words]
    if "snmp_version" in raw:
        ver = str(raw.get("snmp_version") or "2c")
        if ver not in ("2c", "3"):
            raise ValueError("SNMP version must be 2c or 3")
        entry["snmp_version"] = ver
        if ver == "3":
            v = raw.get("snmp_v3") or {}
            user = str(v.get("user") or "").strip()
            if not user or len(user) > 32 or not user.isprintable():
                raise ValueError("Enter the SNMP v3 user name (up to 32 characters)")
            auth = v.get("auth") or None
            priv = v.get("priv") or None
            if auth and auth not in snmplib.AUTH:
                raise ValueError("Unknown SNMP v3 authentication protocol")
            if priv and priv not in snmplib.PRIV:
                raise ValueError("Unknown SNMP v3 privacy protocol")
            if priv and not auth:
                raise ValueError("SNMP v3 privacy needs authentication too")
            clean = {"user": user, "auth": auth, "priv": priv}
            for k in ("auth_pass", "priv_pass"):
                pw = v.get(k)
                if pw not in (None, ""):
                    pw = str(pw)
                    if not 8 <= len(pw) <= 64:
                        raise ValueError("SNMP v3 passwords must be 8 to 64 characters")
                    clean[k] = pw
            entry["snmp_v3"] = clean
    if "icon" in raw:
        icon = str(raw.get("icon") or "")
        if icon and not ICON_REF.match(icon):
            raise ValueError("Unknown icon")
        entry["icon"] = icon
    if "model" in raw:
        model = str(raw.get("model") or "").strip()
        if len(model) > 64 or not model.isprintable():
            raise ValueError("Make and model must be up to 64 ordinary characters")
        entry["model"] = model
    comm = raw.get("snmp_community")
    if comm not in (None, ""):
        comm = str(comm)
        if len(comm) > 64 or not comm.isprintable():
            raise ValueError("The SNMP community must be up to 64 ordinary characters")
        entry["snmp_community"] = comm
    return entry


def load_options() -> dict:
    opts = dict(DEFAULTS)
    try:
        opts.update(json.loads(OPTIONS_PATH.read_text()))
    except FileNotFoundError:
        log.warning("No options file at %s, using defaults", OPTIONS_PATH)
    return opts


def slugify(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_") or "host"


def fmt_duration(seconds: float) -> str:
    seconds = int(seconds)
    if seconds < 60:
        return f"{seconds}s"
    d, rem = divmod(seconds, 86400)
    h, rem = divmod(rem, 3600)
    m, _ = divmod(rem, 60)
    parts = [f"{d}d"] if d else []
    if h or d:
        parts.append(f"{h}h")
    parts.append(f"{m}m")
    return " ".join(parts)


def iso(ts: float | None) -> str | None:
    if ts is None:
        return None
    return time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(ts))


# --------------------------------------------------------------------------
# Storage
# --------------------------------------------------------------------------
class Store:
    """Check results. `host` is the host key, or `<host>__<service>` for services."""

    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS checks ("
            " host TEXT NOT NULL, ts REAL NOT NULL, ok INTEGER NOT NULL, latency REAL)"
        )
        self.db.execute("CREATE INDEX IF NOT EXISTS idx_checks ON checks(host, ts)")
        self.db.commit()

    def add(self, key: str, ts: float, ok: bool | int, latency: float | None) -> None:
        self.db.execute(
            "INSERT INTO checks (host, ts, ok, latency) VALUES (?, ?, ?, ?)",
            (key, ts, int(ok), latency),
        )
        self.db.commit()

    def prune(self, before: float) -> None:
        cur = self.db.execute("DELETE FROM checks WHERE ts < ?", (before,))
        self.db.commit()
        if cur.rowcount:
            log.debug("Pruned %d old check rows", cur.rowcount)

    def clear(self, host: str | None = None) -> int:
        """Delete history for one host (and its services), or everything."""
        if host is None:
            cur = self.db.execute("DELETE FROM checks")
        else:
            prefix = host + "__"
            cur = self.db.execute(
                "DELETE FROM checks WHERE host = ? OR substr(host, 1, ?) = ?",
                (host, len(prefix), prefix),
            )
        self.db.commit()
        return cur.rowcount

    def rows(self, key: str, since: float) -> list[tuple[float, int]]:
        """Checks since `since`, plus the one just before it (state carried in)."""
        prev = self.db.execute(
            "SELECT ts, ok FROM checks WHERE host = ? AND ts < ? ORDER BY ts DESC LIMIT 1",
            (key, since),
        ).fetchall()
        rest = self.db.execute(
            "SELECT ts, ok FROM checks WHERE host = ? AND ts >= ? ORDER BY ts",
            (key, since),
        ).fetchall()
        return prev + rest

    def recent(self, key: str, n: int = 2) -> list[tuple[float, int, float | None]]:
        return self.db.execute(
            "SELECT ts, ok, latency FROM checks WHERE host = ? ORDER BY ts DESC LIMIT ?",
            (key, n),
        ).fetchall()


def coverage(rows, start: float, end: float, max_gap: float) -> tuple[float, float, float]:
    """Seconds (up, down, maintenance) between start and end.

    Each check's result is assumed to hold until the next check, capped at
    max_gap so periods when the add-on wasn't running aren't extrapolated.
    """
    up = down = maint = 0.0
    for i, (ts, ok) in enumerate(rows):
        seg_start = max(ts, start)
        seg_end = rows[i + 1][0] if i + 1 < len(rows) else end
        seg_end = min(seg_end, end, ts + max_gap)
        if seg_end <= seg_start:
            continue
        d = seg_end - seg_start
        if ok == MAINT_OK:
            maint += d
        elif ok:
            up += d
        else:
            down += d
    return up, down, maint


def uptime_pct(rows, start: float, end: float, max_gap: float) -> float | None:
    """Time-weighted % up. Maintenance time counts as neither up nor down."""
    up, down, _ = coverage(rows, start, end, max_gap)
    if up + down <= 0:
        return None
    return round(100.0 * up / (up + down), 2)


# --------------------------------------------------------------------------
# Probing
# --------------------------------------------------------------------------
RTT_RE = re.compile(r"=\s*[\d.]+/([\d.]+)/")


async def resolve(host: str) -> str | None:
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass
    try:
        infos = await asyncio.get_running_loop().getaddrinfo(
            host, None, family=socket.AF_INET, type=socket.SOCK_STREAM
        )
        return infos[0][4][0] if infos else None
    except (socket.gaierror, OSError) as err:
        log.debug("Could not resolve %s: %s", host, err)
        return None


# The add-on doesn't ask for the NET_RAW privilege: ping uses unprivileged ICMP
# sockets, which Docker allows by default. If this system doesn't, hosts are
# checked by TCP instead (any answer, even "connection refused", means it's up).
PING_MODE = "icmp"
PING_BLOCKED = re.compile(r"socket:|Operation not permitted|Lacking privilege|permission denied|not supported by protocol", re.I)
TCP_PROBE_PORTS = [445, 3389, 22, 443, 80, 135, 53, 8080, 8443, 139]


async def detect_ping_mode() -> str:
    """Try pinging this container's own loopback once at start-up."""
    global PING_MODE
    try:
        proc = await asyncio.create_subprocess_exec("ping", "-n", "-c", "1", "-W", "1", "127.0.0.1",
                                                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
        text = out.decode(errors="replace")
        if proc.returncode == 0:
            PING_MODE = "icmp"
        elif PING_BLOCKED.search(text):
            PING_MODE = "tcp"
            log.warning("This system doesn't allow ping without extra privileges (%s). Hosts will be checked by "
                        "TCP instead: a host counts as up if any common port answers, even with 'refused'.",
                        text.strip().splitlines()[-1][:120])
    except (FileNotFoundError, asyncio.TimeoutError, OSError) as err:
        PING_MODE = "tcp"
        log.warning("ping isn't usable (%s); checking hosts by TCP instead", err)
    return PING_MODE


async def tcp_alive(ip: str, ports: list[int], timeout: float) -> tuple[bool, float | None]:
    """Up if any port connects or actively refuses; down if they all time out."""
    async def one(port):
        t0 = time.monotonic()
        try:
            _r, w = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout)
            w.close()
            return (time.monotonic() - t0) * 1000
        except ConnectionRefusedError:
            return (time.monotonic() - t0) * 1000
        except (asyncio.TimeoutError, OSError):
            return None
    tasks = [asyncio.create_task(one(p)) for p in ports]
    try:
        for fut in asyncio.as_completed(tasks):
            ms = await fut
            if ms is not None:
                return True, round(ms, 1)
        return False, None
    finally:
        for t in tasks:
            t.cancel()


async def ping(ip: str, count: int, timeout: int, ports: list[int] | None = None) -> tuple[bool, float | None]:
    if PING_MODE == "tcp":
        seen, order = set(), []
        for p in (ports or []) + TCP_PROBE_PORTS:
            if p and p not in seen:
                seen.add(p)
                order.append(p)
        return await tcp_alive(ip, order[:16], max(1.0, float(timeout)))
    cmd = ["ping", "-n", "-c", str(count), "-W", str(timeout), "-i", "0.5", ip]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT
        )
    except FileNotFoundError:
        log.error("ping binary not found")
        return False, None
    try:
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=count * (timeout + 1) + 5)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        return False, None
    ok = proc.returncode == 0
    match = RTT_RE.search(out.decode(errors="replace"))
    return ok, (round(float(match.group(1)), 1) if ok and match else None)


async def tcp_check(ip: str, port: int, timeout: float) -> tuple[bool, float | None, str]:
    t0 = time.monotonic()
    try:
        _reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout)
    except asyncio.TimeoutError:
        return False, None, "timed out"
    except ConnectionRefusedError:
        return False, None, "connection refused"
    except OSError as err:
        return False, None, (err.strerror or type(err).__name__).lower()
    ms = round((time.monotonic() - t0) * 1000, 1)
    writer.close()
    try:
        await asyncio.wait_for(writer.wait_closed(), 2)
    except Exception:  # noqa: BLE001
        pass
    return True, ms, "port open"


_STATUS_LINE = re.compile(rb"^HTTP/\d(?:\.\d)?\s+(\d{3})")
_tls_ctx: ssl.SSLContext | None = None


def health_tls_context() -> ssl.SSLContext:
    """A deliberately permissive TLS context for health checks.

    We only want to know whether the web service answers, not whether it's
    secure, so this accepts self-signed certs, small keys, TLS 1.0 and the old
    ciphers and renegotiation that devices like Dell iDRAC 6 still use.
    """
    global _tls_ctx
    if _tls_ctx is None:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            ctx.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
        except (ValueError, AttributeError):
            pass
        for ciphers in ("ALL:@SECLEVEL=0", "ALL", "DEFAULT"):
            try:
                ctx.set_ciphers(ciphers)
                break
            except ssl.SSLError:
                continue
        ctx.options |= getattr(ssl, "OP_LEGACY_SERVER_CONNECT", 0x4)
        _tls_ctx = ctx
    return _tls_ctx


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


async def _http_once(scheme: str, host: str, port: int, path: str,
                     timeout: float) -> tuple[bool | None, float | None, str]:
    """One GET request, reading only the status line.

    Returns (ok, ms, detail). ok is None when the port answered but not with
    HTTP over this scheme (TLS failure, connection dropped, garbage), which is
    the case where trying the other scheme is worthwhile.
    """
    t0 = time.monotonic()
    tls = health_tls_context() if scheme == "https" else None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=tls,
                                    server_hostname=(None if not tls or _is_ip(host) else host)),
            timeout)
    except asyncio.TimeoutError:
        return False, None, "timed out"
    except ConnectionRefusedError:
        return False, None, "connection refused"
    except ssl.SSLError as err:
        return None, None, f"TLS handshake failed ({err.reason or type(err).__name__})".replace("_", " ").lower()
    except (ConnectionResetError, asyncio.IncompleteReadError):
        return None, None, "connection reset"
    except OSError as err:
        return False, None, (err.strerror or type(err).__name__).lower()
    try:
        host_header = host if port == (443 if tls else 80) else f"{host}:{port}"
        writer.write((f"GET {path} HTTP/1.1\r\nHost: {host_header}\r\n"
                      "User-Agent: HA-Ping-Monitor\r\nAccept: */*\r\nConnection: close\r\n\r\n").encode())
        await writer.drain()
        remaining = max(0.5, timeout - (time.monotonic() - t0))
        line = await asyncio.wait_for(reader.readline(), remaining)
    except asyncio.TimeoutError:
        return False, None, "no response (timed out)"
    except (ssl.SSLError, OSError, asyncio.IncompleteReadError):
        return None, None, "connection closed"
    finally:
        try:
            writer.close()
        except Exception:  # noqa: BLE001
            pass
    m = _STATUS_LINE.match(line)
    if not m:
        return None, None, "no HTTP response" if not line else "not an HTTP response"
    code = int(m.group(1))
    ms = round((time.monotonic() - t0) * 1000, 1)
    # Anything below 500 means the app answered: 401 (Windows auth) and
    # redirects to a login page count as up. 5xx (e.g. a stopped IIS app pool) fails.
    return (code < 500), (ms if code < 500 else None), f"HTTP {code}"


async def http_check(url: str, timeout: float, fallback: bool = False,
                     preferred: str | None = None) -> tuple[bool, float | None, str, str]:
    """Check a URL. Returns (ok, ms, detail, scheme_that_answered).

    With fallback, if the port answers but not with HTTP over the given scheme,
    the other scheme is tried (e.g. Plex with "secure connections required"
    answers only HTTPS on 32400).
    """
    u = urlparse(url)
    scheme = (preferred or u.scheme).lower()
    host = u.hostname or ""
    port = u.port or (443 if u.scheme == "https" else 80)
    path = (u.path or "/") + (f"?{u.query}" if u.query else "")
    order = [scheme] + ([("http" if scheme == "https" else "https")] if fallback else [])
    first = None
    for i, sch in enumerate(order):
        ok, ms, detail = await _http_once(sch, host, port, path, timeout)
        if ok is not None:
            if sch != u.scheme:
                detail += f" via {sch}"
            return ok, ms, detail, sch
        first = first or detail
    return False, None, first or "no HTTP response", scheme


# --------------------------------------------------------------------------
# Home Assistant
# --------------------------------------------------------------------------
class HomeAssistant:
    def __init__(self, session: ClientSession):
        self.session = session
        self.enabled = bool(SUPERVISOR_TOKEN)
        if not self.enabled:
            log.warning("SUPERVISOR_TOKEN not set; Home Assistant updates disabled")

    async def call(self, method: str, path: str, payload: dict | None = None) -> None:
        if not self.enabled:
            return
        try:
            async with self.session.request(
                method,
                HA_API + path,
                json=payload,
                headers={"Authorization": f"Bearer {SUPERVISOR_TOKEN}"},
            ) as resp:
                if resp.status >= 400:
                    body = (await resp.text())[:200]
                    log.warning("HA API %s %s -> %s %s", method, path, resp.status, body)
        except Exception as err:  # noqa: BLE001
            log.warning("HA API %s %s failed: %s", method, path, err)

    async def set_state(self, entity_id: str, state: str, attributes: dict) -> None:
        await self.call("POST", f"/states/{entity_id}", {"state": state, "attributes": attributes})

    async def service(self, domain: str, service: str, data: dict) -> None:
        await self.call("POST", f"/services/{domain}/{service}", data)

    async def fire(self, event: str, data: dict) -> None:
        await self.call("POST", f"/events/{event}", data)

    async def delete_state(self, entity_id: str) -> None:
        await self.call("DELETE", f"/states/{entity_id}")

    async def clear_option_hosts(self) -> None:
        """Empty the Configuration tab's hosts once they've been imported."""
        if not self.enabled:
            return
        try:
            raw = json.loads(OPTIONS_PATH.read_text())
            raw["hosts"] = []
            async with self.session.post(
                f"{SUPERVISOR_API}/addons/self/options",
                json={"options": raw},
                headers={"Authorization": f"Bearer {SUPERVISOR_TOKEN}"},
            ) as resp:
                if resp.status >= 400:
                    log.warning("Couldn't clear hosts from the Configuration tab (%s). They're imported; "
                                "you can delete them from the Configuration tab yourself.", resp.status)
                else:
                    log.info("Cleared hosts from the Configuration tab; manage them on the dashboard now")
        except Exception as err:  # noqa: BLE001
            log.warning("Couldn't clear hosts from the Configuration tab: %s", err)

    async def restore_options(self, saved: dict) -> str:
        """Put an export's Configuration-tab settings on this install (keeping its own host list)."""
        if not self.enabled:
            return "not changed (no Supervisor access)"
        try:
            current = json.loads(OPTIONS_PATH.read_text())
        except (OSError, ValueError):
            current = {}
        merged = {**current, **{k: v for k, v in saved.items() if k in DEFAULTS and k != "hosts"}}
        merged["hosts"] = current.get("hosts") or []
        try:
            async with self.session.post(f"{SUPERVISOR_API}/addons/self/options", json={"options": merged},
                                         headers={"Authorization": f"Bearer {SUPERVISOR_TOKEN}"}) as resp:
                if resp.status >= 400:
                    body = (await resp.text())[:200]
                    log.warning("Couldn't apply the exported settings (%s): %s", resp.status, body)
                    return f"not applied ({resp.status}); set them in the Configuration tab"
            log.info("Applied the exported Configuration-tab settings")
            return "applied"
        except Exception as err:  # noqa: BLE001
            log.warning("Couldn't apply the exported settings: %s", err)
            return "not applied; set them in the Configuration tab"

    async def restart_self(self) -> bool:
        """Ask the Supervisor to restart this add-on (shortly, so the reply gets out first)."""
        if not self.enabled:
            return False

        async def later():
            await asyncio.sleep(1.5)
            try:
                async with self.session.post(f"{SUPERVISOR_API}/addons/self/restart",
                                             headers={"Authorization": f"Bearer {SUPERVISOR_TOKEN}"}) as resp:
                    if resp.status >= 400:
                        log.warning("Couldn't restart to apply the import (%s); restart the add-on yourself", resp.status)
            except Exception as err:  # noqa: BLE001
                log.warning("Couldn't restart to apply the import (%s); restart the add-on yourself", err)
        asyncio.get_running_loop().create_task(later())
        return True

    async def get_json(self, path: str):
        """GET from HA's REST API; None if unavailable."""
        if not self.enabled:
            return None
        try:
            async with self.session.get(HA_API + path, headers={"Authorization": f"Bearer {SUPERVISOR_TOKEN}"},
                                        timeout=ClientTimeout(total=10)) as resp:
                if resp.status == 404:
                    return {"_missing": True}
                if resp.status >= 400:
                    log.warning("HA API GET %s -> %s", path, resp.status)
                    return None
                return await resp.json()
        except Exception as err:  # noqa: BLE001
            log.warning("HA API GET %s failed: %s", path, err)
            return None

    async def list_users(self) -> list[dict] | None:
        """Home Assistant's user list (id, name, username, admin flags), via the websocket API."""
        if not self.enabled:
            return None
        try:
            async with self.session.ws_connect(HA_WS, timeout=10, heartbeat=None) as ws:
                msg = await ws.receive_json(timeout=10)
                if msg.get("type") == "auth_required":
                    await ws.send_json({"type": "auth", "access_token": SUPERVISOR_TOKEN})
                    msg = await ws.receive_json(timeout=10)
                if msg.get("type") != "auth_ok":
                    log.warning("HA websocket auth failed: %s", msg.get("message") or msg.get("type"))
                    return None
                await ws.send_json({"id": 1, "type": "config/auth/list"})
                while True:
                    msg = await ws.receive_json(timeout=10)
                    if msg.get("id") == 1:
                        break
                if not msg.get("success"):
                    log.warning("Couldn't read HA users: %s", (msg.get("error") or {}).get("message"))
                    return None
                return msg.get("result") or []
        except Exception as err:  # noqa: BLE001
            log.warning("Couldn't read HA users: %s", err)
            return None

    async def addon_network(self) -> dict:
        """This add-on's port mappings, e.g. {"5140/udp": 514}."""
        if not self.enabled:
            return {}
        try:
            async with self.session.get(f"{SUPERVISOR_API}/addons/self/info",
                                        headers={"Authorization": f"Bearer {SUPERVISOR_TOKEN}"}) as resp:
                if resp.status >= 400:
                    return {}
                return (await resp.json()).get("data", {}).get("network") or {}
        except Exception:  # noqa: BLE001
            return {}

    async def addon_slug(self) -> str | None:
        """This add-on's slug from the Supervisor (e.g. local_ping_monitor)."""
        if not self.enabled:
            return None
        try:
            async with self.session.get(
                f"{SUPERVISOR_API}/addons/self/info",
                headers={"Authorization": f"Bearer {SUPERVISOR_TOKEN}"},
            ) as resp:
                if resp.status >= 400:
                    log.debug("Supervisor self info -> %s", resp.status)
                    return None
                return (await resp.json()).get("data", {}).get("slug")
        except Exception as err:  # noqa: BLE001
            log.debug("Supervisor self info failed: %s", err)
            return None


# --------------------------------------------------------------------------
# Monitor
# --------------------------------------------------------------------------
@dataclass
class Service:
    key: str
    label: str
    kind: str                 # "tcp" or "http"
    port: int | None
    url: str | None           # http only; may contain {host}
    desc: str                 # human-readable target, e.g. tcp/1433 or https:443/owa
    fallback: bool = False    # http(s):PORT checks may try the other scheme
    scheme_pref: str | None = None  # the scheme that last answered, tried first next time
    entity: str | None = None       # ha only: the Home Assistant entity to read
    op: str | None = None           # ha only: >, <, =, ... (None: just needs to be available)
    value: str | None = None        # ha only: what the state is compared with
    target: str | None = None       # ping / tcp on another address of the device (None: its main address)
    resolved: str | None = None     # that address's IP at the last check
    status: str = UNKNOWN
    failures: int = 0
    latency: float | None = None
    detail: str | None = None
    last_check: float | None = None
    last_change: float | None = None


@dataclass
class Host:
    key: str
    name: str
    host: str
    ip: str | None = None
    status: str = UNKNOWN
    failures: int = 0
    latency: float | None = None
    last_check: float | None = None
    last_change: float | None = None
    down_since: float | None = None
    next_due: float = 0.0
    checking: bool = False
    maint_until: float | None = None   # set while paused for maintenance
    maint_seen_down: bool = False      # has it stopped replying since the pause began?
    maint_ended: float | None = None   # when the last pause ended (agent gets a fresh stale period)
    schedule: dict | None = None       # None: monitored all the time
    expect_off: bool = False           # usually off (e.g. cold storage): off is normal, checked while on
    no_alerts: bool = False            # show its status, never notify
    off_schedule: bool = False         # outside its monitoring schedule right now
    reachable: bool | None = None      # answered its last ping (shown while off schedule)
    icon: str = ""                     # "b:<built-in>" or "u:<uploaded file>"; blank = pick from what it is
    model: str = ""                    # make and model, e.g. "Dell PowerEdge R720xd"
    snmp_community: str | None = None  # SNMP v2c community (None: "public")
    snmp_version: str = "2c"
    snmp_v3: dict = field(default_factory=dict)  # user, auth, auth_pass, priv, priv_pass
    snmp_watch: list[int] = field(default_factory=list)  # switch ports (ifIndex) that alert when down
    snmp_data: dict | None = None      # latest SNMP poll
    snmp_items: list[dict] = field(default_factory=list)  # problems found in it
    snmp_polled: float | None = None
    syslog_alert: int = 3              # alert on this severity and worse (-1 = never)
    syslog_keywords: list[str] = field(default_factory=list)  # always alert (red)
    syslog_ignore: list[str] = field(default_factory=list)    # never alert
    syslog_ack: float = 0              # alerts before this are acknowledged
    sched_started: float | None = None # when the current on-period began (start-up allowance, agent grace)
    checks: list[str] = field(default_factory=list)   # as configured
    services: list[Service] = field(default_factory=list)
    removed: bool = False              # deleted while a check was in flight
    agent_id: str | None = None        # linked agent
    agent_checks: list[Service] = field(default_factory=list)
    agent_report: dict | None = None   # latest report from the agent
    agent_seen: float | None = None    # when it arrived
    agent_history: dict = field(default_factory=lambda: {"events": [], "security": [], "detections": [], "failed_logons": []})

    @property
    def entity_id(self) -> str:
        return f"sensor.ping_monitor_{self.key}"


def fmt_ago(sec: float) -> str:
    sec = max(0, int(sec))
    return (f"{sec}s ago" if sec < 60 else f"{sec // 60} min ago" if sec < 3600
            else f"{sec // 3600} h ago" if sec < 86400 else f"{sec // 86400} days ago")


def svc_key(h: Host, s: Service) -> str:
    return f"{h.key}__{s.key}"


def svc_entity(h: Host, s: Service) -> str:
    return f"sensor.ping_monitor_{h.key}_{s.key}"


class Monitor:
    def __init__(self, opts: dict, store: Store, ha: HomeAssistant):
        self.opts = opts
        self.store = store
        self.logs = sysloglib.LogStore(store.db)
        self.syslog_unknown: dict[str, dict] = {}
        self.syslog_port: int | None = None  # the port on the Home Assistant machine, if known
        self.ha = ha
        self.interval = int(opts["interval"])
        self.retry_interval = int(opts["retry_interval"])
        self.svc_timeout = float(opts.get("service_timeout") or 5)
        self.max_gap = max(self.interval, self.retry_interval) * 2 + 60
        self.click_url: str | None = None   # set in main() once the slug is known
        self.sem = asyncio.Semaphore(32)
        self.tasks: set[asyncio.Task] = set()
        self.hosts: dict[str, Host] = {}
        self.imported = 0  # hosts taken from the Configuration tab this start
        self.agents: AgentStore | None = None  # set by attach_agents()
        self.started = time.time()  # agents get a full stale period after a restart
        self.agent_settings = {"global_ignore": [], "hosts": {}}
        try:
            self.agent_settings.update(json.loads(AGENT_SETTINGS.read_text()))
        except FileNotFoundError:
            pass
        except Exception as err:  # noqa: BLE001
            log.error("Could not read %s: %s", AGENT_SETTINGS, err)
        self._notice = 0

        now = time.time()
        for i, entry in enumerate(self._load_host_entries(opts.get("hosts") or [])):
            h = self._make_host(entry, now + i * 0.2)
            self.hosts[h.key] = h

        self._load_maint()
        if not self.hosts:
            log.warning("No hosts yet - add some with 'Add computer' on the dashboard")
        log.info(
            "Monitoring %d host(s) and %d service check(s), interval %ss, retry %ss",
            len(self.hosts), sum(len(h.services) for h in self.hosts.values()),
            self.interval, self.retry_interval,
        )

    # -- host list ----------------------------------------------------------
    # The host list lives in /data/hosts.json and is edited from the dashboard.
    # Anything in the Configuration tab's `hosts` option is merged in at start-up
    # (matched by name), after which main() clears that option.
    @staticmethod
    def _new_id(name: str, taken) -> str:
        key, n = slugify(name), 2
        while key in taken:
            key, n = f"{slugify(name)}_{n}", n + 1
        return key

    def _load_host_entries(self, from_options: list) -> list[dict]:
        entries: list[dict] = []
        exists = HOSTS_PATH.exists()
        if exists:
            try:
                entries = json.loads(HOSTS_PATH.read_text())
            except Exception as err:  # noqa: BLE001
                backup = HOSTS_PATH.with_suffix(f".bad-{int(time.time())}.json")
                HOSTS_PATH.rename(backup)
                log.error("Could not read %s (%s); moved it to %s", HOSTS_PATH, err, backup.name)
                entries, exists = [], False
        # Only import when the Configuration tab's list has changed since the last
        # import, so dashboard edits aren't overwritten on every restart if the
        # option couldn't be cleared.
        signatures = [json.dumps(e, sort_keys=True) for e in from_options]
        try:
            seen_before = set(json.loads(IMPORT_MARK.read_text()))
        except (FileNotFoundError, ValueError):
            seen_before = set()
        new_from_options = [e for e, sig in zip(from_options, signatures) if sig not in seen_before]
        if len(new_from_options) < len(from_options):
            log.debug("Skipping %d Configuration tab host(s) already imported",
                      len(from_options) - len(new_from_options))
        from_options = new_from_options
        by_name = {e["name"].lower(): e for e in entries}
        for raw in from_options:
            try:
                entry = validate_entry(raw)
            except ValueError as err:
                log.warning("Skipping host from Configuration %s: %s", raw, err)
                continue
            match = by_name.get(entry["name"].lower())
            if match:
                match.update(host=entry["host"], checks=entry["checks"])
            else:
                entry = {"id": self._new_id(entry["name"], {e["id"] for e in entries}), **entry}
                entries.append(entry)
                by_name[entry["name"].lower()] = entry
            self.imported += 1
        if self.imported or not exists:
            self._write_hosts(entries)
        if signatures:
            IMPORT_MARK.write_text(json.dumps(signatures))
        if self.imported:
            log.info("Imported %d host(s) from the Configuration tab", self.imported)
        return entries

    @staticmethod
    def _write_hosts(entries: list[dict]) -> None:
        tmp = HOSTS_PATH.with_suffix(".tmp")
        tmp.write_text(json.dumps(entries, indent=2))
        tmp.replace(HOSTS_PATH)

    def _save_hosts(self) -> None:
        self._write_hosts([{"id": h.key, "name": h.name, "host": h.host, "checks": h.checks,
                            **({"schedule": h.schedule} if h.schedule else {}),
                            **({"expect_off": True} if h.expect_off else {}),
                            **({"no_alerts": True} if h.no_alerts else {}),
                            **({"icon": h.icon} if h.icon else {}),
                            **({"model": h.model} if h.model else {}),
                            **({"snmp_community": h.snmp_community} if h.snmp_community else {}),
                            **({"snmp_version": "3", "snmp_v3": h.snmp_v3} if h.snmp_version == "3" else {}),
                            **({"snmp_watch": h.snmp_watch} if h.snmp_watch else {}),
                            **({"syslog_alert": h.syslog_alert} if h.syslog_alert != 3 else {}),
                            **({"syslog_keywords": h.syslog_keywords} if h.syslog_keywords else {}),
                            **({"syslog_ignore": h.syslog_ignore} if h.syslog_ignore else {}),
                            **({"syslog_ack": h.syslog_ack} if h.syslog_ack else {})}
                           for h in self.hosts.values()])

    def _make_host(self, entry: dict, due: float) -> Host:
        h = Host(key=entry["id"], name=entry["name"], host=entry["host"],
                 checks=list(entry.get("checks") or []), next_due=due)
        h.expect_off, h.no_alerts = bool(entry.get("expect_off")), bool(entry.get("no_alerts"))
        h.snmp_community = entry.get("snmp_community") or None
        h.icon = str(entry.get("icon") or "") if ICON_REF.match(str(entry.get("icon") or "")) else ""
        h.model = str(entry.get("model") or "")[:64]
        h.snmp_version = "3" if entry.get("snmp_version") == "3" else "2c"
        h.snmp_v3 = dict(entry.get("snmp_v3") or {})
        h.snmp_watch = [int(x) for x in entry.get("snmp_watch") or [] if str(x).isdigit()]
        self._apply_syslog(h, entry)
        try:
            h.syslog_ack = float(entry.get("syslog_ack") or 0)
        except (TypeError, ValueError):
            h.syslog_ack = 0
        try:
            h.schedule = clean_schedule(entry.get("schedule"))
        except ValueError as err:
            log.warning("%s: ignoring its schedule (%s)", h.name, err)
        h.services = self._build_services(h.name, h.checks)
        self._restore(h)
        return h

    async def add_host(self, entry: dict) -> Host:
        h = self._make_host({"id": self._new_id(entry["name"], self.hosts), **entry}, 0)
        self.hosts[h.key] = h
        self._save_hosts()
        log.info("Added %s (%s) with checks %s", h.name, h.host, h.checks or "none")
        return h

    async def update_host(self, h: Host, entry: dict) -> None:
        if entry["host"] != h.host:
            h.host, h.ip, h.failures = entry["host"], None, 0
        h.name = entry["name"]
        h.checks = entry["checks"]
        h.schedule = entry.get("schedule")
        h.expect_off, h.no_alerts = bool(entry.get("expect_off")), bool(entry.get("no_alerts"))
        if entry.get("snmp_community"):  # blank keeps the one already set
            h.snmp_community = entry["snmp_community"]
        if "icon" in entry:
            h.icon = entry["icon"]
        if "model" in entry:
            h.model = entry["model"]
        if "snmp_version" in entry:
            h.snmp_version = entry["snmp_version"]
            if h.snmp_version == "3":
                new = dict(entry["snmp_v3"])
                for k in ("auth_pass", "priv_pass"):  # blank keeps the one already set
                    if k not in new and h.snmp_v3.get(k):
                        new[k] = h.snmp_v3[k]
                h.snmp_v3 = new
        self._apply_syslog(h, entry)
        if h.no_alerts:
            await self.dismiss(f"ping_monitor_{h.key}")
        old = {s.desc: s for s in h.services}
        new = self._build_services(h.name, h.checks)
        for s in new:
            prev = old.pop(s.desc, None)
            if prev:  # same target: keep its key (history) and current state
                s.key = prev.key
                for f in ("status", "failures", "latency", "detail", "last_check", "last_change",
                          "scheme_pref", "resolved"):
                    setattr(s, f, getattr(prev, f))
        for gone in old.values():
            await self.dismiss(f"ping_monitor_{svc_key(h, gone)}")
            await self.ha.delete_state(svc_entity(h, gone))
        h.services = new
        if h.status == DEGRADED and not any(s.status == RED for s in new):
            h.status = GREEN
        h.next_due = 0
        self._save_hosts()
        log.info("Updated %s (%s) with checks %s", h.name, h.host, h.checks or "none")
        await self.publish(h)

    @staticmethod
    def _apply_syslog(h: Host, entry: dict) -> None:
        if "syslog_alert" in entry:
            h.syslog_alert = int(entry["syslog_alert"])
        for k in ("syslog_keywords", "syslog_ignore"):
            if k in entry:
                setattr(h, k, list(entry[k]))

    # ---- Syslog ----
    def _syslog_target(self, ip: str) -> Host | None:
        cands = [h for h in self.hosts.values()
                 if ip in (h.ip, h.host) or any(ip in (s.resolved, s.target) for s in h.services if s.target)]
        return next((h for h in cands if any(s.kind == "syslog" for s in h.services)), None) or (cands[0] if cands else None)

    def on_syslog(self, ip: str, m: dict) -> None:
        now = time.time()
        h = self._syslog_target(ip)
        if h and any(s.kind == "syslog" for s in h.services):
            self.logs.add(h.key, now, m)
            lvl = sysloglib.alert_level(m, h.syslog_alert, h.syslog_keywords, h.syslog_ignore)
            svc = next(s for s in h.services if s.kind == "syslog")
            if lvl and (svc.status == GREEN or (lvl == "red" and svc.status != RED)):
                h.next_due = 0  # show it now rather than at the next check
            return
        u = self.syslog_unknown.get(ip)
        if not u:
            if len(self.syslog_unknown) >= 100:
                self.syslog_unknown.pop(min(self.syslog_unknown, key=lambda k: self.syslog_unknown[k]["last"]))
            u = self.syslog_unknown[ip] = {"ip": ip, "first": now, "count": 0}
            log.info("Syslog from %s, which %s", ip, f"is {h.name} but Syslog isn't ticked for it" if h
                     else "isn't a computer in Rollcall")
        u.update(count=u["count"] + 1, last=now, msg=m["msg"][:200], app=m["app"], sev=m["sev"], name=m["host"],
                 host_key=h.key if h else None)

    def syslog_state(self, h: Host, now: float) -> tuple:
        """Alerts in the last 24 hours that haven't been acknowledged."""
        since = max(now - DAY, h.syslog_ack)
        rows = self.logs.query(h.key, since=since, max_sev=7, limit=2000)
        hits = [(sysloglib.alert_level(r, h.syslog_alert, h.syslog_keywords, h.syslog_ignore), r) for r in rows]
        hits = [(lvl, r) for lvl, r in hits if lvl]
        n, last = self.logs.stats(h.key, now - DAY)
        if not hits:
            return True, None, (f"{n} message{'s' if n != 1 else ''} in 24 h, last {fmt_ago(now - last)}" if n
                                else "No messages in the last 24 h")
        worst = "red" if any(lvl == "red" for lvl, _ in hits) else "amber"
        top = next(r for lvl, r in hits if lvl == worst)
        more = f" (+{len(hits) - 1} more)" if len(hits) > 1 else ""
        detail = f"{sysloglib.SEVERITY[top['sev']]}: {(top['app'] + ': ') if top['app'] else ''}{top['msg']}"[:200] + more
        return False, None, detail, ("now" if worst == "red" else "warn")

    async def delete_host(self, h: Host) -> None:
        h.removed = True
        if self.agent_settings["hosts"].pop(h.key, None) is not None:
            self._save_agent_settings()
        self.hosts.pop(h.key, None)
        self._save_hosts()
        if h.maint_until:
            self._save_maint()
        self.store.clear(h.key)
        self.logs.clear(h.key)
        await self.dismiss(f"ping_monitor_{h.key}")
        await self.ha.delete_state(h.entity_id)
        for s in h.services + h.agent_checks:
            await self.dismiss(f"ping_monitor_{svc_key(h, s)}")
            await self.ha.delete_state(svc_entity(h, s))
        for eid in self._metric_entities(h):
            await self.ha.delete_state(eid)
        if h.agent_id and self.agents and h.agent_id in self.agents.agents:
            a = self.agents.revoke(h.agent_id)
            log.info("Revoked the agent on %s along with it", a["hostname"])
        log.info("Deleted %s (%s)", h.name, h.host)

    @staticmethod
    def _build_services(host_name: str, checks) -> list[Service]:
        if isinstance(checks, str):
            checks = [c for c in re.split(r"[,\s]+", checks) if c]
        services: list[Service] = []
        for entry in checks:
            if not str(entry).strip():
                continue
            try:
                defs = parse_check(entry)
            except ValueError as err:
                log.warning("%s: skipping check: %s", host_name, err)
                continue
            for d in defs:
                if any(s.desc == d["desc"] for s in services):
                    continue  # same target already checked (e.g. dc + fileserver both SMB)
                key, n = slugify(d["label"]), 2
                while any(s.key == key for s in services):
                    key, n = f"{slugify(d['label'])}_{n}", n + 1
                services.append(Service(key=key, **d))
        return services

    def _recent_state(self, key: str) -> tuple[float, float | None, int] | None:
        recent = self.store.recent(key, 2)
        if not recent:
            return None
        fails = 0
        for _, ok, _ in recent:
            if ok:
                break
            fails += 1
        return recent[0][0], (recent[0][2] if recent[0][1] else None), fails

    def _restore(self, h: Host) -> None:
        """Pick up the last known status so a restart doesn't re-alert or show blanks."""
        st = self._recent_state(h.key)
        if not st:
            return
        h.last_check, h.latency, h.failures = st
        h.status = GREEN if h.failures == 0 else AMBER if h.failures == 1 else RED
        if h.status == GREEN:
            for s in h.services:
                sst = self._recent_state(svc_key(h, s))
                if sst:
                    s.last_check, s.latency, s.failures = sst
                    s.status = GREEN if s.failures == 0 else AMBER if s.failures == 1 else RED
            if any(s.status == RED for s in h.services):
                h.status = DEGRADED

    # -- maintenance --------------------------------------------------------
    def _load_maint(self) -> None:
        try:
            saved = json.loads(MAINT_PATH.read_text())
        except FileNotFoundError:
            return
        except Exception as err:  # noqa: BLE001
            log.warning("Could not read %s: %s", MAINT_PATH, err)
            return
        for key, m in saved.items():
            h = self.hosts.get(key)
            if h and m.get("until"):
                h.maint_until = float(m["until"])
                h.maint_seen_down = bool(m.get("seen_down"))
                h.status = MAINT
                for s in h.services:
                    s.status, s.failures = UNKNOWN, 0
                log.info("%s: maintenance restored, until %s", h.name, iso(h.maint_until))

    def _save_maint(self) -> None:
        data = {h.key: {"until": h.maint_until, "seen_down": h.maint_seen_down}
                for h in self.hosts.values() if h.maint_until}
        try:
            MAINT_PATH.write_text(json.dumps(data))
        except Exception as err:  # noqa: BLE001
            log.warning("Could not write %s: %s", MAINT_PATH, err)

    async def start_maintenance(self, h: Host, minutes: int) -> None:
        now = time.time()
        old = h.status
        h.maint_until = now + minutes * 60
        h.maint_seen_down = False
        h.status = MAINT
        h.last_change = now
        h.down_since = None
        self._save_maint()
        log.info("%s: paused for maintenance for %d min", h.name, minutes)
        if old == RED:
            await self.dismiss(f"ping_monitor_{h.key}")
        await self.reset_services(h)
        await self.ha.fire("ping_monitor_status_changed", self._event(h, old, MAINT))
        await self.publish(h)

    async def resume(self, h: Host) -> None:
        """Manual resume: check straight away, starting the amber/red count fresh."""
        if not h.maint_until:
            return
        h.maint_until = None
        h.maint_seen_down = False
        h.maint_ended = time.time()
        h.failures = 0
        h.next_due = 0
        self._save_maint()
        log.info("%s: maintenance ended manually", h.name)

    def _event(self, h: Host, old: str, new: str) -> dict:
        return {"name": h.name, "host": h.host, "ip": h.ip, "old_status": old,
                "new_status": new, "entity_id": h.entity_id}

    # -- scheduling -------------------------------------------------------
    async def run(self) -> None:
        last_publish = last_prune = 0.0
        while True:
            try:
                last_publish, last_prune = await self._tick(last_publish, last_prune)
            except Exception:  # noqa: BLE001 - one bad pass mustn't stop monitoring
                log.exception("Monitoring loop hit an error; carrying on")
            await asyncio.sleep(1)

    async def _tick(self, last_publish: float, last_prune: float) -> tuple[float, float]:
        if True:
            now = time.time()
            for h in list(self.hosts.values()):
                if not h.checking and now >= h.next_due:
                    h.checking = True
                    task = asyncio.create_task(self.check(h))
                    self.tasks.add(task)
                    task.add_done_callback(self.tasks.discard)
            # Re-publish periodically so sensors reappear quickly after an HA restart.
            if now - last_publish >= 60:
                last_publish = now
                for h in list(self.hosts.values()):
                    if h.status != UNKNOWN and not h.removed:
                        await self.publish(h)
            if now - last_prune >= 3600:
                last_prune = now
                self.store.prune(now - int(self.opts["history_days"]) * DAY)
                self.logs.prune(now - int(self.opts["history_days"]) * DAY)
            if self.agents:
                await self.check_stale_agents(now)
        return last_publish, last_prune

    async def check(self, h: Host) -> None:
        try:
            async with self.sem:
                ip = await resolve(h.host)
                if ip:
                    h.ip = ip
                    ok, latency = await ping(
                        ip, int(self.opts["ping_count"]), int(self.opts["ping_timeout"]),
                        [s.port for s in h.services if s.port and not s.target],
                    )
                else:
                    ok, latency = False, None
            now = time.time()
            h.last_check = now
            h.latency = latency if ok else None
            h.failures = 0 if ok else h.failures + 1
            old = h.status
            reason = "unresolved" if ip is None else "down"

            on, since, _next = schedule_state(h.schedule, now)
            if h.expect_off:
                # Only switched on now and then: being off is normal, and it's "on" while it answers.
                on = bool(ok)
                since = (h.sched_started or now) if ok else None
            grace = (h.schedule or {}).get("grace", 15) * 60
            h.reachable = bool(ok)
            was_off = h.off_schedule
            h.off_schedule = not on
            if on and since and (was_off or h.sched_started is None):
                h.sched_started = since
            if not on:
                h.sched_started = None
            in_grace = bool(on and since and now < since + grace and h.status in (MAINT, UNKNOWN) and not h.maint_until)

            if h.maint_until:
                # Paused: keep pinging, but don't alert. End the pause once it has
                # gone away and come back, or when the window runs out.
                if not ok and not h.maint_seen_down:
                    h.maint_seen_down = True
                    self._save_maint()
                if ok and h.maint_seen_down:
                    new, reason = GREEN, "maint_back"
                elif now >= h.maint_until:
                    new = GREEN if ok else RED
                    reason = "maint_quiet" if ok else "maint_timeout"
                else:
                    new = MAINT
                if new != MAINT:
                    h.maint_until = None
                    h.maint_seen_down = False
                    h.maint_ended = now
                    self._save_maint()
                    log.info("%s: maintenance ended (%s)", h.name, reason)
            elif not on:
                # Outside its schedule: keep an eye on it, but it isn't expected to be up.
                new = MAINT
            elif in_grace and not ok:
                # Its window has just started: give it time to start up before alerting.
                new = MAINT
            else:
                if was_off or (h.status == MAINT and since):
                    h.failures = 0 if ok else 2  # past its start-up allowance: alert straight away
                    reason = "down" if ok else "sched_timeout"
                new = GREEN if ok else AMBER if h.failures == 1 else RED

            self.store.add(h.key, now, MAINT_OK if new == MAINT else ok, latency)

            # Services are only checked while the box itself is answering pings.
            # If it's down or paused, their state is cleared so they start fresh.
            if new == GREEN:
                if h.services:
                    await self.check_services(h, now)
                if any(s.status == RED for s in h.services + h.agent_checks):
                    new = DEGRADED
            elif new in (RED, MAINT):
                await self.reset_services(h)

            if h.removed:
                return
            h.status = new
            retry = (new == AMBER or (new == MAINT and not h.off_schedule)
                     or any(s.status == AMBER for s in h.services))
            h.next_due = now + (min(self.retry_interval, self.interval) if retry else self.interval)
            nxt = schedule_state(h.schedule, now)[2] if h.schedule else None
            if nxt and now < nxt < h.next_due:
                h.next_due = nxt + 1  # check as soon as its window opens or closes
            if new != old:
                h.last_change = now
                log.info("%s (%s): %s -> %s", h.name, h.ip or h.host, old, new)
                await self.on_change(h, old, new, reason)
            else:
                log.debug("%s (%s): %s, %s ms", h.name, h.ip or h.host, new, latency)
            await self.publish(h)
        except Exception:  # noqa: BLE001
            log.exception("Check failed for %s", h.name)
            h.next_due = time.time() + self.interval
        finally:
            h.checking = False

    async def check_services(self, h: Host, now: float) -> None:
        async def run_one(s: Service):
            if s.kind == "ha":
                return await self.ha_check(s)
            if s.kind == "snmp":
                return await self.snmp_check(h, now)
            if s.kind == "syslog":
                return self.syslog_state(h, now)
            async with self.sem:
                if s.target:
                    ip = await resolve(s.target)
                    if not ip:
                        return False, None, f"can't resolve {s.target}"
                    s.resolved = ip
                    if s.kind == "ping":
                        ok, ms = await ping(ip, int(self.opts["ping_count"]), int(self.opts["ping_timeout"]), [])
                        return ok, ms, (f"{ip} replied" if ok else f"no reply from {ip}")
                    return await tcp_check(ip, s.port, self.svc_timeout)
                if s.kind == "tcp":
                    return await tcp_check(h.ip, s.port, self.svc_timeout)
                ok, ms, detail, scheme = await http_check(
                    s.url.replace("{host}", h.host), self.svc_timeout, s.fallback, s.scheme_pref)
                if ok:
                    s.scheme_pref = scheme
                return ok, ms, detail

        results = await asyncio.gather(*(run_one(s) for s in h.services), return_exceptions=True)
        for s, res in zip(h.services, results):
            if isinstance(res, Exception):
                log.warning("%s %s: check error: %s", h.name, s.label, res)
                ok, lat, detail = False, None, type(res).__name__
            else:
                ok, lat, detail = res[:3]
            level = res[3] if not isinstance(res, Exception) and len(res) > 3 else None
            warn = level == "warn"
            s.last_check = now
            s.latency = lat if ok else None
            s.detail = detail
            s.failures = 0 if ok or warn else s.failures + 1
            new = GREEN if ok else AMBER if warn or (s.failures == 1 and level != "now") else RED
            ok = ok or warn  # a warning isn't counted as downtime
            self.store.add(svc_key(h, s), now, ok, s.latency)
            if new != s.status:
                old, s.status, s.last_change = s.status, new, now
                log.info("%s %s (%s): %s -> %s [%s]", h.name, s.label, s.desc, old, new, detail)
                await self.on_service_change(h, s, old, new)

    async def snmp_check(self, h: Host, now: float) -> tuple:
        """Poll the device over SNMP. Warnings (e.g. PoE near its budget) stay amber;
        problems (a watched port down, a failed disk) go red if they're still there next time."""
        prev = h.snmp_data
        try:
            v3 = None
            if h.snmp_version == "3":
                c = h.snmp_v3
                v3 = snmplib.V3(c.get("user", ""), c.get("auth"), c.get("auth_pass", ""), c.get("priv"), c.get("priv_pass", ""))
            d = await snmplib.poll(h.ip or h.host, h.snmp_community or "public", timeout=max(1.0, min(self.svc_timeout, 3.0)),
                                  v3=v3,
                                  per=int((prev or {}).get("per") or 25),  # what worked last time
                                  port=int(os.environ.get("PM_SNMP_PORT", "161")))  # port: for testing
        except (snmplib.SnmpError, OSError) as err:
            h.snmp_items = [{"level": "crit", "what": "SNMP", "detail": str(err)}]
            return False, None, str(err)
        h.snmp_data, h.snmp_polled = d, now
        worst, items = snmplib.evaluate(d, set(h.snmp_watch), prev)
        h.snmp_items = items
        if worst == "ok":
            bits = []
            if d.get("ports"):
                bits.append(f"{sum(1 for p in d['ports'] if p['up'])} of {len(d['ports'])} ports up")
            if d.get("poe") and d["poe"].get("used_w") is not None:
                bits.append(f"PoE {d['poe']['used_w']}/{d['poe']['power_w']} W")
            if d.get("nas"):
                bits.append(f"{len(d['nas'].get('disks') or [])} disks OK")
            return True, d.get("took_ms"), "; ".join(bits) or "answering"
        detail = "; ".join(f"{i['what']} {i['detail']}".strip() for i in items if i["level"] == worst)
        return (False, None, detail[:240]) + (("warn",) if worst == "warn" else ())

    async def ha_check(self, s: Service) -> tuple[bool, None, str]:
        """A Home Assistant entity: OK while available and, if a condition is set, not breaching it.

        The condition describes a problem, as in "CPU > 90": met means failing."""
        st = await self.ha.get_json(f"/states/{s.entity}")
        if st is None:
            return False, None, "couldn't reach Home Assistant"
        if st.get("_missing"):
            return False, None, "not found in Home Assistant"
        state = str(st.get("state"))
        unit = (st.get("attributes") or {}).get("unit_of_measurement") or ""
        shown = f"{state}{'' if unit in ('', None) else ('' if unit == '%' else ' ') + unit}"
        if state in ("unavailable", "unknown", "None", ""):
            return False, None, f"{state or 'no value'}"
        if not s.op:
            return True, None, shown
        if s.op in ("=", "!="):
            hit = state.lower() == str(s.value).lower()
            bad = hit if s.op == "=" else not hit
        else:
            try:
                v, limit = float(state), float(s.value)
            except (TypeError, ValueError):
                return False, None, f"{shown} (not a number)"
            bad = {">": v > limit, ">=": v >= limit, "<": v < limit, "<=": v <= limit}[s.op]
        return (not bad), None, shown + (f" ({HA_OPS[s.op]} {s.value})" if bad else "")

    async def reset_services(self, h: Host) -> None:
        for s in h.services:
            if s.status == RED:
                await self.dismiss(f"ping_monitor_{svc_key(h, s)}")
            s.status, s.failures, s.latency, s.detail = UNKNOWN, 0, None, None

    # -- notifications ----------------------------------------------------
    async def dismiss(self, notification_id: str) -> None:
        if self.opts["persistent_notification"]:
            await self.ha.service("persistent_notification", "dismiss",
                                  {"notification_id": notification_id})

    async def persist(self, notification_id: str, title: str, message: str) -> None:
        if self.opts["persistent_notification"] and not self._quiet(notification_id):
            await self.ha.service("persistent_notification", "create",
                                  {"notification_id": notification_id,
                                   "title": title, "message": message})

    async def on_change(self, h: Host, old: str, new: str, reason: str) -> None:
        await self.ha.fire("ping_monitor_status_changed", self._event(h, old, new))
        tag = f"ping_monitor_{h.key}"
        if reason == "maint_back":
            if self.opts["notify_recovery"]:
                await self.notify(
                    f"✅ {h.name} is back online",
                    f"{h.name} ({h.ip or h.host}) is responding again. Maintenance ended and monitoring has resumed.",
                    tag,
                )
            return
        if new == RED and old != RED:
            h.down_since = h.last_check
            why = {
                "unresolved": "Hostname could not be resolved.",
                "maint_timeout": "It did not reply before the maintenance window ended.",
                "sched_timeout": "It didn't come up after its monitoring window started.",
            }.get(reason, "No reply to ping on two consecutive checks.")
            msg = f"{h.name} ({h.ip or h.host}) is DOWN. {why}"
            await self.notify(f"🔴 {h.name} is down", msg, tag)
            await self.persist(tag, f"Rollcall: {h.name} is down", msg)
        elif old == RED and new in (GREEN, DEGRADED):
            await self.dismiss(tag)
            if self.opts["notify_recovery"]:
                dur = f" after {fmt_duration(h.last_check - h.down_since)}" if h.down_since else ""
                await self.notify(
                    f"🟢 {h.name} is back up",
                    f"{h.name} ({h.ip or h.host}) is responding again{dur}.",
                    tag,
                )
            h.down_since = None

    async def on_service_change(self, h: Host, s: Service, old: str, new: str) -> None:
        await self.ha.fire("ping_monitor_service_changed", {
            "name": h.name, "host": h.host, "ip": h.ip, "service": s.label, "target": s.desc,
            "old_status": old, "new_status": new, "detail": s.detail,
            "entity_id": svc_entity(h, s), "host_entity_id": h.entity_id,
        })
        tag = f"ping_monitor_{svc_key(h, s)}"
        if new == RED and s.kind == "syslog":
            msg = f"{h.name} ({h.ip or h.host}) logged {s.detail}"
            await self.notify(f"🟠 {h.name}: syslog alert", msg, tag)
            await self.persist(tag, f"Rollcall: {h.name} syslog", msg)
            return
        if old == RED and new == GREEN and s.kind == "syslog":
            await self.dismiss(tag)
            return
        if new == RED and s.kind == "snmp":
            msg = f"{h.name} ({h.ip or h.host}): {s.detail}."
            await self.notify(f"🟠 {h.name}: {str(s.detail).split(';')[0]}", msg, tag)
            await self.persist(tag, f"Rollcall: {h.name} SNMP", msg)
            return
        if old == RED and new == GREEN and s.kind == "snmp":
            await self.dismiss(tag)
            if self.opts["notify_recovery"]:
                await self.notify(f"🟢 {h.name}: OK again", f"{h.name}: {s.detail}.", tag)
            return
        if new == RED and s.kind == "ha":
            msg = f"{s.label} on {h.name} is {s.detail} ({s.entity})."
            await self.notify(f"🟠 {h.name}: {s.label} {str(s.detail).split(' (')[0]}", msg, tag)
            await self.persist(tag, f"Rollcall: {h.name} {s.label}", msg)
        elif old == RED and new == GREEN and s.kind == "ha":
            await self.dismiss(tag)
            if self.opts["notify_recovery"]:
                await self.notify(f"🟢 {h.name}: {s.label} OK", f"{s.label} on {h.name} is back to {s.detail}.", tag)
        elif new == RED:
            msg = (f"{h.name} ({h.ip or h.host}) is up, but {s.label} ({s.desc}) "
                   f"is not responding: {s.detail}.")
            await self.notify(f"🟠 {h.name}: {s.label} is down", msg, tag)
            await self.persist(tag, f"Rollcall: {h.name} {s.label} is down", msg)
        elif old == RED and new == GREEN:
            await self.dismiss(tag)
            if self.opts["notify_recovery"]:
                await self.notify(f"🟢 {h.name}: {s.label} is back up",
                                  f"{s.label} ({s.desc}) on {h.name} is responding again.", tag)

    def _quiet(self, tag: str | None) -> bool:
        """Notifications for a computer set to never alert are dropped here, in one place.
        Every per-computer tag is ping_monitor_<key> or ping_monitor_<key>__<what>."""
        if not tag or not tag.startswith("ping_monitor_"):
            return False
        h = self.hosts.get(tag[len("ping_monitor_"):].split("__")[0])
        return bool(h and h.no_alerts)

    async def notify(self, title: str, message: str, tag: str | None = None) -> None:
        if self._quiet(tag):
            return
        for svc in self.opts.get("notify_services") or []:
            svc = svc.strip().removeprefix("notify.")
            if not svc:
                continue
            payload = {"title": title, "message": message}
            # Companion app extras. Only sent to mobile_app_* services, since other
            # notify platforms (email, Telegram...) may reject unknown data keys.
            if svc.startswith("mobile_app_"):
                data = {"group": "Rollcall", "channel": "Rollcall"}
                if self.click_url:
                    data["clickAction"] = self.click_url  # Android
                    data["url"] = self.click_url          # iOS
                if tag:
                    data["tag"] = tag  # newer alert for the same thing replaces older
                payload["data"] = data
            await self.ha.service("notify", svc, payload)

    # -- Agents ------------------------------------------------------------
    LEVEL_STATUS = {agentlib.OK: GREEN, agentlib.WARN: AMBER, agentlib.CRIT: RED}

    async def attach_agents(self, store: AgentStore) -> None:
        """Link approved agents to dashboard entries and restore their last reports."""
        self.agents = store
        for agent in list(store.agents.values()):
            h = self.hosts.get(agent.get("host_key") or "") or self._find_host_for(agent)
            h = await self._relink_if_better(agent, h)
            if not h:
                continue
            h.agent_id = agent["id"]
            if agent.get("host_key") != h.key:
                agent["host_key"] = h.key
                store.save()
            saved = store.load_report(agent["id"])
            if saved and saved.get("report"):
                h.agent_history = saved.get("history") or h.agent_history
                await self._apply(h, agent, agentlib.normalize_report(saved["report"]), saved.get("received") or time.time(), restoring=True)
        n = sum(1 for h in self.hosts.values() if h.agent_id)
        if store.agents or store.pending:
            log.info("Agents: %d approved (%d on the dashboard), %d waiting for approval",
                     len(store.agents), n, len(store.pending))

    @staticmethod
    def _name_match(h: Host, agent: dict) -> bool:
        hostname = (agent.get("hostname") or "").lower()
        fqdn = (agent.get("fqdn") or "").lower()
        names = {h.name.lower(), h.host.lower(), h.host.lower().split(".")[0]}
        return bool(hostname and hostname in names) or bool(fqdn and fqdn in names)

    def _find_host_for(self, agent: dict) -> Host | None:
        """The dashboard entry for an agent: by name first, then by IP.

        Name first because a server can hold extra addresses that have their own
        entry, e.g. a DAG or failover-cluster IP on whichever node owns it. Among
        IP matches, the agent's first (primary) address wins."""
        free = [h for h in self.hosts.values() if not h.agent_id or h.agent_id == agent.get("id")]
        for h in free:
            if self._name_match(h, agent):
                return h
        for ip in agent.get("ips") or []:
            for h in free:
                if h.host == ip or h.ip == ip:
                    return h
        return None

    AGENT_CHECK_KEYS = ("agent", "disk", "services", "updates", "iis", "ad", "dhcp", "hyperv", "printers",
                        "defender", "security", "events", "immich", "storage", "hardware", "backups")

    async def _unlink(self, h: Host, report: dict | None = None) -> None:
        """Take an agent's checks and sensors off a dashboard entry it was wrongly linked to.

        At start-up its checks haven't been rebuilt yet, so the entities it could
        have made in Home Assistant are removed by name too."""
        base = f"sensor.ping_monitor_{h.key}"
        for k in self.AGENT_CHECK_KEYS:
            await self.dismiss(f"ping_monitor_{h.key}__agent_{k}")
            await self.ha.delete_state(f"{base}_agent_{k}")
        for s in h.agent_checks:
            await self.dismiss(f"ping_monitor_{svc_key(h, s)}")
            await self.ha.delete_state(svc_entity(h, s))
        if report and not h.agent_report:
            h.agent_report = report
        for eid in set(self._metric_entities(h)) | {f"{base}_cpu", f"{base}_memory"}:
            await self.ha.delete_state(eid)
        h.agent_id, h.agent_checks, h.agent_report, h.agent_seen = None, [], None, None
        h.agent_history = {"events": [], "security": [], "detections": [], "failed_logons": []}
        if h.status == DEGRADED and not any(s.status == RED for s in h.services):
            h.status = GREEN
        await self.publish(h)

    async def _relink_if_better(self, agent: dict, h: Host | None) -> Host | None:
        """Move an agent off an entry matched only by IP when one matches its name."""
        if h is None or self._name_match(h, agent):
            return h
        best = self._find_host_for(agent)
        if best and best is not h and self._name_match(best, agent):
            log.info("Moving the %s agent from %s (matched by IP) to %s (matches its name)",
                     agent.get("hostname"), h.name, best.name)
            saved = self.agents.load_report(agent["id"]) or {}
            await self._unlink(h, agentlib.normalize_report(saved["report"]) if saved.get("report") else None)
            agent["host_key"] = best.key
            self.agents.save()
            return best
        return h

    async def _link(self, agent: dict, create: bool) -> Host | None:
        h = self.hosts.get(agent.get("host_key") or "")
        if h and h.agent_id in (None, agent["id"]):
            h = await self._relink_if_better(agent, h)
            h.agent_id = agent["id"]
            return h
        h = self._find_host_for(agent)
        if not h and create and self.opts.get("agent_auto_add", True):
            # Prefer the IP: .local AD names often don't resolve from Home Assistant.
            addr = (agent.get("ips") or [None])[0] or agent.get("fqdn") or agent["hostname"]
            h = await self.add_host({"name": agent["hostname"], "host": addr, "checks": []})
            log.info("Added %s to the dashboard for its agent", h.name)
        if h:
            h.agent_id = agent["id"]
            agent["host_key"] = h.key
            self.agents.save()
        return h

    async def agent_pending_notice(self, rec: dict) -> None:
        log.info("Agent on %s (%s) is asking to join; approve it under Agents",
                 rec["hostname"], ", ".join(rec.get("ips") or []) or rec.get("source_ip"))
        what = "replace its existing agent" if rec.get("replaces") else "join"
        await self.persist(f"ping_monitor_pending_{rec['id']}", "Rollcall: agent waiting for approval",
                           f"{rec['hostname']} ({', '.join(rec.get('ips') or []) or rec.get('source_ip')}) "
                           f"wants to {what}. Approve or reject it in Rollcall, under Agents.")

    async def approve_agent(self, pid: str) -> dict:
        agent = self.agents.approve(pid)
        await self.dismiss(f"ping_monitor_pending_{pid}")
        h = await self._link(agent, create=True)
        log.info("Approved the agent on %s%s", agent["hostname"], f" (dashboard: {h.name})" if h else "")
        return agent

    async def reject_agent(self, pid: str) -> dict:
        rec = self.agents.reject(pid)
        await self.dismiss(f"ping_monitor_pending_{pid}")
        log.info("Rejected the agent request from %s", rec["hostname"])
        return rec

    async def revoke_agent(self, aid: str) -> dict:
        agent = self.agents.revoke(aid)
        for h in list(self.hosts.values()):
            if h.agent_id == aid:
                for s in h.agent_checks:
                    await self.dismiss(f"ping_monitor_{svc_key(h, s)}")
                    await self.ha.delete_state(svc_entity(h, s))
                for eid in self._metric_entities(h):
                    await self.ha.delete_state(eid)
                h.agent_id, h.agent_checks, h.agent_report, h.agent_seen = None, [], None, None
                h.agent_history = {"events": [], "security": [], "detections": [], "failed_logons": []}
                await self._recompute(h)
                await self.publish(h)
        log.info("Revoked the agent on %s", agent["hostname"])
        return agent

    async def receive_report(self, agent: dict, report: dict, source_ip: str | None) -> None:
        now = time.time()
        report = agentlib.normalize_report(report)
        agent.update(last_report=now, source_ip=source_ip,
                     agent_version=str(report.get("agent_version") or "")[:20],
                     os=str(report.get("os") or "")[:120], os_family=report.get("os_family"),
                     ips=[str(i) for i in (report.get("ips") or [])][:8] or agent.get("ips"),
                     roles=[str(r) for r in (report.get("roles") or [])][:30])
        h = await self._link(agent, create=True)
        self.agents.save()
        if not h:
            self.agents.save_report(agent["id"], {"report": report, "received": now})
            return
        await self._apply(h, agent, report, now)
        self.agents.save_report(agent["id"], {"report": report, "received": now, "history": h.agent_history})

    def _history_add(self, h: Host, kind: str, items: list, received: float) -> None:
        cutoff = received - DAY
        hist = [i for i in h.agent_history.get(kind, []) if i.get("_rx", 0) >= cutoff]
        hist.extend({**i, "_rx": received} for i in items)
        h.agent_history[kind] = hist[-200:]

    def agent_update_offer(self, agent: dict, report: dict) -> dict | None:
        """Offer the agent the version in this add-on if updates are on for its OS (or an
        admin asked for this one) and it's older. Agents never update otherwise."""
        os_name = "linux" if report.get("os_family") == "linux" else "windows"
        latest = _linux_script_version() if os_name == "linux" else _script_version()
        running = report.get("agent_version") or agent.get("agent_version")
        now = set(self.agent_settings.get("update_now") or [])
        if not latest or not running or _vt(latest) <= _vt(running):
            if agent["id"] in now:  # done
                now.discard(agent["id"])
                self.agent_settings["update_now"] = sorted(now)
                self._save_agent_settings()
            return None
        if (self.agent_settings.get("auto_update") or {}).get(os_name) or agent["id"] in now:
            return {"version": latest}
        return None

    async def _backup_alerts(self, h: Host, report: dict) -> None:
        """One notification per failed Veeam job run, and one when a job becomes overdue."""
        jobs = ((report.get("checks") or {}).get("backups") or {}).get("jobs") or []
        if not jobs:
            return
        hs = self.agent_settings["hosts"].setdefault(h.key, {})
        seen = hs.setdefault("backup_notified", [])
        ign = agentlib.Ignore(list(self.opts.get("agent_ignore") or []) + list(hs.get("ignore") or [])
                              + list(self.agent_settings.get("global_ignore") or []))
        now, changed = time.time(), False
        for j in jobs:
            if ign.has("backup", j.get("name")):
                continue
            level, why = agentlib.backup_job_state(j, now)
            if level == agentlib.OK or (level == agentlib.WARN and "no successful run" not in why and "missed" not in why):
                continue
            # A failure is new per run; being overdue is new per last success.
            token = f"{j.get('id')}|{j.get('session') or j.get('finished')}" if level == agentlib.CRIT else f"{j.get('id')}|overdue|{j.get('last_success') or j.get('finished')}"
            if token in seen:
                continue
            seen.append(token)
            del seen[:-100]
            changed = True
            if h.maint_until or h.off_schedule:
                continue
            kind = "Microsoft 365 " if j.get("source") == "Microsoft 365" else ""
            job = f"Veeam {kind}{(j.get('type') or 'backup').lower()} job '{j.get('name')}'"
            if level == agentlib.CRIT:
                title, msg = f"🔴 {h.name}: backup failed", f"{job} failed" + (f": {str(j.get('detail')).rstrip('.')}" if j.get("detail") else "") + "."
            elif "missed" in why:
                title, msg = f"🟠 {h.name}: backup missed", f"{job} missed its scheduled run."
            else:
                title, msg = f"🟠 {h.name}: backup overdue", f"{job} hasn't completed successfully for {why.split('for ')[-1]}."
            await self.notify(title, msg,
                              f"ping_monitor_{h.key}__backup_{slugify(str(j.get('name')))}")
        if changed:
            self._save_agent_settings()

    async def _immich_release(self, h: Host, report: dict) -> None:
        """One notification per new Immich release (the check stays amber until updated)."""
        im = (report.get("checks") or {}).get("immich") or {}
        if not agentlib.immich_update(im):
            return
        hs = self.agent_settings["hosts"].setdefault(h.key, {})
        ignored = {str(x).lower() for x in (hs.get("ignore") or []) + (self.agent_settings.get("global_ignore") or [])
                   + list(self.opts.get("agent_ignore") or [])}
        if "update:immich" in ignored or hs.get("immich_notified") == im["latest"]:
            return
        hs["immich_notified"] = im["latest"]
        self._save_agent_settings()
        if h.maint_until or h.off_schedule:
            return
        await self.notify(f"⬆️ {h.name}: Immich v{im['latest']} available",
                          f"{h.name} is running Immich v{im.get('version')}. Release notes: "
                          f"https://github.com/immich-app/immich/releases/tag/v{im['latest']}",
                          f"ping_monitor_{h.key}__immich_update")

    def _ack_time(self, h: Host, kind: str) -> float:
        return float(((self.agent_settings["hosts"].get(h.key) or {}).get("ack") or {}).get(kind, {}).get("at") or 0)

    def _recent(self, h: Host, kind: str, now: float) -> list:
        """Alert-worthy items from the last 24 h that haven't been acknowledged."""
        acked = self._ack_time(h, kind)
        return [i for i in h.agent_history.get(kind, [])
                if i.get("_rx", 0) >= now - DAY and i.get("alert", True) and i.get("_rx", 0) > acked]

    async def acknowledge(self, h: Host, kind: str, who: str | None, undo: bool = False) -> None:
        """Clear the 24-hour amber for events or security items seen so far. Anything that
        arrives afterwards turns it amber again."""
        hs = self.agent_settings["hosts"].setdefault(h.key, {})
        ack = hs.setdefault("ack", {})
        if undo:
            ack.pop(kind, None)
        else:
            ack[kind] = {"at": time.time(), "by": who or ""}
        self._save_agent_settings()
        log.info("%s: %s %s%s", h.name, "un-acknowledged" if undo else "acknowledged", kind, f" by {who}" if who else "")
        await self.reevaluate(h)

    # -- per-server agent settings (ignores, disk thresholds) -------------------
    def _save_agent_settings(self) -> None:
        tmp = AGENT_SETTINGS.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.agent_settings, indent=2))
        tmp.replace(AGENT_SETTINGS)

    def _host_settings(self, h: Host) -> dict:
        hs = self.agent_settings["hosts"].get(h.key) or {}
        return {"ignore": list(self.agent_settings.get("global_ignore") or []) + list(hs.get("ignore") or []),
                "disks": dict(hs.get("disks") or {})}

    async def set_ignore(self, h: Host, item: str, scope: str, remove: bool) -> None:
        hs = self.agent_settings["hosts"].setdefault(h.key, {})
        lst = self.agent_settings.setdefault("global_ignore", []) if scope == "all" else hs.setdefault("ignore", [])
        if remove:
            for target in (lst, hs.get("ignore") or []) if scope == "all" else (lst,):
                while item in target:
                    target.remove(item)
        elif item not in lst:
            lst.append(item)
            if scope == "all" and item in (hs.get("ignore") or []):
                hs["ignore"].remove(item)  # now covered globally
        self._save_agent_settings()
        log.info("%s %s on %s", "Stopped ignoring" if remove else "Ignoring", item,
                 "all servers" if scope == "all" else h.name)
        targets = [x for x in self.hosts.values() if x.agent_report] if scope == "all" else [h]
        for x in targets:
            await self.reevaluate(x)

    async def set_disk(self, h: Host, disk: str, warn, crit) -> None:
        hs = self.agent_settings["hosts"].setdefault(h.key, {})
        disks = hs.setdefault("disks", {})
        key = agentlib.disk_key(disk)
        if warn is None and crit is None:
            disks.pop(key, None)
        else:
            disks[key] = {"warn": warn, "crit": crit}
        self._save_agent_settings()
        log.info("%s %s disk thresholds: %s", h.name, key, disks.get(key) or "defaults")
        await self.reevaluate(h)

    async def reevaluate(self, h: Host) -> None:
        """Apply changed settings to the latest report now, without re-alerting events."""
        if h.agent_report and h.agent_id and self.agents and h.agent_id in self.agents.agents:
            await self._apply(h, self.agents.agents[h.agent_id], h.agent_report, h.agent_seen or time.time(),
                              reeval=True)

    async def _apply(self, h: Host, agent: dict, report: dict, received: float, restoring: bool = False,
                     reeval: bool = False) -> None:
        settings = self._host_settings(h)
        result = evaluate(report, self.opts, now=received, settings=settings)
        h.agent_report, h.agent_seen = report, received
        notable = result["notable"]
        # Events ignored since they arrived no longer keep the Events chip amber.
        ign = agentlib.Ignore(list(self.opts.get("agent_ignore") or []) + settings["ignore"])
        for e in h.agent_history.get("events", []):
            if ign.has("event", e.get("id")):
                e["alert"] = False
        if not restoring and not reeval:
            self._history_add(h, "events", notable["events"], received)
            self._history_add(h, "security", notable["security"], received)
            self._history_add(h, "detections", notable["detections"], received)
            if notable["failed_logons"]:
                self._history_add(h, "failed_logons", [notable["failed_logons"]], received)

        existing = {s.key: s for s in h.agent_checks}
        run_s = (report.get("run_ms") or 0) / 1000
        slow_limit = float(self.opts.get("agent_slow_seconds", 120))
        timings = report.get("timings") or {}
        slowest = max(timings.items(), key=lambda kv: kv[1]) if timings else None
        agent_detail = f"Agent {report.get('agent_version') or '?'} reporting"
        if run_s:
            agent_detail += f"; run took {run_s:.0f} s" + (f" (slowest: {slowest[0]} {slowest[1] / 1000:.0f} s)"
                                                         if slowest and slowest[1] >= 1000 else "")
        if report.get("errors"):
            agent_detail += f"; {len(report['errors'])} collector warning(s)"
        checks = [{"key": "agent", "label": "Agent", "confirm": False, "detail": agent_detail,
                   "level": agentlib.WARN if slow_limit and run_s > slow_limit else agentlib.OK}]
        checks += result["checks"]
        new_list = []
        for c in checks:
            key = f"agent_{c['key']}"
            sv = existing.pop(key, None) or Service(key=key, label=c["label"], kind="agent", port=None, url=None,
                                                     desc=f"agent: {c['label'].lower()}")
            level, detail = c["level"], c["detail"]
            # Event-type checks stay amber for 24h after something alert-worthy.
            if c["key"] == "events" and level == agentlib.OK:
                recent = self._recent(h, "events", received)
                if recent:
                    last = recent[-1]
                    level, detail = agentlib.WARN, (f"{len(recent)} alert-worthy event(s) in 24h; latest: "
                                                    f"{last.get('source')}" + (f" {last.get('id')}" if last.get("id") else ""))
            if c["key"] == "security" and level == agentlib.OK:
                recent = self._recent(h, "security", received)
                if recent:
                    last = recent[-1]
                    acct = self._pretty_account(last.get("account"))
                    level, detail = agentlib.WARN, (f"{len(recent)} notable security event(s) in 24h; latest: "
                                                    f"{last.get('what')}" + (f" ({acct})" if acct else ""))
            if level == agentlib.CRIT:
                if not reeval:
                    sv.failures += 1
                elif sv.failures == 0:
                    # Re-checking after a settings change (e.g. Stop ignoring): the problem
                    # was already in the report, so don't wait for two more reports.
                    sv.failures = 2
                status = AMBER if c.get("confirm") and sv.failures < 2 else RED
            else:
                sv.failures = 0
                status = self.LEVEL_STATUS[level]
            sv.label, sv.detail, sv.last_check = c["label"], detail, received
            if not restoring and not reeval:
                self.store.add(svc_key(h, sv), received, status != RED, None)
            if status != sv.status:
                old, sv.status, sv.last_change = sv.status, status, received
                if not restoring:
                    log.info("%s %s: %s -> %s [%s]", h.name, sv.label, old, status, detail)
                    await self.on_agent_check_change(h, sv, old, status)
            new_list.append(sv)
        for gone in existing.values():  # e.g. a role was removed from the server
            await self.dismiss(f"ping_monitor_{svc_key(h, gone)}")
            await self.ha.delete_state(svc_entity(h, gone))
        h.agent_checks = new_list
        if not restoring and not reeval:
            await self._alert_notables(h, notable)
            await self._immich_release(h, report)
            await self._backup_alerts(h, report)
        await self._recompute(h, quiet=restoring)
        if not restoring:
            await self.publish(h)

    async def _recompute(self, h: Host, quiet: bool = False) -> None:
        """Agent reports arrive between pings: update Up/Degraded straight away."""
        if h.status not in (GREEN, DEGRADED):
            return
        new = DEGRADED if any(s.status == RED for s in h.services + h.agent_checks) else GREEN
        if new != h.status:
            old, h.status, h.last_change = h.status, new, time.time()
            if not quiet:
                log.info("%s: %s -> %s", h.name, old, new)
                await self.on_change(h, old, new, "agent")

    async def on_agent_check_change(self, h: Host, s: Service, old: str, new: str) -> None:
        await self.ha.fire("ping_monitor_service_changed", {
            "name": h.name, "host": h.host, "ip": h.ip, "service": s.label, "target": s.desc,
            "old_status": old, "new_status": new, "detail": s.detail,
            "entity_id": svc_entity(h, s), "host_entity_id": h.entity_id,
        })
        if h.maint_until or h.off_schedule:
            return
        if s.key == "agent_backups":
            return  # each failed job gets its own notification (_backup_alerts)
        tag = f"ping_monitor_{svc_key(h, s)}"
        if new == RED:
            if s.key == "agent_agent" and h.status == RED:
                return  # the "down" alert already covers it
            await self.notify(f"🟠 {h.name}: {s.label}", s.detail or "", tag)
            await self.persist(tag, f"Rollcall: {h.name} {s.label}", s.detail or "")
        elif old == RED:
            await self.dismiss(tag)
            if self.opts["notify_recovery"]:
                word = "OK" if new == GREEN else "no longer critical"
                await self.notify(f"🟢 {h.name}: {s.label} {word}", s.detail or "", tag)

    @staticmethod
    def _pretty_account(value) -> str:
        v = str(value or "").strip()
        m = re.match(r"^CN=((?:[^,\\]|\\.)+)", v, re.I)
        return m.group(1).replace("\\", "") if m else v

    def _tag(self, h: Host) -> str:
        self._notice += 1
        return f"ping_monitor_{h.key}__note{self._notice}"

    async def _alert_notables(self, h: Host, notable: dict) -> None:
        if h.maint_until or h.off_schedule:
            return
        sent = 0
        if self.opts.get("agent_event_alerts", True):
            for e in [e for e in notable["events"] if e.get("alert")][:5]:
                what = f"event {e.get('id')}" if e.get("id") else "journal"
                await self.notify(f"⚠️ {h.name}: {e.get('source')} {what}",
                                  f"{e.get('level')}: {e.get('message')}", self._tag(h))
                sent += 1
        if self.opts.get("agent_security_alerts", True):
            for i in [i for i in notable["security"] if i.get("alert")][:8]:
                acct, by, grp = self._pretty_account(i.get("account")), i.get("by") or "?", i.get("group")
                eid = int(i.get("id") or 0)
                if eid == 4740:
                    title, msg = "🔒 account locked out", f"{acct} was locked out" + (f" (from {i['source']})" if i.get("source") else "")
                elif eid == 1102:
                    title, msg = "🗑️ Security log cleared", f"The Security log was cleared by {by}"
                elif eid in (4728, 4732, 4756):
                    title, msg = "🛡️ added to a security group", f"{acct} was added to {grp} by {by}"
                elif eid == 4720:
                    title, msg = "👤 account created", f"{acct} was created by {by}"
                elif eid == 4726:
                    title, msg = "👤 account deleted", f"{acct} was deleted by {by}"
                elif eid == 4719:
                    title, msg = "🛡️ audit policy changed", f"Audit policy changed by {by}"
                else:
                    title, msg = i.get("what") or f"event {eid}", f"{acct} ({by})"
                icon, _, text = title.partition(" ") if title[:1] in "🔒🗑🛡👤" else ("🔐", "", title)
                await self.notify(f"{icon} {h.name}: {text}", msg, self._tag(h))
                sent += 1
        for d in notable["detections"][:5]:
            ok = d.get("action_success", True)
            await self.notify(f"🦠 {h.name}: Defender detected {d.get('threat')}",
                              f"{d.get('resource') or ''} ({'dealt with' if ok else 'NOT removed: check this server'})",
                              self._tag(h))
            sent += 1
        if sent:
            log.info("%s: sent %d agent alert(s)", h.name, sent)

    async def check_stale_agents(self, now: float) -> None:
        limit = float(self.opts.get("agent_stale_minutes", 15)) * 60
        for h in list(self.hosts.values()):
            if not h.agent_id or not h.agent_seen or not h.agent_checks:
                continue
            if h.maint_until or h.off_schedule:
                continue  # paused or off schedule: the agent may not be running, and that's expected
            chip = h.agent_checks[0]
            # A fresh stale period after an add-on restart or the end of a pause, so a
            # rebooted server's agent has time to run again before it's flagged.
            age = now - max(h.agent_seen, self.started, h.maint_ended or 0, h.sched_started or 0)
            if age > limit and chip.status != RED:
                old, chip.status, chip.last_change = chip.status, RED, now
                chip.detail = f"No report for {fmt_duration(now - h.agent_seen)}"
                log.info("%s: agent stopped reporting (%s)", h.name, chip.detail)
                await self.on_agent_check_change(h, chip, old, RED)
                await self._recompute(h)
                await self.publish(h)
            elif chip.status == RED and age <= limit:
                pass  # recovered by the next report
            elif chip.status == RED:
                chip.detail = f"No report for {fmt_duration(now - h.agent_seen)}"

    def _agent_summary(self, h: Host) -> dict | None:
        if not h.agent_id:
            return None
        r = h.agent_report or {}
        mem = None
        if r.get("mem_total_mb"):
            mem = round(100 * (1 - (r.get("mem_free_mb") or 0) / r["mem_total_mb"]), 1)
        return {"id": h.agent_id, "last_seen": h.agent_seen, "version": r.get("agent_version"),
                "roles": r.get("roles") or [], "os": r.get("os"), "uptime_s": r.get("uptime_s"),
                # Before the first report, the OS comes from the enrolment request.
                "os_family": r.get("os_family") or ((self.agents.agents.get(h.agent_id) if self.agents else None) or {}).get("os_family") or "windows",
                "load": r.get("load"),
                "cpu_pct": r.get("cpu_pct"), "mem_used_pct": mem, "pending_reboot": r.get("pending_reboot"),
                "hw_vendor": str(r.get("hw_vendor") or "")[:80], "hw_model": str(r.get("hw_model") or "")[:80],
                "serial": str(r.get("serial") or "")[:60],
                # None: an agent too old to say; "": physical; else what it runs on
                "virtual": None if "virtual" not in r else str(r.get("virtual") or "")[:40]}

    def vm_hosts(self) -> dict[str, str]:
        """VM name (lower case, short) -> the Hyper-V host it's on, from the hosts' agent reports."""
        out: dict[str, str] = {}
        for h in list(self.hosts.values()):
            for vm in ((h.agent_report or {}).get("checks") or {}).get("hyperv") or []:
                n = str(vm.get("name") or "").strip().lower().split(".")[0]
                if n:
                    out.setdefault(n, h.name)
        return out

    def _metrics(self, h: Host) -> list[tuple[str, str, dict]]:
        r = h.agent_report
        if not r:
            return []
        out = []
        base = f"sensor.ping_monitor_{h.key}"
        common = {"unit_of_measurement": "%", "state_class": "measurement"}
        if r.get("cpu_pct") is not None:
            out.append((f"{base}_cpu", str(r["cpu_pct"]), {**common, "friendly_name": f"{h.name} CPU", "icon": "mdi:cpu-64-bit"}))
        if r.get("mem_total_mb"):
            used = round(100 * (1 - (r.get("mem_free_mb") or 0) / r["mem_total_mb"]), 1)
            out.append((f"{base}_memory", str(used), {**common, "friendly_name": f"{h.name} memory used", "icon": "mdi:memory"}))
        for d in r.get("disks") or []:
            try:
                size, free = float(d.get("size_gb") or 0), float(d.get("free_gb") or 0)
            except (TypeError, ValueError):
                continue
            if size < 0.5:
                continue
            name = str(d.get("name") or "disk")
            letter = "root" if name == "/" else slugify(name)
            out.append((f"{base}_disk_{letter}_free", str(round(100 * free / size, 1)),
                        {**common, "friendly_name": f"{h.name} {d.get('name')} free", "icon": "mdi:harddisk",
                         "free_gb": free, "size_gb": size}))
        return out

    def _metric_entities(self, h: Host) -> list[str]:
        return [eid for eid, _v, _a in self._metrics(h)]

    def details(self, h: Host, include_security: bool) -> dict:
        r = dict(h.agent_report or {})
        bk = (r.get("checks") or {}).get("backups")
        if bk:  # each job's state as the check sees it, for the Backups tab
            now = time.time()
            r["checks"] = {**r["checks"], "backups": {**bk, "jobs": [
                {**j, "_level": lv, "_why": why} for j in bk.get("jobs") or [] for lv, why in [agentlib.backup_job_state(j, now)]]}}
        if not include_security:
            r.pop("security", None)
        hist = {k: [{**{kk: vv for kk, vv in i.items() if kk != "_rx"}, "received": i.get("_rx")} for i in v[-100:]]
                for k, v in h.agent_history.items() if include_security or k in ("events", "detections")}
        hs = self.agent_settings["hosts"].get(h.key) or {}
        settings = {"ignore": hs.get("ignore") or [], "global_ignore": self.agent_settings.get("global_ignore") or [],
                    "ack": hs.get("ack") or {},
                    "config_ignore": list(self.opts.get("agent_ignore") or []), "disks": hs.get("disks") or {},
                    "defaults": {"warn": self.opts.get("agent_disk_warn", 15), "crit": self.opts.get("agent_disk_crit", 5)}}
        return {"key": h.key, "name": h.name, "agent": self._agent_summary(h), "report": r, "history": hist,
                "settings": settings,
                "received": h.agent_seen, "security_visible": include_security,
                "checks": [{"key": s.key.removeprefix("agent_"), "label": s.label, "status": s.status,
                            "detail": s.detail if include_security or s.key != "agent_security" else SECURITY_HIDDEN}
                           for s in h.agent_checks]}

    # -- reporting --------------------------------------------------------
    def uptime_24h(self, key: str) -> float | None:
        now = time.time()
        return uptime_pct(self.store.rows(key, now - DAY), now - DAY, now, self.max_gap)

    def history(self, key: str) -> list[str]:
        now = time.time()
        rows = self.store.rows(key, now - DAY)
        size = DAY / BUCKETS
        out = []
        for b in range(BUCKETS):
            start = now - DAY + b * size
            up, down, maint = coverage(rows, start, start + size, self.max_gap)
            if up + down <= 0:
                out.append("m" if maint > 0 else "n")
            else:
                out.append("g" if down == 0 else "r" if up == 0 else "a")
        return out

    async def publish(self, h: Host) -> None:
        await self.ha.set_state(
            h.entity_id,
            h.status,
            {
                "friendly_name": h.name,
                "icon": ICONS[h.status],
                "host": h.host,
                "ip": h.ip,
                "uptime_24h": self.uptime_24h(h.key),
                "latency_ms": h.latency,
                "consecutive_failures": h.failures,
                "last_check": iso(h.last_check),
                "last_change": iso(h.last_change),
                "maintenance_until": iso(h.maint_until),
                "off_schedule": h.off_schedule,
                "schedule": "whenever it's on" if h.expect_off else describe_schedule(h.schedule),
                "alerts": not h.no_alerts,
                "services": {s.label: s.status for s in h.services + h.agent_checks},
            },
        )
        for s in h.services + h.agent_checks:
            await self.ha.set_state(
                svc_entity(h, s),
                s.status,
                {
                    "friendly_name": f"{h.name} {s.label}",
                    "icon": SVC_ICONS.get(s.status, SVC_ICONS[UNKNOWN]),
                    "host": h.host,
                    "target": s.desc,
                    "detail": s.detail,
                    "uptime_24h": self.uptime_24h(svc_key(h, s)),
                    "latency_ms": s.latency,
                    "last_check": iso(s.last_check),
                    "last_change": iso(s.last_change),
                },
            )
        for eid, value, attrs in self._metrics(h):
            await self.ha.set_state(eid, value, attrs)

    def snapshot(self) -> dict:
        hosts = []
        vmh = self.vm_hosts()
        for h in list(self.hosts.values()):
            short = h.name.strip().lower().split(".")[0]
            on = vmh.get(short) or vmh.get(str(h.host).lower().split(".")[0])
            hosts.append({
                "key": h.key, "name": h.name, "host": h.host, "ip": h.ip,
                "vm_host": on if on and on != h.name else None,
                "status": h.status, "failures": h.failures, "latency_ms": h.latency,
                "uptime_24h": self.uptime_24h(h.key), "history": self.history(h.key),
                "last_check": h.last_check, "last_change": h.last_change,
                "next_check": h.next_due, "checking": h.checking,
                "entity_id": h.entity_id,
                "maint_until": h.maint_until, "maint_seen_down": h.maint_seen_down,
                "schedule": h.schedule, "schedule_text": describe_schedule(h.schedule) if h.schedule else
                ("Checked whenever it's on" if h.expect_off else None),
                "expect_off": h.expect_off, "no_alerts": h.no_alerts,
                "off_schedule": h.off_schedule, "reachable": h.reachable, "schedule_next": schedule_state(h.schedule, time.time())[2],
                "starting_up": bool(h.schedule and not h.off_schedule and h.status == MAINT and not h.maint_until),
                "checks": h.checks,
                "snmp": any(s.kind == "snmp" for s in h.services), "snmp_community_set": bool(h.snmp_community),
                "snmp_version": h.snmp_version, "icon": h.icon, "model": h.model,
                "snmp_v3": {"user": h.snmp_v3.get("user", ""), "auth": h.snmp_v3.get("auth"), "priv": h.snmp_v3.get("priv"),
                            "auth_set": bool(h.snmp_v3.get("auth_pass")), "priv_set": bool(h.snmp_v3.get("priv_pass"))}
                if h.snmp_version == "3" else None,
                "syslog": any(s.kind == "syslog" for s in h.services), "syslog_alert": h.syslog_alert,
                "syslog_keywords": h.syslog_keywords, "syslog_ignore": h.syslog_ignore,
                "services": [{
                    "key": s.key, "label": s.label, "target": s.desc, "status": s.status, "kind": s.kind,
                    "latency_ms": s.latency, "detail": s.detail,
                    "uptime_24h": self.uptime_24h(svc_key(h, s)),
                    "last_check": s.last_check, "last_change": s.last_change,
                    "agent": s.kind == "agent",
                } for s in h.services + h.agent_checks],
                "agent": self._agent_summary(h),
            })
        return {"now": time.time(), "interval": self.interval,
                "syslog_port": self.syslog_port, "syslog_unknown": sorted(self.syslog_unknown.values(), key=lambda u: -u["last"])[:20],
                "retry_interval": self.retry_interval,
                "maintenance_minutes": int(self.opts["maintenance_minutes"]),
                "ping_mode": PING_MODE,
                "hosts": hosts}


# --------------------------------------------------------------------------
# Access control
# --------------------------------------------------------------------------
class Access:
    """Decides who may change things (add/edit/delete/pause/reset).

    Home Assistant's ingress proxy tells us who is viewing (X-Remote-User-*
    headers) but not whether they're an admin, so the admin list is read from
    HA's user list and cached. Names in the `editors` option can always make
    changes. If the user list can't be read and no editors are set, everyone
    can make changes (the behaviour before this was added), with a warning.
    """
    REFRESH = 300

    def __init__(self, opts: dict, ha: HomeAssistant):
        self.enabled = bool(opts.get("admin_only_changes", True))
        self.editors = {str(e).strip().lower() for e in (opts.get("editors") or []) if str(e).strip()}
        self.ha = ha
        self.admins: set[str] | None = None
        self.loaded_at = 0.0
        self.lock = asyncio.Lock()
        self.warned = False

    async def _refresh(self, force: bool = False) -> None:
        async with self.lock:
            if not force and time.time() - self.loaded_at < self.REFRESH:
                return
            self.loaded_at = time.time()
            users = await self.ha.list_users()
            if users is None:
                if self.admins is None and not self.warned:
                    self.warned = True
                    log.warning("Couldn't read the Home Assistant user list, so admins can't be "
                                "identified. %s", "Only names in 'editors' can make changes."
                                if self.editors else "Everyone can make changes until it can be "
                                "read; add usernames to the 'editors' option to restrict it.")
                return
            self.admins = {u["id"] for u in users if u.get("id") and (
                u.get("is_admin") or u.get("is_owner") or "system-admin" in (u.get("group_ids") or []))}
            log.debug("Loaded %d HA admin user(s)", len(self.admins))

    async def who(self, req) -> dict:
        uid = req.headers.get("X-Remote-User-Id", "")
        name = req.headers.get("X-Remote-User-Name", "")
        display = req.headers.get("X-Remote-User-Display-Name", "") or name
        return {"id": uid, "name": name, "display": display, "can_edit": await self._can_edit(uid, name, display)}

    async def _can_edit(self, uid: str, name: str, display: str) -> bool:
        if not self.enabled:
            return True
        if not SUPERVISOR_TOKEN:
            return True  # running outside Home Assistant (development)
        if not uid:
            return False  # not via HA ingress
        if name.lower() in self.editors or display.lower() in self.editors:
            return True
        await self._refresh()
        # Someone just made an admin shouldn't wait 5 minutes; recheck (at most every 30s).
        if self.admins is not None and uid not in self.admins and time.time() - self.loaded_at > 30:
            await self._refresh(force=True)
        if self.admins is None:
            return not self.editors
        return uid in self.admins


# --------------------------------------------------------------------------
# Web
# --------------------------------------------------------------------------
def build_app(monitor: Monitor, access: Access) -> web.Application:
    def editor_only(handler):
        async def wrapped(req):
            user = await access.who(req)
            if not user["can_edit"]:
                log.info("Blocked change by %s: %s %s", user["display"] or "unknown user",
                         req.method, req.path)
                raise web.HTTPForbidden(
                    text=json.dumps({"error": "Only Home Assistant admins can make changes here."}),
                    content_type="application/json")
            return await handler(req)
        return wrapped

    async def index(_req):
        # Always revalidate, so an add-on update shows the new page straight away.
        return web.FileResponse(WEB_DIR / "index.html", headers={
            "Cache-Control": "no-cache, no-store, must-revalidate", "Pragma": "no-cache", "Expires": "0"})

    async def status(req):
        snap = monitor.snapshot()
        user = await access.who(req)
        snap["user"] = user["display"] or None
        snap["can_edit"] = user["can_edit"]
        if user["can_edit"] and monitor.agents:
            snap["agents_pending"] = len(monitor.agents.pending)
        if not user["can_edit"]:
            for h in snap["hosts"]:
                for sv in h["services"]:
                    if sv["key"] == "agent_security":
                        sv["detail"] = SECURITY_HIDDEN
        return web.json_response(snap)

    async def export_data(_req):
        data = await asyncio.to_thread(make_backup, os.environ.get("PM_VERSION"))
        name = time.strftime("rollcall-export-%Y%m%d-%H%M.zip")
        log.info("Exported data (%d KB)", len(data) // 1024)
        return web.Response(body=data, content_type="application/zip",
                            headers={"Content-Disposition": f'attachment; filename="{name}"'})

    # Home Assistant's ingress proxy refuses large request bodies (HTTP 413), so the
    # dashboard uploads an export in pieces and then asks for it to be imported.
    upload_dir = DB_PATH.parent / "uploads"

    def _upload_path(req) -> Path:
        uid = req.query.get("upload", "")
        if not re.match(r"^[a-z0-9]{8,32}$", uid):
            raise web.HTTPBadRequest(text=json.dumps({"error": "bad upload id"}), content_type="application/json")
        return upload_dir / f"{uid}.zip"

    async def import_chunk(req):
        path = _upload_path(req)
        try:
            offset = int(req.query.get("offset", "-1"))
        except ValueError:
            offset = -1
        data = await req.read()
        upload_dir.mkdir(parents=True, exist_ok=True)
        for old in upload_dir.glob("*.zip"):  # tidy abandoned uploads
            if time.time() - old.stat().st_mtime > 3600 and old != path:
                old.unlink(missing_ok=True)
        size = path.stat().st_size if path.exists() else 0
        if offset != size:
            return web.json_response({"error": f"piece out of order (have {size} bytes, got offset {offset})", "size": size}, status=409)
        if size + len(data) > 1024 ** 3:
            path.unlink(missing_ok=True)
            return web.json_response({"error": "The export is too large"}, status=400)
        with open(path, "ab") as f:
            f.write(data)
        return web.json_response({"size": size + len(data)})

    async def import_data(req):
        if req.query.get("upload"):
            path = _upload_path(req)
            if not path.exists():
                return web.json_response({"error": "Upload not found; try again"}, status=400)
            data = await asyncio.to_thread(path.read_bytes)
            path.unlink(missing_ok=True)
        else:
            data = await req.read()
        try:
            manifest = await asyncio.to_thread(stage_restore, data)
        except ValueError as err:
            return web.json_response({"error": str(err)}, status=400)
        log.info("Import staged (%s hosts, %s agents, exported from version %s); restarting to apply it",
                 manifest.get("hosts"), manifest.get("agents"), manifest.get("addon_version"))
        options_note = None
        if req.query.get("options") == "1" and (RESTORE_DIR / "options.json").exists():
            options_note = await monitor.ha.restore_options(json.loads((RESTORE_DIR / "options.json").read_text()))
        restarting = await monitor.ha.restart_self()
        return web.json_response({"ok": True, "manifest": manifest, "restarting": restarting, "options": options_note})

    async def ha_entities(req):
        """Home Assistant sensors for the Edit dialog's search, best matches first."""
        q = (req.query.get("q") or "").strip().lower()
        states = await monitor.ha.get_json("/states")
        if not isinstance(states, list):
            return web.json_response({"error": "Couldn't read Home Assistant's entities", "entities": []})
        words = [w for w in re.split(r"[\s_.\-]+", q) if w]
        out = []
        for st in states:
            eid = str(st.get("entity_id") or "")
            if not eid.startswith(("sensor.", "binary_sensor.")) or eid.startswith("sensor.ping_monitor_"):
                continue
            attrs = st.get("attributes") or {}
            name = str(attrs.get("friendly_name") or eid)
            hay = (eid + " " + name).lower().replace("_", " ")
            if words and not all(w in hay for w in words):
                continue
            score = sum(k in hay for k in ("cpu", "memory", "temperature", "uptime", "load"))
            out.append({"entity_id": eid, "name": name, "state": st.get("state"),
                        "unit": attrs.get("unit_of_measurement") or "", "score": score})
        out.sort(key=lambda e: (-e["score"], e["entity_id"]))
        return web.json_response({"entities": out[:60], "total": len(out)})

    async def views_get(_req):
        return web.json_response({"views": load_views()})

    async def views_put(req):
        try:
            body = await req.json()
            views = clean_views(body.get("views") if isinstance(body, dict) else None)
        except (json.JSONDecodeError, ValueError) as err:
            msg = str(err) if isinstance(err, ValueError) and not isinstance(err, json.JSONDecodeError) else "Invalid JSON"
            return web.json_response({"error": msg}, status=400)
        save_views(views)
        log.info("Saved %d dashboard tab(s)", len(views))
        return web.json_response({"views": views})

    async def host_details(req):
        h = monitor.hosts.get(req.match_info["key"])
        if not h:
            raise web.HTTPNotFound()
        user = await access.who(req)
        return web.json_response(monitor.details(h, include_security=user["can_edit"]))

    async def agent_ignore(req):
        h = monitor.hosts.get(req.match_info["key"])
        if not h:
            raise web.HTTPNotFound()
        body = await req.json()
        try:
            item = agentlib.clean_ignore_item(body.get("kind"), body.get("value"))
        except (ValueError, AttributeError) as err:
            return web.json_response({"error": str(err)}, status=400)
        scope = "all" if body.get("scope") == "all" else "host"
        await monitor.set_ignore(h, item, scope, bool(body.get("remove")))
        return web.json_response({"ok": True, "item": item, "scope": scope})

    async def agent_ack(req):
        h = monitor.hosts.get(req.match_info["key"])
        if not h:
            raise web.HTTPNotFound()
        try:
            body = await req.json()
        except (json.JSONDecodeError, ValueError):
            body = {}
        kind = body.get("kind")
        if kind not in ("events", "security"):
            return web.json_response({"error": "kind must be events or security"}, status=400)
        user = await access.who(req)
        await monitor.acknowledge(h, kind, user.get("display"), bool(body.get("undo")))
        return web.json_response({"ok": True})

    async def agent_disk(req):
        h = monitor.hosts.get(req.match_info["key"])
        if not h:
            raise web.HTTPNotFound()
        body = await req.json()
        disk = str(body.get("disk") or "").strip()
        if not re.match(r"^([A-Za-z]:?\\?|/[^\x00-\x1f]{0,200})$", disk):
            return web.json_response({"error": "invalid disk"}, status=400)

        def num(v):
            if v in (None, ""):
                return None
            v = float(v)
            if not 0 <= v <= 95:
                raise ValueError("thresholds must be between 0 and 95%")
            return v
        try:
            warn, crit = num(body.get("warn")), num(body.get("crit"))
        except (TypeError, ValueError) as err:
            return web.json_response({"error": str(err) if "between" in str(err) else "thresholds must be numbers"}, status=400)
        if warn is not None and crit is not None and warn and crit > warn:
            return web.json_response({"error": "the red level can't be above the amber level"}, status=400)
        await monitor.set_disk(h, disk, warn, crit)
        return web.json_response({"ok": True})

    # -- Agents (admin) ---------------------------------------------------
    def _agent_row(a):
        h = monitor.hosts.get(a.get("host_key") or "")
        return {"id": a["id"], "hostname": a["hostname"], "fqdn": a.get("fqdn"), "ips": a.get("ips") or [],
                "os": a.get("os"), "version": a.get("agent_version"), "roles": a.get("roles") or [],
                "os_family": a.get("os_family") or "windows",
                "approved_at": a.get("approved_at"), "last_report": a.get("last_report"),
                "host_key": h.key if h else None, "host_name": h.name if h else None,
                "update_queued": a["id"] in (monitor.agent_settings.get("update_now") or [])}

    async def agents_list(_req):
        st = monitor.agents
        return web.json_response({
            "port": AGENT_PORT, "ssl": bool(monitor.opts.get("agent_ssl")),
            "stale_minutes": monitor.opts.get("agent_stale_minutes", 15),
            "key_hint": "…" + st.enrol_key[-4:],
            "agents": sorted((_agent_row(a) for a in st.agents.values()), key=lambda r: r["hostname"]),
            "pending": sorted(({k: p.get(k) for k in ("id", "hostname", "fqdn", "ips", "os", "agent_version",
                                                       "requested_at", "source_ip", "os_family")}
                               | {"replaces": bool(p.get("replaces"))} for p in st.pending.values()),
                              key=lambda r: r["requested_at"]),
            "latest_version": _script_version(),
            "latest_linux_version": _linux_script_version(),
            "auto_update": {k: bool((monitor.agent_settings.get("auto_update") or {}).get(k)) for k in ("windows", "linux")},
        })

    async def agents_approve(req):
        pid = req.match_info["pid"]
        if pid not in monitor.agents.pending:
            raise web.HTTPNotFound()
        a = await monitor.approve_agent(pid)
        return web.json_response({"approved": a["id"]})

    async def agents_approve_all(_req):
        ids = list(monitor.agents.pending)
        for pid in ids:
            await monitor.approve_agent(pid)
        return web.json_response({"approved": len(ids)})

    async def agents_reject(req):
        pid = req.match_info["pid"]
        if pid not in monitor.agents.pending:
            raise web.HTTPNotFound()
        await monitor.reject_agent(pid)
        return web.json_response({"rejected": pid})

    async def agents_revoke(req):
        aid = req.match_info["aid"]
        if aid not in monitor.agents.agents:
            raise web.HTTPNotFound()
        await monitor.revoke_agent(aid)
        return web.json_response({"revoked": aid})

    async def agents_rotate(_req):
        monitor.agents.rotate_key()
        log.info("Rotated the agent enrolment key")
        return web.json_response({"key_hint": "…" + monitor.agents.enrol_key[-4:]})

    async def agents_script(req):
        server = (req.query.get("server") or "").strip().rstrip("/")
        if not SERVER_RE.match(server):
            raise web.HTTPBadRequest(text=json.dumps({"error": "Enter the address as http://host:port"}),
                                     content_type="application/json")
        linux = req.query.get("os") == "linux"
        body = build_agent_script("linux" if linux else "windows", server, monitor.agents.enrol_key,
                                  req.query.get("ignore_cert") == "1")
        return web.Response(body=body, content_type="application/octet-stream", headers={
            "Content-Disposition": f'attachment; filename="{"pingmonitor-agent.py" if linux else "PingMonitorAgent.ps1"}"'})

    async def agents_auto_update(req):
        body = await req.json()
        os_name = body.get("os")
        if os_name not in ("windows", "linux"):
            return web.json_response({"error": "os must be windows or linux"}, status=400)
        au = monitor.agent_settings.setdefault("auto_update", {})
        au[os_name] = bool(body.get("enabled"))
        monitor._save_agent_settings()
        log.info("Automatic %s agent updates %s", os_name.capitalize(), "on" if au[os_name] else "off")
        return web.json_response({"auto_update": au})

    async def agents_update_now(req):
        aid = req.match_info["aid"]
        if aid not in monitor.agents.agents:
            raise web.HTTPNotFound()
        now = set(monitor.agent_settings.get("update_now") or [])
        now.add(aid)
        monitor.agent_settings["update_now"] = sorted(now)
        monitor._save_agent_settings()
        log.info("Agent on %s will update at its next report", monitor.agents.agents[aid].get("hostname"))
        return web.json_response({"ok": True})

    async def check_now(req):
        h = monitor.hosts.get(req.match_info["key"])
        if not h:
            raise web.HTTPNotFound()
        h.next_due = 0
        return web.json_response({"queued": h.key})

    async def reset(req):
        key = req.match_info.get("key")
        if key is not None and key not in monitor.hosts:
            raise web.HTTPNotFound()
        targets = [monitor.hosts[key]] if key else list(monitor.hosts.values())
        removed = monitor.store.clear(key) if key else monitor.store.clear()
        for h in targets:
            h.last_change = None
            for s in h.services:
                s.last_change = None
            await monitor.publish(h)
        log.info("Reset uptime history for %s (%d rows removed)",
                 targets[0].name if key else "all hosts", removed)
        return web.json_response({"reset": key or "all", "rows": removed})

    async def maintenance(req):
        h = monitor.hosts.get(req.match_info["key"])
        if not h:
            raise web.HTTPNotFound()
        try:
            body = await req.json() if req.can_read_body else {}
        except json.JSONDecodeError:
            body = {}
        try:
            raw = body.get("minutes")
            minutes = int(monitor.opts["maintenance_minutes"] if raw is None else raw)
        except (TypeError, ValueError):
            raise web.HTTPBadRequest(text="minutes must be a whole number")
        if not 1 <= minutes <= 1440:
            raise web.HTTPBadRequest(text="minutes must be between 1 and 1440")
        await monitor.start_maintenance(h, minutes)
        return web.json_response({"paused": h.key, "until": h.maint_until})

    async def _bulk_hosts(req) -> tuple[list, dict]:
        try:
            body = await req.json()
        except (json.JSONDecodeError, ValueError):
            raise web.HTTPBadRequest(text="expected JSON")
        keys = body.get("keys") if isinstance(body, dict) else None
        if not isinstance(keys, list) or not keys or len(keys) > 1000:
            raise web.HTTPBadRequest(text="keys must be a list of computers")
        hosts = [monitor.hosts[k] for k in dict.fromkeys(str(k) for k in keys) if str(k) in monitor.hosts]
        return hosts, body

    async def maintenance_bulk(req):
        """Pause several computers at once, e.g. everything in a tab."""
        hosts, body = await _bulk_hosts(req)
        try:
            minutes = int(body.get("minutes") if body.get("minutes") is not None else monitor.opts["maintenance_minutes"])
        except (TypeError, ValueError):
            raise web.HTTPBadRequest(text="minutes must be a whole number")
        if not 1 <= minutes <= 1440:
            raise web.HTTPBadRequest(text="minutes must be between 1 and 1440")
        for h in hosts:
            await monitor.start_maintenance(h, minutes)
        log.info("Paused %d computer(s) together for %d min", len(hosts), minutes)
        return web.json_response({"paused": [h.key for h in hosts]})

    async def resume_bulk(req):
        hosts, _ = await _bulk_hosts(req)
        done = [h for h in hosts if h.maint_until]
        for h in done:
            await monitor.resume(h)
        return web.json_response({"resumed": [h.key for h in done]})

    async def resume(req):
        h = monitor.hosts.get(req.match_info["key"])
        if not h:
            raise web.HTTPNotFound()
        await monitor.resume(h)
        return web.json_response({"resumed": h.key})

    async def presets(_req):
        return web.json_response({
            "presets": [{"name": n, "title": t, "group": g, "summary": preset_summary(n)}
                        for n, t, g in PRESET_INFO],
            "aliases": ALIASES,
        })

    async def read_entry(req) -> dict:
        try:
            body = await req.json()
        except (json.JSONDecodeError, ValueError):
            raise web.HTTPBadRequest(text=json.dumps({"error": "Invalid JSON"}),
                                     content_type="application/json")
        try:
            return validate_entry(body)
        except ValueError as err:
            raise web.HTTPBadRequest(text=json.dumps({"error": str(err)}),
                                     content_type="application/json")

    def check_v3(entry: dict, h: Host | None) -> None:
        """SNMP v3 passwords: needed when adding; left blank when editing keeps the saved ones."""
        if entry.get("snmp_version") != "3":
            return
        v, old = entry["snmp_v3"], (h.snmp_v3 if h else {})
        for proto, pw, what in (("auth", "auth_pass", "authentication"), ("priv", "priv_pass", "privacy")):
            if v.get(proto) and not v.get(pw) and not old.get(pw):
                raise web.HTTPBadRequest(text=json.dumps({"error": f"Enter the SNMP v3 {what} password"}),
                                         content_type="application/json")

    async def add_host(req):
        entry = await read_entry(req)
        check_v3(entry, None)
        h = await monitor.add_host(entry)
        return web.json_response({"added": h.key}, status=201)

    async def update_host(req):
        h = monitor.hosts.get(req.match_info["key"])
        if not h:
            raise web.HTTPNotFound()
        entry = await read_entry(req)
        check_v3(entry, h)
        await monitor.update_host(h, entry)
        return web.json_response({"updated": h.key})

    async def host_snmp(req):
        h = monitor.hosts.get(req.match_info["key"])
        if not h:
            raise web.HTTPNotFound()
        svc = next((s for s in h.services if s.kind == "snmp"), None)
        return web.json_response({"name": h.name, "ip": h.ip, "host": h.host, "polled": h.snmp_polled,
                                  "data": h.snmp_data, "items": h.snmp_items, "watch": h.snmp_watch,
                                  "status": svc.status if svc else None, "detail": svc.detail if svc else None})

    async def host_snmp_watch(req):
        h = monitor.hosts.get(req.match_info["key"])
        if not h:
            raise web.HTTPNotFound()
        body = await req.json()
        try:
            idx = int(body.get("index"))
        except (TypeError, ValueError):
            raise web.HTTPBadRequest(text="index must be a port number")
        watch = set(h.snmp_watch)
        (watch.add if body.get("watch") else watch.discard)(idx)
        h.snmp_watch = sorted(watch)
        monitor._save_hosts()
        log.info("%s: port %s %s", h.name, idx, "watched" if body.get("watch") else "no longer watched")
        if h.snmp_data:  # re-evaluate straight away
            svc = next((s for s in h.services if s.kind == "snmp"), None)
            worst, items = snmplib.evaluate(h.snmp_data, watch, None)
            h.snmp_items = items
            if svc and svc.status != UNKNOWN:
                h.next_due = 0
        return web.json_response({"watch": h.snmp_watch})

    async def host_syslog(req):
        h = monitor.hosts.get(req.match_info["key"])
        if not h:
            raise web.HTTPNotFound()
        try:
            max_sev = max(0, min(7, int(req.query.get("sev", "7"))))
            limit = max(1, min(2000, int(req.query.get("limit", "300"))))
        except ValueError:
            raise web.HTTPBadRequest(text="bad filter")
        now = time.time()
        rows = monitor.logs.query(h.key, 0, max_sev, (req.query.get("q") or "").strip()[:100], limit)
        since = max(now - DAY, h.syslog_ack)
        for r in rows:
            r["alert"] = sysloglib.alert_level(r, h.syslog_alert, h.syslog_keywords, h.syslog_ignore) if r["ts"] >= since else None
            r["acked"] = bool(h.syslog_ack and r["ts"] < h.syslog_ack and r["ts"] >= now - DAY and
                              sysloglib.alert_level(r, h.syslog_alert, h.syslog_keywords, h.syslog_ignore))
        n, last = monitor.logs.stats(h.key, now - DAY)
        svc = next((s for s in h.services if s.kind == "syslog"), None)
        pending = sum(1 for r in monitor.logs.query(h.key, since=since, max_sev=7, limit=5000)
                      if sysloglib.alert_level(r, h.syslog_alert, h.syslog_keywords, h.syslog_ignore))
        return web.json_response({"name": h.name, "pending": pending, "ip": h.ip, "host": h.host, "rows": rows, "count_24h": n, "last": last,
                                  "alert": h.syslog_alert, "keywords": h.syslog_keywords, "ignore": h.syslog_ignore,
                                  "ack": h.syslog_ack, "status": svc.status if svc else None,
                                  "detail": svc.detail if svc else None, "port": monitor.syslog_port, "now": now})

    async def host_syslog_ack(req):
        h = monitor.hosts.get(req.match_info["key"])
        if not h:
            raise web.HTTPNotFound()
        h.syslog_ack = time.time()
        monitor._save_hosts()
        log.info("%s: syslog alerts acknowledged", h.name)
        h.next_due = 0
        return web.json_response({"ack": h.syslog_ack})

    async def syslog_forget(req):
        body = await req.json()
        monitor.syslog_unknown.pop(str(body.get("ip")), None)
        return web.json_response({"ok": True})

    def icons_list() -> list[dict]:
        if not ICONS_DIR.exists():
            return []
        meta = {}
        try:
            meta = json.loads((ICONS_DIR / "names.json").read_text())
        except (OSError, ValueError):
            pass
        return [{"id": "u:" + f.name, "name": meta.get(f.name) or f.stem, "url": "icons/" + f.name}
                for f in sorted(ICONS_DIR.iterdir(), key=lambda f: f.stat().st_mtime) if ICON_FILE.match(f.name)]

    async def icons_get(req):
        return web.json_response({"icons": icons_list()})

    async def icon_upload(req):
        """Body: the image itself. Header X-Icon-Name: a label for it."""
        ext = {"image/png": "png", "image/jpeg": "jpg", "image/webp": "webp", "image/svg+xml": "svg"}.get(
            (req.content_type or "").lower())
        if not ext:
            return web.json_response({"error": "Use a PNG, JPEG, WebP or SVG image"}, status=400)
        data = await req.read()
        if not data or len(data) > 300 * 1024:
            return web.json_response({"error": "Images must be under 300 KB"}, status=400)
        magic = {"png": data[:8] == b"\x89PNG\r\n\x1a\n", "jpg": data[:3] == b"\xff\xd8\xff",
                 "webp": data[:4] == b"RIFF" and data[8:12] == b"WEBP",
                 "svg": b"<svg" in data[:2048].lower()}
        if not magic[ext]:
            return web.json_response({"error": "That file isn't the image type it says it is"}, status=400)
        if len(icons_list()) >= 200:
            return web.json_response({"error": "Up to 200 uploaded icons; delete some first"}, status=400)
        ICONS_DIR.mkdir(parents=True, exist_ok=True)
        fname = secrets.token_hex(6) + "." + ext
        (ICONS_DIR / fname).write_bytes(data)
        label = re.sub(r"[^\w .()+-]", "", (req.headers.get("X-Icon-Name") or "").strip())[:40] or "Uploaded"
        try:
            meta = json.loads((ICONS_DIR / "names.json").read_text())
        except (OSError, ValueError):
            meta = {}
        meta[fname] = label
        (ICONS_DIR / "names.json").write_text(json.dumps(meta))
        log.info("Uploaded icon %s (%s)", label, fname)
        return web.json_response({"id": "u:" + fname, "name": label, "url": "icons/" + fname}, status=201)

    async def icon_delete(req):
        fname = req.match_info["file"]
        if not ICON_FILE.match(fname):
            raise web.HTTPNotFound()
        (ICONS_DIR / fname).unlink(missing_ok=True)
        changed = False
        for h in list(monitor.hosts.values()):
            if h.icon == "u:" + fname:
                h.icon, changed = "", True
        if changed:
            monitor._save_hosts()
        return web.json_response({"ok": True})

    async def icon_file(req):
        fname = req.match_info["file"]
        path = ICONS_DIR / fname
        if not ICON_FILE.match(fname) or not path.exists():
            raise web.HTTPNotFound()
        # SVGs can carry script: shown through <img> it never runs, and this blocks it if opened directly.
        return web.Response(body=path.read_bytes(), content_type=ICON_TYPES[fname.rsplit(".", 1)[1]], headers={
            "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; img-src data:; sandbox",
            "X-Content-Type-Options": "nosniff", "Cache-Control": "private, max-age=86400"})

    async def delete_host(req):
        h = monitor.hosts.get(req.match_info["key"])
        if not h:
            raise web.HTTPNotFound()
        await monitor.delete_host(h)
        return web.json_response({"deleted": h.key})

    @web.middleware
    async def no_store(req, handler):
        resp = await handler(req)
        if req.path.startswith("/api/") and "Cache-Control" not in resp.headers:
            resp.headers["Cache-Control"] = "no-store"
        return resp

    app = web.Application(middlewares=[no_store], client_max_size=512 * 1024 * 1024)  # imports
    app.router.add_get("/api/presets", presets)
    app.router.add_post("/api/hosts", editor_only(add_host))
    app.router.add_put("/api/hosts/{key}", editor_only(update_host))
    app.router.add_get("/api/hosts/{key}/snmp", host_snmp)
    app.router.add_get("/api/icons", icons_get)
    app.router.add_post("/api/icons", editor_only(icon_upload))
    app.router.add_delete("/api/icons/{file}", editor_only(icon_delete))
    app.router.add_get("/icons/{file}", icon_file)
    app.router.add_get("/api/hosts/{key}/syslog", host_syslog)
    app.router.add_post("/api/hosts/{key}/syslog/ack", editor_only(host_syslog_ack))
    app.router.add_post("/api/syslog/forget", editor_only(syslog_forget))
    app.router.add_post("/api/hosts/{key}/snmp/watch", editor_only(host_snmp_watch))
    app.router.add_delete("/api/hosts/{key}", editor_only(delete_host))
    app.router.add_get("/", index)
    app.router.add_get("/api/status", status)
    app.router.add_get("/api/views", views_get)
    app.router.add_get("/api/export", editor_only(export_data))
    app.router.add_post("/api/import", editor_only(import_data))
    app.router.add_post("/api/import/chunk", editor_only(import_chunk))
    app.router.add_get("/api/ha/entities", editor_only(ha_entities))
    app.router.add_put("/api/views", editor_only(views_put))
    app.router.add_post("/api/check/{key}", check_now)  # harmless, so open to all viewers
    app.router.add_post("/api/reset", editor_only(reset))
    app.router.add_post("/api/reset/{key}", editor_only(reset))
    app.router.add_post("/api/maintenance-bulk", editor_only(maintenance_bulk))
    app.router.add_post("/api/resume-bulk", editor_only(resume_bulk))
    app.router.add_post("/api/maintenance/{key}", editor_only(maintenance))
    app.router.add_post("/api/resume/{key}", editor_only(resume))
    app.router.add_get("/api/hosts/{key}/details", host_details)
    app.router.add_post("/api/hosts/{key}/agent/ignore", editor_only(agent_ignore))
    app.router.add_post("/api/hosts/{key}/agent/disk", editor_only(agent_disk))
    app.router.add_post("/api/hosts/{key}/agent/ack", editor_only(agent_ack))
    app.router.add_get("/api/agents", editor_only(agents_list))
    app.router.add_post("/api/agents/approve-all", editor_only(agents_approve_all))
    app.router.add_post("/api/agents/approve/{pid}", editor_only(agents_approve))
    app.router.add_post("/api/agents/reject/{pid}", editor_only(agents_reject))
    app.router.add_delete("/api/agents/{aid}", editor_only(agents_revoke))
    app.router.add_post("/api/agents/rotate-key", editor_only(agents_rotate))
    app.router.add_get("/api/agents/script", editor_only(agents_script))
    app.router.add_post("/api/agents/auto-update", editor_only(agents_auto_update))
    app.router.add_post("/api/agents/{aid}/update-now", editor_only(agents_update_now))
    return app


# --------------------------------------------------------------------------
# Dashboard tabs ("views"): saved filters shared by everyone who opens the panel
# --------------------------------------------------------------------------
VIEW_FIELDS = {
    "name": {"begins", "contains", "ends", "is", "not", "notcontains", "regex"},
    "address": {"begins", "contains", "ends", "is", "not", "notcontains", "regex"},
    "ip": {"in", "notin"},
    "os": {"is", "not"},
    "status": {"is", "not"},
    "role": {"contains", "notcontains"},
    "check": {"contains", "notcontains"},
    "uptime": {"below", "above"},
    "hardware": {"is", "not"},
}
VIEW_HARDWARE = {"physical", "virtual", "hyperv", "vmware", "kvm", "container", "unknown"}
VIEW_OS = {"windows", "linux", "none"}
VIEW_STATUS = {"green", "amber", "red", "degraded", "maintenance", "unknown", "problem", "offschedule"}
IP_RANGE_RE = re.compile(r"^(\d{1,3}(\.\d{1,3}){3}(/\d{1,2}|-\d{1,3}(\.\d{1,3}){3}|-\d{1,3})?|\d{1,3}(\.(\d{1,3}|\*)){1,3})$")


def clean_views(raw) -> list[dict]:
    """Validate the tab list sent by the dashboard."""
    if not isinstance(raw, list) or len(raw) > 50:
        raise ValueError("expected a list of up to 50 tabs")
    out, ids = [], set()
    for v in raw:
        if not isinstance(v, dict):
            raise ValueError("invalid tab")
        name = str(v.get("name") or "").strip()
        if not name or len(name) > 40:
            raise ValueError("each tab needs a name of up to 40 characters")
        vid = str(v.get("id") or "").strip() or secrets.token_hex(4)
        if not re.match(r"^[a-z0-9]{1,16}$", vid) or vid in ids:
            vid = secrets.token_hex(4)
        ids.add(vid)
        rules = v.get("rules") or []
        if not isinstance(rules, list) or len(rules) > 20:
            raise ValueError(f"'{name}': up to 20 conditions")
        clean = []
        for r in rules:
            if not isinstance(r, dict):
                raise ValueError(f"'{name}': invalid condition")
            field, op = str(r.get("field") or ""), str(r.get("op") or "")
            value = str(r.get("value") if r.get("value") is not None else "").strip()
            if field not in VIEW_FIELDS or op not in VIEW_FIELDS[field]:
                raise ValueError(f"'{name}': unknown condition {field} {op}")
            if not value or len(value) > 200:
                raise ValueError(f"'{name}': every condition needs a value")
            if field == "ip":
                for part in re.split(r"[,\s]+", value):
                    if part and not IP_RANGE_RE.match(part):
                        raise ValueError(f"'{name}': '{part}' isn't an IP range (use 10.0.1.0/24, 10.0.1.10-50 or 10.0.1.*)")
            if field == "os" and value not in VIEW_OS:
                raise ValueError(f"'{name}': unknown OS '{value}'")
            if field == "hardware" and value not in VIEW_HARDWARE:
                raise ValueError(f"'{name}': unknown hardware type '{value}'")
            if field == "status" and value not in VIEW_STATUS:
                raise ValueError(f"'{name}': unknown status '{value}'")
            if field == "uptime":
                try:
                    if not 0 <= float(value) <= 100:
                        raise ValueError
                except ValueError:
                    raise ValueError(f"'{name}': uptime must be a percentage")
            if op == "regex":
                try:
                    re.compile(value)
                except re.error:
                    raise ValueError(f"'{name}': '{value}' isn't a valid pattern")
            clean.append({"field": field, "op": op, "value": value})
        out.append({"id": vid, "name": name, "match": "any" if v.get("match") == "any" else "all", "rules": clean})
    return out


def load_views() -> list[dict]:
    try:
        return clean_views(json.loads(VIEWS_PATH.read_text()))
    except FileNotFoundError:
        return []
    except Exception as err:  # noqa: BLE001
        log.error("Could not read %s: %s", VIEWS_PATH, err)
        return []


def save_views(views: list[dict]) -> None:
    tmp = VIEWS_PATH.with_suffix(".tmp")
    tmp.write_text(json.dumps(views, indent=2))
    tmp.replace(VIEWS_PATH)


# --------------------------------------------------------------------------
# Export / import: everything the add-on has learnt, to move it to a new install
# --------------------------------------------------------------------------
BACKUP_FORMAT = "ping_monitor_backup"
RESTORE_DIR = DB_PATH.parent / "restore_pending"
REPORT_NAME = re.compile(r"^agent_reports/[0-9a-f]{6,32}\.json$")


def backup_files() -> dict[str, Path]:
    return {"hosts.json": HOSTS_PATH, "maintenance.json": MAINT_PATH, "agents.json": AGENTS_PATH,
            "agent_settings.json": AGENT_SETTINGS, "views.json": VIEWS_PATH, "imported_options.json": IMPORT_MARK}


def make_backup(version: str | None) -> bytes:
    """A zip of the host list, tabs, agent enrolments and settings, last reports and check history."""
    buf = io.BytesIO()
    counts = {}
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, path in backup_files().items():
            if path.exists():
                z.write(path, name)
        for f in sorted(AGENT_REPORTS.glob("*.json")) if AGENT_REPORTS.exists() else []:
            if re.match(r"^[0-9a-f]{6,32}\.json$", f.name):
                z.write(f, "agent_reports/" + f.name)
        for f in sorted(ICONS_DIR.iterdir()) if ICONS_DIR.exists() else []:
            if ICON_FILE.match(f.name):
                z.write(f, "icons/" + f.name)
        with tempfile.TemporaryDirectory() as tmp:
            # sqlite's backup API gives a consistent copy while the monitor keeps writing.
            snap = Path(tmp) / "history.db"
            src, dst = sqlite3.connect(DB_PATH), sqlite3.connect(snap)
            try:
                src.backup(dst)
                counts["history_rows"] = dst.execute("SELECT COUNT(*) FROM checks").fetchone()[0]
            finally:
                src.close()
                dst.close()
            z.write(snap, "history.db")
        try:
            raw = json.loads(OPTIONS_PATH.read_text())
            raw.pop("hosts", None)
            z.writestr("options.json", json.dumps(raw, indent=2))
        except (OSError, ValueError):
            pass
        try:
            counts["hosts"] = len(json.loads(HOSTS_PATH.read_text()))
            counts["agents"] = len(json.loads(AGENTS_PATH.read_text()).get("agents") or {})
        except (OSError, ValueError, AttributeError):
            pass
        z.writestr("manifest.json", json.dumps({"format": BACKUP_FORMAT, "version": 1, "addon_version": version,
                                                "created": time.time(), **counts}, indent=2))
    return buf.getvalue()


def stage_restore(data: bytes) -> dict:
    """Check an export and unpack it to be applied at the next start. Returns its manifest."""
    try:
        z = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        raise ValueError("That isn't an export file from this add-on (not a zip)")
    with z:
        names = z.namelist()
        try:
            manifest = json.loads(z.read("manifest.json"))
        except (KeyError, ValueError):
            raise ValueError("That isn't an export file from this add-on (no manifest)")
        if manifest.get("format") != BACKUP_FORMAT:
            raise ValueError("That isn't an export file from this add-on")
        allowed = set(backup_files()) | {"manifest.json", "history.db", "options.json"}
        for n in names:
            if n not in allowed and not REPORT_NAME.match(n) and not (n.startswith("icons/") and ICON_FILE.match(n[6:])):
                raise ValueError(f"Unexpected file in the export: {n}")
        if sum(i.file_size for i in z.infolist()) > 1024 ** 3:
            raise ValueError("The export is too large")
        for n in names:
            if n.endswith(".json"):
                try:
                    json.loads(z.read(n))
                except ValueError:
                    raise ValueError(f"{n} in the export is damaged")
        if "agents.json" in names and not json.loads(z.read("agents.json")).get("enrol_key"):
            raise ValueError("agents.json in the export is damaged")
        shutil.rmtree(RESTORE_DIR, ignore_errors=True)
        RESTORE_DIR.mkdir(parents=True)
        for n in names:
            target = RESTORE_DIR / n
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(z.read(n))
    if (RESTORE_DIR / "history.db").exists():
        try:
            con = sqlite3.connect(RESTORE_DIR / "history.db")
            ok = con.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
            con.execute("SELECT COUNT(*) FROM checks").fetchone()
            con.close()
        except sqlite3.Error:
            ok = False
        if not ok:
            shutil.rmtree(RESTORE_DIR, ignore_errors=True)
            raise ValueError("The history in the export is damaged")
    (RESTORE_DIR / "ready").write_text(str(time.time()))
    return manifest


def apply_pending_restore() -> None:
    """At start-up, before anything is loaded: swap in an imported export.

    The data it replaces is kept in before_import_<time>/ in the data folder."""
    if not (RESTORE_DIR / "ready").exists():
        return
    keep = DB_PATH.parent / time.strftime("before_import_%Y%m%d_%H%M%S")
    keep.mkdir(parents=True, exist_ok=True)
    targets = {**backup_files(), "history.db": DB_PATH}
    for name, path in targets.items():
        if path.exists():
            shutil.move(str(path), keep / name)
        for extra in ("-wal", "-shm", "-journal"):
            side = Path(str(path) + extra)
            if side.exists():
                side.unlink()
        staged = RESTORE_DIR / name
        if staged.exists():
            shutil.move(str(staged), path)
    if AGENT_REPORTS.exists():
        shutil.move(str(AGENT_REPORTS), keep / "agent_reports")
    if (RESTORE_DIR / "agent_reports").exists():
        shutil.move(str(RESTORE_DIR / "agent_reports"), AGENT_REPORTS)
    if (RESTORE_DIR / "icons").exists():
        if ICONS_DIR.exists():
            shutil.move(str(ICONS_DIR), keep / "icons")
        shutil.move(str(RESTORE_DIR / "icons"), ICONS_DIR)
    shutil.rmtree(RESTORE_DIR, ignore_errors=True)
    print(f"Imported an export; the previous data is kept in {keep}", flush=True)


SERVER_RE = re.compile(r"^https?://[A-Za-z0-9.\-\[\]:]+$")


def build_agent_script(os_name: str, server: str, enrol_key: str, ignore_cert: bool) -> bytes:
    """The agent script with this add-on's address and enrolment key built in."""
    if os_name == "linux":
        text = LINUX_AGENT_SCRIPT.read_text(encoding="utf-8")
        text = text.replace('SERVER = "__PM_SERVER__"', f'SERVER = "{server}"', 1)
        text = text.replace('ENROL_KEY = "__PM_ENROL_KEY__"', f'ENROL_KEY = "{enrol_key}"', 1)
        if ignore_cert:
            text = text.replace("IGNORE_CERT = False", "IGNORE_CERT = True", 1)
        return text.encode("utf-8")
    text = AGENT_SCRIPT.read_text(encoding="utf-8")
    text = text.replace("[string]$Server = '__PM_SERVER__'", f"[string]$Server = '{server}'", 1)
    text = text.replace("[string]$EnrolKey = '__PM_ENROL_KEY__'", f"[string]$EnrolKey = '{enrol_key}'", 1)
    if ignore_cert:
        text = text.replace("[switch]$IgnoreCertificate,", "[switch]$IgnoreCertificate = $true,", 1)
    # Windows PowerShell 5.1 reads BOM-less scripts as ANSI; add a BOM so it's read as UTF-8.
    return b"\xef\xbb\xbf" + text.replace("\r\n", "\n").replace("\n", "\r\n").encode("utf-8")


def _vt(v) -> tuple:
    return tuple(int(x) for x in re.findall(r"\d+", str(v or ""))[:3])


def _linux_script_version() -> str | None:
    try:
        m = re.search(r'^AGENT_VERSION = "([^"]+)"', LINUX_AGENT_SCRIPT.read_text(encoding="utf-8"), re.M)
        return m.group(1) if m else None
    except OSError:
        return None


def _script_version() -> str | None:
    try:
        m = re.search(r"\$AgentVersion = '([^']+)'", AGENT_SCRIPT.read_text(encoding="utf-8"))
        return m.group(1) if m else None
    except OSError:
        return None


def build_agent_app(monitor: Monitor) -> web.Application:
    """The small API the agents talk to, on its own LAN port.

    Only enrol and report live here; the dashboard stays behind HA ingress.
    """
    store = monitor.agents

    async def read_json(req) -> dict:
        try:
            body = await req.json()
        except (json.JSONDecodeError, ValueError):
            raise web.HTTPBadRequest(text="invalid JSON")
        if not isinstance(body, dict):
            raise web.HTTPBadRequest(text="expected an object")
        return body

    async def enrol(req):
        body = await read_json(req)
        if not store.check_key(body.get("enrol_key")):
            log.warning("Agent enrolment from %s refused: wrong enrolment key", req.remote)
            return web.json_response({"error": "wrong enrolment key"}, status=403)
        token = str(body.get("token") or "")
        if not agentlib.TOKEN_RE.match(token):
            raise web.HTTPBadRequest(text="invalid token")
        try:
            info = clean_enrol_info(body)
        except ValueError as err:
            raise web.HTTPBadRequest(text=str(err))
        state, rec = store.request(info, token, req.remote)
        if state == "approved":
            return web.json_response({"status": "approved"})
        if state == "rejected":
            return web.json_response({"status": "rejected"}, status=410)
        if state == "new":
            await monitor.agent_pending_notice(rec)
        return web.json_response({"status": "pending"}, status=202)

    async def report(req):
        auth = req.headers.get("Authorization", "")
        token = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
        state, agent = store.lookup(token)
        if state == "pending":
            return web.json_response({"status": "pending"}, status=202)
        if state != "approved":
            return web.json_response({"error": "unknown agent"}, status=401)
        body = await read_json(req)
        try:
            await monitor.receive_report(agent, body, req.remote)
        except Exception as err:  # noqa: BLE001
            log.exception("Couldn't process the report from %s: %s", agent["hostname"], err)
            try:  # keep a copy to diagnose with
                (AGENT_REPORTS / f"failed-{agent['id']}.json").write_text(json.dumps(body, indent=1)[:2_000_000])
            except Exception:  # noqa: BLE001
                pass
            return web.json_response({"error": "report could not be processed"}, status=500)
        watch = [str(x) for x in monitor.opts.get("agent_watch_services") or [] if str(x).strip()]
        resp = {"ok": True, "watch_services": watch}
        offer = monitor.agent_update_offer(agent, body)
        if offer:
            resp["agent_update"] = offer
        return web.json_response(resp)

    async def update(req):
        """A newer agent for an approved agent that has been offered one, signed with an
        HMAC of the agent's own token so it can check nothing changed it on the way."""
        auth = req.headers.get("Authorization", "")
        token = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
        state, agent = store.lookup(token)
        if state != "approved":
            return web.json_response({"error": "unknown agent"}, status=401)
        os_name = "linux" if agent.get("os_family") == "linux" else "windows"
        if not monitor.agent_update_offer(agent, {"os_family": os_name, "agent_version": agent.get("agent_version")}):
            return web.json_response({"error": "no update offered"}, status=404)
        server = (req.query.get("server") or "").strip().rstrip("/")
        if not SERVER_RE.match(server):
            raise web.HTTPBadRequest(text="invalid server address")
        body = build_agent_script(os_name, server, store.enrol_key, req.query.get("ignore_cert") == "1")
        key = bytes.fromhex(agentlib.token_hash(token))
        sig = hmac.new(key, body, hashlib.sha256).hexdigest()
        log.info("Sending the %s agent update to %s", os_name.capitalize(), agent.get("hostname"))
        return web.Response(body=body, content_type="application/octet-stream", headers={"X-Rollcall-Signature": sig})

    async def ping_view(_req):
        return web.json_response({"ok": True, "service": "ping-monitor-agent-api"})

    app = web.Application(client_max_size=4 * 1024 * 1024)
    app.router.add_post("/agent/enrol", enrol)
    app.router.add_post("/agent/report", report)
    app.router.add_get("/agent/ping", ping_view)
    app.router.add_get("/agent/update", update)
    return app


def agent_ssl_context(opts: dict) -> ssl.SSLContext | None:
    if not opts.get("agent_ssl"):
        return None
    cert = SSL_DIR / str(opts.get("agent_certfile") or "fullchain.pem")
    key = SSL_DIR / str(opts.get("agent_keyfile") or "privkey.pem")
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.load_cert_chain(cert, key)
    return ctx


async def main() -> None:
    opts = load_options()
    logging.basicConfig(
        level=getattr(logging, str(opts["log_level"]).upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    logging.getLogger("aiohttp.access").setLevel(logging.WARNING)
    apply_pending_restore()
    store = Store(DB_PATH)
    async with ClientSession(timeout=ClientTimeout(total=15)) as session:
        ha = HomeAssistant(session)
        monitor = Monitor(opts, store, ha)
        if monitor.imported:
            await ha.clear_option_hosts()
        url = str(opts.get("notification_url") or "").strip()
        if not url:
            slug = await ha.addon_slug() or "local_ping_monitor"
            url = f"/{slug}"
        monitor.click_url = url if url.startswith(("/", "http://", "https://")) else "/" + url
        log.info("Phone notifications will open %s", monitor.click_url)
        await detect_ping_mode()
        log.info("Checking hosts by %s", "ping" if PING_MODE == "icmp" else "TCP (ping isn't permitted)")
        global TZ
        cfg = await ha.get_json("/config")
        try:
            TZ = ZoneInfo((cfg or {}).get("time_zone") or os.environ.get("TZ") or "UTC")
        except Exception as err:  # noqa: BLE001
            log.warning("Couldn't use Home Assistant's time zone (%s); schedules use UTC", err)
            TZ = ZoneInfo("UTC")
        log.info("Schedules use the %s time zone", TZ)
        await monitor.attach_agents(AgentStore(AGENTS_PATH, AGENT_REPORTS))
        access = Access(opts, ha)
        if access.enabled:
            log.info("Changes allowed for HA admins%s", f" and {', '.join(sorted(access.editors))}"
                     if access.editors else "")
        else:
            log.info("admin_only_changes is off: anyone who can open the panel can make changes")
        runner = web.AppRunner(build_app(monitor, access), access_log=None)
        await runner.setup()
        await web.TCPSite(runner, "0.0.0.0", PORT).start()
        log.info("Dashboard listening on port %d", PORT)
        try:
            ctx = agent_ssl_context(opts)
            agent_runner = web.AppRunner(build_agent_app(monitor), access_log=None)
            await agent_runner.setup()
            await web.TCPSite(agent_runner, "0.0.0.0", AGENT_PORT, ssl_context=ctx).start()
            log.info("Agent API listening on port %d (%s)", AGENT_PORT, "HTTPS" if ctx else "HTTP")
        except Exception as err:  # noqa: BLE001
            log.error("Windows agent API could not start on port %d: %s", AGENT_PORT, err)
        try:
            loop = asyncio.get_running_loop()
            await loop.create_datagram_endpoint(lambda: sysloglib.Receiver(monitor.on_syslog), local_addr=("0.0.0.0", SYSLOG_PORT))
            net = await ha.addon_network()
            monitor.syslog_port = net.get(f"{SYSLOG_PORT}/udp") if net else None
            if net and not monitor.syslog_port:
                log.info("Syslog: receiver ready, but its port isn't mapped (add-on Configuration > Network)")
            else:
                log.info("Syslog: listening on UDP port %s", monitor.syslog_port or SYSLOG_PORT)

            async def flusher():
                while True:
                    await asyncio.sleep(1)
                    try:
                        monitor.logs.flush()
                    except Exception as err:  # noqa: BLE001
                        log.warning("Syslog: couldn't save messages: %s", err)
            monitor._syslog_flusher = asyncio.create_task(flusher())
        except Exception as err:  # noqa: BLE001
            log.error("Syslog receiver could not start on UDP port %d: %s", SYSLOG_PORT, err)
        await monitor.run()


if __name__ == "__main__":
    asyncio.run(main())
