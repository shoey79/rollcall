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
import base64
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
import updatesign
import messages as msglib
import agenttls
import wingetidx
import snmp as snmplib
import syslogrx as sysloglib
import metrics as metricslib
import emailer as emaillib
from html import escape as html_escape
import certcheck
import sipcheck
import syslogreadings
import watchdog as watchdoglib
import addonlog
import discovery
import hadevice
import ilo as ilolib
import iprange
import jellyfin as jflib
import plex as pxlib
import starlink as sllib
import dbhealth as dblib
import hints as hintlib
import vulns as vulnlib
import msi as msilib
import settingslib
from agents import AgentStore, clean_enrol_info, evaluate

OPTIONS_PATH = Path(os.environ.get("PM_OPTIONS", "/data/options.json"))
DB_PATH = Path(os.environ.get("PM_DB", "/data/ping_monitor.db"))
WEB_DIR = Path(__file__).parent / "web"
PORT = int(os.environ.get("PM_PORT", "8099"))
SUPERVISOR_TOKEN = os.environ.get("SUPERVISOR_TOKEN")
LOG_BUFFER = addonlog.Buffer()
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
DISCOVERY_PATH = Path(os.environ.get("PM_DISCOVERY", str(DB_PATH.parent / "discovery.json")))  # the last network scan
ICONS_DIR = Path(os.environ.get("PM_ICONS", str(DB_PATH.parent / "icons")))  # uploaded device pictures
ICON_TYPES = {"png": "image/png", "jpg": "image/jpeg", "webp": "image/webp", "svg": "image/svg+xml"}
ICON_FILE = re.compile(r"^[a-z0-9]{12}\.(png|jpg|webp|svg)$")
ICON_REF = re.compile(r"^(b:[a-z0-9-]{1,24}|u:[a-z0-9]{12}\.(png|jpg|webp|svg))$")
AGENT_PORT = int(os.environ.get("PM_AGENT_PORT", "8100"))
AGENT_HTTPS_PORT = int(os.environ.get("PM_AGENT_HTTPS_PORT", "8101"))  # built-in HTTPS for agents (agenttls.py)
AGENT_FRESH = int(os.environ.get("PM_AGENT_FRESH", "600"))  # a report this recent counts as "up" (two agent runs)
SYSLOG_PORT = int(os.environ.get("PM_SYSLOG_PORT", "5140"))  # inside the container; the host maps 514/udp to it
SYSLOG_HELD = 200  # messages kept per sender that isn't matched to a device yet
AGENT_SCRIPT = Path(__file__).parent / "agent" / "PingMonitorAgent.ps1"
LINUX_AGENT_SCRIPT = Path(__file__).parent / "agent" / "pingmonitor-agent.py"
SH_AGENT_SCRIPT = Path(__file__).parent / "agent" / "rollcall-agent.sh"  # OpenWrt / BusyBox: no Python needed
WINGET_PATH = Path(os.environ.get("PM_WINGET", str(DB_PATH.parent / "winget-source2.msix")))  # the winget catalogue, refreshed daily
VULN_DIR = Path(os.environ.get("PM_VULNS", str(DB_PATH.parent / "vulns")))  # vulnerability data, refreshed daily
SOFTWARE_DIR = Path(os.environ.get("PM_SOFTWARE", str(DB_PATH.parent / "software")))  # each agent's installed software
SECRETS_DIR = Path(os.environ.get("PM_SECRETS", str(DB_PATH.parent / "secrets")))  # where each agent found passwords (never the passwords)
VIEWS_PATH = Path(os.environ.get("PM_VIEWS", str(DB_PATH.parent / "views.json")))
CLAUDE_HINTS_PATH = Path(os.environ.get("PM_CLAUDE_HINTS", str(DB_PATH.parent / "claude_hints.json")))  # hints from Claude: cache and today's count
DB_HEALTH_PATH = Path(os.environ.get("PM_DB_HEALTH", str(DB_PATH.parent / "db_health.json")))  # the last database check
MESSAGES_PATH = Path(os.environ.get("PM_MESSAGES", str(DB_PATH.parent / "messages.json")))  # messages to screens
AGENT_TLS = agenttls.AgentTLS(Path(os.environ.get("PM_AGENT_TLS", str(DB_PATH.parent / "agent_tls"))))
AGENT_SETTINGS = Path(os.environ.get("PM_AGENT_SETTINGS", str(DB_PATH.parent / "agent_settings.json")))
# Rollcall's own key for signing agent updates and the addresses agents report to (private: never leaves it)
UPDATE_KEY_PATH = Path(os.environ.get("PM_UPDATE_KEY", str(DB_PATH.parent / "update_key.pem")))
SIGNER = updatesign.SigningKey(UPDATE_KEY_PATH)
SSL_DIR = Path(os.environ.get("PM_SSL_DIR", "/ssl"))
DAY = 86400
SECURITY_HIDDEN = "Security details are visible to Home Assistant admins"
SECURITY_KEYS = ("agent_security", "agent_domain", "agent_secrets", "agent_integrity", "agent_vulns")
UPS_LIMIT_KEYS = {"runtime_warn": (0, 600), "runtime_crit": (0, 600), "load_warn": (1, 100)}


def clean_ups_limits(raw, strict: bool = False) -> dict:
    """A UPS's own limits: whole minutes (0 turns that level off) and a load %. Bad values are
    dropped when loading, or refused when strict (from the dashboard)."""
    out = {}
    for k, v in (raw or {}).items() if isinstance(raw, dict) else []:
        if k not in UPS_LIMIT_KEYS:
            continue
        lo, hi = UPS_LIMIT_KEYS[k]
        try:
            n = int(float(v))
            if not lo <= n <= hi or float(v) != n:
                raise ValueError
        except (TypeError, ValueError):
            if strict:
                raise ValueError(f"{'load' if k == 'load_warn' else 'runtime'} must be a whole number from {lo} to {hi}") from None
            continue
        out[k] = n
    return out


SUBTITLES = ("", "auto", "model", "os", "address", "user", "none")  # "" = the add-on's name_line default  # checks whose detail names accounts
BUCKETS = 48  # 24h strip on the dashboard, 30 min per bucket

log = logging.getLogger("ping_monitor")

DEFAULTS = {
    "interval": 300,
    "retry_interval": 300,
    "ping_count": 3,
    "ping_timeout": 2,
    "service_timeout": 5,
    "history_days": 7,
    "metrics_days": 365,
    "notify_services": [],
    "persistent_notification": True,
    "notify_recovery": True,
    "log_level": "info",
    "maintenance_minutes": 30,
    "notification_url": "",
    "email_send": "off",
    "email_to": [],
    "email_from": "",
    "email_red": True,
    "email_recovery": True,
    "email_warnings": False,
    "email_digest": True,
    "email_digest_time": "08:00",
    **{f"email_about_{c}": True for c in emaillib.CATEGORIES},
    "smtp_host": "",
    "smtp_port": 25,
    "smtp_security": "starttls",
    "smtp_check_certificate": True,
    "smtp_username": "",
    "smtp_password": "",
    "m365_tenant_id": "",
    "m365_client_id": "",
    "m365_client_secret": "",
    "admin_only_changes": True,
    "editors": [],
    "cert_warn_days": 30,
    "cert_crit_days": 7,
    "ups_runtime_warn_minutes": 15,
    "ups_runtime_crit_minutes": 5,
    "ups_load_warn": 80,
    "agent_stale_minutes": 15,
    "agent_slow_seconds": 120,
    "agent_disk_warn": 15,
    "agent_disk_crit": 5,
    "agent_memory_warn": 90,
    "agent_memory_crit": 95,
    "agent_cpu_warn": 90,
    "agent_cpu_reports": 3,
    "messages": False,
    "agent_failed_logons": 20,
    "agent_laps_overdue_days": 3,
    "agent_bitlocker_require": "workstations",
    "agent_sql_backup_hours": 36,
    "printer_supply_warn": 10,
    "software_updates": True,
    "vuln_checks": True,
    "vuln_min_score": 9,
    "vuln_linux_source": "local",
    "agent_secret_scan": "off",
    "name_line": "auto",
    "ip_ranges": [],
    "agent_exchange_queue_warn": 250,
    "agent_time_warn_seconds": 60,
    "agent_time_crit_seconds": 240,
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
    "claude_hints": False,
    "claude_api_key": "",
    "claude_model": "claude-haiku-5-5",
    "claude_hints_per_day": 30,
    "ai_provider": "anthropic",
    "openai_api_key": "",
    "openai_model": "gpt-5.4-mini",
    "gemini_api_key": "",
    "gemini_model": "gemini-3.5-flash-lite",
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
    ("fileserver", "File server", _W, [("SMB", "tcp:445")]),
    ("rds", "Remote Desktop", _W, [("RDP", "tcp:3389")]),
    ("sql", "SQL Server", _W, [("SQL", "tcp:1433")]),
    ("iis", "IIS (HTTP)", _W, [("HTTP", "http:80/")]),
    ("iis-https", "IIS (HTTPS)", _W, [("HTTPS", "https:443/")]),
    ("sharepoint", "SharePoint", _W, [("SharePoint", "https:443/")]),
    ("exchange", "Exchange", _W, [("OWA", "https:443/owa"), ("SMTP", "tcp:25")]),
    ("wsus", "WSUS", _W, [("WSUS", "tcp:8530")]),
    ("adfs", "AD FS", _W, [("ADFS", "https:443/FederationMetadata/2007-06/FederationMetadata.xml")]),
    ("adcs", "Certificate Services", _W, [("CertSrv", "http:80/certsrv/")]),
    ("configmgr", "ConfigMgr management point", _W, [("MP", "http:80/sms_mp/.sms_aut?mplist")]),
    ("kms", "KMS", _W, [("KMS", "tcp:1688")]),
    ("winrm", "WinRM", _W, [("WinRM", "tcp:5985")]),
    ("veeam", "Veeam Backup & Replication", _W, [("Veeam", "tcp:9392")]),
    ("rdweb", "RD Web Access", _W, [("RD Web", "https:443/RDWeb/")]),
    ("rdgateway", "RD Gateway", _W, [("RD Gateway", "tcp:443")]),
    # Databases
    ("mysql", "MySQL / MariaDB", _DB, [("MySQL", "tcp:3306")]),
    ("postgres", "PostgreSQL", _DB, [("PostgreSQL", "tcp:5432")]),
    ("mongodb", "MongoDB", _DB, [("MongoDB", "tcp:27017")]),
    ("redis", "Redis", _DB, [("Redis", "tcp:6379")]),
    ("oracle", "Oracle", _DB, [("Oracle", "tcp:1521")]),
    ("elasticsearch", "Elasticsearch", _DB, [("Elasticsearch", "http:9200/")]),
    ("influxdb", "InfluxDB", _DB, [("InfluxDB", "http:8086/ping")]),
    # Mail & files
    ("smtp", "SMTP", _MAIL, [("SMTP", "tcp:25")]),
    ("imap", "IMAPS", _MAIL, [("IMAPS", "tcp:993")]),
    ("pop3", "POP3S", _MAIL, [("POP3S", "tcp:995")]),
    ("ftp", "FTP", _MAIL, [("FTP", "tcp:21")]),
    ("nextcloud", "Nextcloud", _MAIL, [("Nextcloud", "https:443/status.php")]),
    # Remote access
    ("ssh", "SSH / SFTP", _REM, [("SSH", "tcp:22")]),
    ("vnc", "VNC", _REM, [("VNC", "tcp:5900")]),
    ("telnet", "Telnet", _REM, [("Telnet", "tcp:23")]),
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
    ("unifi", "UniFi controller (8443)", _NET, [("UniFi", "https:8443/"), ("Inform", "tcp:8080")]),
    ("unifi-os", "UniFi OS console", _NET, [("UniFi", "https:443/")]),
    ("unifi-os-server", "UniFi OS Server", _NET, [("UniFi", "https:11443/"), ("Inform", "tcp:8080")]),
    ("idrac", "iDRAC / BMC", _NET, [("iDRAC", "https:443/")]),
    ("hpilo", "HPE iLO health", _NET, [("iLO", "ilo:device")]),
    ("pihole", "Pi-hole", _NET, [("DNS", "tcp:53"), ("Pi-hole", "http:80/admin/")]),
    ("adguard", "AdGuard Home", _NET, [("DNS", "tcp:53"), ("AdGuard", "http:80/")]),
    ("npm", "Nginx Proxy Manager", _NET, [("NPM", "http:81/")]),
    ("squid", "Web proxy", _NET, [("Proxy", "tcp:3128")]),
    ("printer", "Printer", _NET, [("Printer", "tcp:9100")]),
    ("omada", "TP-Link Omada controller", _NET, [("Omada", "https:8043/")]),
    ("mikrotik", "MikroTik (Winbox)", _NET, [("Winbox", "tcp:8291")]),
    ("openfire", "Openfire / XMPP chat", _NET, [("XMPP", "tcp:5222"), ("Openfire admin", "http:9090/")]),
    ("snmp", "SNMP", _NET, [("SNMP", "snmp:device")]),
    ("cert", "Certificate expiry", _NET, [("Cert 443", "cert:443")]),
    ("syslog", "Syslog", _NET, [("Syslog", "syslog:device")]),
    ("camera", "Camera / NVR", _NET, [("RTSP", "tcp:554")]),
    ("onvif", "ONVIF camera", _NET, [("RTSP", "tcp:554"), ("ONVIF", "tcp:2020")]),
    ("voip", "VoIP / SIP", _NET, [("SIP", "sip:5060")]),
    ("ata2", "Two-line ATA", _NET, [("Line 1", "sip:5060"), ("Line 2", "sip:5061")]),
    ("starlink", "Starlink dish", _NET, [("Starlink", "starlink:device")]),
    # Home & automation
    ("homeassistant", "Home Assistant", _HOME, [("Home Assistant", "http:8123/")]),
    ("nodered", "Node-RED", _HOME, [("Node-RED", "http:1880/")]),
    ("mqtt", "MQTT broker", _HOME, [("MQTT", "tcp:1883")]),
    ("frigate", "Frigate NVR", _HOME, [("Frigate", "http:5000/api/version")]),
    ("zigbee2mqtt", "Zigbee2MQTT", _HOME, [("Zigbee2MQTT", "http:8080/")]),
    ("zwavejs", "Z-Wave JS UI", _HOME, [("Z-Wave JS", "http:8091/")]),
    ("esphome", "ESPHome dashboard", _HOME, [("ESPHome", "http:6052/")]),
    ("hue", "Philips Hue bridge", _HOME, [("Hue", "http:80/api/config")]),
    ("shelly", "Shelly device", _HOME, [("Shelly", "http:80/shelly")]),
    ("neohub", "Heatmiser neoHub", _HOME, [("neoHub API", "tcp:4243")]),
    ("vaultwarden", "Vaultwarden", _HOME, [("Vaultwarden", "http:80/alive")]),
    ("paperless", "Paperless-ngx", _HOME, [("Paperless", "http:8000/")]),
    ("uptimekuma", "Uptime Kuma", _HOME, [("Uptime Kuma", "http:3001/")]),
    # Media
    ("plex", "Plex", _MEDIA, [("Plex", "http:32400/identity")]),
    ("jellyfin", "Jellyfin", _MEDIA, [("Jellyfin", "http:8096/health")]),
    ("jellyfin-api", "Jellyfin health (API key)", _MEDIA, [("Jellyfin", "jellyfin:device")]),
    ("plex-api", "Plex (token)", _MEDIA, [("Plex", "plex:device")]),
    ("emby", "Emby", _MEDIA, [("Emby", "http:8096/emby/System/Info/Public")]),
    ("immich", "Immich", _MEDIA, [("Immich", "http:2283/api/server/ping")]),
    ("audiobookshelf", "Audiobookshelf", _MEDIA, [("Audiobookshelf", "http:13378/")]),
    ("navidrome", "Navidrome", _MEDIA, [("Navidrome", "http:4533/")]),
    ("tautulli", "Tautulli", _MEDIA, [("Tautulli", "http:8181/")]),
    ("overseerr", "Overseerr / Jellyseerr", _MEDIA, [("Overseerr", "http:5055/api/v1/status")]),
    ("ombi", "Ombi", _MEDIA, [("Ombi", "http:5000/")]),
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
# A line of explanation, shown when hovering over a service in the form (and found by its search)
PRESET_NOTES = {
    "ombi": "Ombi media request site",
    "dc": "DNS, Kerberos, LDAP, SMB and Global Catalog", "rds": "Remote Desktop / Terminal Server",
    "adcs": "Certificate Services web enrolment (/certsrv)", "configmgr": "ConfigMgr / SCCM management point",
    "kms": "KMS activation", "winrm": "WinRM / PowerShell remoting",
    "rdweb": "Remote Desktop Web Access page (/RDWeb)", "rdgateway": "Remote Desktop Gateway (HTTPS 443)",
    "smtp": "SMTP relay or mail server", "imap": "IMAP over TLS", "pop3": "POP3 over TLS",
    "telnet": "Telnet (switches, old kit)", "unifi": "UniFi Network, old self-hosted controller",
    "unifi-os": "UniFi OS console, e.g. Cloud Key or UDM", "unifi-os-server": "UniFi OS Server, self-hosted",
    "idrac": "Dell iDRAC or another server management controller", "squid": "Squid or another web proxy",
    "hpilo": "HPE iLO 3 or iLO 4: drives, fans, temperatures and power supplies (needs an iLO login)",
    "jellyfin-api": "Version, pending restart, updates, failed scheduled tasks and active streams (needs a Jellyfin API key)",
    "plex-api": "Version, updates and what's playing, by whom (needs a Plex token)",
    "starlink": "Starlink dish: online, outages, obstructions, latency, drops, throughput and the dish's own alerts",
    "printer": "Network printer (raw printing on 9100)",
    "snmp": "Switch ports and PoE, NAS disks and RAID, UPS battery and power, printer supplies, Sophos firewall VPNs",
    "cert": "Warns before the HTTPS certificate on 443 expires",
    "syslog": "Keep this device's log messages and alert on errors",
    "camera": "IP camera or NVR (RTSP)", "onvif": "IP camera with RTSP and ONVIF, e.g. TP-Link Tapo",
    "voip": "VoIP phone, ATA or PBX (SIP on UDP 5060)", "ata2": "Two-line ATA, e.g. Cisco SPA112/122 (SIP lines 1 and 2)",
    "mqtt": "MQTT broker, e.g. Mosquitto", "fileserver": "File server (SMB)",
    "omada": "TP-Link Omada software controller", "mikrotik": "MikroTik router or switch (Winbox port)",
    "openfire": "Openfire or another XMPP chat server, and Openfire's admin console",
    "zigbee2mqtt": "Zigbee2MQTT web interface", "zwavejs": "Z-Wave JS UI web interface",
    "esphome": "ESPHome dashboard", "hue": "Philips Hue bridge", "shelly": "Shelly relay, plug or sensor",
    "neohub": "Heatmiser neoHub local API (secure WebSocket on 4243, always on)",
}
ALIASES = {
    "smb": "fileserver", "file": "fileserver", "rdp": "rds", "terminal": "rds",
    "domain": "dc", "mssql": "sql", "owa": "exchange",
    "tapo": "onvif", "heatmiser": "neohub", "neostat": "neohub", "zigbee": "zigbee2mqtt", "zwave": "zwavejs",
    "xmpp": "openfire", "jabber": "openfire", "winbox": "mikrotik", "rdgw": "rdgateway",
    "ilo": "idrac", "bmc": "idrac", "ipmi": "idrac",
    "jellyfin-health": "jellyfin-api", "jellyfinapi": "jellyfin-api", "plexapi": "plex-api", "plex-token": "plex-api",
    "ilo3": "hpilo", "ilo4": "hpilo", "hp-ilo": "hpilo", "hpe-ilo": "hpilo", "ilo-health": "hpilo",
    "mariadb": "mysql", "postgresql": "postgres", "pgsql": "postgres", "mongo": "mongodb",
    "elastic": "elasticsearch", "influx": "influxdb", "certsrv": "adcs", "sccm": "configmgr",
    "mecm": "configmgr", "sftp": "ssh", "pve": "proxmox", "vmware": "esxi", "dsm": "synology",
    "nvr": "camera", "rtsp": "camera", "ha": "homeassistant", "node-red": "nodered",
    "mosquitto": "mqtt", "bitwarden": "vaultwarden", "kuma": "uptimekuma",
    "jellyseerr": "overseerr", "forgejo": "gitea", "pi-hole": "pihole",
    "sip": "voip", "ata": "voip", "pbx": "voip", "phone": "voip", "asterisk": "voip", "freepbx": "voip", "3cx": "voip",
    "spa112": "ata2", "spa122": "ata2", "dishy": "starlink", "satellite": "starlink",
}


def preset_summary(name: str) -> str:
    """Short description of what a preset checks, e.g. 'TCP 1433' or 'DNS 53 · LDAP 389'."""
    checks = PRESETS[name]

    def short(spec: str) -> str:
        kind, _, rest = spec.partition(":")
        if spec == "snmp:device":
            return "SNMP polling"
        if spec == "syslog:device":
            return "log messages"
        if spec == "ilo:device":
            return "health, with an iLO login"
        if spec == "jellyfin:device":
            return "health and tasks, with an API key"
        if spec == "plex:device":
            return "what's playing, with a Plex token"
        if spec == "starlink:device":
            return "status, outages and alerts"
        if kind == "tcp":
            return f"TCP {rest}"
        if kind == "cert":
            return f"certificate on {rest}"
        if kind == "sip":
            return f"SIP {rest}"
        if kind in ("http", "https"):
            port, _, path = rest.partition("/")
            first = path.split("/")[0].split("?")[0]
            return f"{kind.upper()} {port}" + (f" /{first}" + ("…" if len(first) < len(path.rstrip("/")) else "") if first else "")
        return spec
    if len(checks) == 1:
        return short(checks[0][1])
    return " · ".join(f"{label} {short(spec).removeprefix('TCP ')}" for label, spec in checks)


_LABELLED = re.compile(r"^([^=:/]+)=(.+)$")
_TCP = re.compile(r"^tcp:(\d{1,5})$", re.I)
_ADDR = r"(?:[A-Za-z0-9](?:[A-Za-z0-9.\-]{0,251}[A-Za-z0-9])?|\[[0-9A-Fa-f:]+\])"
_PING = re.compile(rf"^ping:({_ADDR})$", re.I)             # another address of the same device
_CERT = re.compile(rf"^cert(?::({_ADDR}))?(?::(\d{{1,5}}))?$", re.I)  # certificate expiry: cert, cert:8443, cert:host:443
_SIP = re.compile(rf"^sip(?::({_ADDR}))?(?::(\d{{1,5}}))?$", re.I)  # SIP OPTIONS over UDP: sip, sip:5061, sip:host:5060
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


def clean_reading_setting(v) -> dict:
    """One reading's name and alert limits, checked."""
    v = v if isinstance(v, dict) else {}
    out = {}
    name = str(v.get("name") or "").strip()
    if name:
        if len(name) > 40 or not name.isprintable():
            raise ValueError("Reading names are up to 40 ordinary characters")
        out["name"] = name
    for k in ("warn", "crit"):
        if v.get(k) not in (None, ""):
            try:
                out[k] = float(v[k]) if not float(v[k]).is_integer() else int(float(v[k]))
            except (TypeError, ValueError):
                raise ValueError("Alert limits must be numbers") from None
    return out


def clean_readings_cfg(raw) -> dict:
    out = {}
    for k, v in (raw.items() if isinstance(raw, dict) else []):
        if re.fullmatch(r"[a-z0-9_]{1,24}", str(k)):
            try:
                c = clean_reading_setting(v)
            except ValueError:
                continue
            if c:
                out[str(k)] = c
    return out


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
    if (m := _CERT.match(entry)) and not (m.group(1) and m.group(1).isdigit() and m.group(2)):
        addr, port = m.group(1), m.group(2)
        if addr and addr.isdigit() and not port:  # "cert:8443"
            addr, port = None, addr
        port = int(port or 443)
        if not 1 <= port <= 65535:
            raise ValueError(f"port out of range in '{entry}'")
        addr = addr.strip("[]") if addr else None
        return [{"label": label or (f"Cert {port}" + (f" {addr}" if addr else "")), "kind": "cert", "port": port, "url": None,
                 "desc": f"certificate on {addr}:{port}" if addr else f"certificate on port {port}", "target": addr}]
    if (m := _SIP.match(entry)) and not (m.group(1) and m.group(1).isdigit() and m.group(2)):
        addr, port = m.group(1), m.group(2)
        if addr and addr.isdigit() and not port:  # "sip:5061"
            addr, port = None, addr
        port = int(port or 5060)
        if not 1 <= port <= 65535:
            raise ValueError(f"port out of range in '{entry}'")
        addr = addr.strip("[]") if addr else None
        return [{"label": label or (f"SIP {port}" + (f" {addr}" if addr else "")), "kind": "sip", "port": port, "url": None,
                 "desc": f"SIP on {addr}:{port} (UDP)" if addr else f"SIP on UDP {port}", "target": addr}]
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
    if low == "hadev:device":
        return [{"label": label or "Home Assistant", "kind": "hadev", "port": None, "url": None,
                 "desc": "the linked Home Assistant device"}]
    if low == "syslog:device":
        return [{"label": label or "Syslog", "kind": "syslog", "port": 514, "url": None, "desc": "syslog"}]
    if low == "snmp:device":
        return [{"label": label or "SNMP", "kind": "snmp", "port": 161, "url": None, "desc": "snmp"}]
    if low == "ilo:device":
        return [{"label": label or "iLO", "kind": "ilo", "port": 443, "url": None, "desc": "ilo"}]
    if low == "jellyfin:device":
        return [{"label": label or "Jellyfin", "kind": "jellyfin", "port": None, "url": None, "desc": "jellyfin api"}]
    if low == "plex:device":
        return [{"label": label or "Plex", "kind": "plex", "port": None, "url": None, "desc": "plex api"}]
    if low == "starlink:device":
        return [{"label": label or "Starlink", "kind": "starlink", "port": None, "url": None, "desc": "starlink"}]
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
# Monitoring schedules: some devices are only meant to be on at certain times
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


def _grace_minutes(value, default: int = 15) -> int:
    try:
        v = int(value)
    except (TypeError, ValueError):
        return default
    return v if 0 <= v <= 240 else default


def startup_until(h, now: float) -> float | None:
    """While a scheduled or "whenever it's on" device is starting up, the time its start-up
    allowance ends (services and agent checks don't alert until then); otherwise None."""
    if h.maint_until or h.off_schedule or not h.sched_started:
        return None
    minutes = h.startup_grace if h.expect_off else (h.schedule or {}).get("grace", 15) if h.schedule else 0
    end = h.sched_started + minutes * 60
    return end if now < end else None


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
        try:
            grace = int(raw.get("grace", 15))
        except (TypeError, ValueError):
            raise ValueError("The start-up allowance must be a whole number of minutes") from None
        if not 0 <= grace <= 240:
            raise ValueError("The start-up allowance must be between 0 and 240 minutes")
        entry["grace"] = grace  # minutes after it comes on before its services alert
    else:
        sched = clean_schedule(raw.get("schedule"))
        if sched:
            entry["schedule"] = sched
    if raw.get("no_alerts"):
        entry["no_alerts"] = True
    elif raw.get("critical"):
        entry["critical"] = True  # its "down" alerts get through a silenced phone
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
        if ver not in ("1", "2c", "3"):
            raise ValueError("SNMP version must be 1, 2c or 3")
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
    if "check_by" in raw:
        cb = str(raw.get("check_by") or "auto")
        if cb not in ("auto", "ping", "agent"):
            raise ValueError("check_by must be auto, ping or agent")
        entry["check_by"] = cb
    if "icon" in raw:
        icon = str(raw.get("icon") or "")
        if icon and not ICON_REF.match(icon):
            raise ValueError("Unknown icon")
        entry["icon"] = icon
    if "ha_device" in raw:
        HA_MORE_MAX = 5
        dev = str(raw.get("ha_device") or "").strip()
        if dev and not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", dev):
            raise ValueError("Unknown Home Assistant device")
        entry["ha_device"] = dev
        entry["ha_device_name"] = str(raw.get("ha_device_name") or "").strip()[:100] if dev else ""
        # More Home Assistant devices for the same thing (1.93.0), e.g. a myenergi hub and Harvi beside the Zappi
        more, seen = [], {dev}
        for x in (raw.get("ha_more") or [])[:HA_MORE_MAX] if dev and isinstance(raw.get("ha_more"), list) else []:
            xid = str((x or {}).get("id") or "").strip() if isinstance(x, dict) else ""
            if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", xid):
                raise ValueError("Unknown Home Assistant device")
            if xid not in seen:
                seen.add(xid)
                more.append({"id": xid, "name": str(x.get("name") or "").strip()[:100]})
        entry["ha_more"] = more
    if "group" in raw:
        group = " ".join(str(raw.get("group") or "").split())
        if len(group) > 40 or not group.isprintable():
            raise ValueError("Group must be up to 40 ordinary characters")
        entry["group"] = group
    if "parent" in raw:
        parent = str(raw.get("parent") or "").strip()
        if parent and not re.fullmatch(r"[a-z0-9_]{1,80}", parent):
            raise ValueError("Unknown upstream device")
        entry["parent"] = parent
    if "subtitle" in raw:
        sub = str(raw.get("subtitle") or "")
        if sub not in SUBTITLES:
            raise ValueError("Unknown choice for the line under the name")
        entry["subtitle"] = sub
    if "model" in raw:
        model = str(raw.get("model") or "").strip()
        if len(model) > 64 or not model.isprintable():
            raise ValueError("Make and model must be up to 64 ordinary characters")
        entry["model"] = model
    if "ilo_user" in raw:
        user = str(raw.get("ilo_user") or "").strip()
        if len(user) > 39 or not user.isprintable():
            raise ValueError("The iLO user name must be up to 39 ordinary characters")
        entry["ilo_user"] = user
        pw = raw.get("ilo_pass")
        if pw not in (None, ""):
            pw = str(pw)
            if len(pw) > 63 or not pw.isprintable():
                raise ValueError("The iLO password must be up to 63 ordinary characters")
            entry["ilo_pass"] = pw
    if "jellyfin_url" in raw:
        url = str(raw.get("jellyfin_url") or "").strip()
        entry["jellyfin_url"] = jflib.clean_url(url) if url else ""
        key = str(raw.get("jellyfin_key") or "").strip()
        if key:
            if not jflib.KEY_RE.match(key):
                raise ValueError("That doesn't look like a Jellyfin API key (letters and numbers, usually 32)")
            entry["jellyfin_key"] = key
    if "plex_url" in raw:
        url = str(raw.get("plex_url") or "").strip()
        entry["plex_url"] = pxlib.clean_url(url) if url else ""
        key = str(raw.get("plex_token") or "").strip()
        if key:
            if not pxlib.TOKEN_RE.match(key):
                raise ValueError("That doesn't look like a Plex token (letters, numbers, - and _, usually 20)")
            entry["plex_token"] = key
    if "starlink_source" in raw:
        src = str(raw.get("starlink_source") or "local")
        if src not in ("local", "account"):
            raise ValueError("Read the Starlink dish locally or through the account")
        entry["starlink_source"] = src
        addr = str(raw.get("starlink_addr") or "").strip()
        entry["starlink_addr"] = sllib.clean_addr(addr) if addr else ""
        cookie = str(raw.get("starlink_cookie") or "").strip()
        if cookie:
            entry["starlink_cookie"] = sllib.clean_cookie(cookie)
        dish = str(raw.get("starlink_dish") or "").strip()
        if dish and not re.match(r"^[A-Za-z0-9._\-]{4,100}$", dish):
            raise ValueError("That isn't a Starlink dish from the account")
        entry["starlink_dish"] = dish
        entry["starlink_dish_name"] = str(raw.get("starlink_dish_name") or "").strip()[:100]
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


def day_summary(rows, first: float, now: float, size: float, n: int, max_gap: float) -> tuple[float | None, list[str]]:
    """24-hour uptime % and the history strip (n segments of `size` seconds from `first`), in one pass
    over the rows. Same rules as coverage() and uptime_pct(): each result holds until the next check,
    for at most max_gap; maintenance counts as neither up nor down."""
    day0 = now - DAY
    up = down = 0.0
    acc = [[0.0, 0.0, 0.0] for _ in range(n)]  # up, down, maintenance seconds per segment
    for i, (ts, ok) in enumerate(rows):
        end = rows[i + 1][0] if i + 1 < len(rows) else now
        end = min(end, now, ts + max_gap)
        if end <= ts:
            continue
        kind = 2 if ok == MAINT_OK else 0 if ok else 1
        if kind != 2 and end > day0:
            d = end - max(ts, day0)
            if kind == 0:
                up += d
            else:
                down += d
        a = max(ts, first)
        while a < end:
            b = int((a - first) // size)
            if b >= n:
                break
            stop = min(first + (b + 1) * size, end)
            acc[b][kind] += stop - a
            a = stop
    strip = [("m" if m > 0 else "n") if u + dn <= 0 else ("g" if dn == 0 else "r" if u == 0 else "a") for u, dn, m in acc]
    return (round(100.0 * up / (up + down), 2) if up + down > 0 else None), strip


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
_legacy_tls_ctx: ssl.SSLContext | None = None


def _permissive_tls_context(max_tls12: bool) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
    except (ValueError, AttributeError):
        pass
    if max_tls12:
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    for ciphers in ("ALL:@SECLEVEL=0", "ALL", "DEFAULT"):
        try:
            ctx.set_ciphers(ciphers)
            break
        except ssl.SSLError:
            continue
    ctx.options |= getattr(ssl, "OP_LEGACY_SERVER_CONNECT", 0x4)
    return ctx


def health_tls_context() -> ssl.SSLContext:
    """A deliberately permissive TLS context for health checks.

    We only want to know whether the web service answers, not whether it's
    secure, so this accepts self-signed certs, small keys, TLS 1.0 and the old
    ciphers and renegotiation that devices like Dell iDRAC 6 still use.
    """
    global _tls_ctx
    if _tls_ctx is None:
        _tls_ctx = _permissive_tls_context(max_tls12=False)
    return _tls_ctx


def legacy_tls_context() -> ssl.SSLContext:
    """health_tls_context() capped at TLS 1.2, for old embedded web servers (HPE iLO 3, Dell iDRAC 6).

    Since OpenSSL 3.5 (Alpine 3.22 on), offering TLS 1.3 adds a post-quantum key share
    (X25519MLKEM768) to the first message, taking it from about 500 bytes to over 1,600.
    Some old embedded TLS stacks can't take a first message that size, or key types they
    don't know, and answer with an "internal error" alert. Without TLS 1.3 there's no key
    share, so the first message is back to its old size.
    """
    global _legacy_tls_ctx
    if _legacy_tls_ctx is None:
        _legacy_tls_ctx = _permissive_tls_context(max_tls12=True)
    return _legacy_tls_ctx


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


async def _http_once(scheme: str, host: str, port: int, path: str,
                     timeout: float, legacy: bool = False) -> tuple[bool | None, float | None, str]:
    """One GET request, reading only the status line.

    Returns (ok, ms, detail). ok is None when the port answered but not with
    HTTP over this scheme (TLS failure, connection dropped, garbage), which is
    the case where trying the other scheme is worthwhile. If the TLS handshake
    fails, it's tried once more capped at TLS 1.2 (see legacy_tls_context).
    """
    t0 = time.monotonic()
    tls = (legacy_tls_context() if legacy else health_tls_context()) if scheme == "https" else None
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
        if tls is not None and not legacy:
            return await _http_once(scheme, host, port, path, max(1.0, timeout - (time.monotonic() - t0)), legacy=True)
        return None, None, f"TLS handshake failed ({err.reason or type(err).__name__})".replace("_", " ").lower()
    except (ConnectionResetError, asyncio.IncompleteReadError):
        if tls is not None and not legacy:  # some old stacks just drop the connection instead
            return await _http_once(scheme, host, port, path, max(1.0, timeout - (time.monotonic() - t0)), legacy=True)
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
        self.sem = asyncio.Semaphore(6)  # a few updates at a time, so a slow Home Assistant isn't swamped
        if not self.enabled:
            log.warning("SUPERVISOR_TOKEN not set; Home Assistant updates disabled")

    async def call(self, method: str, path: str, payload: dict | None = None) -> None:
        if not self.enabled:
            return
        try:
            async with self.sem, self.session.request(
                method,
                HA_API + path,
                json=payload,
                headers={"Authorization": f"Bearer {SUPERVISOR_TOKEN}"},
            ) as resp:
                if resp.status >= 400:
                    body = (await resp.text())[:200]
                    log.warning("HA API %s %s -> %s %s", method, path, resp.status, body)
        except asyncio.TimeoutError:
            log.warning("HA API %s %s failed: Home Assistant didn't answer in time", method, path)
        except Exception as err:  # noqa: BLE001
            log.warning("HA API %s %s failed: %s", method, path, err)

    async def set_state(self, entity_id: str, state: str, attributes: dict) -> None:
        await self.call("POST", f"/states/{entity_id}", {"state": state, "attributes": attributes})

    async def service(self, domain: str, service: str, data: dict) -> None:
        await self.call("POST", f"/services/{domain}/{service}", data)

    async def run_service(self, domain: str, service: str, data: dict) -> str | None:
        """Call a service and wait for it; None if it worked, else why not."""
        if not self.enabled:
            return "Home Assistant isn't available"
        try:
            async with self.session.post(f"{HA_API}/services/{domain}/{service}", json=data, timeout=ClientTimeout(total=30),
                                         headers={"Authorization": f"Bearer {SUPERVISOR_TOKEN}"}) as resp:
                if resp.status >= 400:
                    return f"Home Assistant said {resp.status}: {(await resp.text())[:150]}"
                return None
        except Exception as err:  # noqa: BLE001
            return f"couldn't reach Home Assistant ({err})"

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

    async def write_options(self, options: dict) -> str | None:
        """Save the add-on's options (what the Configuration tab shows) through the Supervisor,
        which checks them against config.yaml's schema. None if saved, else why not."""
        if not self.enabled:
            return "no Supervisor access"
        try:
            async with self.session.post(f"{SUPERVISOR_API}/addons/self/options", json={"options": options},
                                         headers={"Authorization": f"Bearer {SUPERVISOR_TOKEN}"}) as resp:
                if resp.status < 400:
                    return None
                text = (await resp.text())[:400]
                try:
                    text = json.loads(text).get("message") or text
                except (ValueError, AttributeError):
                    pass
                log.warning("Home Assistant didn't accept the settings (%s): %s", resp.status, text)
                return f"Home Assistant didn't accept them: {text}"
        except Exception as err:  # noqa: BLE001
            log.warning("Couldn't save the settings: %s", err)
            return f"couldn't reach Home Assistant ({err})"

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

    async def ws_calls(self, types: list[str], what: str) -> list | None:
        """Run websocket commands on one connection; each result, or None if anything failed."""
        if not self.enabled:
            return None
        try:
            async with self.session.ws_connect(HA_WS, timeout=10, heartbeat=None, max_msg_size=64 * 1024 * 1024) as ws:
                msg = await ws.receive_json(timeout=10)
                if msg.get("type") == "auth_required":
                    await ws.send_json({"type": "auth", "access_token": SUPERVISOR_TOKEN})
                    msg = await ws.receive_json(timeout=10)
                if msg.get("type") != "auth_ok":
                    log.warning("HA websocket auth failed: %s", msg.get("message") or msg.get("type"))
                    return None
                out = []
                for n, t in enumerate(types, 1):
                    await ws.send_json({"id": n, "type": t})
                    while True:
                        msg = await ws.receive_json(timeout=20)
                        if msg.get("id") == n:
                            break
                    if not msg.get("success"):
                        log.warning("Couldn't read HA %s: %s", what, (msg.get("error") or {}).get("message"))
                        return None
                    out.append(msg.get("result") or [])
                return out
        except Exception as err:  # noqa: BLE001
            log.warning("Couldn't read HA %s: %s", what, err)
            return None

    async def list_users(self) -> list[dict] | None:
        """Home Assistant's user list (id, name, username, admin flags), via the websocket API."""
        got = await self.ws_calls(["config/auth/list"], "users")
        return got[0] if got else None

    async def registry(self) -> dict | None:
        """HA's devices and their entities (from the device and entity registries), cached 10 minutes."""
        now = time.time()
        cached = getattr(self, "_registry", None)
        if cached and now - cached[0] < 600:
            return cached[1]
        got = await self.ws_calls(["config/device_registry/list", "config/entity_registry/list"], "devices")
        if not got:
            return cached[1] if cached else None  # keep using the last good copy
        devices = {d["id"]: d for d in got[0] if isinstance(d, dict) and d.get("id")}
        by_device: dict[str, list] = {}
        for e in got[1]:
            if isinstance(e, dict) and e.get("device_id") and not e.get("disabled_by"):
                by_device.setdefault(e["device_id"], []).append(e)
        reg = {"devices": devices, "entities": by_device}
        self._registry = (now, reg)
        return reg

    async def states_map(self) -> dict | None:
        """Every entity's state, keyed by entity id; shared by checks running together (5 seconds)."""
        now = time.time()
        cached = getattr(self, "_states", None)
        if cached and now - cached[0] < 5:
            return cached[1]
        lock = getattr(self, "_states_lock", None) or asyncio.Lock()
        self._states_lock = lock
        async with lock:
            cached = getattr(self, "_states", None)
            if cached and time.time() - cached[0] < 5:
                return cached[1]
            st = await self.get_json("/states")
            if not isinstance(st, list):
                return None
            m = {x.get("entity_id"): x for x in st if isinstance(x, dict)}
            self._states = (time.time(), m)
            return m

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

    async def host_interfaces(self) -> list[dict]:
        """Home Assistant's connected network interfaces from the Supervisor:
        [{"name": "eth0", "addresses": ["192.168.1.5/24"], "primary": True}, ...]. "primary" is the one
        with the default route, which reaches anything not on a directly attached subnet."""
        if not self.enabled:
            return []
        try:
            async with self.session.get(f"{SUPERVISOR_API}/network/info",
                                        headers={"Authorization": f"Bearer {SUPERVISOR_TOKEN}"}) as resp:
                if resp.status >= 400:
                    return []
                data = (await resp.json()).get("data") or {}
        except Exception:  # noqa: BLE001
            return []
        out = []
        for i in data.get("interfaces") or []:
            if i.get("connected") is False:
                continue
            addrs = [a for a in ((i.get("ipv4") or {}).get("address") or []) if isinstance(a, str)]
            if addrs:
                out.append({"name": str(i.get("interface") or "?"), "addresses": addrs, "primary": i.get("primary") is True})
        return out

    async def host_networks(self) -> list[str]:
        """Home Assistant's own IPv4 addresses with prefix, e.g. ["192.168.1.5/24"], from the Supervisor."""
        return [a for i in await self.host_interfaces() for a in i["addresses"]]

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
SECURITY_CHECKS = ("security", "defender", "secrets", "integrity", "domain", "vulns")  # emailed under "Security"
TIME_ACK_KINDS = ("events", "security", "secrets", "integrity", "domain")
NO_ACK = ("defender",)  # cleared on the device itself (a threat removed), then the next report shows it
TIME_ACK_TEXT = {"events": "alert-worthy events up to then", "security": "security alerts up to then",
                 "secrets": "passwords found up to then", "integrity": "changes to the agent's files up to then",
                 "domain": "privileged group changes up to then"}


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
    acked: bool = False                # acknowledged: counts as OK while it stays like this
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
    maint_seen_down: bool = False      # has it stopped replying (or restarted) since the pause began?
    maint_started: float | None = None # when the pause began
    ping_seen: float | None = None     # last time it really answered ping (not counted as up by its agent)
    maint_ended: float | None = None   # when the last pause ended (agent gets a fresh stale period)
    schedule: dict | None = None       # None: monitored all the time
    expect_off: bool = False           # usually off (e.g. cold storage): off is normal, checked while on
    startup_grace: int = 15            # expect_off: minutes after it comes on before its services and agent alert
    startup_end: float | None = None   # when the current start-up allowance ends (None: not starting up)
    no_alerts: bool = False            # show its status, never notify
    critical: bool = False             # its problem alerts are critical notifications on phones
    off_schedule: bool = False         # outside its monitoring schedule right now
    reachable: bool | None = None      # answered its last ping (shown while off schedule)
    check_by: str = "auto"             # how to tell it's up: "auto" (ping, or a recent agent report), "ping" or "agent"
    via_agent: bool = False            # up only because its agent is reporting (no ping reply)
    icon: str = ""                     # "b:<built-in>" or "u:<uploaded file>"; blank = pick from what it is
    model: str = ""                    # make and model, e.g. "Dell PowerEdge R720xd"
    subtitle: str = ""                 # the line under the name: "" (the default), model, os, address or none
    group: str = ""                    # the Overview group, e.g. "Servers"; "" = from the icon's type
    nic_prev: tuple | None = None      # (received, {adapter: counters}) from the last agent report, for rates
    nic_rates: dict = field(default_factory=dict)  # adapter -> {rx_bps, tx_bps, new_errors}
    snmp_community: str | None = None  # SNMP v2c community (None: "public")
    snmp_version: str = "2c"
    snmp_v3: dict = field(default_factory=dict)  # user, auth, auth_pass, priv, priv_pass
    snmp_watch: list[int] = field(default_factory=list)  # switch ports (ifIndex) that alert when down
    ups_limits: dict = field(default_factory=dict)  # this UPS's own runtime_warn / runtime_crit / load_warn, over the add-on's
    snmp_data: dict | None = None      # latest SNMP poll
    snmp_items: list[dict] = field(default_factory=list)  # problems found in it
    snmp_polled: float | None = None
    snmp_rediscover: bool = False      # Check now: re-read the port list (names, descriptions) at the next poll
    snmp_restart_ack: float = 0        # start time of an acknowledged restart (not flagged)
    snmp_acks: dict = field(default_factory=dict)  # acknowledged problems: what -> its level (warn / crit) then
    snmp_vpn_ignore: list[str] = field(default_factory=list)  # Sophos VPN connections that never alert
    snmp_ignore: list[str] = field(default_factory=list)  # SNMP problems that never alert here, e.g. "Server" (powered off)
    vpn_alerted: set = field(default_factory=set)    # VPN connections already alerted as down
    vpn_down_prev: set = field(default_factory=set)  # VPN connections down at the previous poll
    vpn_polled: bool = False                         # polled since the add-on started
    readings_cfg: dict = field(default_factory=dict)  # syslog readings: {"temp0": {"name": "CPU", "warn": 80, "crit": 90}}
    ilo_user: str = ""                 # HPE iLO login for its health (ilo:device)
    ilo_pass: str = ""
    ilo_data: dict | None = None       # latest iLO reading
    ilo_items: list[dict] = field(default_factory=list)  # problems found in it
    ilo_polled: float | None = None    # when it was last read (or tried)
    ilo_result: tuple | None = None    # the check result from that reading, reused until the next one
    ilo_err: str | None = None         # the last reading failed: "login" (refused) or "read"
    ilo_recheck: bool = False          # something new failed: read it again at the next check
    ilo_acks: dict = field(default_factory=dict)  # acknowledged problems: what -> its level (warn / crit) then
    ilo_ignore: list[str] = field(default_factory=list)  # problems that never alert here, e.g. "Power redundancy"
    jf_url: str = ""                   # Jellyfin's address ("" = http://<host>:8096)
    jf_key: str = ""                   # Jellyfin API key: only ever sent to jf_url, never shown again
    jf_data: dict | None = None        # its latest reading
    px_url: str = ""                   # Plex's address ("" = http://<host>:32400)
    px_key: str = ""                   # Plex token: only ever sent to px_url, never shown again
    px_data: dict | None = None        # its latest reading
    px_base: str = ""                  # the address that last answered (https when Plex drops plain HTTP)
    sl_source: str = "local"           # Starlink: read the dish itself ("local") or through the account ("account")
    sl_addr: str = ""                  # the dish's local API ("" = 192.168.100.1:9200)
    sl_cookie: str = ""                # starlink.com session cookie: only ever sent to starlink.com, never shown again
    sl_dish: str = ""                  # the account's dish to read (its id, "ut...")
    sl_dish_name: str = ""
    sl_data: dict | None = None        # its latest reading
    sl_map: dict | None = None         # its obstruction map, read when the Starlink tab opens (not saved)
    sl_map_at: float = 0.0
    sl_state: dict = field(default_factory=dict)  # the short-lived starlink.com token (not saved)
    ha_device: str = ""                # linked Home Assistant device id ("" = none)
    ha_device_name: str = ""
    ha_more: list = field(default_factory=list)  # more linked HA devices: [{"id", "name"}] (1.93.0)
    ha_data: dict | None = None        # its entities as last read, with what Rollcall made of them
    parent: str = ""                   # the upstream device it's reached through (its key), e.g. a router; "" = none
    unreachable: bool = False          # not answering while a device upstream of it is down: shown, not alerted
    upstream_down: str = ""            # while unreachable: the key of that upstream device
    alert_held: tuple | None = None    # (reason, since): its down alert waits for its upstream device's next check
    down_quiet: bool = False           # its down alert wasn't sent (unreachable), so no "back up" either
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
        self._day_cache: dict = {}  # key -> (worked out at, strip start, (uptime %, strip)); see _day
        self._pub_pending: set = set()  # hosts to send to Home Assistant in the background
        self._pub_task: asyncio.Task | None = None
        self._pub_all: asyncio.Task | None = None
        self._sw: dict = {}          # agent id -> its software list, loaded when first needed
        self._sec: dict = {}         # agent id -> where its password scan found passwords, loaded when first needed
        self.want_secrets: set = set()  # agents whose scan findings Rollcall is missing
        self.winget = None           # the winget catalogue (wingetidx.Index), for newer versions of Windows programs
        self.winget_info: dict = {}
        self._newer: dict = {}       # (agent id, list hash, catalogue) -> {program index: newer version}
        self.want_apps: set = set()  # agents whose software list Rollcall is missing
        self.vulnfeeds = vulnlib.Feeds(VULN_DIR, log)  # known vulnerabilities: Microsoft, OSV.dev, CISA (vulns.py)
        try:
            self.vulnfeeds.load()
        except Exception as err:  # noqa: BLE001 - a damaged cache is downloaded again
            log.warning("Couldn't read the saved vulnerability data (%s); it will be downloaded again", err)
        self._vf: dict = {}          # agent id -> (what it was worked out from, findings)
        self.opts = opts
        self.store = store
        self.logs = sysloglib.LogStore(store.db)
        self.metrics = metricslib.Metrics(store.db)
        self.dbh = dblib.Health(DB_HEALTH_PATH)  # Manage > Database (dbhealth.py)
        self.claude = hintlib.ClaudeHints(CLAUDE_HINTS_PATH)  # hints for errors (hints.py)
        self.db_started = time.time()
        self.email = emaillib.Emailer(lambda: self.opts, {}, lambda: None)
        self.syslog_unknown: dict[str, dict] = {}
        self.scan: discovery.Scan | None = None
        self.discovery = self._load_discovery()
        self._ifaces: tuple[float, list] = (0.0, [])  # (when fetched, Home Assistant's interfaces)
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
        self.messages = msglib.Messages(MESSAGES_PATH)  # messages to users' screens
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
            log.warning("No hosts yet - add some with 'Add device' on the dashboard")
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
        self._write_hosts([self._entry(h) for h in self.hosts.values()])

    @staticmethod
    def _entry(h: "Host") -> dict:
        """A dashboard entry as it's saved in hosts.json."""
        return {"id": h.key, "name": h.name, "host": h.host, "checks": h.checks,
                **({"schedule": h.schedule} if h.schedule else {}),
                **({"expect_off": True, "grace": h.startup_grace} if h.expect_off else {}),
                **({"no_alerts": True} if h.no_alerts else {}),
                **({"critical": True} if h.critical else {}),
                **({"check_by": h.check_by} if h.check_by != "auto" else {}),
                **({"icon": h.icon} if h.icon else {}),
                **({"model": h.model} if h.model else {}),
                **({"subtitle": h.subtitle} if h.subtitle else {}),
                **({"group": h.group} if h.group else {}),
                **({"parent": h.parent} if h.parent else {}),
                **({"ha_device": h.ha_device, "ha_device_name": h.ha_device_name} if h.ha_device else {}),
                **({"ha_more": h.ha_more} if h.ha_device and h.ha_more else {}),
                **({"snmp_community": h.snmp_community} if h.snmp_community else {}),
                **({"snmp_version": "3", "snmp_v3": h.snmp_v3} if h.snmp_version == "3" else
                               {"snmp_version": "1"} if h.snmp_version == "1" else {}),
                            **({"snmp_watch": h.snmp_watch} if h.snmp_watch else {}),
                            **({"ups_limits": h.ups_limits} if h.ups_limits else {}),
                            **({"snmp_restart_ack": h.snmp_restart_ack} if h.snmp_restart_ack else {}),
                            **({"snmp_acks": h.snmp_acks} if h.snmp_acks else {}),
                            **({"snmp_vpn_ignore": h.snmp_vpn_ignore} if h.snmp_vpn_ignore else {}),
                **({"snmp_ignore": h.snmp_ignore} if h.snmp_ignore else {}),
                **({"ilo_user": h.ilo_user, "ilo_pass": h.ilo_pass} if h.ilo_user or h.ilo_pass else {}),
                **({"ilo_acks": h.ilo_acks} if h.ilo_acks else {}),
                **({"ilo_ignore": h.ilo_ignore} if h.ilo_ignore else {}),
                **({"jellyfin_url": h.jf_url} if h.jf_url else {}),
                **({"jellyfin_key": h.jf_key} if h.jf_key else {}),
                **({"plex_url": h.px_url} if h.px_url else {}),
                **({"plex_token": h.px_key} if h.px_key else {}),
                **({"starlink_source": h.sl_source} if h.sl_source != "local" else {}),
                **({"starlink_addr": h.sl_addr} if h.sl_addr else {}),
                **({"starlink_cookie": h.sl_cookie} if h.sl_cookie else {}),
                **({"starlink_dish": h.sl_dish, "starlink_dish_name": h.sl_dish_name} if h.sl_dish else {}),
                            **({"readings_cfg": h.readings_cfg} if h.readings_cfg else {}),
                            **({"syslog_alert": h.syslog_alert} if h.syslog_alert != 3 else {}),
                            **({"syslog_keywords": h.syslog_keywords} if h.syslog_keywords else {}),
                            **({"syslog_ignore": h.syslog_ignore} if h.syslog_ignore else {}),
                            **({"syslog_ack": h.syslog_ack} if h.syslog_ack else {})}

    def _make_host(self, entry: dict, due: float) -> Host:
        h = Host(key=entry["id"], name=entry["name"], host=entry["host"],
                 checks=list(entry.get("checks") or []), next_due=due)
        h.expect_off, h.no_alerts = bool(entry.get("expect_off")), bool(entry.get("no_alerts"))
        h.startup_grace = _grace_minutes(entry.get("grace"))
        h.critical = bool(entry.get("critical")) and not h.no_alerts
        h.snmp_community = entry.get("snmp_community") or None
        h.check_by = entry.get("check_by") if entry.get("check_by") in ("ping", "agent") else "auto"
        h.icon = str(entry.get("icon") or "") if ICON_REF.match(str(entry.get("icon") or "")) else ""
        h.model = str(entry.get("model") or "")[:64]
        h.subtitle = entry.get("subtitle") if entry.get("subtitle") in SUBTITLES else ""
        h.group = str(entry.get("group") or "")[:40]
        h.parent = str(entry.get("parent") or "")[:80]
        h.ha_device = str(entry.get("ha_device") or "")[:64]
        h.ha_device_name = str(entry.get("ha_device_name") or "")[:100]
        h.ha_more = [{"id": str(x.get("id"))[:64], "name": str(x.get("name") or "")[:100]} for x in (entry.get("ha_more") or [])
                     if isinstance(x, dict) and x.get("id")][:5] if h.ha_device else []
        h.snmp_version = entry.get("snmp_version") if entry.get("snmp_version") in ("1", "3") else "2c"
        h.snmp_v3 = dict(entry.get("snmp_v3") or {})
        h.snmp_watch = [int(x) for x in entry.get("snmp_watch") or [] if str(x).isdigit()]
        h.snmp_vpn_ignore = [str(x)[:100] for x in entry.get("snmp_vpn_ignore") or [] if str(x).strip()][:200]
        h.snmp_ignore = [str(x)[:100] for x in entry.get("snmp_ignore") or [] if str(x).strip()][:200]
        h.ups_limits = clean_ups_limits(entry.get("ups_limits"))
        h.readings_cfg = clean_readings_cfg(entry.get("readings_cfg"))
        h.ilo_user, h.ilo_pass = str(entry.get("ilo_user") or "")[:39], str(entry.get("ilo_pass") or "")[:63]
        h.ilo_acks = ({str(k)[:100]: v for k, v in entry["ilo_acks"].items() if v in ("warn", "crit")}
                      if isinstance(entry.get("ilo_acks"), dict) else {})
        h.ilo_ignore = [str(x)[:100] for x in entry.get("ilo_ignore") or [] if str(x).strip()][:200]
        h.jf_url = str(entry.get("jellyfin_url") or "")[:300]
        h.jf_key = str(entry.get("jellyfin_key") or "")[:128]
        h.px_url = str(entry.get("plex_url") or "")[:300]
        h.px_key = str(entry.get("plex_token") or "")[:128]
        h.sl_source = "account" if entry.get("starlink_source") == "account" else "local"
        h.sl_addr = str(entry.get("starlink_addr") or "")[:300]
        h.sl_cookie = str(entry.get("starlink_cookie") or "")[:16000]
        h.sl_dish, h.sl_dish_name = str(entry.get("starlink_dish") or "")[:100], str(entry.get("starlink_dish_name") or "")[:100]
        try:
            h.snmp_restart_ack = float(entry.get("snmp_restart_ack") or 0)
            h.snmp_acks = ({str(k)[:200]: v for k, v in entry["snmp_acks"].items() if v in ("warn", "crit")}
                           if isinstance(entry.get("snmp_acks"), dict) else {})
        except (TypeError, ValueError):
            h.snmp_restart_ack = 0
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
        old_jf_base = h.jf_url or jflib.default_url(h.host)
        old_px_base = h.px_url or pxlib.default_url(h.host)
        if entry["host"] != h.host:
            h.host, h.ip, h.failures = entry["host"], None, 0
        h.name = entry["name"]
        h.checks = entry["checks"]
        h.schedule = entry.get("schedule")
        h.expect_off, h.no_alerts = bool(entry.get("expect_off")), bool(entry.get("no_alerts"))
        h.startup_grace = _grace_minutes(entry.get("grace"))
        h.critical = bool(entry.get("critical")) and not h.no_alerts
        if entry.get("snmp_community"):  # blank keeps the one already set
            h.snmp_community = entry["snmp_community"]
        if "ilo_user" in entry:
            pw = entry.get("ilo_pass") or h.ilo_pass  # blank keeps the one already set
            if (entry["ilo_user"], pw) != (h.ilo_user, h.ilo_pass):
                h.ilo_user, h.ilo_pass = entry["ilo_user"], pw
                h.ilo_polled = h.ilo_result = None  # read it again with the new login
        if h.jf_key or "jellyfin_url" in entry:
            old_base = old_jf_base
            new_url = entry.get("jellyfin_url", h.jf_url)
            new_base = new_url or jflib.default_url(entry["host"])
            if entry.get("jellyfin_key"):
                h.jf_key = entry["jellyfin_key"]
            elif h.jf_key and not jflib.same_server(old_base, new_base):
                h.jf_key = ""  # a key only goes to the server it was given for: enter it again for a new one
                log.info("%s: Jellyfin address changed, so its API key was cleared", h.name)
            h.jf_url, h.jf_data = new_url, None
        if h.px_key or "plex_url" in entry:
            new_url = entry.get("plex_url", h.px_url)
            new_base = new_url or pxlib.default_url(entry["host"])
            if entry.get("plex_token"):
                h.px_key = entry["plex_token"]
            elif h.px_key and not pxlib.same_server(old_px_base, new_base):
                h.px_key = ""  # a token only goes to the server it was given for: enter it again for a new one
                log.info("%s: Plex address changed, so its token was cleared", h.name)
            h.px_url, h.px_data = new_url, None
        if "starlink_source" in entry:
            new = (entry["starlink_source"], entry.get("starlink_addr", ""), entry.get("starlink_dish", ""))
            if new != (h.sl_source, h.sl_addr, h.sl_dish):
                h.sl_data = None
            h.sl_source, h.sl_addr, h.sl_dish = new
            h.sl_dish_name = entry.get("starlink_dish_name", "") or (h.sl_dish_name if h.sl_dish else "")
            if entry.get("starlink_cookie"):              # blank keeps the one already set
                h.sl_cookie, h.sl_state = entry["starlink_cookie"], {}
                h.sl_data = None
        if "check_by" in entry:
            h.check_by = entry["check_by"]
            h.next_due = 0
        if "icon" in entry:
            h.icon = entry["icon"]
        if "model" in entry:
            h.model = entry["model"]
        if "subtitle" in entry:
            h.subtitle = entry["subtitle"]
        if "group" in entry:
            h.group = entry["group"]
        if "parent" in entry and entry["parent"] != h.parent:
            h.parent = entry["parent"]
            if not h.parent:
                h.unreachable, h.upstream_down = False, ""
            h.next_due = 0
        if "ha_device" in entry:
            if entry["ha_device"] != h.ha_device or entry.get("ha_more", []) != h.ha_more:
                h.ha_data = None
            h.ha_device, h.ha_device_name = entry["ha_device"], entry.get("ha_device_name", "")
            h.ha_more = list(entry.get("ha_more") or []) if h.ha_device else []
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
        self.publish_soon(h)

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
            self._syslog_claim(ip, h)
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
            u = self.syslog_unknown[ip] = {"ip": ip, "first": now, "count": 0, "held": []}
            log.info("Syslog from %s, which %s", ip, f"is {h.name} but Syslog isn't ticked for it" if h
                     else "isn't a device in Rollcall (yet)")
        # Kept in memory for a while: a device added by name isn't matched until its name has been
        # looked up (just after a restart, or after its address changes), and these are filed then.
        u["held"] = (u["held"] + [(now, m)])[-SYSLOG_HELD:]
        u.update(count=u["count"] + 1, last=now, msg=m["msg"][:200], app=m["app"], sev=m["sev"], name=m["host"],
                 host_key=h.key if h else None)

    def _syslog_claim(self, ip: str, h: Host) -> None:
        """This sender turned out to be a known device: file what was held and stop listing it as unknown."""
        u = self.syslog_unknown.pop(ip, None)
        if not u:
            return
        held = [(ts, m) for ts, m in u.get("held", []) if ts > time.time() - 3600]
        for ts, m in held:
            self.logs.add(h.key, ts, m)
        log.info("Syslog from %s is %s: %d held message(s) filed", ip, h.name, len(held))

    def syslog_sweep(self) -> None:
        for ip in list(self.syslog_unknown):
            h = self._syslog_target(ip)
            if h and any(s.kind == "syslog" for s in h.services):
                self._syslog_claim(ip, h)

    def syslog_state(self, h: Host, now: float) -> tuple:
        """Alerts in the last 24 hours that haven't been acknowledged."""
        since = max(now - DAY, h.syslog_ack)
        rows = self.logs.query(h.key, since=since, max_sev=7, limit=2000)
        hits = [(sysloglib.alert_level(r, h.syslog_alert, h.syslog_keywords, h.syslog_ignore), r) for r in rows]
        hits = [(lvl, r) for lvl, r in hits if lvl]
        n, last = self.logs.stats(h.key, now - DAY)
        # SIP lines whose registration the device logs (e.g. Cisco SPA ATAs): failed or lapsed goes red
        regs = syslogreadings.registrations(self.logs, h.key, now)
        bad = [r for r in regs if r["state"] in ("failed", "lapsed")]
        over = []
        if h.readings_cfg:  # readings with alert limits set
            over = [r for r in syslogreadings.readings(self.logs, h.key, now, h.readings_cfg)["sensors"] if r.get("level")]
        if over and not bad:
            worst = "crit" if any(r["level"] == "crit" for r in over) else "warn"
            detail = "; ".join(f"{r['label']} {r['value']:g} {r['unit']} ({'below' if r['dir'] == 'below' else 'over'} "
                               f"{r['crit'] if r['level'] == 'crit' else r['warn']:g})" for r in over)
            if hits:
                detail += f" (and {len(hits)} log alert{'s' if len(hits) != 1 else ''})"
            return False, None, detail[:240], ("now" if worst == "crit" else "warn")
        if bad:
            detail = "; ".join(f"Line {r['line']}: {r['detail']}" for r in bad)
            if over:
                detail += "; " + "; ".join(f"{r['label']} {r['value']:g} {r['unit']}" for r in over)
            if hits:
                detail += f" (and {len(hits)} log alert{'s' if len(hits) != 1 else ''})"
            return False, None, detail[:240], "now"
        if not hits:
            reg = (" · " + ", ".join(f"line {r['line']} registered" for r in regs if r["state"] == "registered")) if regs else ""
            return True, None, (f"{n} message{'s' if n != 1 else ''} in 24 h, last {fmt_ago(now - last)}" if n
                                else "No messages in the last 24 h") + reg
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
        for c in self.hosts.values():  # devices that were behind it: no upstream device any more
            if c.parent == h.key:
                c.parent, c.unreachable, c.upstream_down, c.next_due = "", False, "", 0
        self._save_hosts()
        if h.maint_until:
            self._save_maint()
        self.store.clear(h.key)
        self.logs.clear(h.key)
        self.metrics.clear(h.key)
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

    # -- upstream devices: a device reached through another (e.g. a router) ---------------
    PARENT_WAIT = 180  # longest a device's down alert waits to hear whether its upstream device is down too

    def ancestors(self, h: Host) -> list[Host]:
        """Its upstream device, that device's upstream device, and so on (nearest first)."""
        out, seen, key = [], {h.key}, h.parent
        while key and key not in seen and len(out) < 20:
            p = self.hosts.get(key)
            if not p:
                break
            out.append(p)
            seen.add(key)
            key = p.parent
        return out

    def children(self, h: Host) -> list[Host]:
        return [c for c in self.hosts.values() if c.parent == h.key and c is not h]

    def descendants(self, h: Host) -> list[Host]:
        """Every device behind it, however many levels down."""
        out, seen, todo = [], {h.key}, [h]
        while todo:
            for c in self.children(todo.pop()):
                if c.key not in seen:
                    seen.add(c.key)
                    out.append(c)
                    todo.append(c)
        return out

    def check_parent(self, key: str | None, parent: str) -> None:
        """Raises ValueError if `parent` can't be the upstream device of the device `key` (None: a new one)."""
        if not parent:
            return
        p = self.hosts.get(parent)
        if not p:
            raise ValueError("The upstream device doesn't exist any more")
        if key and (parent == key or any(a.key == key for a in self.ancestors(p))):
            raise ValueError(f"{p.name} is behind this device, so it can't be its upstream device too")

    def check_downstream(self, h: Host, keys: list, parent: str | None = None) -> list:
        """The devices to put behind h (its downstream list, from its Edit): known devices, not h itself, and
        none that h is behind (a loop), counting the upstream device it's being given (`parent`) in the same
        edit. Raises ValueError naming the first that can't be."""
        p = self.hosts.get(h.parent if parent is None else parent)
        anc = {a.key for a in self.ancestors(p)} | {p.key} if p else set()
        wanted = []
        for k in dict.fromkeys(str(k) for k in keys if k):
            c = self.hosts.get(k)
            if not c or c is h:
                continue
            if c.key in anc:
                raise ValueError(f"{h.name} is behind {c.name}, so {c.name} can't be behind it too")
            wanted.append(c)
        return wanted

    def set_downstream(self, h: Host, wanted: list) -> int:
        """Make h the upstream device of exactly the devices in `wanted` (from check_downstream): ticked ones
        get it, ones that had it and aren't ticked any more are cleared. Returns how many changed."""
        keep, changed = {c.key for c in wanted}, 0
        for c in self.hosts.values():
            new = h.key if c.key in keep else ("" if c.parent == h.key else c.parent)
            if new != c.parent:
                c.parent, changed = new, changed + 1
                if not new:
                    c.unreachable, c.upstream_down = False, ""
                c.next_due = 0
        if changed:
            self._save_hosts()
            log.info("%s: %d device(s) now behind it", h.name, len(keep))
        return changed

    def upstream(self, h: Host) -> tuple[Host | None, bool]:
        """The device upstream of it that's down, furthest up (the cause), with True; else the nearest
        one that has just missed a check, with False."""
        anc = self.ancestors(h)
        down = [p for p in anc if p.status == RED or ((p.maint_until or p.off_schedule) and p.reachable is False)]
        if down:
            return down[-1], True
        return next((p for p in anc if p.status == AMBER), None), False

    async def settle_held(self, h: Host, now: float) -> None:
        """A device whose down alert is waiting on its upstream device: unreachable once that's down
        too (no alert of its own: the upstream device's alert lists it), or alerted as usual once that
        has answered a check since, or after PARENT_WAIT whatever happens."""
        if not h.alert_held:
            return
        reason, since = h.alert_held
        if h.status != RED or h.removed or h.maint_until or h.off_schedule:
            h.alert_held = None
            return
        blocker, sure = self.upstream(h)
        if sure:
            h.alert_held, h.unreachable, h.upstream_down, h.down_quiet = None, True, blocker.key, True
            log.info("%s: unreachable, behind %s which is down; no alert of its own", h.name, blocker.name)
            self.publish_soon(h)
            return
        p = self.hosts.get(h.parent)
        waiting = blocker is not None or (p is not None and (p.checking or (p.last_check or 0) < since))
        if waiting and now - since < self.PARENT_WAIT:
            return
        h.alert_held = None
        await self._alert_down(h, reason)

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
                h.maint_started = m.get("started")
                h.status = MAINT
                for s in h.services:
                    s.status, s.failures = UNKNOWN, 0
                log.info("%s: maintenance restored, until %s", h.name, iso(h.maint_until))

    def _save_maint(self) -> None:
        data = {h.key: {"until": h.maint_until, "seen_down": h.maint_seen_down, "started": h.maint_started}
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
        h.maint_started = now
        h.status = MAINT
        h.last_change = now
        h.down_since = None
        self._save_maint()
        log.info("%s: paused for maintenance for %d min", h.name, minutes)
        if old == RED:
            await self.dismiss(f"ping_monitor_{h.key}")
        await self.reset_services(h)
        await self.ha.fire("ping_monitor_status_changed", self._event(h, old, MAINT))
        self.publish_soon(h)

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
                "new_status": new, "entity_id": h.entity_id, "unreachable": h.unreachable,
                "upstream": (self.hosts[h.upstream_down].name if h.upstream_down in self.hosts else None)}

    # -- settings changed while running ------------------------------------
    def apply_options(self, changed: dict) -> list[str]:
        """Use new settings straight away. Most are read from self.opts each time they're needed;
        this updates the few that are kept elsewhere. Returns notes for the person who changed them."""
        notes = []
        old = dict(self.opts)
        self.opts.update(changed)
        now = time.time()
        if {"interval", "retry_interval"} & changed.keys():
            self.interval = int(self.opts["interval"])
            self.retry_interval = int(self.opts["retry_interval"])
            self.max_gap = max(self.interval, self.retry_interval) * 2 + 60
            # Shorter intervals start now, rather than after each device's current wait.
            moved = 0
            for i, h in enumerate(list(self.hosts.values())):
                if h.checking or not h.last_check:
                    continue
                wait = min(self.retry_interval, self.interval) if h.status == AMBER else self.interval
                due = max(h.last_check + wait, now + i * 0.2)
                if due < h.next_due:
                    h.next_due, moved = due, moved + 1
            if moved:
                notes.append(f"{moved} device(s) will be checked sooner to match the new interval")
        if "service_timeout" in changed:
            self.svc_timeout = float(self.opts.get("service_timeout") or 5)
        if "log_level" in changed:
            logging.getLogger().setLevel(getattr(logging, str(self.opts["log_level"]).upper(), logging.INFO))
        if "history_days" in changed and int(changed["history_days"]) < int(old.get("history_days") or 0):
            self.store.prune(now - int(self.opts["history_days"]) * DAY)
            self.logs.prune(now - int(self.opts["history_days"]) * DAY)
            notes.append("older history has been removed")
        if {"vuln_checks", "vuln_min_score", "vuln_linux_source"} & changed.keys():
            self._vf.clear()
            task = getattr(self, "_vulns_task", None)
            if task:  # fetch what the new settings need now, then work every device out again
                task.cancel()
                self._vulns_task = asyncio.create_task(self.vulns_loop(first_wait=1, reeval=True))
        if "software_updates" in changed and bool(changed["software_updates"]) != bool(old.get("software_updates", True)):
            task = getattr(self, "_winget_task", None)
            if task:
                task.cancel()
                self._winget_task = asyncio.create_task(self.winget_loop())
        thresholds = {"cert_warn_days", "cert_crit_days", "agent_disk_warn", "agent_disk_crit", "agent_memory_warn", "agent_memory_crit", "agent_cpu_warn", "agent_cpu_reports", "agent_patch_days",
                      "agent_laps_overdue_days", "agent_bitlocker_require", "agent_sql_backup_hours",
                      "agent_exchange_queue_warn", "agent_time_warn_seconds", "agent_time_crit_seconds", "agent_failed_logons", "agent_event_watch", "agent_security_alert_ids",
                      "agent_watch_services", "agent_ignore", "ups_runtime_warn_minutes", "ups_runtime_crit_minutes",
                      "ups_load_warn", "printer_supply_warn", "agent_secret_scan"}
        if thresholds & changed.keys():
            notes.append("new limits apply from each device's next check or agent report")
        return notes

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
                self.rollout_watch(now)
                await self.email_summary_tick(now)
                await self.db_health_tick(now)
                if not self._pub_all or self._pub_all.done():  # in the background: a slow Home Assistant mustn't hold up checks
                    self._pub_all = asyncio.create_task(self._publish_all())
            if now - last_prune >= 3600:
                last_prune = now
                self.store.prune(now - int(self.opts["history_days"]) * DAY)
                self.logs.prune(now - int(self.opts["history_days"]) * DAY)
                try:
                    self.metrics.rollup(now, int(self.opts.get("metrics_days") or 365))
                except sqlite3.Error as e:
                    log.warning("Couldn't tidy the metrics history: %s", e)
            for h in list(self.hosts.values()):
                if h.alert_held and now - h.alert_held[1] >= self.PARENT_WAIT:
                    await self.settle_held(h, now)
            if self.agents:
                await self.check_stale_agents(now)
        return last_publish, last_prune

    async def check(self, h: Host) -> None:
        try:
            if h.check_by == "agent":
                # Up while its agent reports on time: for devices that report over the internet
                # and can't be pinged. Late (more than 2 runs) is amber; past agent_stale_minutes, down.
                now = time.time()
                age = now - h.agent_seen if h.agent_seen else None
                late, stale = 11 * 60, max(int(self.opts["agent_stale_minutes"]) * 60, 12 * 60)
                if os.environ.get("PM_AGENT_LATE"):  # for testing
                    late, stale = (int(x) for x in os.environ["PM_AGENT_LATE"].split(","))
                ok, latency, ip = age is not None and age <= late, None, await self._agent_host_ip(h)
                h.ip = ip or h.ip
                h.via_agent = ok
                h.last_check = now
                h.latency = None
                h.failures = 0 if ok else (1 if age is None or age <= stale else 2)  # never reported: amber, not a down alert
                old = h.status
                pinged = ok
                reason = "agent_never" if age is None else "agent_late"
            else:
                async with self.sem:
                    ip = await resolve(h.host)
                    if ip:
                        if ip != h.ip and self.syslog_unknown:
                            h.ip = ip
                            self.syslog_sweep()  # syslog that arrived before this name was looked up
                        h.ip = ip
                        ok, latency = await ping(
                            ip, int(self.opts["ping_count"]), int(self.opts["ping_timeout"]),
                            [s.port for s in h.services if s.port and not s.target and s.kind not in ("cert", "sip")],
                        )
                    else:
                        ok, latency = False, None
                now = time.time()
                pinged = ok
                if pinged:
                    h.ping_seen = now
                # Automatic: a device whose agent reported in the last 10 minutes is up even if it
                # doesn't answer ping (e.g. a laptop reporting over the internet, or ICMP blocked).
                h.via_agent = bool(not ok and h.check_by == "auto" and h.agent_id and h.agent_seen
                                   and now - h.agent_seen <= AGENT_FRESH)
                if h.via_agent:
                    ok = True
                h.last_check = now
                h.latency = latency if ok and not h.via_agent else None
                h.failures = 0 if ok else h.failures + 1
                old = h.status
                reason = "unresolved" if ip is None else ("down_agent" if h.check_by == "auto" and h.agent_id else "down")

            on, since, _next = schedule_state(h.schedule, now)
            if h.expect_off:
                # Only switched on now and then: being off is normal, and it's "on" while it answers.
                on = bool(ok)
                # Already up before an add-on restart (its status was restored): no fresh start-up allowance
                since = (h.sched_started or (now - 86400 if h.status in (GREEN, DEGRADED) else now)) if ok else None
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
                alive = ok
                if (h.check_by == "auto" and h.via_agent and h.ping_seen
                        and h.ping_seen >= (h.maint_started or now) - 900):
                    # It normally answers ping, so a missed ping means it's restarting, even though
                    # its agent reported a few minutes ago; and it's back when ping answers again.
                    alive = pinged
                if not alive and not h.maint_seen_down:
                    h.maint_seen_down = True
                    self._save_maint()
                    log.info("%s: stopped answering during maintenance", h.name)
                if alive and h.maint_seen_down:
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
            was_unreachable = h.unreachable
            blocker, sure = self.upstream(h) if new in (AMBER, RED) and h.parent else (None, False)
            h.unreachable, h.upstream_down = bool(sure), blocker.key if sure else ""
            if h.unreachable and new == RED:
                h.alert_held = None
            h.status = new
            prev_end, starting = h.startup_end, startup_until(h, now)
            retry = (new == AMBER or (new == MAINT and not h.off_schedule)
                     or any(s.status == AMBER for s in h.services)
                     or (starting and any(s.status == MAINT for s in h.services)))
            h.next_due = now + (min(self.retry_interval, self.interval) if retry else self.interval)
            if starting and any(s.status == MAINT for s in h.services + h.agent_checks):
                h.next_due = min(h.next_due, starting + 1)  # check again as soon as its allowance ends
            h.startup_end = starting
            if prev_end and not starting and any(s.status == MAINT for s in h.agent_checks):
                await self.reevaluate(h)  # allowance over: anything the agent still finds wrong alerts now
            if h.maint_until and not h.maint_seen_down:
                h.next_due = min(h.next_due, now + 5)  # paused until it's back: check often, so a quick restart isn't missed
            nxt = schedule_state(h.schedule, now)[2] if h.schedule else None
            if nxt and now < nxt < h.next_due:
                h.next_due = nxt + 1  # check as soon as its window opens or closes
            if new != old:
                h.last_change = now
                log.info("%s (%s): %s -> %s%s", h.name, h.ip or h.host, old, new,
                         f" (unreachable: {blocker.name} is down)" if h.unreachable else "")
                await self.on_change(h, old, new, reason)
            else:
                log.debug("%s (%s): %s, %s ms", h.name, h.ip or h.host, new, latency)
                if new == RED and was_unreachable and not h.unreachable and not h.alert_held:
                    # Its upstream device is back, but it isn't: now it gets its own down alert
                    # (or, if that device has only just missed a check again, after its next one).
                    if blocker:
                        h.alert_held = (reason, now)
                    else:
                        await self._alert_down(h, reason)
            await self.publish(h)
            if old == RED and new in (GREEN, DEGRADED):
                for d in self.descendants(h):  # back up: see straight away which devices behind it are too
                    if d.unreachable and not d.checking:
                        d.next_due = min(d.next_due, now + 1)
            for c in self.children(h):
                if c.alert_held:
                    await self.settle_held(c, now)
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
            if s.kind == "hadev":
                return await self.hadev_check(h, now)
            if s.kind == "ilo":
                return await self.ilo_check(h, now)
            if s.kind == "jellyfin":
                return await self.jellyfin_check(h)
            if s.kind == "plex":
                return await self.plex_check(h)
            if s.kind == "starlink":
                return await self.starlink_check(h)
            async with self.sem:
                if s.kind == "cert":
                    ip = await resolve(s.target) if s.target else h.ip
                    if not ip:
                        return False, None, f"can't resolve {s.target}"
                    s.resolved = ip if s.target else None
                    return await certcheck.check(ip, s.port, s.target or h.host, int(self.opts["cert_warn_days"]),
                                                 int(self.opts["cert_crit_days"]), self.svc_timeout)
                if s.kind == "sip":
                    ip = await resolve(s.target) if s.target else h.ip
                    if not ip:
                        return False, None, f"can't resolve {s.target}"
                    s.resolved = ip if s.target else None
                    return await sipcheck.check(ip, s.port, self.svc_timeout)
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
        starting = startup_until(h, now)
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
            if not ok and starting:
                # Just switched on (or its window just opened): give it time to start before alerting.
                # Once the allowance is over, the next failed check alerts straight away.
                new, s.failures = MAINT, 1
                s.detail = f"starting up: {detail}"
            self.store.add(svc_key(h, s), now, MAINT_OK if new == MAINT else ok, s.latency)
            turned_red = new == RED and s.status != RED
            if new != s.status:
                old, s.status, s.last_change = s.status, new, now
                log.info("%s %s (%s): %s -> %s [%s]", h.name, s.label, s.desc, old, new, detail)
                await self.on_service_change(h, s, old, new)
            elif s.kind == "snmp" and new == RED and h.vpn_polled:
                await self._vpn_more_down(h, s)
            if s.kind == "snmp":
                down = {i["what"] for i in h.snmp_items if i["level"] == "crit" and not i.get("acked") and not i.get("ignored") and i["what"].startswith(("VPN ", "RED "))}
                if new == RED and not turned_red and h.vpn_polled and self.opts.get("notify_recovery"):
                    for what in sorted(h.vpn_alerted - down):  # back up while another is still down
                        await self.notify(f"🟢 {h.name}: {what} back up", f"{h.name}: {what} is up again.",
                                          f"ping_monitor_{svc_key(h, s)}__{re.sub(r'[^a-z0-9]+', '_', what.lower())}", cat="network")
                # Down when it went red: covered by that alert. Back up: alerts again if it drops again.
                # First poll since the add-on started, already red: those were alerted before the restart.
                h.vpn_alerted = set() if new != RED else down if turned_red or not h.vpn_polled else h.vpn_alerted & down
                h.vpn_down_prev, h.vpn_polled = down, True

    @staticmethod
    def _snmp_per(prev: dict | None) -> int:
        """Rows per request: what worked last time, doubled after a poll without timeouts, up to the
        most this device has coped with (so a device that dropped large requests isn't pushed again)."""
        if not prev:
            return 25
        per = int(prev.get("per") or 25)
        if not prev.get("timeouts"):
            per *= 2
        return max(1, min(per, int(prev.get("per_cap") or 25), 25))

    async def hadev_check(self, h: Host, now: float) -> tuple:
        """The linked Home Assistant device: its entities, with problems picked out (see hadevice.py)."""
        if not h.ha_device:
            return False, None, "no Home Assistant device linked (Edit to link one)", "warn"
        reg = await self.ha.registry()
        states = await self.ha.states_map()
        if reg is None or states is None:
            return False, None, "couldn't read Home Assistant", "warn"
        dev = reg["devices"].get(h.ha_device)
        if not dev:
            h.ha_data = None
            return False, None, f"the linked device ({h.ha_device_name or h.ha_device}) is no longer in Home Assistant", "warn"
        parts, missing = [(dev, reg["entities"].get(h.ha_device, []))], []
        for x in h.ha_more:
            more = reg["devices"].get(x["id"])
            if more:
                parts.append((more, reg["entities"].get(x["id"], [])))
            else:
                missing.append(x.get("name") or x["id"])
        d = hadevice.read_many(parts, states, missing)
        d["read"] = now
        h.ha_data = d
        h.ha_device_name = d["devices"][0]["device"]["name"] or h.ha_device_name
        for x, part in zip([y for y in h.ha_more if reg["devices"].get(y["id"])], d["devices"][1:]):
            x["name"] = part["device"]["name"] or x.get("name") or ""
        worst = "crit" if any(i["level"] == "crit" for i in d["items"]) else "warn" if any(i["level"] == "warn" for i in d["items"]) else "ok"
        if worst == "ok":
            return True, None, d["summary"]
        detail = "; ".join(f"{i['what']}: {i['detail']}" if i["detail"] else i["what"] for i in d["items"] if i["level"] == worst)
        return (False, None, detail[:240]) + (("warn",) if worst == "warn" else ())

    def snmp_eval(self, h: Host, d: dict, prev: dict | None, watch: set | None = None, prune: bool = False) -> tuple:
        """snmplib.evaluate, then the problems someone acknowledged: marked acked and left out of the
        worst level while they're there and no worse (its figures may change, e.g. a UPS's runtime). If
        one gets worse (amber to red, e.g. non-critical to critical) it shows again. prune (after a real
        poll): forget acknowledgements of problems that have cleared, so they alert if they come back."""
        worst, items = snmplib.evaluate(d, set(h.snmp_watch) if watch is None else watch, prev, self.ups_limits(h),
                                        h.snmp_restart_ack, vpn_ignore=set(h.snmp_vpn_ignore))
        acks = h.snmp_acks or {}
        ignore = {x.lower() for x in h.snmp_ignore}
        for i in items:
            if i["what"] != "SNMP" and i["what"].lower() in ignore:
                i["ignored"] = True  # never alerts here, e.g. a server that's often meant to be off
            elif i.get("ack") != "restart" and (acks.get(i["what"]) == i["level"] or acks.get(i["what"]) == "crit"):
                i["acked"] = True
        if prune:
            keep = {i["what"]: acks[i["what"]] for i in items if i.get("acked")}
            if keep != acks:
                h.snmp_acks = keep
                self._save_hosts()
        live = [i for i in items if not i.get("acked") and not i.get("ignored")]
        worst = "crit" if any(i["level"] == "crit" for i in live) else "warn" if live else "ok"
        return worst, items

    def ups_limits(self, h: "Host | None" = None) -> dict:
        """The add-on's UPS and printer limits, with this device's own UPS limits on top."""
        return {**self.ups_defaults(), **((h.ups_limits or {}) if h else {})}

    def ups_defaults(self) -> dict:
        o = self.opts
        return {"runtime_warn": int(o.get("ups_runtime_warn_minutes", 15)), "runtime_crit": int(o.get("ups_runtime_crit_minutes", 5)),
                "load_warn": int(o.get("ups_load_warn", 80)), "supply_warn": int(o.get("printer_supply_warn", 10))}

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
                                  v3=v3, version=1 if h.snmp_version == "1" else 2,
                                  per=self._snmp_per(prev),
                                  discovery=None if h.snmp_rediscover else (prev or {}).get("discovery"),
                                  ask_hr=(prev or {}).get("hr") is not False,  # stop asking a device that didn't answer
                                  port=int(os.environ.get("PM_SNMP_PORT", "161")))  # port: for testing
        except (snmplib.SnmpError, OSError) as err:
            h.snmp_items = [{"level": "crit", "what": "SNMP", "detail": str(err)}]
            return False, None, str(err)
        # Remember the most rows per request this device copes with, so it isn't pushed past it again.
        if d.get("timeouts"):
            d["per_cap"], d["per_cap_at"] = d["per"], now
        elif prev and prev.get("per_cap") and now - (prev.get("per_cap_at") or 0) < 6 * 3600:
            d["per_cap"], d["per_cap_at"] = prev["per_cap"], prev.get("per_cap_at")  # retried after 6 hours
        snmplib.red_activity(d, prev)
        h.snmp_data, h.snmp_polled = d, now
        h.snmp_rediscover = False
        worst, items = self.snmp_eval(h, d, prev, prune=True)
        h.snmp_items = items
        if worst == "ok":
            bits = []
            if d.get("ports"):
                bits.append(f"{sum(1 for p in d['ports'] if p['up'])} of {len(d['ports'])} ports up")
            if d.get("poe") and d["poe"].get("used_w") is not None:
                bits.append(f"PoE {d['poe']['used_w']}/{d['poe']['power_w']} W")
            if d.get("nas"):
                bits.append(f"{len(d['nas'].get('disks') or [])} disks OK")
            vpn = [v for v in ((d.get("vpn") or {}).get("tunnels") or []) if v.get("active")]
            if vpn:
                bits.append(f"{sum(1 for v in vpn if v.get('up'))} of {len(vpn)} VPNs up")
            u = d.get("ups")
            if u and not u.get("error"):
                bits.append(", ".join(x for x in (
                    f"UPS {u['output']}" if u.get("output") else "UPS",
                    f"battery {u['charge_pct']}%" if u.get("charge_pct") is not None else "",
                    f"{u['runtime_min']} min runtime" if u.get("runtime_min") is not None else "",
                    f"load {u['load_pct']}%" if u.get("load_pct") is not None else "") if x))
            acked = [i["what"] for i in items if i.get("acked")]
            if acked:
                bits.append("acknowledged: " + ", ".join(acked))
            ignored = [f"{i['what']} {i['detail']}" for i in items if i.get("ignored")]
            if ignored:
                bits.append("ignored: " + ", ".join(ignored))
            return True, d.get("took_ms"), "; ".join(bits) or "answering"
        detail = "; ".join(f"{i['what']} {i['detail']}".strip() for i in items if i["level"] == worst and not i.get("acked") and not i.get("ignored"))
        return (False, None, detail[:240]) + (("warn",) if worst == "warn" else ())

    ILO_EVERY = 300          # read an iLO at most every 5 minutes: its health takes it a few seconds to gather
    ILO_LOGIN_RETRY = 1800   # after it turned the login down, so its security log isn't filled with failures

    def ilo_eval(self, h: Host, d: dict, prune: bool = False) -> tuple[str, list]:
        """ilolib.evaluate, then what someone acknowledged or ignored, as for SNMP: an acknowledged
        problem doesn't count while it's there and no worse; an ignored one never alerts here.
        prune (after a real reading): forget acknowledgements of problems that have cleared."""
        items = ilolib.evaluate(d)
        acks, ignore = h.ilo_acks or {}, {x.lower() for x in h.ilo_ignore}
        for i in items:
            if i["what"].lower() in ignore:
                i["ignored"] = True
            elif acks.get(i["what"]) == i["level"] or acks.get(i["what"]) == "crit":
                i["acked"] = True
        if prune:
            keep = {i["what"]: acks[i["what"]] for i in items if i.get("acked")}
            if keep != acks:
                h.ilo_acks = keep
                self._save_hosts()
        live = [i for i in items if not i.get("acked") and not i.get("ignored")]
        return ("crit" if any(i["level"] == "crit" for i in live) else "warn" if live else "ok"), items

    def ilo_result(self, h: Host) -> tuple:
        """The check result from the last reading, with acknowledgements as they are now."""
        d = h.ilo_data or {}
        worst, items = self.ilo_eval(h, d)
        h.ilo_items = items
        if worst == "ok":
            bits = [ilolib.summary(d)]
            acked = [i["what"] for i in items if i.get("acked")]
            if acked:
                bits.append("acknowledged: " + ", ".join(acked))
            ignored = [f"{i['what']} {i['detail']}" for i in items if i.get("ignored")]
            if ignored:
                bits.append("ignored: " + ", ".join(ignored))
            return True, d.get("took_ms"), "; ".join(bits)
        detail = "; ".join(f"{i['what']}: {i['detail']}" for i in items if i["level"] == worst and not i.get("acked") and not i.get("ignored"))
        return (False, None, detail[:240]) + (("warn",) if worst == "warn" else ())

    async def ilo_check(self, h: Host, now: float) -> tuple:
        """An HPE iLO's health (ilo.py), read every ILO_EVERY seconds with its login. A new failure is
        read again at the next check, and goes red only if it's still there."""
        if not h.ilo_user or not h.ilo_pass:
            h.ilo_items = []
            return False, None, "enter the iLO user name and password (Edit)", "warn"
        res = h.ilo_result
        wait = self.ILO_LOGIN_RETRY if h.ilo_err == "login" else self.ILO_EVERY
        if res is not None and h.ilo_polled and now - h.ilo_polled < wait and not h.ilo_recheck:
            if not h.ilo_err and h.ilo_data:
                res = h.ilo_result = self.ilo_result(h)  # acknowledgements may have changed
            return res
        was_red = res is not None and not res[0] and len(res) == 3
        h.ilo_polled = now
        try:
            try:
                d = await ilolib.poll(h.ip or h.host, h.ilo_user, h.ilo_pass, legacy_tls_context(), timeout=60)
            except ilolib.IloError:
                raise
            except Exception as err:  # noqa: BLE001 - anything unexpected is a failed reading, not a stale "OK"
                log.warning("%s: reading the iLO failed: %s", h.name, err)
                raise ilolib.IloError(f"unexpected error ({type(err).__name__})") from err
        except ilolib.IloError as err:
            if err.login:
                h.ilo_err = "login"
                h.ilo_items = [{"level": "warn", "what": "iLO", "detail": str(err)}]
                log.warning("%s: the iLO refused the login; trying again in %d minutes", h.name, self.ILO_LOGIN_RETRY // 60)
                h.ilo_result = (False, None, str(err), "warn")
            else:
                h.ilo_err = "read"
                h.ilo_items = [{"level": "crit", "what": "iLO", "detail": str(err)}]
                h.ilo_result = (False, None, f"can't read the iLO: {err}")
            h.ilo_recheck = not was_red and not err.login
            return h.ilo_result
        h.ilo_err = None
        d["read"] = now
        h.ilo_data = d
        self.ilo_eval(h, d, prune=True)
        h.ilo_result = self.ilo_result(h)
        # Something new has failed: read it again at the next check, and only then does it go red
        h.ilo_recheck = not h.ilo_result[0] and len(h.ilo_result) == 3 and not was_red
        return h.ilo_result

    async def jellyfin_check(self, h: Host) -> tuple:
        """Jellyfin's health (jellyfin.py), read with its API key at each check."""
        if not h.jf_key:
            h.jf_data = None
            return False, None, "enter a Jellyfin API key under Edit", "warn"
        base = h.jf_url or jflib.default_url(h.host)
        try:
            d = await jflib.poll(base, h.jf_key, health_tls_context(), timeout=max(self.svc_timeout, 10))
        except jflib.JellyfinError as err:
            h.jf_data = None
            return (False, None, str(err), "warn") if err.login else (False, None, str(err))
        h.jf_data = d
        return jflib.evaluate(d, await jflib.latest_release())

    async def plex_check(self, h: Host) -> tuple:
        """Plex: what's playing and the server's state (plex.py), read with its token at each check."""
        if not h.px_key:
            h.px_data = None
            return False, None, "enter a Plex token under Edit", "warn"
        base = h.px_url or pxlib.default_url(h.host)
        if h.px_base and pxlib.same_server(h.px_base.replace("https://", "http://", 1), base.replace("https://", "http://", 1)):
            base = h.px_base  # HTTPS answered last time, where plain HTTP was dropped
        try:
            d = await pxlib.poll(base, h.px_key, health_tls_context(), timeout=max(self.svc_timeout, 10))
        except pxlib.PlexError as err:
            h.px_data, h.px_base = None, ""
            return (False, None, str(err), "warn") if err.login else (False, None, str(err))
        h.px_base = d.pop("base", "") or ""
        h.px_data = d
        return pxlib.evaluate(d)

    async def starlink_check(self, h: Host) -> tuple:
        """A Starlink dish (starlink.py): from the dish's local API, or through the Starlink account."""
        try:
            if h.sl_source == "account":
                if not h.sl_cookie:
                    h.sl_data = None
                    return False, None, "paste the starlink.com sign-in under Edit", "warn"
                if not h.sl_dish:
                    h.sl_data = None
                    return False, None, "choose the dish under Edit", "warn"
                acct = sllib.Account(h.sl_cookie, h.sl_state, health_tls_context())
                try:
                    async with ClientSession() as session:
                        d = await acct.status(session, h.sl_dish)
                except sllib.StarlinkError as err:
                    # What starlink.com answered, step by step: status codes and cookie names only, never values
                    log.warning("Starlink account for %s: %s [%s]", h.name, err, "; ".join(acct.trace[-12:]))
                    raise
                finally:
                    if acct.changed and acct.cookie != h.sl_cookie:  # starlink.com renewed part of it: keep that
                        h.sl_cookie = acct.cookie
                        self._save_hosts()
            else:
                d = await sllib.read_local(h.sl_addr or sllib.DEFAULT_ADDR, timeout=max(self.svc_timeout, 10))
        except sllib.StarlinkError as err:
            h.sl_data = None
            return (False, None, str(err), "warn") if err.login else (False, None, str(err))
        d["read_at"] = int(time.time())
        h.sl_data = d
        return sllib.evaluate(d)

    async def starlink_map(self, h: Host, fresh: bool = False) -> dict:
        """The dish's obstruction map, read at most every few minutes (it's a bigger answer than the status, and
        changes slowly), with a summary in words. Raises StarlinkError."""
        if h.sl_map and not fresh and time.time() - h.sl_map_at < self.SL_MAP_EVERY:
            return h.sl_map
        if h.sl_source == "account":
            if not h.sl_cookie or not h.sl_dish:
                raise sllib.StarlinkError("the Starlink account isn't set up under Edit")
            acct = sllib.Account(h.sl_cookie, h.sl_state, health_tls_context())
            try:
                async with ClientSession() as session:
                    m = await acct.obstruction_map(session, h.sl_dish)
            finally:
                if acct.changed and acct.cookie != h.sl_cookie:
                    h.sl_cookie = acct.cookie
                    self._save_hosts()
        else:
            m = await sllib.read_map_local(h.sl_addr or sllib.DEFAULT_ADDR, timeout=max(self.svc_timeout, 15))
        al = (h.sl_data or {}).get("alignment") or {}
        m["summary"] = sllib.map_summary(m, al.get("az", 0.0) if m["frame"] == "dish" else 0.0)
        m["read_at"] = int(time.time())
        h.sl_map, h.sl_map_at = m, time.time()
        return m

    SL_MAP_EVERY = 300

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
                    tag, level="ok", cat="devices",
                )
            return
        if new == RED and old != RED:
            h.down_since = h.last_check
            if h.unreachable:
                h.down_quiet = True  # the upstream device's alert covers it
                return
            p = self.hosts.get(h.parent) if h.parent else None
            if p and not h.alert_held and (self.upstream(h)[0] or p.checking or p.status == UNKNOWN
                                           or (p.last_check or 0) < (h.last_check or 0) - 30):
                # Its upstream device hasn't been checked just now: hear from it first, so a router
                # going down sends one alert rather than one for every device behind it.
                h.alert_held, h.down_quiet = (reason, h.last_check or time.time()), True
                if not p.checking:
                    p.next_due = 0
                log.info("%s: holding its down alert until %s has been checked", h.name, p.name)
                return
            await self._alert_down(h, reason)
        elif old == RED and new in (GREEN, DEGRADED):
            h.alert_held = None
            quiet, h.down_quiet = h.down_quiet, False
            if quiet:  # never alerted as down (it was behind a device that was down)
                h.down_since = None
                return
            await self.dismiss(tag)
            if self.opts["notify_recovery"]:
                dur = f" after {fmt_duration(h.last_check - h.down_since)}" if h.down_since else ""
                await self.notify(
                    f"🟢 {h.name} is back up",
                    f"{h.name} ({h.ip or h.host}) is responding again{dur}.",
                    tag, cat="devices",
                )
            h.down_since = None

    async def _alert_down(self, h: Host, reason: str) -> None:
        """The down alert for a device, listing the devices behind it."""
        tag = f"ping_monitor_{h.key}"
        h.down_quiet = False
        why = {
            "unresolved": "Hostname could not be resolved.",
            "maint_timeout": "It did not reply before the maintenance window ended.",
            "sched_timeout": "It didn't come up after its monitoring window started.",
            "down_agent": "No reply to ping, and its agent hasn't reported for over 10 minutes.",
            "agent_late": f"Its agent hasn't reported for over {max(int(self.opts['agent_stale_minutes']), 12)} minutes.",
            "agent_never": "Its agent hasn't reported yet.",
        }.get(reason, "No reply to ping on two consecutive checks.")
        p = self.hosts.get(h.parent) if h.parent else None
        if p and p.status in (GREEN, DEGRADED) and reason in ("down", "down_agent", "sched_timeout"):
            why += f" {p.name}, which it's reached through, is answering."
        msg = f"{h.name} ({h.ip or h.host}) is DOWN. {why}"
        behind = [d for d in self.descendants(h) if not d.maint_until and not d.off_schedule]
        if behind:
            names = [d.name for d in sorted(behind, key=lambda d: d.name.lower())]
            shown = ", ".join(names[:10]) + (f" and {len(names) - 10} more" if len(names) > 10 else "")
            msg += f" Devices behind it may also be affected ({len(names)}): {shown}."
        await self.notify(f"🔴 {h.name} is down", msg, tag, critical=h.critical, cat="devices")
        await self.persist(tag, f"Rollcall: {h.name} is down", msg)

    async def _vpn_more_down(self, h: Host, s: Service) -> None:
        """A firewall already alerting: another of its VPN connections has gone down (seen on two polls
        in a row, like the first), so it gets its own alert rather than going unnoticed."""
        down = {i["what"] for i in h.snmp_items if i["level"] == "crit" and not i.get("acked") and not i.get("ignored") and i["what"].startswith(("VPN ", "RED "))}
        for what in sorted((down & h.vpn_down_prev) - h.vpn_alerted):
            msg = f"{h.name} ({h.ip or h.host}): {what} is down."
            tag = f"ping_monitor_{svc_key(h, s)}__{re.sub(r'[^a-z0-9]+', '_', what.lower())}"
            await self.notify(f"🟠 {h.name}: {what} down", msg, tag, critical=h.critical, cat="network")
            h.vpn_alerted.add(what)

    async def on_service_change(self, h: Host, s: Service, old: str, new: str) -> None:
        await self.ha.fire("ping_monitor_service_changed", {
            "name": h.name, "host": h.host, "ip": h.ip, "service": s.label, "target": s.desc,
            "old_status": old, "new_status": new, "detail": s.detail,
            "entity_id": svc_entity(h, s), "host_entity_id": h.entity_id,
        })
        tag = f"ping_monitor_{svc_key(h, s)}"
        cat = self._email_cat(s)
        if new == RED and s.kind == "cert":
            msg = f"{h.name} ({h.ip or h.host}) port {s.port}: certificate {s.detail}"
            await self.notify(f"🟠 {h.name}: certificate expiring", msg, tag, cat=cat)
            await self.persist(tag, f"Rollcall: {h.name} certificate", msg)
            return
        if old == RED and new == GREEN and s.kind == "cert":
            await self.dismiss(tag)
            if self.opts["notify_recovery"]:
                await self.notify(f"🟢 {h.name}: certificate renewed", f"{h.name} port {s.port}: {s.detail}.", tag, cat=cat)
            return
        if new == RED and s.kind == "syslog":
            msg = f"{h.name} ({h.ip or h.host}) logged {s.detail}"
            await self.notify(f"🟠 {h.name}: syslog alert", msg, tag, cat=cat)
            await self.persist(tag, f"Rollcall: {h.name} syslog", msg)
            return
        if old == RED and new == GREEN and s.kind == "syslog":
            await self.dismiss(tag)
            return
        if new == RED and s.kind in ("snmp", "ilo"):
            msg = f"{h.name} ({h.ip or h.host}): {s.detail}."
            await self.notify(f"🟠 {h.name}: {str(s.detail).split(';')[0]}", msg, tag, critical=h.critical, cat=cat)
            await self.persist(tag, f"Rollcall: {h.name} {'SNMP' if s.kind == 'snmp' else 'iLO'}", msg)
            return
        if old == RED and new == GREEN and s.kind in ("snmp", "ilo"):
            await self.dismiss(tag)
            if self.opts["notify_recovery"]:
                await self.notify(f"🟢 {h.name}: OK again", f"{h.name}: {s.detail}.", tag, cat=cat)
            return
        if new == RED and s.kind == "ha":
            msg = f"{s.label} on {h.name} is {s.detail} ({s.entity})."
            await self.notify(f"🟠 {h.name}: {s.label} {str(s.detail).split(' (')[0]}", msg, tag, critical=h.critical, cat=cat)
            await self.persist(tag, f"Rollcall: {h.name} {s.label}", msg)
        elif old == RED and new == GREEN and s.kind == "ha":
            await self.dismiss(tag)
            if self.opts["notify_recovery"]:
                await self.notify(f"🟢 {h.name}: {s.label} OK", f"{s.label} on {h.name} is back to {s.detail}.", tag, cat=cat)
        elif new == RED:
            msg = (f"{h.name} ({h.ip or h.host}) is up, but {s.label} ({s.desc}) "
                   f"is not responding: {s.detail}.")
            await self.notify(f"🟠 {h.name}: {s.label} is down", msg, tag, critical=h.critical, cat=cat)
            await self.persist(tag, f"Rollcall: {h.name} {s.label} is down", msg)
        elif old == RED and new == GREEN:
            await self.dismiss(tag)
            if self.opts["notify_recovery"]:
                await self.notify(f"🟢 {h.name}: {s.label} is back up",
                                  f"{s.label} ({s.desc}) on {h.name} is responding again.", tag, cat=cat)

    def _quiet(self, tag: str | None) -> bool:
        """Notifications for a device set to never alert are dropped here, in one place.
        Every per-computer tag is ping_monitor_<key> or ping_monitor_<key>__<what>."""
        if not tag or not tag.startswith("ping_monitor_"):
            return False
        h = self.hosts.get(tag[len("ping_monitor_"):].split("__")[0])
        return bool(h and h.no_alerts)

    @staticmethod
    def _email_cat(s: "Service") -> str:
        """Which email category (Settings, Email alerts) a check's alerts belong to."""
        if s.kind == "agent":
            k = s.key.removeprefix("agent_")
            return "backups" if k == "backups" else "security" if k in SECURITY_CHECKS else "agents"
        return "network" if s.kind in ("snmp", "syslog", "vpn", "ilo") else "services"

    async def notify(self, title: str, message: str, tag: str | None = None, critical: bool = False,
                     level: str | None = None, cat: str | None = None) -> None:
        """critical: sent to the Home Assistant app as a critical alert, which gets through a silenced
        phone (a device marked Critical, for problems only, never "back up").
        level, for email: red (emailed now), ok (back up), amber or event (in the daily summary), info.
        Left out, it's ok for a 🟢 title, info for ⬆️, else red."""
        if self._quiet(tag):
            return
        if level is None:
            level = "ok" if title.startswith("🟢") else "info" if title.startswith("⬆") else "red"
        self.email.alert(title, message, level, cat)
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
                if critical:
                    # iPhone: a critical alert plays even when muted or on Do Not Disturb.
                    data["push"] = {"sound": {"name": "default", "critical": 1, "volume": 1.0}, "interruption-level": "critical"}
                    # Android: delivered at once and played on the alarm stream, so it sounds on silent.
                    data.update(ttl=0, priority="high", channel="alarm_stream")
                payload["data"] = data
            await self.ha.service("notify", svc, payload)

    # -- Agents ------------------------------------------------------------
    LEVEL_STATUS = {agentlib.OK: GREEN, agentlib.WARN: AMBER, agentlib.CRIT: RED}

    # -- Built-in HTTPS for agents (agenttls.py) ----------------------------------
    def tls_builtin(self) -> bool:
        """Rollcall's own HTTPS is on (and the agent port isn't HTTPS with your own certificate instead)."""
        return AGENT_TLS.on and not self.opts.get("agent_ssl")

    def tls_hosts(self) -> set[str]:
        """The addresses agents reach Rollcall by over plain HTTP: the certificate lists them (for the router agent,
        which checks names; the others check the key)."""
        out = set()
        urls = list(self.agent_servers() or [])
        r = self.agent_route() or {}
        urls += [r.get("inside") or "", r.get("outside") or ""]
        urls += [a.get("sent_to") or "" for a in (self.agents.agents.values() if self.agents else [])]
        for u in urls:
            try:
                p = urlparse(str(u))
            except ValueError:
                continue
            if p.scheme == "http" and p.hostname:
                out.add(p.hostname.lower())
        return out

    async def tls_refresh(self) -> None:
        """New addresses turned up: remake the certificate (same key) and restart the HTTPS listener."""
        try:
            if self.tls_builtin() and await asyncio.to_thread(AGENT_TLS.ensure_cert, self.tls_hosts()) and getattr(self, "agent_listener", None):
                log.info("Agent HTTPS certificate now lists: %s", ", ".join(AGENT_TLS.names()))
                await self.agent_listener.set_builtin(True)
        except Exception as err:  # noqa: BLE001
            log.warning("Couldn't update the agent HTTPS certificate: %s", err)

    def tls_reply(self, agent: dict) -> dict:
        """For the reply to a report: the HTTPS port and key, signed with the update key agents already trust, so
        it can't be changed on the way; the router agent (which can't check either) gets the certificate itself."""
        port = getattr(self, "tls_public_port", AGENT_HTTPS_PORT)
        if not self.tls_builtin() or not port:
            return {}  # off, or its port isn't mapped (Configuration → Network): agents stay as they are
        out = {"tls": {"port": int(port), "pin": AGENT_TLS.pin()}}
        try:
            out["tls_sig"] = SIGNER.sign(agenttls.tls_text(int(port), AGENT_TLS.pin()))
        except Exception as err:  # noqa: BLE001
            log.warning("Couldn't sign the agent HTTPS details: %s", err)
            return {}
        if agent.get("agent_kind") == "sh":
            out["tls_cert"] = AGENT_TLS.cert_pem()
        return out

    # -- Messages to users' screens (messages.py) ---------------------------------
    def messages_for(self, agent: dict) -> list[dict]:
        """What this agent's device should show now, signed, for the reply to its report (empty unless the
        messages option is on and an admin has included the device)."""
        if not self.opts.get("messages") or agent.get("os_family") not in ("windows", "linux") or agent.get("agent_kind") == "sh":
            return []
        out = []
        for m in self.messages.pending(agent.get("host_key") or ""):
            try:
                out.append({"id": m["id"], "text": m["text"], "expires": int(m["expires"]), "sig": SIGNER.sign(msglib.signed_text(m))})
            except Exception as err:  # noqa: BLE001
                log.warning("Couldn't sign a message: %s", err)
        return out[:3]

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
                await self._apply(h, agent, agentlib.normalize_report(saved["report"]), saved.get("received") or time.time(), restoring=True,
                                  failures=saved.get("failures"))  # None: saved by an older version
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
                        "defender", "security", "events", "immich", "storage", "hardware", "backups", "laps", "bitlocker", "certs", "tasks", "sql", "gpo", "sysvol", "exchange", "domain", "nics", "secrets", "integrity")

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
        self.publish_soon(h)

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

    def same_computer(self, h: Host) -> Host | None:
        """For an entry without an agent: another entry whose agent is on the same device
        (by name or address), e.g. one added for ping before the agent was installed."""
        if h.agent_id or not self.agents:
            return None
        for o in self.hosts.values():
            a = self.agents.agents.get(o.agent_id or "")
            if o is h or not a:
                continue
            ips = set(a.get("ips") or [])
            if self._name_match(h, a) or h.host in ips or (h.ip and h.ip in ips):
                return o
        return None

    async def merge_agent_into(self, h: Host, other: Host, who: str | None = None) -> None:
        """Move the agent from `other` onto `h`, the entry without one, then remove `other`.
        h keeps its name, address, history and Home Assistant entities; it gains other's checks
        and agent settings (ignores, filters, acknowledgements) and its graphs."""
        agent = self.agents.agents.get(other.agent_id or "")
        if h.agent_id or not agent:
            raise ValueError("only an entry without an agent can take one over")
        entry = self._entry(h)
        entry["checks"] = list(h.checks) + [c for c in other.checks if c not in h.checks]
        for k in ("schedule", "icon", "model", "group"):
            if not entry.get(k) and getattr(other, k):
                entry[k] = getattr(other, k)
        hs = self.agent_settings["hosts"]
        moved = hs.pop(other.key, None)
        if moved:
            hs[h.key] = {**moved, **hs.get(h.key, {})}
            self._save_agent_settings()
        saved = self.agents.load_report(agent["id"]) or {}
        was = {c.key: c for c in other.agent_checks}  # their state carries over: nothing re-alerts
        await self._unlink(other)
        try:
            self.metrics.rename(other.key, h.key)
        except sqlite3.Error as e:
            log.warning("Couldn't move the graphs from %s: %s", other.name, e)
        await self.update_host(h, entry)
        h.agent_id, agent["host_key"] = agent["id"], h.key
        self.agents.save()
        await self.delete_host(other)
        if saved.get("report"):
            h.agent_history = saved.get("history") or h.agent_history
            await self._apply(h, agent, agentlib.normalize_report(saved["report"]), saved.get("received") or time.time(),
                              restoring=True)
            for c in h.agent_checks:
                if c.key in was:
                    for f in ("status", "detail", "last_change", "last_check", "failures"):
                        setattr(c, f, getattr(was[c.key], f))
            await self._recompute(h, quiet=True)
        self._save_hosts()
        self.publish_soon(h)
        log.info("Merged %s into %s: its agent now reports to %s (by %s)", other.name, h.name, h.name, who or "someone")

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
                self.publish_soon(h)
        log.info("Revoked the agent on %s", agent["hostname"])
        return agent

    async def receive_report(self, agent: dict, report: dict, source_ip: str | None, forwarded_for: str | None = None) -> None:
        now = time.time()
        acks = report.pop("messages_shown", None) if isinstance(report, dict) else None  # which messages it showed
        if acks is not None and agent.get("host_key"):
            self.messages.record(agent["host_key"], acks, now)
        raw_sec = report.get("secrets") if isinstance(report, dict) else None
        findings = raw_sec.get("findings") if isinstance(raw_sec, dict) else None  # kept apart: the tidy-up below drops them
        report = agentlib.normalize_report(report)
        sent_to = str(report.get("sent_to") or "")[:200]
        if sent_to.startswith("http://") and self.tls_builtin():
            host = (urlparse(sent_to).hostname or "").lower()
            if host and host not in AGENT_TLS.names():
                asyncio.create_task(self.tls_refresh())
        if sent_to and sent_to != agent.get("sent_to") and agent.get("sent_to"):
            log.info("%s now reports via %s (was %s)", agent.get("hostname"), sent_to, agent.get("sent_to"))
        agent.update(last_report=now, source_ip=source_ip, sent_to=sent_to or agent.get("sent_to"),
                     forwarded_for=(forwarded_for or "")[:60] or None,
                     agent_version=str(report.get("agent_version") or "")[:20],
                     os=str(report.get("os") or "")[:120], os_family=report.get("os_family"), agent_kind=report.get("agent_kind"),
                     ips=[str(i) for i in (report.get("ips") or [])][:8] or agent.get("ips"),
                     roles=[str(r) for r in (report.get("roles") or [])][:30])
        apps, ahash = report.pop("apps", None), str(report.pop("apps_hash", "") or "")[:64]
        sec = report.get("secrets") if isinstance(report.get("secrets"), dict) else None
        if sec is not None:
            if not sec.get("on"):
                self._clear_secrets(agent)
            elif findings is not None:
                self._store_secrets(agent, findings, str(sec.get("hash") or "")[:64], now)
            elif sec.get("hash") and self.secret_findings(agent["id"]).get("hash") != str(sec["hash"])[:64]:
                self.want_secrets.add(agent["id"])  # Rollcall hasn't got these findings: the reply asks for them
        if apps is not None:
            self._store_apps(agent, apps, ahash, now)
        elif ahash and self.software(agent["id"]).get("hash") != ahash:
            self.want_apps.add(agent["id"])  # Rollcall hasn't got this list: the reply asks for it
        h = await self._link(agent, create=True)
        self.agents.save()
        if not h:
            self.agents.save_report(agent["id"], {"report": report, "received": now})
            return
        await self._apply(h, agent, report, now)
        self.agents.save_report(agent["id"], {"report": report, "received": now, "history": h.agent_history,
                                              "failures": {c.key: c.failures for c in h.agent_checks if c.failures}})

    # -- password exposure scan -------------------------------------------
    # Agents send only where a password is (file, line, setting name, length), never the password;
    # clean_secret_finding keeps just those fields whatever arrives.
    def _sec_path(self, agent_id: str) -> Path:
        return SECRETS_DIR / (re.sub(r"[^A-Za-z0-9_-]", "", str(agent_id))[:64] + ".json")

    def secret_findings(self, agent_id: str | None) -> dict:
        """{hash, updated, findings: [{path, line, rule, key, len, first}]} ({} if none)."""
        if not agent_id:
            return {}
        if agent_id not in self._sec:
            try:
                self._sec[agent_id] = json.loads(self._sec_path(agent_id).read_text())
            except (OSError, ValueError):
                self._sec[agent_id] = {}
        return self._sec[agent_id]

    def _store_secrets(self, agent: dict, findings, fhash: str, now: float) -> None:
        clean = []
        for f in findings if isinstance(findings, list) else []:
            c = agentlib.clean_secret_finding(f)
            if c:
                clean.append(c)
            if len(clean) >= 500:
                break
        # When each was first found (what "Ignore all" goes by). A finding keeps its date if it's on the
        # same line as before, or if it has only moved because lines were added or removed above it.
        prev = list(self.secret_findings(agent["id"]).get("findings") or [])
        exact = {}
        for i, f in enumerate(prev):
            exact.setdefault((agentlib.secret_key(f), f.get("line")), []).append(i)
        used, rest = set(), []
        for c in clean:
            hit = next((i for i in exact.get((agentlib.secret_key(c), c["line"]), []) if i not in used), None)
            if hit is None:
                rest.append(c)
            else:
                used.add(hit)
                c["first"] = prev[hit].get("first") or int(now)
        for c in rest:
            hit = next((i for i, f in enumerate(prev) if i not in used and agentlib.secret_key(f) == agentlib.secret_key(c)), None)
            if hit is not None:
                used.add(hit)
            c["first"] = (prev[hit].get("first") if hit is not None else None) or int(now)
        before = len(self.secret_findings(agent["id"]).get("findings") or [])
        self._sec[agent["id"]] = {"hash": fhash, "updated": int(now), "findings": clean}
        self.want_secrets.discard(agent["id"])
        try:
            SECRETS_DIR.mkdir(parents=True, exist_ok=True)
            tmp = self._sec_path(agent["id"]).with_suffix(".tmp")
            tmp.write_text(json.dumps(self._sec[agent["id"]], separators=(",", ":")))
            os.chmod(tmp, 0o600)
            tmp.replace(self._sec_path(agent["id"]))
        except OSError as err:
            log.warning("Couldn't save the password scan findings for %s: %s", agent.get("hostname"), err)
        if len(clean) != before:
            log.info("%s: password scan found %d place%s with a password", agent.get("hostname"), len(clean), "" if len(clean) == 1 else "s")

    def _clear_secrets(self, agent: dict) -> None:
        if self.secret_findings(agent["id"]):
            self._sec[agent["id"]] = {}
            try:
                self._sec_path(agent["id"]).unlink()
            except OSError:
                pass
            log.info("%s: password scan turned off; its findings were removed", agent.get("hostname"))
        self.want_secrets.discard(agent["id"])

    def secret_scan_config(self, agent: dict) -> dict:
        """What the agent is told: scan or not, extra folders, how often. The add-on option picks
        which devices scan by default; each device's details can turn it on or off."""
        h = self.hosts.get(agent.get("host_key") or "")
        hs = (self.agent_settings["hosts"].get(h.key) or {}).get("secret_scan") or {} if h else {}
        mode = hs.get("mode") or "default"
        if mode == "default":
            dflt = str(self.opts.get("agent_secret_scan", "off"))
            ws = ((h.agent_report or {}) if h else {}).get("workstation") is True
            on = dflt == "all" or (dflt == "servers" and not ws) or (dflt == "workstations" and ws)
        else:
            on = mode == "on"
        sh = agent.get("agent_kind") == "sh"  # the OpenWrt agent doesn't scan files
        return {"on": bool(on and h and not sh), "paths": list(hs.get("paths") or []), "hours": int(hs.get("hours") or 24)}

    async def set_secret_scan(self, h: Host, mode: str, paths: list, hours: int, who: str | None) -> None:
        hs = self.agent_settings["hosts"].setdefault(h.key, {})
        if mode == "default" and not paths and hours == 24:
            hs.pop("secret_scan", None)
        else:
            hs["secret_scan"] = {"mode": mode, "paths": paths, "hours": hours}
        self._save_agent_settings()
        log.info("%s: password scan set to %s%s by %s", h.name, mode, f" (+{len(paths)} folder{'s' if len(paths) != 1 else ''})" if paths else "",
                 who or "someone")
        ag = self.agents.agents.get(h.agent_id) if h.agent_id else None
        if ag and not self.secret_scan_config({**ag, "host_key": h.key})["on"]:
            self._clear_secrets(ag)  # gone now, not after the agent's next reports
        await self.reevaluate(h)

    # -- installed software ----------------------------------------------
    def _sw_path(self, agent_id: str) -> Path:
        return SOFTWARE_DIR / (re.sub(r"[^A-Za-z0-9_-]", "", str(agent_id))[:64] + ".json")

    def software(self, agent_id: str | None) -> dict:
        """An agent's last software list: {hash, updated, apps, changes} ({} if none yet). Cached in memory."""
        if not agent_id:
            return {}
        if agent_id not in self._sw:
            try:
                self._sw[agent_id] = json.loads(self._sw_path(agent_id).read_text())
            except (OSError, ValueError):
                self._sw[agent_id] = {}
        return self._sw[agent_id]

    def _store_apps(self, agent: dict, apps, ahash: str, now: float) -> None:
        """Keep the new list, and log what was installed, removed or updated since the last one."""
        clean = []
        for a in apps if isinstance(apps, list) else []:
            if not isinstance(a, dict) or not str(a.get("name") or "").strip():
                continue
            clean.append({"name": str(a["name"]).strip()[:150], "version": str(a.get("version") or "")[:60],
                          "publisher": str(a.get("publisher") or "")[:100], "installed": str(a.get("installed") or "")[:10],
                          "size_mb": a["size_mb"] if isinstance(a.get("size_mb"), (int, float)) and a["size_mb"] >= 0 else 0,
                          "arch": str(a.get("arch") or "")[:12], "scope": "user" if a.get("scope") == "user" else "machine",
                          **({"code": str(a["code"])[:100]} if a.get("code") else {}),
                          **({"src": str(a["src"])[:150], "srcver": str(a.get("srcver") or "")[:60]} if a.get("src") else {}),
                          **({"available": str(a["available"])[:60]} if a.get("available") else {})})
            if len(clean) >= 5000:
                break
        old = self.software(agent["id"])
        changes = list(old.get("changes") or [])
        if old.get("apps") is not None:
            key = lambda a: (a["name"].lower(), a["arch"], a["scope"])  # noqa: E731
            before, after = {}, {}
            for a in old["apps"]:
                before.setdefault(key(a), []).append(a["version"])
            for a in clean:
                after.setdefault(key(a), []).append(a["version"])
            at = int(now)
            for k in after.keys() - before.keys():
                changes.append({"at": at, "change": "installed", "name": next(a["name"] for a in clean if key(a) == k), "version": ", ".join(after[k])})
            for k in before.keys() - after.keys():
                changes.append({"at": at, "change": "removed", "name": next(a["name"] for a in old["apps"] if key(a) == k), "version": ", ".join(before[k])})
            for k in after.keys() & before.keys():
                if sorted(after[k]) != sorted(before[k]):
                    vk = lambda v: [int(x) if x.isdigit() else x for x in re.split(r"[.\-+_ ]", v)]  # noqa: E731
                    try:
                        down = max(map(vk, after[k])) < max(map(vk, before[k]))
                    except TypeError:  # versions that don't compare (mixed text and numbers)
                        down = False
                    changes.append({"at": at, "change": "downgraded" if down else "updated", "name": next(a["name"] for a in clean if key(a) == k),
                                    "version": ", ".join(after[k]), "was": ", ".join(before[k])})
        changes = [c for c in changes if c.get("at", 0) >= now - 180 * DAY][-500:]
        sw = {"hash": ahash, "updated": int(now), "apps": clean, "changes": changes, "first": old.get("first") or int(now)}
        self._sw[agent["id"]] = sw
        self.want_apps.discard(agent["id"])
        try:
            SOFTWARE_DIR.mkdir(parents=True, exist_ok=True)
            tmp = self._sw_path(agent["id"]).with_suffix(".tmp")
            tmp.write_text(json.dumps(sw, separators=(",", ":")))
            tmp.replace(self._sw_path(agent["id"]))
        except OSError as err:
            log.warning("Couldn't save the software list for %s: %s", agent.get("hostname"), err)
        n = len(changes) - len(old.get("changes") or [])
        log.info("%s: software list %s (%d programs%s)", agent.get("hostname"), "updated" if old else "received", len(clean),
                 f", {n} change{'s' if n != 1 else ''}" if old and n > 0 else "")

    def software_newer(self, agent_id: str | None) -> dict:
        """{index into the agent's list: {"version", "id"?}} for programs with a newer version available:
        from the package manager on Linux, from the winget catalogue on Windows. Only highlighted, never alerted."""
        sw = self.software(agent_id)
        apps = sw.get("apps") or []
        key = (agent_id, sw.get("hash"), sw.get("updated"), id(self.winget))
        if key in self._newer:
            return self._newer[key]
        linux = (self.agents.agents.get(agent_id) or {}).get("os_family") == "linux" if self.agents else False
        out = {}
        for i, a in enumerate(apps):
            if a.get("available") and a["available"] != a.get("version"):
                out[i] = {"version": a["available"]}
            elif self.winget and not linux:
                try:
                    n = self.winget.newer(a)
                except Exception:  # noqa: BLE001 - one odd name mustn't stop the rest
                    n = None
                if n:
                    out[i] = n
        self._newer = {k: v for k, v in self._newer.items() if k[0] != agent_id}
        self._newer[key] = out
        return out

    async def winget_loop(self) -> None:
        """Keep the winget catalogue about a day old: download it when Microsoft has a newer copy."""
        await asyncio.sleep(20)
        meta_path, loaded = WINGET_PATH.with_suffix(".json"), None
        while True:
            try:
                if not self.opts.get("software_updates", True) or wingetidx.re is None:
                    self.winget, self.winget_info = None, {"off": True}
                    await asyncio.sleep(3600)
                    continue
                try:
                    meta = json.loads(meta_path.read_text())
                except (OSError, ValueError):
                    meta = {}
                if not WINGET_PATH.exists() or time.time() - (meta.get("fetched") or 0) > 20 * 3600:
                    hdrs = {"If-None-Match": meta["etag"]} if WINGET_PATH.exists() and meta.get("etag") else {}
                    async with ClientSession(timeout=ClientTimeout(total=900)) as session:
                        async with session.get(wingetidx.INDEX_URL, headers=hdrs) as r:
                            if r.status == 200:
                                data = await r.read()
                                tmp = WINGET_PATH.with_suffix(".tmp")
                                tmp.write_bytes(data)
                                tmp.replace(WINGET_PATH)
                                meta = {"etag": r.headers.get("ETag"), "size": len(data)}
                                log.info("Software updates: downloaded the winget catalogue (%.1f MB)", len(data) / 1e6)
                            elif r.status != 304:
                                raise RuntimeError(f"HTTP {r.status}")
                    meta["fetched"] = int(time.time())
                    meta_path.write_text(json.dumps(meta))
                stamp = WINGET_PATH.stat().st_mtime
                if self.winget is None or loaded != stamp:
                    idx = await asyncio.get_running_loop().run_in_executor(None, lambda: wingetidx.Index.from_msix(WINGET_PATH.read_bytes()))
                    self.winget, loaded = idx, stamp
                    self._newer.clear()
                    log.info("Software updates: the winget catalogue has %d packages", len(idx.packages))
                self.winget_info = {"fetched": meta.get("fetched"), "packages": len(self.winget.packages)}
            except Exception as err:  # noqa: BLE001
                log.warning("Software updates: couldn't get the winget catalogue (%s); trying again in an hour", err)
                self.winget_info = {**self.winget_info, "error": str(err)[:200]}
            await asyncio.sleep(3600)

    # -- known vulnerabilities (vulns.py) --------------------------------------
    def _vuln_key(self, h: Host) -> str | None:
        r = h.agent_report or {}
        return vulnlib.os_key(r.get("os_id"), r.get("os_version_id")) if r.get("os_family") == "linux" else None

    def vuln_findings(self, h: Host) -> list | None:
        """This device's known vulnerabilities at or above the score (or known to be exploited), or
        None when it can't be checked (turned off, an older agent, a distro that isn't covered, no data)."""
        r = h.agent_report or {}
        if not self.opts.get("vuln_checks", True) or not h.agent_id or not r:
            return None
        f, ms, mode = self.vulnfeeds, float(self.opts.get("vuln_min_score", 9)), str(self.opts.get("vuln_linux_source") or "local")
        sw = self.software(h.agent_id)
        key = (r.get("os_family"), r.get("os"), r.get("os_build"), r.get("os_id"), r.get("os_version_id"), sw.get("hash"), sw.get("updated"), f.version, ms, mode)
        hit = self._vf.get(h.agent_id)
        if hit and hit[0] == key:
            return hit[1]
        out = None
        if r.get("os_family") == "linux":
            k = self._vuln_key(h)
            if k and mode != "off" and (k in f.osv or k in f.covered) and any(a.get("src") for a in sw.get("apps") or []):
                out = vulnlib.linux_findings(sw["apps"], k, f.osv, f.kev, ms)
        else:
            b = str(r.get("os_build") or "")
            server = self._vuln_server(h)
            if f.msrc and re.fullmatch(r"\d+\.\d+\.\d+\.\d+", b) and vulnlib.msrc_key(b.rsplit(".", 1)[0], "server" if server else "client") in f.msrc:
                out = vulnlib.windows_findings(b, f.msrc, f.kev, ms, server=server)
        self._vf[h.agent_id] = (key, out)
        return out

    @staticmethod
    def _vuln_server(h: Host) -> bool:
        """Windows Server, rather than desktop Windows: they can share a build number but are updated separately."""
        return vulnlib.msrc_family(str((h.agent_report or {}).get("os") or "")) == "server"

    def _vuln_why_not(self, h: Host) -> str:
        """Why a device isn't checked, for the check's detail."""
        r, f = h.agent_report or {}, self.vulnfeeds
        if r.get("os_family") == "linux":
            k = self._vuln_key(h)
            if not r.get("os_id"):
                return "Not checked yet: needs Linux agent 1.0.20 or later"
            if not k:
                return "Not checked: Rollcall has vulnerability data for Debian, Ubuntu, AlmaLinux and Rocky Linux only"
            if not any(a.get("src") for a in self.software(h.agent_id).get("apps") or []):
                return "Waiting for the agent to send its package list"
            return (f.info.get("errors") or {}).get("OSV") and f"Linux vulnerability data couldn't be downloaded ({f.info['errors']['OSV']})" \
                or "Waiting for the Linux vulnerability data to download (checked hourly)"
        b = str(r.get("os_build") or "")
        if not f.msrc:
            err = (f.info.get("errors") or {}).get("Microsoft")
            return f"Microsoft's update data couldn't be downloaded ({err})" if err else "Waiting for Microsoft's update data to download"
        if not re.fullmatch(r"\d+\.\d+\.\d+\.\d+", b):
            return "Not checked: the agent didn't report the Windows build with its update revision"
        return (f"Not checked: Microsoft hasn't released security updates for this Windows version "
                f"({'Windows Server' if self._vuln_server(h) else 'Windows'}, build {b.rsplit('.', 1)[0]}) "
                "in the last 12 months, so it's probably out of support")

    def vuln_check(self, h: Host) -> dict | None:
        """The Vulnerabilities agent check: amber at or above the score, red if any is known to be exploited."""
        if not self.opts.get("vuln_checks", True):
            return None
        r = h.agent_report or {}
        if r.get("os_family") == "linux" and str(self.opts.get("vuln_linux_source") or "local") == "off":
            return None
        if r.get("agent_kind") == "sh":
            return None  # OpenWrt: no installed-package list or vulnerability data for it
        found = self.vuln_findings(h)
        if found is None:
            return {"key": "vulns", "label": "Vulnerabilities", "level": agentlib.OK, "detail": self._vuln_why_not(h), "ids": []}
        level, detail = vulnlib.summarise(found, float(self.opts.get("vuln_min_score", 9)))
        return {"key": "vulns", "label": "Vulnerabilities", "detail": detail, "ids": sorted({x["cve"] for x in found}),
                "level": {"ok": agentlib.OK, "warn": agentlib.WARN, "crit": agentlib.CRIT}[level]}

    def vulns_by_app(self, h: Host) -> dict:
        """{index into the software list: [{"cve", "score", "exploited", "fixed"}]} for Linux packages."""
        found = self.vuln_findings(h) or []
        if not found or (h.agent_report or {}).get("os_family") != "linux":
            return {}
        by_src: dict = {}
        for x in found:
            by_src.setdefault(x["what"], []).append({k: x[k] for k in ("cve", "score", "exploited", "fixed")})
        inst = {x["what"]: x["installed"] for x in found}  # the version that was checked (the newest installed)
        out = {}
        for i, a in enumerate(self.software(h.agent_id).get("apps") or []):
            for n in (a.get("src"), a.get("name")):
                if n in by_src and (a.get("srcver") or a.get("version")) == inst[n]:
                    out[i] = by_src[n]
                    break
        return out

    def vulns_view(self, h: Host) -> dict | None:
        """For the Software tab: everything found, and where the data came from."""
        if not self.opts.get("vuln_checks", True) or not h.agent_id:
            return None
        found = self.vuln_findings(h)
        return {"found": sorted(found or [], key=lambda f: (not f["exploited"], -(f["score"] or 0), f["cve"]))[:500],
                "checked": found is not None, "why_not": None if found is not None else self._vuln_why_not(h),
                "min_score": int(self.opts.get("vuln_min_score", 9)), "linux_source": str(self.opts.get("vuln_linux_source") or "local"),
                "info": self.vulnfeeds.info}

    def _vuln_wanted(self, mode: str) -> tuple[set, list]:
        """The Linux releases the agents run, and (online) every package and version to ask OSV about."""
        wanted, queries = set(), set()
        for h in list(self.hosts.values()):
            k = self._vuln_key(h) if h.agent_id else None
            if not k:
                continue
            wanted.add(k)
            if mode == "online":
                rpm = k.split(":")[0] in vulnlib.RPM_DISTROS
                for a in self.software(h.agent_id).get("apps") or []:
                    if a.get("src") and (a.get("srcver") or a.get("version")):
                        queries.add((k, a["src"], a.get("srcver") or a["version"]))
                        if rpm and a.get("name") and a["name"] != a["src"]:  # RPM advisories may name binary packages
                            queries.add((k, a["name"], a.get("srcver") or a["version"]))
        if len(queries) > 50000:
            log.warning("Vulnerabilities: %d packages to ask OSV about; only the first 50,000 are checked", len(queries))
        return wanted, sorted(queries)[:50000]

    async def vulns_loop(self, first_wait: float = 40, reeval: bool = False) -> None:
        """Keep the vulnerability data about a day old (each source is only fetched when it's due),
        and work every device out again when it changes."""
        await asyncio.sleep(first_wait)
        while True:
            try:
                if self.opts.get("vuln_checks", True):
                    mode = str(self.opts.get("vuln_linux_source") or "local")
                    wanted, queries = self._vuln_wanted(mode)
                    async with ClientSession(timeout=ClientTimeout(total=3600, sock_connect=30, sock_read=300)) as session:
                        changed = await self.vulnfeeds.refresh(session, time.time(), mode, wanted if mode == "local" else set(), queries)
                    if changed or reeval:
                        self._vf.clear()
                        for h in list(self.hosts.values()):
                            if h.agent_id:
                                await self.reevaluate(h)
                    reeval = False
                elif reeval:
                    for h in list(self.hosts.values()):
                        if h.agent_id:
                            await self.reevaluate(h)
                    reeval = False
            except asyncio.CancelledError:
                raise
            except Exception as err:  # noqa: BLE001
                log.warning("Vulnerabilities: update failed (%s); trying again in an hour", err)
            await asyncio.sleep(3600)

    def software_search(self, q: str, include_security: bool = True) -> list:
        """Every device with software whose name or publisher contains q."""
        q, out = q.strip().lower(), []
        for h in self.hosts.values():
            sw = self.software(h.agent_id) if h.agent_id else {}
            newer = self.software_newer(h.agent_id) if sw else {}
            vul = self.vulns_by_app(h) if sw and include_security else {}
            hits = [{**a, "newer": (newer.get(i) or {}).get("version"), **({"cves": len(vul[i])} if i in vul else {})}
                    for i, a in enumerate(sw.get("apps") or []) if q in a["name"].lower() or q in a["publisher"].lower()]
            if hits:
                out.append({"key": h.key, "name": h.name, "updated": sw.get("updated"), "apps": hits[:50]})
        return sorted(out, key=lambda x: x["name"].lower())

    def _history_add(self, h: Host, kind: str, items: list, received: float) -> None:
        cutoff = received - DAY
        hist = [i for i in h.agent_history.get(kind, []) if i.get("_rx", 0) >= cutoff]
        hist.extend({**i, "_rx": received} for i in items)
        h.agent_history[kind] = hist[-200:]

    def internal_networks(self) -> list[str]:
        """Subnets set under Agents as inside the network, e.g. ["10.0.1.0/24"] ([] if none)."""
        return [str(n) for n in self.agent_settings.get("internal_networks") or []]

    def agent_route(self) -> dict | None:
        """What agents need to choose an address themselves: on an internal network, the inside one first;
        elsewhere, the outside one first. None until both addresses and at least one network are set."""
        sv = self.agent_settings.get("servers") or {}
        nets = self.internal_networks()
        if not (sv.get("inside") and sv.get("outside") and nets):
            return None
        return {"inside": sv["inside"], "outside": sv["outside"], "networks": nets}

    def agent_side(self, agent: dict) -> dict:
        """Which of the two addresses an agent last reported through, and which it should use going by its
        own addresses: {"via": "inside" | "outside" | None, "expected": "inside" | "outside" | None}."""
        sv = self.agent_settings.get("servers") or {}
        norm = lambda u: str(u or "").strip().rstrip("/").lower()  # noqa: E731
        sent = norm(agent.get("sent_to"))
        via = "inside" if sent and sent == norm(sv.get("inside")) else "outside" if sent and sent == norm(sv.get("outside")) else None
        nets = []
        for n in self.internal_networks():
            try:
                nets.append(ipaddress.ip_network(n, strict=False))
            except ValueError:
                pass
        expected = None
        if nets and sv.get("inside") and sv.get("outside"):
            ips = []
            for ip in agent.get("ips") or []:
                try:
                    ips.append(ipaddress.ip_address(str(ip).split("%")[0]))
                except ValueError:
                    pass
            v4 = [ip for ip in ips if ip.version == 4]
            if v4:
                expected = "inside" if any(ip in n for ip in v4 for n in nets if n.version == 4) else "outside"
        return {"via": via, "expected": expected}

    def agent_servers(self) -> list[str]:
        """The inside then outside address set under Agents ([] if never set)."""
        sv = self.agent_settings.get("servers") or {}
        return [v for v in (sv.get("inside"), sv.get("outside")) if v]

    def agent_update_offer(self, agent: dict, report: dict) -> dict | None:
        """Offer the agent the version in this add-on if updates are on for its OS (or an
        admin asked for this one) and it's older. Agents never update otherwise."""
        if (report.get("agent_kind") or agent.get("agent_kind")) == "sh":
            return None  # the OpenWrt shell agent is updated by downloading it again, never with the Python one
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
        if agent["id"] in now:  # an admin asked for this one
            return {"version": latest}
        if (self.agent_settings.get("auto_update") or {}).get(os_name):
            return {"version": latest} if self._rollout_allows(os_name, latest, agent, report) else None
        return None

    # -- staged agent updates ---------------------------------------------
    # A new agent version goes to one device first (the pilot). Everyone else only gets it once
    # the pilot has reported on the new version. If the pilot goes quiet after updating, the
    # rollout stops and admins are told, so a bad version can't silence every agent at once.
    ROLLOUT_WAIT = 20 * 60         # the pilot must report on the new version within this long of fetching it
    ROLLOUT_REPICK = 60 * 60       # a pilot that never fetched it is swapped for another device after this

    def rollout(self, os_name: str, latest: str) -> dict:
        ro = self.agent_settings.setdefault("rollout", {})
        r = ro.get(os_name)
        if not r or r.get("version") != latest:
            r = ro[os_name] = {"version": latest, "state": "waiting", "pilot": None, "pilot_name": None,
                               "chosen": None, "sent": None, "done": None, "skip": []}
            self._save_agent_settings()
        return r

    def _rollout_allows(self, os_name: str, latest: str, agent: dict, report: dict) -> bool:
        r, now = self.rollout(os_name, latest), time.time()
        if r["state"] == "ok":
            return True
        if r["state"] == "failed":
            return False
        if r["state"] == "testing" and r["pilot"] != agent["id"]:
            if r.get("sent") and now - r["sent"] > self.ROLLOUT_WAIT:
                self._rollout_failed(os_name, r)
                return False
            if not r.get("sent") and now - (r.get("chosen") or now) > self.ROLLOUT_REPICK:
                r["skip"] = (r.get("skip") or []) + [r["pilot"]]
                r["state"] = "waiting"  # the pilot never fetched it (switched off?): try another device
        if r["state"] == "waiting":
            if agent["id"] in (r.get("skip") or []):
                return False
            # Prefer a server as the pilot; take any device if no server has asked within 30 minutes
            ws = report.get("workstation") is True or agent.get("workstation") is True
            r.setdefault("waiting_since", now)
            if ws and now - r["waiting_since"] < 1800:
                return False
            r.update(state="testing", pilot=agent["id"], pilot_name=agent.get("hostname"), chosen=now, sent=None)
            self._save_agent_settings()
            log.info("%s agent %s: trying it on %s first", os_name.capitalize(), latest, agent.get("hostname"))
            return True
        return r["pilot"] == agent["id"]

    def rollout_seen(self, agent: dict, report: dict) -> None:
        """A report arrived: if it's the pilot running the new version, roll it out to everyone."""
        os_name = "linux" if report.get("os_family") == "linux" else "windows"
        r = (self.agent_settings.get("rollout") or {}).get(os_name)
        if (r and r.get("state") in ("testing", "failed") and r.get("pilot") == agent["id"]
                and report.get("agent_version") == r.get("version")):
            r.update(state="ok", done=time.time())
            self._save_agent_settings()
            log.info("%s agent %s works on %s: updating the other %s agents", os_name.capitalize(), r["version"],
                     agent.get("hostname"), os_name.capitalize())

    def _rollout_failed(self, os_name: str, r: dict) -> None:
        r["state"] = "failed"
        self._save_agent_settings()
        msg = (f"{r.get('pilot_name') or 'The first device'} hasn't reported since updating to {os_name.capitalize()} agent "
               f"{r['version']}, so the update has been stopped for the other agents. Check its agent log, then choose "
               f"Retry or Update the rest under Manage > Agents.")
        log.warning("%s agent %s update stopped: %s", os_name.capitalize(), r["version"], msg)
        asyncio.get_event_loop().create_task(self.notify(f"⚠️ {os_name.capitalize()} agent update stopped", msg,
                                                         f"ping_monitor_rollout_{os_name}", cat="updates"))

    async def email_summary_tick(self, now: float) -> None:
        """At email_digest_time (Home Assistant's time zone), once a day: the daily summary email."""
        at = str(self.opts.get("email_digest_time") or "").strip()
        if not at or not self.opts.get("email_digest", True) or not emaillib.configured(self.opts):
            return
        local = datetime.fromtimestamp(now, TZ) if TZ else datetime.fromtimestamp(now)
        day = local.strftime("%Y-%m-%d")
        hh, mm = (int(x) for x in at.split(":"))
        if (local.hour, local.minute) < (hh, mm) or self.agent_settings.get("email_summary_day") == day:
            return
        if (local.hour * 60 + local.minute) - (hh * 60 + mm) > 60:
            self.agent_settings["email_summary_day"] = day  # started well after the time: skip today's
            self._save_agent_settings()
            return
        self.agent_settings["email_summary_day"] = day
        self._save_agent_settings()
        sections, summary = self.summary_sections()
        try:
            await self.email.digest(sections, summary)
        except emaillib.EmailError as e:
            log.warning("Couldn't send the daily summary email: %s", e)

    # -- Hints from Claude (hints.py) ---------------------------------------
    AI_OPTS = {"anthropic": ("claude_api_key", "claude_model"), "openai": ("openai_api_key", "openai_model"),
               "gemini": ("gemini_api_key", "gemini_model")}

    def ai_settings(self) -> tuple[str, str, str]:
        """(provider, its API key, its model) for hints from AI."""
        prov = str(self.opts.get("ai_provider") or "anthropic")
        prov = prov if prov in self.AI_OPTS else "anthropic"
        k, m = self.AI_OPTS[prov]
        return prov, str(self.opts.get(k) or ""), str(self.opts.get(m) or "") or hintlib.PROVIDERS[prov]["model"]

    def claude_on(self) -> bool:
        """Hints from AI are on, with a key for the chosen provider."""
        return bool(self.opts.get("claude_hints") and self.ai_settings()[1])

    def claude_question(self, h: Host, key: str) -> tuple[dict, str]:
        """(the check, what would be sent to Claude) for one amber or red check, with every name and address that
        Rollcall knows of replaced, and the generic patterns (addresses, accounts, domain names) caught as well."""
        s = next((x for x in h.services + h.agent_checks if x.key == key), None)
        short = key.removeprefix("agent_")
        if not s:
            raise ValueError("That check doesn't exist")
        if short in hintlib.NEVER or key in SECURITY_KEYS:
            raise ValueError("Security checks are never sent to Claude")
        if s.status not in (RED, AMBER) or not s.detail:
            raise ValueError("Only amber and red checks with an error can be asked about")
        names, domains, users = [], [], []
        for o in self.hosts.values():
            names += [o.name, str(o.host or "")]
            r = o.agent_report or {}
            names += [str(r.get("hostname") or ""), str(r.get("fqdn") or "").split(".")[0]]
            fq = str(r.get("fqdn") or "")
            if "." in fq:
                domains.append(fq.split(".", 1)[1])
                domains.append(fq.split(".", 1)[1].split(".")[0])
            dm = ((r.get("checks") or {}).get("domain") or {}).get("domain")
            if dm:
                domains += [str(dm), str(dm).split(".")[0]]
            for x in r.get("sessions") or []:
                u = str(x.get("user") or "")
                users.append(u.split("\\")[-1].split("@")[0])
        names = [n for n in names if n and not re.fullmatch(r"[\d.:]+", n)]
        red = hintlib.Redactor(names, domains, users)
        r = h.agent_report or {}
        roles = r.get("roles") or []
        kind = "domain controller" if "Domain controller" in roles else "server" if re.search(r"(?i)server", str(r.get("os") or "")) else \
            "workstation" if r.get("os") else ""
        ctx = {"Device": " ".join(x for x in (red(str(r.get("os") or "")), f"({kind})" if kind else "") if x) or None,
               "Joined to a domain": None if not r.get("fqdn") else ("yes" if "." in str(r.get("fqdn")) else "no"),
               "Last agent report": (f"{int((time.time() - h.agent_seen) // 60)} minutes ago" if h.agent_seen else None) if s.kind == "agent" else None}
        return {"label": red(s.label), "status": s.status}, hintlib.prompt(red(s.label), s.status, red(s.detail), ctx)

    # -- Manage > Database (dbhealth.py) -----------------------------------
    async def db_health_tick(self, now: float) -> None:
        """Once a minute: the daily integrity check when it's due, and an alert when the disk is nearly full."""
        local = datetime.fromtimestamp(now, TZ) if TZ else datetime.fromtimestamp(now)
        if not self.dbh.busy and self.dbh.due(now, local.hour, self.db_started):
            await self.db_check()
        d = dblib.disk(DB_PATH.parent)
        lvl = dblib.disk_level(d)
        if lvl == "crit" and self.dbh.alerted.get("disk") != "crit":
            self.dbh.alerted["disk"] = "crit"
            await self.notify("🔴 Home Assistant's disk is nearly full",
                              f"Only {d['free_pct']:.1f}% ({dblib.fmt_bytes(d['free'])}) is free on the disk Rollcall keeps its data on. "
                              "Rollcall and Home Assistant stop saving history once it's full. See Manage > Database in Rollcall.",
                              tag="rollcall_disk", level="red")
        elif lvl == "ok" and self.dbh.alerted.get("disk") == "crit":
            self.dbh.alerted["disk"] = "ok"
            await self.notify("🟢 Home Assistant's disk has room again", f"{d['free_pct']:.0f}% is free.", tag="rollcall_disk", level="ok")

    async def db_check(self) -> dict:
        """SQLite's quick_check on Rollcall's database; damage is red with an alert."""
        self.dbh.busy = "check"
        try:
            ok, found, took = await asyncio.to_thread(dblib.quick_check, self.store.db)
        finally:
            self.dbh.busy = ""
        was = self.dbh.state.get("ok")
        self.dbh.record_check(ok, found, took, time.time())
        if not ok:
            log.error("Rollcall's database is damaged: %s", "; ".join(found[:5]))
            if was is not False:
                await self.notify("🔴 Rollcall's database is damaged",
                                  "SQLite's integrity check found problems in Rollcall's database (history and readings). "
                                  "Restore it from a Rollcall export (Manage > Export / import) or a Home Assistant backup. "
                                  "Details are under Manage > Database.", tag="rollcall_db", level="red")
        else:
            log.info("Database check: OK (%.1f s)", took)
            if was is False:
                await self.notify("🟢 Rollcall's database is OK again", "The integrity check found no problems.", tag="rollcall_db", level="ok")
        return self.dbh.state

    def db_details(self) -> dict:
        """Everything Manage > Database shows (run in a worker thread: counting rows takes a moment)."""
        rows, pages = dblib.tables(self.store.db, self.opts, self.logs.per_host)
        return {"path": str(DB_PATH), "tables": rows, **pages, "folder": dblib.folder(DB_PATH.parent, DB_PATH.name),
                "summary": self.dbh.summary(DB_PATH), "state": self.dbh.state,
                "disk_warn": dblib.DISK_WARN, "disk_crit": dblib.DISK_CRIT}

    def summary_sections(self) -> tuple[list, str]:
        """What needs attention now, for the daily summary: [(heading, [(colour, what, detail)])], and a line of totals."""
        down, red, amber, paused = [], [], [], []
        want = lambda cat: self.opts.get(f"email_about_{cat}", True)  # noqa: E731  (what's ticked under Email about)
        for h in sorted(self.hosts.values(), key=lambda x: x.name.lower()):
            if h.removed:
                continue
            if h.maint_until or (h.status == MAINT and not h.off_schedule):
                paused.append(("grey", h.name, "paused" if h.maint_until else "starting up"))
                continue
            if h.off_schedule:
                continue
            if h.status == RED:
                if not want("devices"):
                    continue
                down.append(("red", h.name, f"not responding ({h.ip or h.host})" + (f" since {datetime.fromtimestamp(h.last_change, TZ).strftime('%d %b %H:%M')}" if h.last_change and TZ else "")))
                continue
            for s in h.services + h.agent_checks:
                if s.status in (RED, AMBER) and not want(self._email_cat(s)):
                    continue
                if s.status == RED:
                    red.append(("red", f"{h.name} · {s.label}", s.detail or ""))
                elif s.status == AMBER:
                    amber.append(("amber", f"{h.name} · {s.label}", s.detail or ""))
        sections = [x for x in (("Not responding", down), ("Red", red), ("Amber", amber), ("Paused", paused)) if x[1]]
        total = len([h for h in self.hosts.values() if not h.removed])
        up = len([h for h in self.hosts.values() if not h.removed and h.status in (GREEN, DEGRADED)])
        summary = (f"{up} of {total} devices up. " + (f"{len(down)} not responding, {len(red)} red and {len(amber)} amber checks."
                                                     if down or red or amber else "Everything else is OK."))
        return sections, summary

    def rollout_watch(self, now: float) -> None:
        """Once a minute: stop a rollout whose first device went quiet after updating, even when
        no other agent of that kind is left to ask for the update (e.g. only one agent)."""
        for os_name, r in list((self.agent_settings.get("rollout") or {}).items()):
            if r.get("state") == "testing" and r.get("sent") and now - r["sent"] > self.ROLLOUT_WAIT:
                self._rollout_failed(os_name, r)

    def rollout_sent(self, agent: dict, os_name: str) -> None:
        r = (self.agent_settings.get("rollout") or {}).get(os_name)
        if r and r.get("state") == "testing" and r.get("pilot") == agent["id"] and not r.get("sent"):
            r["sent"] = time.time()
            self._save_agent_settings()

    def _track_admins(self, h: Host, report: dict, now: float) -> None:
        """Remember who is in the Administrators group, so additions and removals show with a date.
        Members there when Rollcall first looked have no date."""
        adm = (report.get("security") or {}).get("admins")
        if adm is None:
            return
        hs = self.agent_settings["hosts"].setdefault(h.key, {})
        cur = {agentlib.admin_key(a): a for a in adm}
        seen = hs.get("admins_seen")
        if seen is None:
            hs["admins_seen"] = {k: {"account": a.get("account"), "since": None} for k, a in cur.items()}
            hs["admins_changes"] = []
            self._save_agent_settings()
            return
        changes, changed = hs.setdefault("admins_changes", []), False
        for k in cur.keys() - seen.keys():
            seen[k] = {"account": cur[k].get("account"), "since": now}
            changes.append({"time": now, "change": "added", "account": cur[k].get("account"), "type": cur[k].get("type")})
            log.info("%s: %s added to Administrators", h.name, cur[k].get("account"))
            changed = True
        for k in seen.keys() - cur.keys():
            gone = seen.pop(k)
            changes.append({"time": now, "change": "removed", "account": gone.get("account")})
            log.info("%s: %s removed from Administrators", h.name, gone.get("account"))
            changed = True
        for k, a in cur.items():  # e.g. an Azure AD SID that Windows can now name
            if a.get("account") and seen[k].get("account") != a.get("account"):
                seen[k]["account"], changed = a.get("account"), True
        if changed:
            hs["admins_changes"] = changes[-30:]
            self._save_agent_settings()

    def _track_domain(self, h: Host, report: dict, now: float) -> None:
        """Remember who is in the domain's privileged groups (from the PDC emulator's report), so additions
        and removals show with a date and additions alert for 24 hours. Members there at first sight have no date."""
        dm = (report.get("checks") or {}).get("domain")
        if not dm or not dm.get("groups"):
            return
        hs = self.agent_settings["hosts"].setdefault(h.key, {})
        cur = {agentlib.domain_key(g["name"], a["name"]): (g["name"], a) for g in dm["groups"] for a in g["members"]}
        seen = hs.get("domain_seen")
        if seen is None:
            hs["domain_seen"] = {k: {"group": g, "account": a["name"], "since": None} for k, (g, a) in cur.items()}
            hs["domain_changes"] = []
            self._save_agent_settings()
            return
        changes, changed = hs.setdefault("domain_changes", []), False
        for k in cur.keys() - seen.keys():
            g, a = cur[k]
            seen[k] = {"group": g, "account": a["name"], "since": now}
            changes.append({"time": now, "change": "added", "group": g, "account": a["name"], "kind": a["kind"]})
            log.info("%s: %s added to %s", h.name, a["name"], g)
            changed = True
        for k in seen.keys() - cur.keys():
            gone = seen.pop(k)
            changes.append({"time": now, "change": "removed", "group": gone["group"], "account": gone["account"]})
            log.info("%s: %s removed from %s", h.name, gone["account"], gone["group"])
            changed = True
        if changed:
            hs["domain_changes"] = changes[-50:]
            self._save_agent_settings()

    # ---- Network discovery ----
    @staticmethod
    def _load_discovery() -> dict:
        try:
            d = json.loads(DISCOVERY_PATH.read_text())
            return {"results": list(d.get("results") or []), "summary": dict(d.get("summary") or {}),
                    "ranges": str(d.get("ranges") or ""), "hidden": list(d.get("hidden") or []),
                    "networks": [str(x) for x in d.get("networks") or []] or None}
        except (OSError, ValueError):
            return {"results": [], "summary": {}, "ranges": "", "hidden": [], "networks": None}

    # ---- Networks Rollcall uses ----
    # Rollcall doesn't pick an interface: Home Assistant's host sends each check out of the interface on
    # the device's subnet (or the default route). This choice keeps discovery to the networks picked,
    # and the dashboard shows which interface each device is reached through.
    async def interfaces(self) -> list[dict]:
        now = time.time()
        if now - self._ifaces[0] > 300:
            got = await self.ha.host_interfaces()
            self._ifaces = (now, got if got or now - self._ifaces[0] > 3600 else self._ifaces[1])
        return self._ifaces[1]

    async def network_view(self) -> dict:
        ifs = await self.interfaces()
        use = self.discovery.get("networks")
        return {"interfaces": [{**i, "used": use is None or i["name"] in use} for i in ifs], "chosen": use is not None}

    async def allowed(self, ip: str) -> tuple[bool, dict | None]:
        """Is this address reached through a network Rollcall uses? (True, None) when unknown."""
        ifs = await self.interfaces()
        use = self.discovery.get("networks")
        via = discovery.route_for(ip, ifs)
        if not via or use is None:
            return True, via
        return via["name"] in use, via

    async def set_networks(self, names: list[str] | None, who: str) -> None:
        self.discovery["networks"] = names
        self._save_discovery()
        log.info("Networks Rollcall uses set to %s by %s", ", ".join(names) if names is not None else "all", who or "someone")

    def _save_discovery(self) -> None:
        try:
            tmp = DISCOVERY_PATH.with_suffix(".tmp")
            tmp.write_text(json.dumps(self.discovery))
            tmp.replace(DISCOVERY_PATH)
        except OSError as err:
            log.warning("Couldn't save the network scan: %s", err)

    def known_addresses(self) -> dict[str, str]:
        """Every address a device in Rollcall uses, mapped to its key."""
        out: dict[str, str] = {}
        for h in self.hosts.values():
            for a in [h.ip, h.host] + [x for s in h.services for x in (s.resolved, s.target) if x]:
                if a:
                    out.setdefault(str(a), h.key)
        return out

    async def start_scan(self, ranges: str, community: str, who: str) -> dict:
        if self.scan and self.scan.finished is None:
            return {"error": "a scan is already running"}
        addrs, problems = discovery.parse_ranges(ranges)
        if problems:
            return {"error": "; ".join(problems)}
        outside = {}
        for ip in addrs:
            ok, via = await self.allowed(ip)
            if not ok:
                outside.setdefault(via["name"], ip)
        if outside:
            return {"error": "; ".join(f"{ip} is reached through {n}, which isn't one of the networks Rollcall uses" for n, ip in outside.items())}
        if not addrs:
            return {"error": "give an address range to scan, e.g. 192.168.1.0/24"}
        ping_one = lambda ip: ping(ip, 1, 1)  # noqa: E731
        self.scan = discovery.Scan(addrs, community, ping_one, self.known_addresses(), who)
        log.info("Network scan of %s (%d addresses) started by %s", ranges.strip(), len(addrs), who or "someone")

        async def run(sc=self.scan):
            await sc.run()
            self.discovery.update(results=sc.results, summary=sc.summary(), ranges=ranges.strip())
            self._save_discovery()
            log.info("Network scan finished: %d device(s) found in %d addresses%s", sc.found, sc.done, " (cancelled)" if sc.cancelled else "")
        self.scan.task = asyncio.create_task(run())
        return {"ok": True, "total": len(addrs)}

    async def discovery_view(self) -> dict:
        sc = self.scan if self.scan and self.scan.finished is None else None
        results = sc.results if sc else self.discovery["results"]
        known = self.known_addresses()
        by_name = {h.host.lower().rstrip("."): h.key for h in self.hosts.values() if h.host}  # added by name, not looked up yet
        for d in results:
            n = (d.get("dns") or "").lower().rstrip(".")
            if d["ip"] not in known and n and (n in by_name or n.split(".")[0] in by_name):
                known[d["ip"]] = by_name.get(n) or by_name[n.split(".")[0]]
        hidden = set(self.discovery["hidden"])
        name_of = lambda k: self.hosts[k].name if k in self.hosts else None  # noqa: E731
        out = [{**d, "known": known.get(d["ip"]), "known_name": name_of(known.get(d["ip"])), "hidden": d["ip"] in hidden}
               for d in sorted(results, key=lambda d: tuple(int(x) for x in d["ip"].split(".")))]
        nv = await self.network_view()
        nets = [a for i in nv["interfaces"] if i["used"] for a in i["addresses"]]
        ips = []
        for h in self.hosts.values():
            if (await self.allowed(h.ip or h.host))[0]:
                ips.append(h.ip or h.host)
        return {"running": bool(sc), "summary": sc.summary() if sc else self.discovery["summary"], "results": out,
                "ranges": self.discovery["ranges"], "suggested": discovery.suggest_ranges(ips, nets),
                "ha_networks": nets, "networks": nv}

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
        for j in agentlib.backup_jobs_view(jobs, hs.get("backup_forgot")):
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
            # A backup result is a fact about a run that happened, so it's sent even outside the
            # device's schedule (a backup server that's only on overnight); only a pause holds it back.
            if h.maint_until:
                continue
            kind = "Microsoft 365 " if j.get("source") == "Microsoft 365" else ""
            job = f"Veeam {kind}{(j.get('type') or 'backup').lower()} job '{j.get('name')}'"
            if level == agentlib.CRIT:
                title, msg = f"🔴 {h.name}: backup failed", f"{job} failed" + (f": {str(j.get('detail')).rstrip('.')}" if j.get("detail") else "") + "."
            elif "missed" in why:
                title, msg = f"🟠 {h.name}: backup missed", f"{job} missed its scheduled run."
            else:
                title, msg = f"🟠 {h.name}: backup overdue", f"{job} hasn't completed successfully for {why.split('for ')[-1]}."
            await self.notify(title, msg, f"ping_monitor_{h.key}__backup_{slugify(str(j.get('name')))}",
                              critical=h.critical and level == agentlib.CRIT,  # a failed backup, not a late one
                              level="red" if level == agentlib.CRIT else "amber", cat="backups")
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
                          f"ping_monitor_{h.key}__immich_update", cat="updates")

    def acks_summary(self, h: Host) -> list:
        """What's acknowledged on this device, for the Overview's Acknowledged list (with Undo)."""
        hs = self.agent_settings["hosts"].get(h.key) or {}
        out = []
        for k, a in (hs.get("check_acks") or {}).items():
            sv = next((s for s in h.agent_checks if s.key == f"agent_{k}"), None)
            if sv and sv.acked:
                out.append({"type": "check", "key": k, "label": sv.label, "detail": sv.detail, "at": a.get("at"), "by": a.get("by")})
        now = time.time()
        for k, a in (hs.get("ack") or {}).items():
            if k in TIME_ACK_KINDS and a.get("at") and now - a["at"] < DAY:
                sv = next((s for s in h.agent_checks if s.key == f"agent_{k}"), None)
                out.append({"type": "kind", "key": k, "label": sv.label if sv else k.capitalize(),
                            "detail": TIME_ACK_TEXT.get(k, "everything up to then"), "at": a["at"], "by": a.get("by")})
        for i in h.snmp_items:
            if i.get("acked"):
                out.append({"type": "snmp", "key": i["what"], "label": i["what"], "detail": i["detail"]})
        for i in h.ilo_items:
            if i.get("acked"):
                out.append({"type": "ilo", "key": i["what"], "label": "iLO: " + i["what"], "detail": i["detail"]})
        hidden = (self.agent_settings.get("ack_hidden") or {}).get(h.key) or {}
        for a in out:
            if f"{a['type']}:{a['key']}" in hidden and hidden[f"{a['type']}:{a['key']}"] == self._ack_mark(a):
                a["hidden"] = True
        return out

    @staticmethod
    def _ack_mark(a: dict) -> str:
        """What identifies this acknowledgement: a new one (acknowledged again, or SNMP showing
        something different) brings a dismissed row back."""
        return str(a.get("at") or a.get("detail") or "")

    def dismiss_acks(self, items: list, undo: bool, who: str | None) -> int:
        """Take acknowledged items off the Overview's Acknowledged list (they stay acknowledged)."""
        hidden = self.agent_settings.setdefault("ack_hidden", {})
        n = 0
        for hk, typ, key in items:
            h = self.hosts.get(hk)
            a = next((a for a in self.acks_summary(h) if a["type"] == typ and a["key"] == key), None) if h else None
            mine = hidden.setdefault(hk, {})
            if undo:
                n += mine.pop(f"{typ}:{key}", None) is not None
            elif a:
                mine[f"{typ}:{key}"] = self._ack_mark(a)
                n += 1
        for hk in list(hidden):  # forget dismissals whose acknowledgement has gone
            h = self.hosts.get(hk)
            live = {f"{a['type']}:{a['key']}": self._ack_mark(a) for a in self.acks_summary(h)} if h else {}
            hidden[hk] = {k: v for k, v in hidden[hk].items() if live.get(k) == v}
            if not hidden[hk]:
                del hidden[hk]
        self._save_agent_settings()
        log.info("%s %d acknowledged item(s) %s the Overview list", who or "Someone", n, "back on" if undo else "dismissed from")
        return n

    async def acknowledge_check(self, h: Host, check: str, who: str | None, undo: bool = False) -> None:
        """Acknowledge an agent check that's amber or red (e.g. a reboot that's waiting for a maintenance
        window): it counts as OK while it stays as it is or better, and alerts again if it gets worse or
        clears and comes back. Event-type checks use acknowledge() instead (everything up to now)."""
        hs = self.agent_settings["hosts"].setdefault(h.key, {})
        acks = hs.setdefault("check_acks", {})
        if undo:
            acks.pop(check, None)
        else:
            sv = next((s for s in h.agent_checks if s.key == f"agent_{check}"), None)
            if check in NO_ACK:
                raise ValueError("that's cleared on the device itself, e.g. a threat Defender has to remove")
            if check in TIME_ACK_KINDS or check == "agent" or not sv or sv.status not in (AMBER, RED):
                raise ValueError("that check has nothing to acknowledge")
            acks[check] = {"status": sv.status, "at": time.time(), "by": who or "", "detail": sv.detail[:300]}
            if check == "vulns":  # a vulnerability that isn't in this list alerts again
                acks[check]["ids"] = sorted({f["cve"] for f in self.vuln_findings(h) or []})
        self._save_agent_settings()
        log.info("%s: %s %s%s", h.name, "un-acknowledged" if undo else "acknowledged", check, f" by {who}" if who else "")
        await self.reevaluate(h)

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
                "disks": dict(hs.get("disks") or {}), "domain_changes": list(hs.get("domain_changes") or []),
                "nic_watch": dict(hs.get("nic_watch") or {}), "backup_forgot": dict(hs.get("backup_forgot") or {}),
                "resources": dict(hs.get("resources") or {}),
                "secret_findings": list(self.secret_findings(h.agent_id).get("findings") or []),
                "secret_ack": self._ack_time(h, "secrets"),
                "integrity_ack": self._ack_time(h, "integrity"),
                "domain_ack": self._ack_time(h, "domain"),
                "secret_scan_on": self.secret_scan_config({**(self.agents.agents.get(h.agent_id) or {}), "host_key": h.key})["on"],
                "sec_filters": list(self.agent_settings.get("global_sec_filters") or []) + list(hs.get("sec_filters") or [])}

    async def set_sec_filter(self, h: Host, action: str, scope: str, flt: dict | None = None, fid: str = "",
                             who: str | None = None) -> dict | None:
        """Add, remove or widen ("promote" to all servers) a security filter, then apply it straight
        away to the events already received, so an alert it covers clears now."""
        hs = self.agent_settings["hosts"].setdefault(h.key, {})
        mine, everyone = hs.setdefault("sec_filters", []), self.agent_settings.setdefault("global_sec_filters", [])
        lst = everyone if scope == "all" else mine
        done = None
        if action == "add" and flt:
            if len(lst) >= 100:
                raise ValueError("that's the limit of 100 filters; remove one first")
            keys = ("kind", "events", *agentlib.SEC_FILTER_FIELDS, *agentlib.LOGON_FILTER_FIELDS)
            same = next((f for f in lst if all(f.get(k) == flt.get(k) for k in keys)), None)
            done = same or {**flt, "id": secrets.token_hex(4), "at": time.time(), "by_user": who or ""}
            if not same:
                lst.append(done)
        elif action == "remove":
            done = next((f for f in lst if f.get("id") == fid), None)
            if done:
                lst.remove(done)
        elif action == "promote":
            done = next((f for f in mine if f.get("id") == fid), None)
            if done:
                mine.remove(done)
                everyone.append(done)
                scope = "all"
        if not done:
            return None
        self._save_agent_settings()
        log.info("Security filter %s (%s) %s by %s: %s", done.get("id"), "all servers" if scope == "all" else h.name,
                 {"add": "added", "remove": "removed", "promote": "applied to all servers"}[action], who or "someone",
                 {k: done.get(k) for k in ("kind", "events", *agentlib.SEC_FILTER_FIELDS, "source", "reason", "note") if done.get(k)})
        for x in ([x for x in self.hosts.values() if x.agent_report] if scope == "all" else [h]):
            await self.reevaluate(x)
        return done

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

    async def set_resources(self, h: Host, res: dict | None) -> None:
        """A device's own memory and CPU limits (None: back to the add-on's), or the check off."""
        hs = self.agent_settings["hosts"].setdefault(h.key, {})
        if res:
            hs["resources"] = res
        else:
            hs.pop("resources", None)
        self._save_agent_settings()
        log.info("%s: resource limits %s", h.name, res or "defaults")
        await self.reevaluate(h)

    async def forget_backup_job(self, h: Host, key: str, forget: bool) -> bool:
        """Hide a retired Veeam job until it runs again (a later result brings it back)."""
        hs = self.agent_settings["hosts"].setdefault(h.key, {})
        fg = hs.setdefault("backup_forgot", {})
        if forget:
            jobs = (((h.agent_report or {}).get("checks") or {}).get("backups") or {}).get("jobs") or []
            j = next((x for x in jobs if agentlib.backup_job_key(x) == key), None)
            if not j:
                return False
            fg[key] = {"name": str(j.get("name") or "")[:200], "finished": j.get("finished") or "", "at": int(time.time())}
            while len(fg) > 200:
                fg.pop(min(fg, key=lambda k: fg[k].get("at") or 0))
        elif not fg.pop(key, None):
            return False
        if not fg:
            hs.pop("backup_forgot", None)
        self._save_agent_settings()
        log.info("%s: Veeam job %s %s", h.name, key, "forgotten" if forget else "brought back")
        await self.reevaluate(h)
        return True

    async def _agent_host_ip(self, h: Host) -> str:
        """The IP column for a device checked by its agent (it isn't pinged): the address if
        it's already an IP, else a DNS lookup of it, else the first address the agent reports."""
        try:
            return str(ipaddress.ip_address(h.host))
        except ValueError:
            pass
        async with self.sem:
            ip = await resolve(h.host)
        if ip:
            return ip
        for x in (h.agent_report or {}).get("ips") or []:
            try:
                a = ipaddress.ip_address(str(x).split("/")[0])
            except ValueError:
                continue
            if a.version == 4 and not a.is_loopback and not a.is_link_local:
                return str(a)
        return ""

    async def set_nic_watch(self, h: Host, name: str, watch: bool) -> None:
        """Tick or untick a network adapter. Its link speed now is remembered, so a slower link later shows amber."""
        hs = self.agent_settings["hosts"].setdefault(h.key, {})
        nw, key = hs.setdefault("nic_watch", {}), agentlib.nic_key(name)
        if watch:
            a = next((x for x in (((h.agent_report or {}).get("checks") or {}).get("nics") or {}).get("adapters") or []
                      if agentlib.nic_key(x["name"]) == key), None)
            nw[key] = {"name": a["name"] if a else name, "speed": (a or {}).get("speed_mbps") or 0}
        else:
            nw.pop(key, None)
        if not nw:
            hs.pop("nic_watch", None)
        self._save_agent_settings()
        log.info("%s: network adapter %s %s", h.name, name, "watched" if watch else "no longer watched")
        await self.reevaluate(h)

    def _nic_rates(self, h: Host, report: dict, received: float) -> None:
        """Traffic and new errors per adapter since the previous report (kept in memory only)."""
        cur = {agentlib.nic_key(a["name"]): a for a in (((report.get("checks") or {}).get("nics") or {}).get("adapters") or [])}
        prev, rates = h.nic_prev, {}
        if prev and 0 < received - prev[0] < 3600:
            secs = received - prev[0]
            for k, a in cur.items():
                b = prev[1].get(k)
                if not b:
                    continue
                r = {}
                for f in ("rx_bytes", "tx_bytes"):
                    if a.get(f) is not None and b.get(f) is not None and a[f] >= b[f]:
                        r[f.replace("bytes", "bps")] = round((a[f] - b[f]) * 8 / secs)
                new_err = sum(max(0, (a.get(f) or 0) - (b.get(f) or 0)) for f in ("rx_errors", "tx_errors") if a.get(f) is not None and b.get(f) is not None)
                r["new_errors"] = new_err
                rates[k] = r
        h.nic_prev, h.nic_rates = (received, cur), rates

    async def reevaluate(self, h: Host) -> None:
        """Apply changed settings to the latest report now, without re-alerting events."""
        if h.agent_report and h.agent_id and self.agents and h.agent_id in self.agents.agents:
            await self._apply(h, self.agents.agents[h.agent_id], h.agent_report, h.agent_seen or time.time(),
                              reeval=True)

    async def _apply(self, h: Host, agent: dict, report: dict, received: float, restoring: bool = False,
                     reeval: bool = False, failures: dict | None = None) -> None:
        if not restoring and not reeval:
            self._track_domain(h, report, received)
        if not reeval:
            self._nic_rates(h, report, received)
        if not reeval and not restoring:
            try:
                self.metrics.record(h.key, received, metricslib.Metrics.from_report(report, h.nic_rates))
            except sqlite3.Error as e:
                log.warning("%s: couldn't record its metrics: %s", h.name, e)
        settings = self._host_settings(h)
        # CPU in the last few reports (each is a moment): the Resources check wants it high in all of them.
        # Agents report every 5 minutes; a gap (a missed report) means it isn't "in a row".
        n = max(1, int(self.opts.get("agent_cpu_reports", 3)))
        try:
            settings["cpu_recent"] = self.metrics.recent(h.key, "cpu", received - n * 330, received, n)
        except sqlite3.Error:
            settings["cpu_recent"] = []
        result = evaluate(report, self.opts, now=received, settings=settings)
        prev_up = (h.agent_report or {}).get("uptime_s")
        h.agent_report, h.agent_seen = report, received
        up = report.get("uptime_s")
        if (h.maint_until and not h.maint_seen_down and h.maint_started and not restoring and not reeval
                and isinstance(up, (int, float)) and isinstance(prev_up, (int, float))
                and up < prev_up and received - up > h.maint_started - 300):
            # Paused until it's back: it booted after the pause began, so it has been down and come back,
            # even if it was quick enough that no check saw it (agents count as up for 10 minutes).
            h.maint_seen_down = True
            self._save_maint()
            h.next_due = 0
            log.info("%s: restarted during maintenance (booted %s)", h.name, iso(received - up))
        if h.check_by != "ping" and h.status not in (GREEN, DEGRADED) and not restoring:
            h.next_due = 0  # it's reporting again: show it as up now, not at the next check
        notable = result["notable"]
        # Events ignored since they arrived no longer keep the Events chip amber.
        ign = agentlib.Ignore(list(self.opts.get("agent_ignore") or []) + settings["ignore"])
        for e in h.agent_history.get("events", []):
            if ign.has("event", e.get("id")):
                e["alert"] = False
        # Security filters added or removed since an event arrived apply to it too.
        agentlib.apply_sec_filters(h.agent_history.get("security", []), settings["sec_filters"],
                                   set(int(i) for i in self.opts.get("agent_security_alert_ids", agentlib.DEFAULT_SECURITY_ALERT_IDS)))
        for fl in h.agent_history.get("failed_logons", []):
            agentlib.apply_logon_filters(fl, settings["sec_filters"], int(self.opts.get("agent_failed_logons", 20)))
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
        vc = self.vuln_check(h)
        if vc:
            checks.append(vc)
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
            if c["key"] == "security" and level == agentlib.CRIT and self._ack_time(h, "security") >= received:
                # A failed-logon burst in this report was acknowledged: green until a later report has another.
                level, detail = agentlib.OK, "Failed logons acknowledged"
            if c["key"] == "security" and level == agentlib.OK:
                recent = self._recent(h, "security", received)
                if recent:
                    last = recent[-1]
                    acct = self._pretty_account(last.get("account"))
                    level, detail = agentlib.WARN, (f"{len(recent)} notable security event(s) in 24h; latest: "
                                                    f"{last.get('what')}" + (f" ({acct})" if acct else ""))
            if level == agentlib.CRIT:
                if restoring and failures is not None:
                    # Back as it was before the restart: a problem already confirmed stays red, so the
                    # next report doesn't turn it amber -> red and alert a second time.
                    sv.failures = int(failures.get(sv.key) or 1)
                elif not reeval:
                    sv.failures += 1
                elif sv.failures == 0:
                    # Re-checking after a settings change (e.g. Stop ignoring): the problem
                    # was already in the report, so don't wait for two more reports.
                    sv.failures = 2
                status = AMBER if c.get("confirm") and sv.failures < 2 else RED
                if startup_until(h, time.time()) and not restoring:
                    # Just switched on: services may still be starting, so wait before alerting.
                    # Checked again when the allowance ends (see check_startup_end).
                    status, sv.failures = MAINT, max(sv.failures, 2)
                    detail = f"starting up: {detail}"
            else:
                sv.failures = 0
                status = self.LEVEL_STATUS[level]
            # Acknowledged (Overview or details): OK while it stays as it is or better. Worse, or cleared,
            # and the acknowledgement goes, so it alerts again (now, or when it comes back).
            ack = (self.agent_settings["hosts"].get(h.key) or {}).get("check_acks", {}).get(c["key"])
            if ack and c["key"] == "vulns" and "ids" in ack and set(c.get("ids") or []) - set(ack["ids"]):
                ack = None  # a new vulnerability since it was acknowledged: it alerts again
                if not restoring:
                    self.agent_settings["hosts"][h.key]["check_acks"].pop("vulns", None)
                    self._save_agent_settings()
            sv.acked = False
            if ack:
                if status in (AMBER, RED) and (ack.get("status") == RED or status == AMBER):
                    sv.acked, status = True, GREEN
                elif not restoring:
                    self.agent_settings["hosts"][h.key]["check_acks"].pop(c["key"], None)
                    self._save_agent_settings()
            sv.label, sv.detail, sv.last_check = c["label"], detail, received
            if not restoring and not reeval:
                self.store.add(svc_key(h, sv), received, MAINT_OK if status == MAINT else status != RED, None)
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
            self._track_admins(h, report, received)
        await self._recompute(h, quiet=restoring)
        if not restoring:
            self.publish_soon(h)

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
        if s.acked:
            await self.dismiss(f"ping_monitor_{svc_key(h, s)}")  # acknowledged: not an alert, and not a recovery either
            return
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
        cat = self._email_cat(s)
        if new == RED:
            if s.key == "agent_agent" and h.status == RED:
                return  # the "down" alert already covers it
            await self.notify(f"🟠 {h.name}: {s.label}", s.detail or "", tag, critical=h.critical, cat=cat)
            await self.persist(tag, f"Rollcall: {h.name} {s.label}", s.detail or "")
        elif old == RED:
            await self.dismiss(tag)
            if self.opts["notify_recovery"]:
                word = "OK" if new == GREEN else "no longer critical"
                await self.notify(f"🟢 {h.name}: {s.label} {word}", s.detail or "", tag, cat=cat)

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
                                  f"{e.get('level')}: {e.get('message')}", self._tag(h), level="event", cat="agents")
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
                await self.notify(f"{icon} {h.name}: {text}", msg, self._tag(h), level="event", cat="security")
                sent += 1
        for d in notable["detections"][:5]:
            ok = d.get("action_success", True)
            await self.notify(f"🦠 {h.name}: Defender detected {d.get('threat')}",
                              f"{d.get('resource') or ''} ({'dealt with' if ok else 'NOT removed: check this server'})",
                              self._tag(h), level="event" if ok else "red", cat="security")
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
                self.publish_soon(h)
            elif chip.status == RED and age <= limit:
                pass  # recovered by the next report
            elif chip.status == RED:
                chip.detail = f"No report for {fmt_duration(now - h.agent_seen)}"

    def _agent_gone(self, h: Host) -> bool:
        """Down, off schedule, unreachable, or its agent hasn't reported for agent_stale_minutes: what its last
        report says about the moment (who's signed in) no longer holds."""
        if h.status == RED or h.off_schedule or getattr(h, "unreachable", False):
            return True
        stale = max(float(self.opts.get("agent_stale_minutes", 15)), 12) * 60
        return bool(h.agent_seen) and time.time() - h.agent_seen > stale

    def _agent_summary(self, h: Host) -> dict | None:
        if not h.agent_id:
            return None
        r = h.agent_report or {}
        mem = None
        if r.get("mem_total_mb"):
            mem = round(100 * (1 - (r.get("mem_free_mb") or 0) / r["mem_total_mb"]), 1)
        rec = (self.agents.agents.get(h.agent_id) if self.agents else None) or {}
        return {"id": h.agent_id, "last_seen": h.agent_seen, "version": r.get("agent_version"),
                "sent_to": rec.get("sent_to"), "source_ip": rec.get("source_ip"), "forwarded_for": rec.get("forwarded_for"),
                "roles": r.get("roles") or [], "os": r.get("os"), "uptime_s": r.get("uptime_s"),
                # Before the first report, the OS comes from the enrolment request.
                "os_family": r.get("os_family") or ((self.agents.agents.get(h.agent_id) if self.agents else None) or {}).get("os_family") or "windows",
                "load": r.get("load"),
                "cpu_pct": r.get("cpu_pct"), "mem_used_pct": mem, "pending_reboot": r.get("pending_reboot"),
                "hw_vendor": agentlib.clean_hw(r.get("hw_vendor"))[:80], "hw_model": agentlib.clean_hw(r.get("hw_model"))[:80],
                "serial": agentlib.clean_hw(r.get("serial"))[:60], "hw_board": r.get("hw_board") is True,
                # who is signed in: active sessions first, one entry per person (None: an agent too old to say).
                # Nobody while it's off or its agent has stopped reporting: the last report's users aren't there now.
                "users": None if "sessions" not in r else [] if self._agent_gone(h) else list(dict.fromkeys(
                    x["user"] for x in sorted(r["sessions"], key=lambda x: (x["state"] != "active", x["session"] != "console")))),
                "users_active": None if "sessions" not in r else 0 if self._agent_gone(h) else len({x["user"] for x in r["sessions"] if x["state"] == "active"}),
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
            if size <= 0 or (size < 0.5 and r.get("agent_kind") != "sh"):  # small ones only from routers (their flash)
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
            now, forgot = time.time(), self._host_settings(h).get("backup_forgot") or {}
            r["checks"] = {**r["checks"], "backups": {**bk, "jobs": [
                {**j, "_level": lv, "_why": why} for j in agentlib.backup_jobs_view(bk.get("jobs") or [], forgot)
                for lv, why in [agentlib.backup_job_state(j, now)]]}}
        sq = (r.get("checks") or {}).get("sql")
        if sq and sq.get("instances"):  # each database's state as the check sees it, for the Roles tab
            ign = agentlib.Ignore(list(self.opts.get("agent_ignore") or []) + list(self._host_settings(h).get("ignore") or []))
            now, hrs = time.time(), float(self.opts.get("agent_sql_backup_hours", 36))
            r["checks"] = {**r["checks"], "sql": {**sq, "instances": [
                {**i, "databases": [{**d, "_level": lv, "_state": st, "_why": why} for d in i.get("databases") or []
                                    for lv, st, why in [agentlib.sql_db_state(i, d, now, hrs, ign)]]} for i in sq["instances"]]}}
        tk = (r.get("checks") or {}).get("tasks")
        if tk and tk.get("tasks"):  # each task's state as the check sees it, for the Services tab
            ign = agentlib.Ignore(list(self.opts.get("agent_ignore") or []) + list(self._host_settings(h).get("ignore") or []))
            now = time.time()
            r["checks"] = {**r["checks"], "tasks": {**tk, "tasks": [{**t, "_state": st, "_why": why} for t in tk["tasks"]
                                                                    for st, why in [agentlib.task_state(t, now, ign, agentlib.boot_time(r, now))]]}}
        bk = (r.get("checks") or {}).get("backups")
        if bk and bk.get("jobs"):  # a well-known reason a Veeam run warned or failed, explained (hints.py)
            def _hinted(j):
                iss = j.get("issue")
                if not isinstance(iss, dict):
                    return j
                objs = [{**o, **({"_hint": hk[0]} if (hk := hintlib.known("backups", " ".join([str(o.get("reason") or "")] + [str(d) for d in o.get("details") or []]), 1)) else {})}
                        for o in iss.get("objects") or [] if isinstance(o, dict)]
                if not any("_hint" in o for o in objs):
                    hk = hintlib.known("backups", " ".join(str(x.get("text") or "") for x in iss.get("log") or [] if isinstance(x, dict)), 1)
                    return {**j, "issue": {**iss, "objects": objs, **({"_hint": hk[0]} if hk else {})}}
                return {**j, "issue": {**iss, "objects": objs}}
            r["checks"] = {**r["checks"], "backups": {**bk, "jobs": [_hinted(j) for j in bk["jobs"]]}}
        cs = (r.get("checks") or {}).get("certs")
        if cs and cs.get("certs"):  # each certificate's state as the check sees it, for the Security tab
            ign = agentlib.Ignore(list(self.opts.get("agent_ignore") or []) + list(self._host_settings(h).get("ignore") or []))
            res = agentlib.cert_store_state(cs["certs"], time.time(), int(self.opts.get("cert_warn_days", 30)),
                                            int(self.opts.get("cert_crit_days", 7)), ign)
            states = res[2]["states"] if res else {}
            r["checks"] = {**r["checks"], "certs": {**cs, "certs": [{**c, "_state": (states.get(c["thumbprint"]) or ["", ""])[0]}
                                                                    for c in cs["certs"]]}}
        secrets_out = None
        ag = self.agents.agents.get(h.agent_id) or {}
        if include_security and ag.get("agent_kind") != "sh":  # the OpenWrt agent doesn't scan files
            hsc = (self.agent_settings["hosts"].get(h.key) or {}).get("secret_scan") or {}
            secrets_out = {"status": r.get("secrets"), "findings": self.secret_findings(h.agent_id).get("findings") or [],
                           "rules": agentlib.SECRET_RULES, "config": {"mode": hsc.get("mode") or "default", "paths": hsc.get("paths") or [],
                                                                      "hours": hsc.get("hours") or 24},
                           "on": self.secret_scan_config({**ag, "host_key": h.key})["on"],
                           "default": str(self.opts.get("agent_secret_scan", "off")), "linux": ag.get("os_family") == "linux"}
        if not include_security:
            r.pop("security", None)
            r.pop("sessions", None)
            r.pop("secrets", None)
        hist = {k: [{**{kk: vv for kk, vv in i.items() if kk != "_rx"}, "received": i.get("_rx")} for i in v[-100:]]
                for k, v in h.agent_history.items() if include_security or k in ("events", "detections")}
        hs = self.agent_settings["hosts"].get(h.key) or {}
        settings = {"ignore": hs.get("ignore") or [], "global_ignore": self.agent_settings.get("global_ignore") or [],
                    "ack": hs.get("ack") or {},
                    "sec_filters": (hs.get("sec_filters") or []) if include_security else [],
                    "global_sec_filters": (self.agent_settings.get("global_sec_filters") or []) if include_security else [],
                    "config_ignore": list(self.opts.get("agent_ignore") or []), "disks": hs.get("disks") or {},
                    "nic_watch": hs.get("nic_watch") or {}, "nic_rates": h.nic_rates, "backup_forgot": hs.get("backup_forgot") or {},
                    "defaults": {"warn": self.opts.get("agent_disk_warn", 15), "crit": self.opts.get("agent_disk_crit", 5)},
                    "resources": hs.get("resources") or {}, "res_limits": agentlib.resource_limits(self.opts, {"resources": hs.get("resources") or {}})}
        if include_security and hs.get("domain_seen") is not None:
            dseen = hs["domain_seen"]
            dm = (r.get("checks") or {}).get("domain")
            if dm:
                r["checks"] = {**r["checks"], "domain": {**dm, "groups": [
                    {**g, "members": [{**a, "_since": (dseen.get(agentlib.domain_key(g["name"], a["name"])) or {}).get("since")} for a in g["members"]]}
                    for g in dm.get("groups") or []]}}
            settings["domain_changes"] = hs.get("domain_changes") or []
        elif not include_security and (r.get("checks") or {}).get("domain"):
            r["checks"] = {**r["checks"], "domain": {"hidden": True}}  # account names are for admins and editors
        if include_security and hs.get("admins_seen") is not None:
            seen = hs["admins_seen"]
            sec = r.get("security") or {}
            if sec.get("admins") is not None:
                r["security"] = {**sec, "admins": [{**a, "_since": (seen.get(agentlib.admin_key(a)) or {}).get("since")}
                                                   for a in sec["admins"]]}
            settings["admin_changes"] = hs.get("admins_changes") or []
        sw = self.software(h.agent_id)
        if sw:
            newer, vul = self.software_newer(h.agent_id), self.vulns_by_app(h) if include_security else {}
            sw = {**sw, "apps": [{**a, **({"newer": newer[i]["version"]} if i in newer else {}), **({"vulns": vul[i]} if i in vul else {})}
                                 for i, a in enumerate(sw.get("apps") or [])],
                  "updates_from": "package manager" if (self.agents.agents.get(h.agent_id) or {}).get("os_family") == "linux"
                  else ("winget" if self.winget else None), "winget": self.winget_info}
        return {"key": h.key, "name": h.name, "agent": self._agent_summary(h), "report": r, "history": hist,
                "settings": settings, "software": {k: sw.get(k) for k in ("updated", "apps", "first", "updates_from", "winget")} | {"changes": (sw.get("changes") or [])[-100:]} if sw else None,
                "vulns": self.vulns_view(h) if include_security else None,
                "received": h.agent_seen, "security_visible": include_security, "secrets": secrets_out,
                "checks": [{"key": s.key.removeprefix("agent_"), "label": s.label, "status": s.status,
                            "detail": s.detail if include_security or s.key not in SECURITY_KEYS else SECURITY_HIDDEN,
                            **({"hint": hk} if s.status in (RED, AMBER) and s.key not in SECURITY_KEYS
                               and (hk := hintlib.known(s.key.removeprefix("agent_"), s.detail or "")) else {}),
                            **({"acked": True} if s.acked else {})}
                           for s in h.agent_checks]}

    # -- reporting --------------------------------------------------------
    DAY_CACHE_SECONDS = 30

    def _day(self, key: str) -> tuple[float | None, list[str]]:
        """24-hour uptime and history strip for a host or check, worked out in one pass and kept for
        DAY_CACHE_SECONDS: the dashboard and Home Assistant ask for them for everything, often."""
        now = time.time()
        first = self.history_start(now)
        hit = self._day_cache.get(key)
        if hit and now - hit[0] < self.DAY_CACHE_SECONDS and hit[1] == first:
            return hit[2]
        res = day_summary(self.store.rows(key, now - DAY), first, now, DAY / BUCKETS, BUCKETS, self.max_gap)
        self._day_cache[key] = (now, first, res)
        return res

    def uptime_24h(self, key: str) -> float | None:
        return self._day(key)[0]

    @staticmethod
    def history_start(now: float | None = None) -> int:
        """Where the uptime strip starts. Segments are whole half hours on the clock (16:00-16:30 ...);
        the last one is the current half hour, up to now."""
        size = int(DAY / BUCKETS)
        return int((now or time.time()) // size * size - (BUCKETS - 1) * size)

    def history(self, key: str) -> list[str]:
        return self._day(key)[1]

    async def publish(self, h: Host) -> None:
        sends = [self.ha.set_state(
            h.entity_id,
            h.status,
            {
                "friendly_name": h.name,
                "icon": ICONS[h.status],
                "host": h.host,
                "ip": h.ip,
                "ip_range": self.ip_ranges().name_of(h.ip),
                "uptime_24h": self.uptime_24h(h.key),
                "latency_ms": h.latency,
                "consecutive_failures": h.failures,
                "last_check": iso(h.last_check),
                "last_change": iso(h.last_change),
                "maintenance_until": iso(h.maint_until),
                "off_schedule": h.off_schedule,
                "schedule": "whenever it's on" if h.expect_off else describe_schedule(h.schedule),
                "alerts": not h.no_alerts,
                "critical": h.critical,
                "upstream_device": self.hosts[h.parent].name if h.parent in self.hosts else None,
                "unreachable": h.unreachable,
                "services": {s.label: s.status for s in h.services + h.agent_checks},
            },
        )]
        for s in h.services + h.agent_checks:
            sends.append(self.ha.set_state(
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
            ))
        sends += [self.ha.set_state(eid, value, attrs) for eid, value, attrs in self._metrics(h)]
        await asyncio.gather(*sends)

    def publish_soon(self, h: Host) -> None:
        """Send a host's sensors to Home Assistant in the background, so a dashboard action or an
        agent report doesn't wait for it (Home Assistant can be slow, e.g. while the host is busy)."""
        self._pub_pending.add(h.key)
        if not self._pub_task or self._pub_task.done():
            self._pub_task = asyncio.create_task(self._publish_pending())

    async def _publish_pending(self) -> None:
        await asyncio.sleep(0.5)  # several changes in a row: each host is sent once
        while self._pub_pending:
            h = self.hosts.get(self._pub_pending.pop())
            if h and not h.removed:
                try:
                    await self.publish(h)
                except Exception:  # noqa: BLE001
                    log.exception("Couldn't update %s in Home Assistant", h.name)

    async def _publish_all(self) -> None:
        for h in list(self.hosts.values()):
            if h.status != UNKNOWN and not h.removed:
                await self.publish(h)

    def ip_ranges(self) -> "iprange.Ranges":
        """The named IP ranges (Settings, Display), worked out again only when they change."""
        raw = tuple(self.opts.get("ip_ranges") or [])
        if getattr(self, "_ranges", (None, None))[0] != raw:
            self._ranges = (raw, iprange.Ranges(raw))
        return self._ranges[1]

    def snapshot(self) -> dict:
        hosts = []
        vmh = self.vm_hosts()
        ranges = self.ip_ranges()
        for h in list(self.hosts.values()):
            short = h.name.strip().lower().split(".")[0]
            on = vmh.get(short) or vmh.get(str(h.host).lower().split(".")[0])
            hosts.append({
                "key": h.key, "name": h.name, "host": h.host, "ip": h.ip,
                "vm_host": on if on and on != h.name else None,
                "status": h.status, "failures": h.failures, "latency_ms": h.latency,
                "uptime_24h": self.uptime_24h(h.key), "history": self.history(h.key), "history_start": self.history_start(),
                "last_check": h.last_check, "last_change": h.last_change,
                "next_check": h.next_due, "checking": h.checking,
                "entity_id": h.entity_id,
                "maint_until": h.maint_until, "maint_seen_down": h.maint_seen_down,
                "schedule": h.schedule, "schedule_text": describe_schedule(h.schedule) if h.schedule else
                ("Checked whenever it's on" if h.expect_off else None),
                "expect_off": h.expect_off, "startup_grace": h.startup_grace, "no_alerts": h.no_alerts, "critical": h.critical,
                "off_schedule": h.off_schedule, "reachable": h.reachable, "schedule_next": schedule_state(h.schedule, time.time())[2],
                "starting_up": bool(h.schedule and not h.off_schedule and h.status == MAINT and not h.maint_until)
                or bool(startup_until(h, time.time()) and h.status in (GREEN, DEGRADED)),
                "starting_until": startup_until(h, time.time()),
                "checks": h.checks,
                "snmp": any(s.kind == "snmp" for s in h.services), "snmp_community_set": bool(h.snmp_community),
                "ha_device": h.ha_device, "ha_device_name": h.ha_device_name, "ha_more": h.ha_more,
                "ilo": any(s.kind == "ilo" for s in h.services), "ilo_user": h.ilo_user, "ilo_pass_set": bool(h.ilo_pass),
                "jellyfin_url": h.jf_url, "jellyfin_key_set": bool(h.jf_key), "jellyfin": h.jf_data,
                "plex_url": h.px_url, "plex_token_set": bool(h.px_key), "plex": h.px_data,
                "starlink_source": h.sl_source, "starlink_addr": h.sl_addr, "starlink_cookie_set": bool(h.sl_cookie),
                "starlink_dish": h.sl_dish, "starlink_dish_name": h.sl_dish_name, "starlink": h.sl_data,
                "snmp_version": h.snmp_version, "icon": h.icon, "model": h.model, "subtitle": h.subtitle, "group": h.group, "check_by": h.check_by, "via_agent": h.via_agent,
                "ip_range": ranges.name_of(h.ip), "parent": h.parent if h.parent in self.hosts else "", "unreachable": h.unreachable,
                "upstream_down": self.hosts[h.upstream_down].name if h.upstream_down in self.hosts else None,
                "alert_held": bool(h.alert_held),
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
                    "agent": s.kind == "agent", **({"acked": True} if s.acked else {}),
                    **({"hint": hk} if s.status in (RED, AMBER) and (hk := hintlib.known(s.key.removeprefix("agent_"), s.detail or "")) else {}),
                    **({"ackable": any(i["what"] != "SNMP" and not i.get("acked") and not i.get("ignored") for i in h.snmp_items)} if s.kind == "snmp" else
                       {"ackable": any(i["what"] != "iLO" and not i.get("acked") and not i.get("ignored") for i in h.ilo_items)} if s.kind == "ilo" else {}),
                } for s in h.services + h.agent_checks],
                "acks": self.acks_summary(h),
                "agent": self._agent_summary(h),
                **({"same_as": {"key": o.key, "name": o.name}} if (o := self.same_computer(h)) else {}),
            })
        self.syslog_sweep()
        return {"now": time.time(), "interval": self.interval,
                "agent_stale_minutes": int(self.opts.get("agent_stale_minutes", 15)), "laps_overdue_days": int(self.opts.get("agent_laps_overdue_days", 3)), "bitlocker_require": str(self.opts.get("agent_bitlocker_require", "workstations")), "cert_warn_days": int(self.opts.get("cert_warn_days", 30)), "cert_crit_days": int(self.opts.get("cert_crit_days", 7)), "sql_backup_hours": int(self.opts.get("agent_sql_backup_hours", 36)), "exchange_queue_warn": int(self.opts.get("agent_exchange_queue_warn", 250)), "time_warn": int(self.opts.get("agent_time_warn_seconds", 60)), "time_crit": int(self.opts.get("agent_time_crit_seconds", 240)), "mem_warn": int(self.opts.get("agent_memory_warn", 90)), "mem_crit": int(self.opts.get("agent_memory_crit", 95)), "cpu_warn": int(self.opts.get("agent_cpu_warn", 90)), "name_line": str(self.opts.get("name_line", "auto")),
                "syslog_port": self.syslog_port, "syslog_unknown": [{k: v for k, v in u.items() if k != "held"} for u in sorted(self.syslog_unknown.values(), key=lambda u: -u["last"])[:20]],
                "retry_interval": self.retry_interval,
                "maintenance_minutes": int(self.opts["maintenance_minutes"]),
                "ping_mode": PING_MODE, "db_health": self.dbh.summary(DB_PATH), "claude_hints": self.claude_on(),
                "ai_name": hintlib.PROVIDERS[self.ai_settings()[0]]["name"],
                "hosts": hosts}


# --------------------------------------------------------------------------
# Access control
# --------------------------------------------------------------------------
class Access:
    """Decides who may change things (add/edit/delete/pause/reset).

    Home Assistant's ingress proxy tells us who is viewing (X-Remote-User-*
    headers) but not whether they're an admin, so the admin list is read from
    HA's user list and cached. Names in the `editors` option can always make
    changes. If the user list can't be read, nobody else can until it can be
    (before 1.92.1 everyone could when no editors were set: the panel is open to
    every Home Assistant user, so that let anyone approve agents and change
    settings). `editors` is set in the add-on's Configuration tab, outside
    Rollcall, so this can't lock an admin out for good.
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
                                "identified. %s", "Only names in 'editors' can make changes until it can be read."
                                if self.editors else "Nobody can make changes until it can be read; to make "
                                "changes meanwhile, add your Home Assistant username to the 'editors' option "
                                "in the add-on's Configuration tab.")
                return
            self.admins = {u["id"] for u in users if u.get("id") and (
                u.get("is_admin") or u.get("is_owner") or "system-admin" in (u.get("group_ids") or []))}
            log.debug("Loaded %d HA admin user(s)", len(self.admins))

    def update(self, opts: dict) -> None:
        """New admin_only_changes / editors settings, used from the next request."""
        self.enabled = bool(opts.get("admin_only_changes", True))
        self.editors = {str(e).strip().lower() for e in (opts.get("editors") or []) if str(e).strip()}
        self.warned = False

    async def is_admin(self, req) -> bool:
        """A real Home Assistant admin (not just someone in `editors`): only they may change who can edit."""
        if not SUPERVISOR_TOKEN:
            return True  # running outside Home Assistant (development)
        uid = req.headers.get("X-Remote-User-Id", "")
        if not uid:
            return False
        await self._refresh()
        if self.admins is not None and uid not in self.admins and time.time() - self.loaded_at > 30:
            await self._refresh(force=True)
        return self.admins is not None and uid in self.admins

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
            return False  # fails closed: names in editors were let in above
        return uid in self.admins

    def blocked(self) -> bool:
        """Changes are off for admins because HA's user list can't be read (the dashboard says so)."""
        return self.enabled and bool(SUPERVISOR_TOKEN) and self.admins is None and self.loaded_at > 0


# --------------------------------------------------------------------------
# Web
# --------------------------------------------------------------------------
def build_app(monitor: Monitor, access: Access, live: "LiveSettings | None" = None) -> web.Application:
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

    def admin_only(handler):
        """Home Assistant admins only (not editors): e.g. messages to users' screens."""
        async def wrapped(req):
            if not await access.is_admin(req):
                user = await access.who(req)
                log.info("Blocked %s (admins only): %s %s", user["display"] or "unknown user", req.method, req.path)
                raise web.HTTPForbidden(text=json.dumps({"error": "Only Home Assistant admins can do this."}), content_type="application/json")
            return await handler(req)
        return wrapped

    def _msg_devices():
        out = []
        for h in monitor.hosts.values():
            a = next((x for x in (monitor.agents.agents.values() if monitor.agents else []) if x.get("host_key") == h.key), None)
            if a and a.get("os_family") in ("windows", "linux") and a.get("agent_kind") != "sh":
                out.append({"key": h.key, "name": h.name, "os": a.get("os_family"), "version": a.get("agent_version") or "",
                            "included": h.key in monitor.messages.included})
        return sorted(out, key=lambda x: x["name"].lower())

    async def _json_body(req) -> dict:
        try:
            b = await req.json()
        except ValueError:
            b = None
        if not isinstance(b, dict):
            raise web.HTTPBadRequest(text=json.dumps({"error": "expected a JSON object"}), content_type="application/json")
        return b

    async def messages_list(req):
        names = {h.key: h.name for h in monitor.hosts.values()}
        now = time.time()
        sent = []
        for m in reversed(monitor.messages.sent):
            st = m.get("status") or {}
            rows = [{"key": k, "name": names.get(k, k), **(st.get(k) or {})} for k in m["to"]]
            sent.append({"id": m["id"], "text": m["text"], "by": m.get("by"), "at": m["at"], "expires": m["expires"], "label": m.get("label"),
                         "cancelled": m.get("cancelled"), "live": not m.get("cancelled") and m["expires"] > now, "devices": rows})
        return web.json_response({"enabled": bool(monitor.opts.get("messages")), "heading": msglib.HEADING, "max_chars": msglib.MAX_CHARS,
                                  "hours": list(msglib.EXPIRY_HOURS), "devices": _msg_devices(), "sent": sent[:30]})

    async def messages_send(req):
        if not monitor.opts.get("messages"):
            return web.json_response({"error": "Messages are turned off (Manage → Settings → Messages)"}, status=400)
        body = await _json_body(req)
        user = await access.who(req)
        try:
            keys = [str(k) for k in body.get("keys") or []][:2000]
            m = monitor.messages.send(body.get("text"), user["display"] or "an admin", keys, int(body.get("hours") or 0), str(body.get("label") or ""))
        except (ValueError, TypeError) as err:
            return web.json_response({"error": str(err)}, status=400)
        log.info("%s sent a message to %d device(s)%s: %s", user["display"] or "an admin", len(m["to"]),
                 f" ({m['label']})" if m["label"] else "", m["text"][:120].replace("\n", " / "))
        return web.json_response({"ok": True, "id": m["id"], "to": len(m["to"])})

    async def messages_included(req):
        body = await _json_body(req)
        known = {d["key"] for d in _msg_devices()}
        keys = [str(k) for k in body.get("keys") or [] if str(k) in known]
        user = await access.who(req)
        before = set(monitor.messages.included)
        monitor.messages.set_included(keys)
        added, removed = set(keys) - before, before - set(keys)
        if added or removed:
            log.info("%s changed who can receive messages: %d added, %d removed (%d in all)", user["display"] or "an admin", len(added), len(removed), len(keys))
        return web.json_response({"ok": True, "included": len(keys)})

    async def messages_cancel(req):
        user = await access.who(req)
        if not monitor.messages.cancel(req.match_info["id"]):
            raise web.HTTPNotFound()
        log.info("%s withdrew a message", user["display"] or "an admin")
        return web.json_response({"ok": True})

    async def hints_test(req):
        """Settings → Error hints → Test: one tiny question to the chosen provider, to check its key and model."""
        prov, key, model = monitor.ai_settings()
        p = hintlib.PROVIDERS[prov]
        if not key:
            return web.json_response({"error": f"No {p['key_name']} is saved yet."}, status=400)
        try:
            text, used = await hintlib.call(monitor.ha.session, prov, key, model, "Answer in one word.", "Reply with the word OK.", 200)
        except ValueError as e:
            return web.json_response({"error": str(e), "provider": p["name"], "model": model}, status=502)
        user = await access.who(req)
        log.info("%s tested hints from %s (%s): it answered", user["display"] or "an admin", p["name"], used)
        return web.json_response({"ok": True, "provider": p["name"], "model": used, "text": text[:100]})

    async def hints_ask(req):
        """💡 Ask the AI about one amber or red check (or, with preview, just show what would be sent)."""
        try:
            body = await req.json()
        except (json.JSONDecodeError, ValueError):
            raise web.HTTPBadRequest(text="invalid JSON")
        h = monitor.hosts.get(str((body or {}).get("host") or ""))
        if not h:
            return web.json_response({"error": "No such device"}, status=404)
        try:
            check, sent = monitor.claude_question(h, str(body.get("check") or ""))
        except ValueError as e:
            return web.json_response({"error": str(e)}, status=400)
        opts = monitor.opts
        limit = int(opts.get("claude_hints_per_day") or 30)
        local = datetime.fromtimestamp(time.time(), TZ) if TZ else datetime.now()
        day = local.strftime("%Y-%m-%d")
        base = {"sent": sent, "check": check, "left": monitor.claude.left_today(day, limit), "limit": limit}
        if body.get("preview"):
            return web.json_response(base)
        if not monitor.claude_on():
            return web.json_response({**base, "error": "Hints from AI are off. An admin can turn them on under Settings → Error hints."}, status=409)
        user = await access.who(req)
        prov, key, model = monitor.ai_settings()
        name = hintlib.PROVIDERS[prov]["name"]
        try:
            out = await monitor.claude.ask(monitor.ha.session, key, model, check["label"], sent, day, limit, time.time(), prov)
        except ValueError as e:
            log.warning("Hint from %s for %s / %s: %s", name, h.name, check["label"], e)
            return web.json_response({**base, "left": monitor.claude.left_today(day, limit), "error": str(e)}, status=502)
        if not out["cached"]:
            log.info("%s asked %s about %s on %s", user["display"] or "someone", name, check["label"], h.name)
        return web.json_response({**base, **out, "left": monitor.claude.left_today(day, limit)})

    async def database_info(_req):
        """Manage > Database: sizes, what takes the room, and the last check."""
        out = await asyncio.to_thread(monitor.db_details)
        return web.json_response(out, headers={"Cache-Control": "no-store"})

    async def database_check(_req):
        if monitor.dbh.busy:
            return web.json_response({"error": "A database check or compaction is already running."}, status=409)
        await monitor.db_check()
        return web.json_response(await asyncio.to_thread(monitor.db_details))

    async def database_compact(req):
        """Compact now (VACUUM): admins only, and only with room for the temporary copies."""
        if monitor.dbh.busy:
            return web.json_response({"error": "A database check or compaction is already running."}, status=409)
        room, need, free = dblib.vacuum_room(DB_PATH)
        if not room:
            return web.json_response({"error": f"Not enough free space to compact: it needs about {dblib.fmt_bytes(need)} "
                                               f"and {dblib.fmt_bytes(free)} is free."}, status=409)
        user = await access.who(req)
        log.info("%s compacted the database", user["display"] or "an admin")
        monitor.dbh.busy = "compact"
        try:
            before, after, took = await asyncio.to_thread(dblib.vacuum, monitor.store.db, DB_PATH)
        except sqlite3.Error as e:
            log.warning("Couldn't compact the database: %s", e)
            return web.json_response({"error": f"Couldn't compact the database: {e}"}, status=500)
        finally:
            monitor.dbh.busy = ""
        monitor.dbh.record_compact(before, after, took, time.time())
        log.info("Database compacted: %s to %s in %.1f s", dblib.fmt_bytes(before), dblib.fmt_bytes(after), took)
        return web.json_response({"before": before, "after": after, "took": took, **await asyncio.to_thread(monitor.db_details)})

    async def addon_log(req):
        """The add-on's log (Manage > Log), newest last, with secrets masked."""
        try:
            limit = max(100, min(5000, int(req.query.get("lines", 1000))))
        except ValueError:
            limit = 1000
        source, lines = await addonlog.read(monitor.ha.session, SUPERVISOR_API, SUPERVISOR_TOKEN, LOG_BUFFER, limit)
        return web.json_response({"source": source, "lines": lines}, headers={"Cache-Control": "no-store"})

    async def index(_req):
        # The browser may keep a copy but must check it each time (a 304 when unchanged), so the
        # page isn't downloaded again on every visit and an add-on update still shows straight away.
        return web.FileResponse(WEB_DIR / "index.html", headers={"Cache-Control": "no-cache"})

    async def status(req):
        snap = monitor.snapshot()
        user = await access.who(req)
        snap["user"] = user["display"] or None
        snap["can_edit"] = user["can_edit"]
        snap["edit_blocked"] = not user["can_edit"] and access.blocked()  # the user list can't be read: say why
        snap["can_admin"] = await access.is_admin(req)  # Messages, HTTPS for agents
        snap["messages_on"] = bool(monitor.opts.get("messages"))
        # Agents report over plain HTTP and Rollcall's own HTTPS isn't on: admins are offered it
        snap["tls_prompt"] = bool(not AGENT_TLS.on and not monitor.opts.get("agent_ssl") and monitor.agents and monitor.agents.agents)
        # Rollcall's own HTTPS is on and every agent has moved to it, but plain HTTP is still open: suggest closing it
        rows = list(monitor.agents.agents.values()) if monitor.agents else []
        snap["tls_plain_prompt"] = bool(monitor.tls_builtin() and AGENT_TLS.plain_http and rows
                                        and not any(str(a.get("sent_to") or "").startswith("http://") for a in rows))
        snap["networks"] = await monitor.network_view()
        if user["can_edit"] and monitor.agents:
            snap["agents_pending"] = len(monitor.agents.pending)
        if not user["can_edit"]:
            for h in snap["hosts"]:
                if h.get("agent") and h["agent"].get("users") is not None:
                    h["agent"] = {**h["agent"], "users": [], "users_hidden": True}
                for sv in h["services"]:
                    if sv["key"] in SECURITY_KEYS:
                        sv["detail"] = SECURITY_HIDDEN
        return web.json_response(snap)

    async def settings_get(req):
        """The add-on's settings for Manage > Settings."""
        notify = []
        services = await monitor.ha.get_json("/services")
        for d in services if isinstance(services, list) else []:
            if isinstance(d, dict) and d.get("domain") == "notify":
                notify = sorted(s for s in (d.get("services") or {}) if s not in ("send_message", "persistent_notification"))
        return web.json_response({
            "groups": [{"key": k, "label": v} for k, v in settingslib.GROUPS],
            "fields": settingslib.fields(),
            "values": settingslib.values(monitor.opts),
            "can_admin": await access.is_admin(req),
            "notify_services": notify,
            "ssl_files": live.ssl_files() if live else [],
            "agent_port": "HTTPS" if live and live.agent_listener and live.agent_listener.https else "HTTP",
            "agent_tls": _tls_info(),  # Rollcall's own HTTPS (Manage → Agents), so the Agent port note tells the whole story
        })

    async def settings_post(req):
        if not live:
            return web.json_response({"error": "Settings can't be changed here; use the Configuration tab."}, status=503)
        try:
            body = await req.json()
        except (json.JSONDecodeError, ValueError):
            raise web.HTTPBadRequest(text="invalid JSON")
        changes = body.get("values") if isinstance(body, dict) else None
        if not isinstance(changes, dict):
            raise web.HTTPBadRequest(text="expected {\"values\": {...}}")
        if set(settingslib.ACCESS_KEYS) & changes.keys() and not await access.is_admin(req):
            same = all(monitor.opts.get(k) == changes[k] for k in settingslib.ACCESS_KEYS if k in changes)
            if not same:
                return web.json_response({"error": "Only Home Assistant admins can change who can make changes, messages or hints from Claude.",
                                          "errors": {k: "Only Home Assistant admins can change this"
                                                     for k in settingslib.ACCESS_KEYS if k in changes}}, status=403)
            changes = {k: v for k, v in changes.items() if k not in settingslib.ACCESS_KEYS}
        user = await access.who(req)
        try:
            result = await live.save(changes, user["display"] or "")
        except ValueError as err:
            problems = err.args[0] if err.args and isinstance(err.args[0], dict) else {}
            return web.json_response({"error": "Some settings need changing first.", "errors": problems}, status=400)
        except RuntimeError as err:
            return web.json_response({"error": f"Not saved: {err}"}, status=502)
        return web.json_response({"ok": True, **result, "values": settingslib.values(monitor.opts)})

    async def acks_dismiss(req):
        """Dismiss acknowledged items from the Overview's list, or bring them back (undo)."""
        try:
            body = await req.json()
        except (json.JSONDecodeError, ValueError):
            body = {}
        items = [i for i in body.get("items") or [] if isinstance(i, list) and len(i) == 3 and all(isinstance(x, str) for x in i)][:500]
        if not items:
            return web.json_response({"error": "nothing to dismiss"}, status=400)
        user = await access.who(req)
        return web.json_response({"ok": True, "n": monitor.dismiss_acks(items, bool(body.get("undo")), user.get("display"))})

    async def email_test(req):
        """Send a test email with the settings in the dialog (saved or not), so they can be tried first."""
        try:
            body = await req.json()
        except (json.JSONDecodeError, ValueError):
            body = {}
        vals = body.get("values") if isinstance(body, dict) and isinstance(body.get("values"), dict) else {}
        vals = {k: v for k, v in vals.items() if k.startswith(("email_", "smtp_", "m365_"))}
        cleaned, errors = settingslib.clean(vals)
        if errors:
            return web.json_response({"error": "Fix these first: " + "; ".join(f"{k}: {v}" for k, v in errors.items())}, status=400)
        opts = {**monitor.opts, **cleaned}
        user = await access.who(req)
        sections, summary = monitor.summary_sections()
        text = (f"This is a test from Rollcall, sent by {user['display'] or 'someone'} from the Settings.\n\n"
                f"{emaillib.describe(opts)}\n\n{summary}")
        page = emaillib._page("Rollcall test email", f"<p>This is a test from Rollcall, sent by {html_escape(user['display'] or 'someone')} from the Settings.</p>"
                              f"<p>{html_escape(emaillib.describe(opts))}</p>"
                              f"<p style='color:#4b5563'>{html_escape(summary)}</p>", str(opts.get("notification_url") or ""))
        try:
            await monitor.email.send("Rollcall test email", text + monitor.email._footer_text(), page, opts)
        except emaillib.EmailError as e:
            return web.json_response({"error": str(e)}, status=502)
        return web.json_response({"ok": True, "to": opts["email_to"]})

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

    async def ha_devices(req):
        """Home Assistant devices for the Edit dialog's "link a device" search."""
        q = (req.query.get("q") or "").strip().lower()
        reg = await monitor.ha.registry()
        if reg is None:
            return web.json_response({"error": "Couldn't read Home Assistant's devices", "devices": []})
        words = [w for w in re.split(r"[\s_.\-]+", q) if w]
        out = []
        for dev_id, dev in reg["devices"].items():
            ents = reg["entities"].get(dev_id, [])
            if not ents or dev.get("disabled_by"):
                continue
            name = dev.get("name_by_user") or dev.get("name") or ""
            platforms = sorted({e.get("platform") or "" for e in ents} - {""})
            hay = " ".join([name, dev.get("manufacturer") or "", dev.get("model") or "", " ".join(platforms)]).lower().replace("_", " ")
            if words and not all(w in hay for w in words):
                continue
            out.append({"id": dev_id, "name": name, "manufacturer": dev.get("manufacturer") or "", "model": dev.get("model") or "",
                        "integration": hadevice.integration_name(platforms), "entities": len(ents),
                        "known": any(p in hadevice.KNOWN for p in platforms)})
        out.sort(key=lambda d: (not d["known"], d["name"].lower()))
        return web.json_response({"devices": out[:50], "total": len(out)})

    async def host_ha(req):
        h = monitor.hosts.get(req.match_info["key"])
        if not h:
            raise web.HTTPNotFound()
        return web.json_response({"name": h.name, "device_id": h.ha_device, "device_name": h.ha_device_name, "more": h.ha_more, "data": h.ha_data})

    async def host_ha_action(req):
        """Press a button or turn a switch on or off on the device linked to this device. Only its
        own buttons and switches, as Rollcall last read them, can be used."""
        h = monitor.hosts.get(req.match_info["key"])
        if not h:
            raise web.HTTPNotFound()
        body = await req.json()
        eid, action = str(body.get("entity_id") or ""), str(body.get("action") or "")
        ent = next((e for e in ((h.ha_data or {}).get("entities") or []) if e.get("entity_id") == eid), None)
        allowed = {"button": ("press",), "switch": ("turn_on", "turn_off")}
        domain = eid.split(".", 1)[0]
        if not ent or action not in allowed.get(domain, ()):
            raise web.HTTPBadRequest(text=json.dumps({"error": "That control isn't on this device"}), content_type="application/json")
        user = await access.who(req)
        err = await monitor.ha.run_service(domain, action, {"entity_id": eid})
        log.info("%s: %s %s %s%s", h.name, user["display"] or "someone", action.replace("_", " "), eid, f" failed: {err}" if err else "")
        if err:
            return web.json_response({"error": err}, status=502)
        h.next_due = 0  # read it again soon so the new state shows
        return web.json_response({"ok": True})

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

    async def host_merge(req):
        """Move the agent from another entry for the same device onto this one, and remove that entry."""
        h = monitor.hosts.get(req.match_info["key"])
        try:
            body = await req.json()
        except (json.JSONDecodeError, ValueError):
            body = {}
        other = monitor.hosts.get(str(body.get("from") or ""))
        if not h or not other or other is h:
            raise web.HTTPNotFound()
        if monitor.same_computer(h) is not other:
            return web.json_response({"error": f"{other.name} doesn't look like the same device as {h.name}"}, status=400)
        user = await access.who(req)
        try:
            await monitor.merge_agent_into(h, other, user.get("display"))
        except ValueError as err:
            return web.json_response({"error": str(err)}, status=400)
        return web.json_response({"ok": True})

    async def agent_sec_filter(req):
        """Add, remove or widen a security filter (events that match don't alert)."""
        h = monitor.hosts.get(req.match_info["key"])
        if not h:
            raise web.HTTPNotFound()
        try:
            body = await req.json()
        except (json.JSONDecodeError, ValueError):
            body = {}
        action = body.get("action")
        if action not in ("add", "remove", "promote"):
            return web.json_response({"error": "action must be add, remove or promote"}, status=400)
        scope = "all" if body.get("scope") == "all" else "host"
        user = await access.who(req)
        try:
            flt = agentlib.clean_sec_filter(body.get("filter")) if action == "add" else None
            done = await monitor.set_sec_filter(h, action, scope, flt, str(body.get("id") or ""), user.get("display"))
        except ValueError as err:
            return web.json_response({"error": str(err)}, status=400)
        if not done:
            return web.json_response({"error": "That filter isn't there any more"}, status=404)
        return web.json_response({"ok": True, "filter": done})

    async def agent_ack(req):
        h = monitor.hosts.get(req.match_info["key"])
        if not h:
            raise web.HTTPNotFound()
        try:
            body = await req.json()
        except (json.JSONDecodeError, ValueError):
            body = {}
        kind = body.get("kind")
        user = await access.who(req)
        if kind == "check":  # any other check, until it gets worse or clears
            try:
                await monitor.acknowledge_check(h, str(body.get("check") or ""), user.get("display"), bool(body.get("undo")))
            except ValueError as e:
                return web.json_response({"error": str(e)}, status=400)
            return web.json_response({"ok": True})
        if kind not in TIME_ACK_KINDS:
            return web.json_response({"error": "kind must be check, " + ", ".join(TIME_ACK_KINDS)}, status=400)
        await monitor.acknowledge(h, kind, user.get("display"), bool(body.get("undo")))
        return web.json_response({"ok": True})

    async def agent_backup_forget(req):
        h = monitor.hosts.get(req.match_info["key"])
        if not h:
            raise web.HTTPNotFound()
        body = await req.json()
        key = str(body.get("id") or "")
        if not key or len(key) > 200:
            return web.json_response({"error": "invalid job"}, status=400)
        if not await monitor.forget_backup_job(h, key, body.get("forget") is not False):
            return web.json_response({"error": "that job isn't in the last report"}, status=404)
        return web.json_response({"ok": True})

    async def software_search(req):
        q = (req.query.get("q") or "").strip()
        if len(q) < 2 or len(q) > 100:
            return web.json_response({"error": "search for at least 2 characters"}, status=400)
        user = await access.who(req)
        return web.json_response({"results": monitor.software_search(q, include_security=user["can_edit"])})

    async def agent_secret_scan(req):
        h = monitor.hosts.get(req.match_info["key"])
        if not h:
            raise web.HTTPNotFound()
        body = await req.json()
        mode = str(body.get("mode") or "default")
        if mode not in ("default", "on", "off"):
            return web.json_response({"error": "invalid setting"}, status=400)
        raw = body.get("paths") or []
        if isinstance(raw, str):
            raw = raw.splitlines()
        paths = []
        for p in raw if isinstance(raw, list) else []:
            p = str(p).strip()
            if not p:
                continue
            if len(p) > 260 or not p.isprintable() or not re.match(r"^(/|[A-Za-z]:\\|\\\\)", p):
                return web.json_response({"error": f"not a full folder path: {p[:80]}"}, status=400)
            if p not in paths:
                paths.append(p)
        if len(paths) > 20:
            return web.json_response({"error": "20 folders at most"}, status=400)
        try:
            hours = int(body.get("hours") or 24)
        except (TypeError, ValueError):
            hours = 0
        if not 1 <= hours <= 720:
            return web.json_response({"error": "how often must be 1 to 720 hours"}, status=400)
        user = await access.who(req)
        await monitor.set_secret_scan(h, mode, paths, hours, user["display"])
        return web.json_response({"ok": True})

    async def agent_nic(req):
        h = monitor.hosts.get(req.match_info["key"])
        if not h:
            raise web.HTTPNotFound()
        body = await req.json()
        name = str(body.get("name") or "").strip()
        if not name or len(name) > 80 or not name.isprintable():
            return web.json_response({"error": "invalid adapter name"}, status=400)
        await monitor.set_nic_watch(h, name, body.get("watch") is True)
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

    async def agent_resources(req):
        h = monitor.hosts.get(req.match_info["key"])
        if not h:
            raise web.HTTPNotFound()
        body = await req.json()
        if not isinstance(body, dict):
            return web.json_response({"error": "expected an object"}, status=400)
        res = {}
        try:
            for k in ("mem_warn", "mem_crit", "cpu_warn"):
                v = body.get(k)
                if v not in (None, ""):
                    v = float(v)
                    if not 0 <= v <= 100:
                        raise ValueError
                    res[k] = int(v) if v.is_integer() else v
        except (TypeError, ValueError):
            return web.json_response({"error": "limits must be numbers from 0 to 100 (0 turns one off)"}, status=400)
        if res.get("mem_warn") and res.get("mem_crit") and res["mem_crit"] < res["mem_warn"]:
            return web.json_response({"error": "the red level can't be below the amber level"}, status=400)
        if body.get("off") is True:
            res["off"] = True
        await monitor.set_resources(h, res or None)
        return web.json_response({"ok": True})

    # -- Agents (admin) ---------------------------------------------------
    def _agent_row(a):
        h = monitor.hosts.get(a.get("host_key") or "")
        return {"id": a["id"], "hostname": a["hostname"], "fqdn": a.get("fqdn"), "ips": a.get("ips") or [],
                "os": a.get("os"), "version": a.get("agent_version"), "roles": a.get("roles") or [],
                "os_family": a.get("os_family") or "windows", "agent_kind": a.get("agent_kind"),
                "approved_at": a.get("approved_at"), "last_report": a.get("last_report"),
                "sent_to": a.get("sent_to"), "source_ip": a.get("source_ip"), "forwarded_for": a.get("forwarded_for"),
                "host_key": h.key if h else None, "host_name": h.name if h else None,
                **monitor.agent_side(a),
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
            "latest_linux_version": _linux_script_version(), "latest_sh_version": _sh_script_version(),
            "auto_update": {k: bool((monitor.agent_settings.get("auto_update") or {}).get(k)) for k in ("windows", "linux")},
            "rollout": {k: v for k, v in (monitor.agent_settings.get("rollout") or {}).items()
                        if v.get("version") == (_linux_script_version() if k == "linux" else _script_version())},
            "servers": monitor.agent_settings.get("servers") or {},
            "internal_networks": monitor.internal_networks(),
            "suggested_networks": await _suggested_networks(),
            "tls": _tls_info(),
        })

    def _tls_info() -> dict:
        rows = [a for a in monitor.agents.agents.values()] if monitor.agents else []
        tp = getattr(monitor, "tls_public_port", AGENT_HTTPS_PORT) or AGENT_HTTPS_PORT
        https = [a for a in rows if str(a.get("sent_to") or "").startswith("https://") and str(a.get("sent_to") or "").rstrip("/").endswith(f":{tp}")]
        plain = [a for a in rows if str(a.get("sent_to") or "").startswith("http://")]
        port = getattr(monitor, "tls_public_port", AGENT_HTTPS_PORT)
        return {"on": AGENT_TLS.on, "builtin": monitor.tls_builtin(), "own_cert": bool(monitor.opts.get("agent_ssl")),
                "plain_http": AGENT_TLS.plain_http, "port": port or AGENT_HTTPS_PORT, "port_off": not port, "http_port": AGENT_PORT,
                "pin": AGENT_TLS.pin() if AGENT_TLS.on else "", "names": AGENT_TLS.names() if AGENT_TLS.on else [],
                "agents_https": len(https), "agents_http": sorted(a.get("hostname") or "?" for a in plain)}

    async def agents_tls(req):
        """Turn Rollcall's own HTTPS for agents on or off, or plain HTTP off once agents have moved (admins only)."""
        body = await _json_body(req)
        user = await access.who(req)
        listener = getattr(monitor, "agent_listener", None)
        if not listener:
            return web.json_response({"error": "The agent port isn't running (see the log)"}, status=503)
        if monitor.opts.get("agent_ssl"):
            return web.json_response({"error": "The agent port already uses HTTPS with your own certificate (Settings → Agent port)"}, status=400)
        try:
            if "https" in body:
                on = body["https"] is True
                if on:
                    await asyncio.to_thread(AGENT_TLS.ensure_cert, monitor.tls_hosts())
                    AGENT_TLS.set(https=True)
                    await listener.set_builtin(True)
                else:
                    AGENT_TLS.set(https=False, plain_http=True)
                    await listener.set_plain(True)
                    await listener.set_builtin(False)
                log.info("%s turned Rollcall's own HTTPS for agents %s", user["display"] or "an admin", "on" if on else "off")
            if "plain_http" in body:
                keep = body["plain_http"] is not False
                if not keep and not AGENT_TLS.on:
                    return web.json_response({"error": "Turn on HTTPS first"}, status=400)
                AGENT_TLS.set(plain_http=keep)
                await listener.set_plain(keep)
                log.info("%s turned plain HTTP for agents %s", user["display"] or "an admin", "back on" if keep else "off")
        except Exception as err:  # noqa: BLE001
            log.exception("Changing agent HTTPS failed")
            return web.json_response({"error": f"That didn't work: {err}"}, status=500)
        return web.json_response({"ok": True, "tls": _tls_info()})

    async def _suggested_networks() -> list[str]:
        """Home Assistant's own networks, offered as a starting point for the internal networks."""
        out = []
        for i in await monitor.interfaces():
            for a in i.get("addresses") or []:
                try:
                    n = str(ipaddress.ip_interface(a).network)
                except ValueError:
                    continue
                if n not in out:
                    out.append(n)
        return out

    async def agents_networks(req):
        """Set the internal networks: agents on one try the inside address first, the rest the outside one."""
        body = await req.json()
        raw = body.get("networks")
        if isinstance(raw, str):
            raw = re.split(r"[\s,;]+", raw)
        out, errors = [], []
        for x in raw or []:
            x = str(x).strip()
            if not x:
                continue
            try:
                n = ipaddress.ip_network(x, strict=False)
            except ValueError:
                errors.append(x)
                continue
            if n.version != 4:
                errors.append(x)
                continue
            if str(n) not in out:
                out.append(str(n))
        if errors:
            return web.json_response({"error": "Enter each network as an IPv4 subnet like 10.0.1.0/24 ("
                                      + ", ".join(errors[:3]) + (" isn't" if len(errors) == 1 else " aren't") + ")"}, status=400)
        if len(out) > 50:
            return web.json_response({"error": "At most 50 networks"}, status=400)
        monitor.agent_settings["internal_networks"] = out
        monitor._save_agent_settings()
        user = await access.who(req)
        log.info("Internal networks for agents set to %s by %s", ", ".join(out) or "none", user["display"] or "someone")
        return web.json_response({"internal_networks": out})

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
        server = clean_servers(req.query.get("server") or "")
        if not server:
            raise web.HTTPBadRequest(text=json.dumps({"error": "Enter each address as http://host:port (up to 4)"}),
                                     content_type="application/json")
        os_name = req.query.get("os") if req.query.get("os") in ("linux", "openwrt") else "windows"
        body = build_agent_script(os_name, server, monitor.agents.enrol_key, req.query.get("ignore_cert") == "1")
        name = {"linux": "pingmonitor-agent.py", "openwrt": "rollcall-agent.sh"}.get(os_name, "PingMonitorAgent.ps1")
        return web.Response(body=body, content_type="application/octet-stream", headers={
            "Content-Disposition": f'attachment; filename="{name}"'})

    async def agents_msi(req):
        """A Windows installer with the addresses and enrolment key built in: for people who just double-click."""
        server = clean_servers(req.query.get("server") or "") or ",".join(monitor.agent_servers())
        if not server:
            raise web.HTTPBadRequest(text=json.dumps({"error": "Enter the address first"}), content_type="application/json")
        if not msilib.available():
            return web.json_response({"error": "This add-on build can't make installers (msitools is missing)"}, status=501)
        script = build_agent_script("windows", server, monitor.agents.enrol_key, req.query.get("ignore_cert") == "1")
        version = _script_version() or "1.0.0"
        try:
            body = await msilib.build(script, version)
        except (RuntimeError, OSError, asyncio.TimeoutError) as err:
            log.error("Couldn't build the agent installer: %s", err)
            return web.json_response({"error": "Couldn't build the installer; see the add-on log"}, status=500)
        log.info("Built the Windows agent installer (version %s) for %s", version, server)
        return web.Response(body=body, content_type="application/x-msi", headers={
            "Content-Disposition": f'attachment; filename="RollcallAgent-{version}.msi"'})

    async def agents_servers(req):
        body = await req.json()
        out = {}
        for k in ("inside", "outside"):
            v = str(body.get(k) or "").strip().rstrip("/")
            if v and not _ONE_SERVER.match(v):
                return web.json_response({"error": f"Enter the {k} address as http://host:port"}, status=400)
            out[k] = v
        if not out["inside"] and not out["outside"]:
            return web.json_response({"error": "Enter at least one address"}, status=400)
        monitor.agent_settings["servers"] = out
        monitor._save_agent_settings()
        log.info("Agents will report to %s", " then ".join(v for v in (out["inside"], out["outside"]) if v))
        return web.json_response({"servers": out})

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

    async def agents_rollout(req):
        body = await req.json()
        os_name, action = body.get("os"), body.get("action")
        if os_name not in ("windows", "linux") or action not in ("retry", "go"):
            return web.json_response({"error": "invalid request"}, status=400)
        latest = _linux_script_version() if os_name == "linux" else _script_version()
        r = monitor.rollout(os_name, latest)
        if action == "go":
            r.update(state="ok", done=time.time())
        else:  # try again, on a different device
            r.update(state="waiting", skip=(r.get("skip") or []) + ([r["pilot"]] if r.get("pilot") else []),
                     pilot=None, pilot_name=None, chosen=None, sent=None, waiting_since=time.time())
        monitor._save_agent_settings()
        user = await access.who(req)
        log.info("%s agent %s rollout: %s by %s", os_name.capitalize(), latest, "update the rest" if action == "go" else "retry",
                 user["display"] or "someone")
        return web.json_response({"ok": True})

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
        h.snmp_rediscover = True     # someone wants it fresh: re-read the port names too (normally every 6 hours)
        return web.json_response({"queued": h.key})

    async def host_metrics(req):
        """History for graphs: ?series=disk|C:|used,disk|C:|size&range=30d (24h, 7d, 30d, 90d, 1y).
        A disk's used space comes with when it's likely to be full, going by the last 30 days or more."""
        h = monitor.hosts.get(req.match_info["key"])
        if not h:
            raise web.HTTPNotFound()
        rng = req.query.get("range", "24h")
        if rng not in metricslib.RANGES:
            raise web.HTTPBadRequest(text="range must be one of " + ", ".join(metricslib.RANGES))
        names = [s for s in req.query.get("series", "").split(",") if s][:8]
        now = time.time()
        out = await asyncio.to_thread(monitor.metrics.view, h.key, names, rng, now)
        out["keep_days"] = int(monitor.opts.get("metrics_days") or 365)
        fc = {}
        for s in names:
            if s.startswith("disk|") and s.endswith("|used"):
                base = s[:-len("used")]
                span = max(30 * 86400, metricslib.RANGES[rng])
                pts = await asyncio.to_thread(monitor.metrics.query, h.key, s, now - span, now, 86400)
                size = await asyncio.to_thread(monitor.metrics.query, h.key, base + "size", now - 3 * 86400, now, 3 * 86400)
                f = metricslib.disk_forecast(pts, size[-1][1] if size else None, now)
                if f:
                    fc[s] = f
        out["forecast"] = fc
        return web.json_response(out)

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
            raise web.HTTPBadRequest(text="keys must be a list of devices")
        hosts = [monitor.hosts[k] for k in dict.fromkeys(str(k) for k in keys) if str(k) in monitor.hosts]
        return hosts, body

    async def maintenance_bulk(req):
        """Pause several devices at once, e.g. everything in a tab."""
        hosts, body = await _bulk_hosts(req)
        try:
            minutes = int(body.get("minutes") if body.get("minutes") is not None else monitor.opts["maintenance_minutes"])
        except (TypeError, ValueError):
            raise web.HTTPBadRequest(text="minutes must be a whole number")
        if not 1 <= minutes <= 1440:
            raise web.HTTPBadRequest(text="minutes must be between 1 and 1440")
        for h in hosts:
            await monitor.start_maintenance(h, minutes)
        log.info("Paused %d device(s) together for %d min", len(hosts), minutes)
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
            "presets": [{"name": n, "title": t, "group": g, "summary": preset_summary(n), "note": PRESET_NOTES.get(n, "")}
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

    async def same_machine(a: str, b: str) -> bool:
        """Two addresses on the same machine: the same name or IP, or names that look up to the same address."""
        if jflib.same_server(a, b):
            return True
        loop = asyncio.get_running_loop()
        ips = []
        for url in (a, b):
            try:
                host = urlparse(url).hostname or ""
                infos = await asyncio.wait_for(loop.getaddrinfo(host, None), 5)
                ips.append({i[4][0] for i in infos})
            except (OSError, ValueError, asyncio.TimeoutError):
                return False
        return bool(ips[0] & ips[1])

    async def check_media_keys(entry: dict, h: Host) -> None:
        """A Jellyfin key or Plex token only goes to the machine it was entered for. Left blank, it's kept while
        the address stays on that machine (http/https, the port, or its name for its IP can change); moved to
        another machine, the form asks for it again rather than quietly dropping it."""
        for url_k, key_k, saved, old, default, what in (
                ("jellyfin_url", "jellyfin_key", h.jf_key, h.jf_url, jflib.default_url, "Jellyfin API key"),
                ("plex_url", "plex_token", h.px_key, h.px_url, pxlib.default_url, "Plex token")):
            if url_k not in entry or entry.get(key_k) or not saved:
                continue
            new_base, old_base = entry[url_k] or default(entry["host"]), old or default(h.host)
            if await same_machine(old_base, new_base):
                entry[key_k] = saved  # the same machine: keep it
            else:
                raise web.HTTPBadRequest(text=json.dumps({"error": f"That address is on a different machine, so enter the {what} "
                                                          "again (it's only ever sent to the server it was entered for)."}),
                                         content_type="application/json")

    def check_parent(entry: dict, h: Host | None) -> None:
        try:
            monitor.check_parent(h.key if h else None, entry.get("parent") or "")
        except ValueError as err:
            raise web.HTTPBadRequest(text=json.dumps({"error": str(err)}), content_type="application/json")

    async def starlink_dishes(req):
        """The dishes on a Starlink account, for the Edit form: from the cookie typed in, or the one a device has."""
        try:
            raw = await req.json()
        except ValueError:
            raw = {}
        cookie, h = str((raw or {}).get("cookie") or "").strip(), monitor.hosts.get(str((raw or {}).get("key") or ""))
        try:
            cookie = sllib.clean_cookie(cookie) if cookie else (h.sl_cookie if h else "")
        except ValueError as err:
            return web.json_response({"error": str(err)}, status=400)
        if not cookie:
            return web.json_response({"error": "Paste the starlink.com cookie first."}, status=400)
        acct = sllib.Account(cookie, h.sl_state if h and cookie == h.sl_cookie else {}, health_tls_context())
        try:
            async with ClientSession() as session:
                dishes = await acct.dishes(session)
        except sllib.StarlinkError as err:
            return web.json_response({"error": str(err)}, status=400)
        if h and cookie == h.sl_cookie and acct.changed:
            h.sl_cookie = acct.cookie
            monitor._save_hosts()
        return web.json_response({"dishes": dishes})

    async def add_host(req):
        entry = await read_entry(req)
        check_v3(entry, None)
        check_parent(entry, None)
        h = await monitor.add_host(entry)
        return web.json_response({"added": h.key}, status=201)

    async def update_host(req):
        h = monitor.hosts.get(req.match_info["key"])
        if not h:
            raise web.HTTPNotFound()
        entry = await read_entry(req)
        check_v3(entry, h)
        check_parent(entry, h)
        await check_media_keys(entry, h)
        raw = await req.json()
        behind = None
        if isinstance(raw.get("downstream"), list):  # the devices behind it, ticked in its Edit
            try:
                behind = monitor.check_downstream(h, raw["downstream"][:2000], entry.get("parent", h.parent) or "")
            except ValueError as err:
                raise web.HTTPBadRequest(text=json.dumps({"error": str(err)}), content_type="application/json")
        await monitor.update_host(h, entry)
        if behind is not None:
            monitor.set_downstream(h, behind)
        return web.json_response({"updated": h.key})

    async def host_snmp(req):
        h = monitor.hosts.get(req.match_info["key"])
        if not h:
            raise web.HTTPNotFound()
        svc = next((s for s in h.services if s.kind == "snmp"), None)
        return web.json_response({"name": h.name, "ip": h.ip, "host": h.host, "polled": h.snmp_polled,
                                  "data": h.snmp_data, "items": h.snmp_items, "watch": h.snmp_watch,
                                  "vpn_ignore": h.snmp_vpn_ignore, "ignore": h.snmp_ignore, "ups_limits": monitor.ups_limits(h),
                                  "ups_defaults": monitor.ups_defaults(), "ups_custom": h.ups_limits,
                                  "status": svc.status if svc else None, "detail": svc.detail if svc else None})

    async def host_ups_limits(req):
        """Set this UPS's own runtime and load limits; a blank value goes back to the add-on's."""
        h = monitor.hosts.get(req.match_info["key"])
        if not h:
            raise web.HTTPNotFound()
        body = await req.json()
        try:
            lim = clean_ups_limits({k: body.get(k) for k in UPS_LIMIT_KEYS if body.get(k) not in (None, "")}, strict=True)
        except ValueError as err:
            return web.json_response({"error": str(err)}, status=400)
        both = {**monitor.ups_defaults(), **lim}
        if both["runtime_crit"] and both["runtime_warn"] and both["runtime_crit"] > both["runtime_warn"]:
            return web.json_response({"error": "the red runtime can't be above the amber one"}, status=400)
        h.ups_limits = lim
        monitor._save_hosts()
        log.info("%s: UPS limits %s", h.name, lim or "back to the add-on's")
        if h.snmp_data:  # re-evaluate straight away
            svc = next((s for s in h.services if s.kind == "snmp"), None)
            worst, items = monitor.snmp_eval(h, h.snmp_data, None)
            h.snmp_items = items
            if svc and svc.status != UNKNOWN:
                h.next_due = 0
        return web.json_response({"ups_limits": monitor.ups_limits(h), "ups_custom": h.ups_limits})

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
            worst, items = monitor.snmp_eval(h, h.snmp_data, None, watch=watch)
            h.snmp_items = items
            if svc and svc.status != UNKNOWN:
                h.next_due = 0
        return web.json_response({"watch": h.snmp_watch})

    async def host_snmp_vpn_ignore(req):
        """Ignore a Sophos VPN connection (e.g. one that's only up on demand), or stop ignoring it."""
        h = monitor.hosts.get(req.match_info["key"])
        if not h:
            raise web.HTTPNotFound()
        body = await req.json()
        name = str(body.get("name") or "").strip()[:100]
        if not name:
            raise web.HTTPBadRequest(text="name is required")
        keep = [x for x in h.snmp_vpn_ignore if x.lower() != name.lower()]
        h.snmp_vpn_ignore = keep + [name] if body.get("ignore") else keep
        monitor._save_hosts()
        log.info("%s: VPN %s %s", h.name, name, "ignored" if body.get("ignore") else "no longer ignored")
        if h.snmp_data:  # re-evaluate straight away
            svc = next((s for s in h.services if s.kind == "snmp"), None)
            worst, items = monitor.snmp_eval(h, h.snmp_data, None)
            h.snmp_items = items
            if svc and svc.status != UNKNOWN:
                h.next_due = 0
        return web.json_response({"vpn_ignore": h.snmp_vpn_ignore})

    async def host_snmp_ignore(req):
        """Never alert on an SNMP problem on this device (e.g. "Server": powered off, for a server that's
        often off), or stop ignoring it. {what, ignore}"""
        h = monitor.hosts.get(req.match_info["key"])
        if not h:
            raise web.HTTPNotFound()
        body = await req.json()
        what = str(body.get("what") or "").strip()[:100]
        if not what or what == "SNMP":
            return web.json_response({"error": "That can't be ignored"}, status=400)
        keep = [x for x in h.snmp_ignore if x.lower() != what.lower()]
        h.snmp_ignore = keep + [what] if body.get("ignore") else keep
        if body.get("ignore"):
            h.snmp_acks = {k: v for k, v in (h.snmp_acks or {}).items() if k.lower() != what.lower()}
        monitor._save_hosts()
        user = await access.who(req)
        log.info("%s: SNMP %s %s by %s", h.name, what, "ignored" if body.get("ignore") else "no longer ignored", user["display"] or "someone")
        if h.snmp_data:  # re-evaluate straight away
            worst, items = monitor.snmp_eval(h, h.snmp_data, None)
            h.snmp_items = items
            svc = next((s for s in h.services if s.kind == "snmp"), None)
            if svc and svc.status != UNKNOWN:
                h.next_due = 0
        return web.json_response({"ignore": h.snmp_ignore})

    async def host_snmp_ack_item(req):
        """Acknowledge an SNMP problem (e.g. a server that's meant to be off): it stops counting while it
        is there and no worse. {what, undo}, or {all: true} for everything it shows now (the Overview)."""
        h = monitor.hosts.get(req.match_info["key"])
        if not h:
            raise web.HTTPNotFound()
        body = await req.json()
        what = str(body.get("what") or "")
        item = next((i for i in h.snmp_items if i["what"] == what and i.get("ack") != "restart"), None)
        acks = dict(h.snmp_acks or {})
        user = await access.who(req)
        if body.get("all"):
            for i in h.snmp_items:
                if i.get("ack") == "restart":
                    h.snmp_restart_ack = snmplib.boot_time(h.snmp_data, h.snmp_polled) or h.snmp_restart_ack
                elif i["what"] != "SNMP" and not i.get("acked") and not i.get("ignored"):
                    acks[i["what"]] = i["level"]
            log.info("%s: all SNMP problems acknowledged by %s", h.name, user["display"] or "someone")
        elif body.get("undo"):
            acks.pop(what, None)
            log.info("%s: %s no longer acknowledged (%s)", h.name, what, user["display"] or "someone")
        else:
            if not item:
                return web.json_response({"error": "That problem has cleared"}, status=400)
            acks[what] = item["level"]
            log.info("%s: %s (%s) acknowledged by %s", h.name, what, item["detail"], user["display"] or "someone")
        h.snmp_acks = acks
        monitor._save_hosts()
        if h.snmp_data:
            worst, items = monitor.snmp_eval(h, h.snmp_data, None)
            h.snmp_items = items
            svc = next((s for s in h.services if s.kind == "snmp"), None)
            if svc and svc.status != UNKNOWN:
                h.next_due = 0  # re-check so the status updates
        return web.json_response({"acks": h.snmp_acks})

    def _ilo_redo(h):
        """Re-judge the last iLO reading now (after an acknowledgement or ignore) and re-check soon."""
        if h.ilo_data and not h.ilo_err:
            h.ilo_result = monitor.ilo_result(h)
            svc = next((s for s in h.services if s.kind == "ilo"), None)
            if svc and svc.status != UNKNOWN:
                h.next_due = 0

    async def host_starlink_map(req):
        """The dish's obstruction map, for the Starlink tab: read when it's opened (at most every 5 minutes)."""
        h = monitor.hosts.get(req.match_info["key"])
        if not h or not any(s.kind == "starlink" for s in h.services):
            raise web.HTTPNotFound()
        try:
            m = await monitor.starlink_map(h, fresh=req.query.get("fresh") == "1")
        except sllib.StarlinkError as err:
            return web.json_response({"error": str(err)}, status=502)
        return web.json_response(m, headers={"Cache-Control": "no-store"})

    async def host_ilo(req):
        h = monitor.hosts.get(req.match_info["key"])
        if not h:
            raise web.HTTPNotFound()
        svc = next((s for s in h.services if s.kind == "ilo"), None)
        return web.json_response({"name": h.name, "polled": h.ilo_polled, "data": h.ilo_data, "items": h.ilo_items,
                                  "ignore": h.ilo_ignore, "every": monitor.ILO_EVERY,
                                  "status": svc.status if svc else None, "detail": svc.detail if svc else None})

    async def host_ilo_ack(req):
        """Acknowledge an iLO problem (e.g. a drive that's on order): it stops counting while it's there
        and no worse. {what, undo}, or {all: true} for everything it shows now (the Overview)."""
        h = monitor.hosts.get(req.match_info["key"])
        if not h:
            raise web.HTTPNotFound()
        body = await req.json()
        what = str(body.get("what") or "")
        acks = dict(h.ilo_acks or {})
        user = await access.who(req)
        if body.get("all"):
            for i in h.ilo_items:
                if i["what"] != "iLO" and not i.get("acked") and not i.get("ignored"):
                    acks[i["what"]] = i["level"]
            log.info("%s: all iLO problems acknowledged by %s", h.name, user["display"] or "someone")
        elif body.get("undo"):
            acks.pop(what, None)
            log.info("%s: iLO %s no longer acknowledged (%s)", h.name, what, user["display"] or "someone")
        else:
            item = next((i for i in h.ilo_items if i["what"] == what and what != "iLO"), None)
            if not item:
                return web.json_response({"error": "That problem has cleared"}, status=400)
            acks[what] = item["level"]
            log.info("%s: iLO %s (%s) acknowledged by %s", h.name, what, item["detail"], user["display"] or "someone")
        h.ilo_acks = acks
        monitor._save_hosts()
        _ilo_redo(h)
        return web.json_response({"acks": h.ilo_acks})

    async def host_ilo_ignore(req):
        """Never alert on an iLO problem on this server (e.g. power redundancy on a server that's only
        ever had one power supply), or stop ignoring it. {what, ignore}"""
        h = monitor.hosts.get(req.match_info["key"])
        if not h:
            raise web.HTTPNotFound()
        body = await req.json()
        what = str(body.get("what") or "").strip()[:100]
        if not what or what == "iLO":
            return web.json_response({"error": "That can't be ignored"}, status=400)
        keep = [x for x in h.ilo_ignore if x.lower() != what.lower()]
        h.ilo_ignore = keep + [what] if body.get("ignore") else keep
        if body.get("ignore"):
            h.ilo_acks = {k: v for k, v in (h.ilo_acks or {}).items() if k.lower() != what.lower()}
        monitor._save_hosts()
        user = await access.who(req)
        log.info("%s: iLO %s %s by %s", h.name, what, "ignored" if body.get("ignore") else "no longer ignored", user["display"] or "someone")
        _ilo_redo(h)
        return web.json_response({"ignore": h.ilo_ignore})

    async def host_snmp_ack(req):
        """Acknowledge a restart (e.g. a planned one): it stops showing amber. A later restart still shows."""
        h = monitor.hosts.get(req.match_info["key"])
        if not h:
            raise web.HTTPNotFound()
        booted = snmplib.boot_time(h.snmp_data, h.snmp_polled) if h.snmp_data else None
        if not booted:
            raise web.HTTPBadRequest(text=json.dumps({"error": "No restart to acknowledge"}), content_type="application/json")
        h.snmp_restart_ack = booted
        monitor._save_hosts()
        user = await access.who(req)
        log.info("%s: restart acknowledged by %s", h.name, user["display"] or "someone")
        h.snmp_items = [i for i in h.snmp_items if i.get("ack") != "restart"]
        svc = next((s for s in h.services if s.kind == "snmp"), None)
        if svc and svc.status != UNKNOWN:
            h.next_due = 0  # re-check so the chip updates
        return web.json_response({"ok": True})

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
        try:
            found = syslogreadings.readings(monitor.logs, h.key, now, h.readings_cfg)
        except Exception:  # noqa: BLE001 - readings are extra; never break the Logs tab
            log.exception("%s: couldn't work out readings from syslog", h.name)
            found = {"sensors": [], "status": []}
        return web.json_response({"name": h.name, "pending": pending, "ip": h.ip, "host": h.host, "rows": rows, "count_24h": n, "last": last,
                                  "readings": found,
                                  "alert": h.syslog_alert, "keywords": h.syslog_keywords, "ignore": h.syslog_ignore,
                                  "ack": h.syslog_ack, "status": svc.status if svc else None,
                                  "detail": svc.detail if svc else None, "port": monitor.syslog_port, "now": now})

    async def host_reading_set(req):
        """Name a log reading and set its alert limits (blank clears them)."""
        h = monitor.hosts.get(req.match_info["key"])
        if not h:
            raise web.HTTPNotFound()
        body = await req.json()
        k = str(body.get("key") or "")
        if not re.fullmatch(r"[a-z0-9_]{1,24}", k):
            raise web.HTTPBadRequest(text=json.dumps({"error": "Unknown reading"}), content_type="application/json")
        try:
            c = clean_reading_setting(body)
        except ValueError as err:
            raise web.HTTPBadRequest(text=json.dumps({"error": str(err)}), content_type="application/json")
        if c:
            h.readings_cfg[k] = c
        else:
            h.readings_cfg.pop(k, None)
        monitor._save_hosts()
        svc = next((s for s in h.services if s.kind == "syslog"), None)
        if svc and svc.status != UNKNOWN:
            h.next_due = 0
        return web.json_response({"ok": True, "setting": c})

    async def host_syslog_ack(req):
        h = monitor.hosts.get(req.match_info["key"])
        if not h:
            raise web.HTTPNotFound()
        h.syslog_ack = time.time()
        monitor._save_hosts()
        log.info("%s: syslog alerts acknowledged", h.name)
        h.next_due = 0
        return web.json_response({"ack": h.syslog_ack})

    async def discovery_get(_req):
        return web.json_response(await monitor.discovery_view())

    async def discovery_scan(req):
        body = await req.json()
        user = await access.who(req)
        res = await monitor.start_scan(str(body.get("ranges") or "")[:2000], str(body.get("community") or "public")[:64], user["display"] or "")
        return web.json_response(res, status=400 if res.get("error") else 200)

    async def discovery_networks(req):
        body = await req.json()
        names = body.get("networks")
        if names is not None:
            known = {i["name"] for i in await monitor.interfaces()}
            names = [str(n) for n in names if str(n) in known] if isinstance(names, list) else []
            if not names:
                return web.json_response({"error": "pick at least one network"}, status=400)
            if set(names) == known:
                names = None  # all of them, including any added later
        user = await access.who(req)
        await monitor.set_networks(names, user["display"] or "")
        return web.json_response({"ok": True})

    async def discovery_cancel(_req):
        if monitor.scan and monitor.scan.finished is None:
            monitor.scan.cancelled = True
        return web.json_response({"ok": True})

    async def discovery_hide(req):
        body = await req.json()
        ip, hide = str(body.get("ip") or ""), bool(body.get("hide", True))
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return web.json_response({"error": "invalid address"}, status=400)
        hidden = set(monitor.discovery["hidden"])
        (hidden.add if hide else hidden.discard)(ip)
        monitor.discovery["hidden"] = sorted(hidden)[:2000]
        monitor._save_discovery()
        return web.json_response({"ok": True})

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
    app.router.add_get("/api/discovery", editor_only(discovery_get))
    app.router.add_post("/api/discovery/scan", editor_only(discovery_scan))
    app.router.add_post("/api/discovery/networks", editor_only(discovery_networks))
    app.router.add_post("/api/discovery/cancel", editor_only(discovery_cancel))
    app.router.add_post("/api/discovery/hide", editor_only(discovery_hide))
    app.router.add_post("/api/hosts/{key}/snmp/watch", editor_only(host_snmp_watch))
    app.router.add_post("/api/hosts/{key}/merge", editor_only(host_merge))
    app.router.add_post("/api/hosts/{key}/snmp/vpn-ignore", editor_only(host_snmp_vpn_ignore))
    app.router.add_post("/api/hosts/{key}/snmp/ignore", editor_only(host_snmp_ignore))
    app.router.add_post("/api/hosts/{key}/snmp/ack", editor_only(host_snmp_ack_item))
    app.router.add_post("/api/hosts/{key}/snmp/ups-limits", editor_only(host_ups_limits))
    app.router.add_post("/api/hosts/{key}/snmp/ack-restart", editor_only(host_snmp_ack))
    app.router.add_get("/api/hosts/{key}/ilo", host_ilo)
    app.router.add_get("/api/hosts/{key}/starlink/map", host_starlink_map)
    app.router.add_post("/api/hosts/{key}/ilo/ack", editor_only(host_ilo_ack))
    app.router.add_post("/api/hosts/{key}/ilo/ignore", editor_only(host_ilo_ignore))
    app.router.add_post("/api/hosts/{key}/readings", editor_only(host_reading_set))
    app.router.add_delete("/api/hosts/{key}", editor_only(delete_host))
    app.router.add_get("/", index)
    app.router.add_get("/api/status", status)
    app.router.add_get("/api/views", views_get)
    app.router.add_get("/api/settings", editor_only(settings_get))
    app.router.add_post("/api/settings", editor_only(settings_post))
    app.router.add_get("/api/export", admin_only(export_data))  # holds the update-signing and HTTPS private keys
    app.router.add_post("/api/starlink/dishes", editor_only(starlink_dishes))
    app.router.add_post("/api/import", admin_only(import_data))  # replaces everything, keys included
    app.router.add_post("/api/import/chunk", admin_only(import_chunk))
    app.router.add_get("/api/ha/entities", editor_only(ha_entities))
    app.router.add_get("/api/ha/devices", editor_only(ha_devices))
    app.router.add_get("/api/hosts/{key}/ha", host_ha)
    app.router.add_post("/api/hosts/{key}/ha/action", editor_only(host_ha_action))
    app.router.add_put("/api/views", editor_only(views_put))
    app.router.add_post("/api/check/{key}", check_now)  # harmless, so open to all viewers
    app.router.add_post("/api/reset", editor_only(reset))
    app.router.add_post("/api/reset/{key}", editor_only(reset))
    app.router.add_post("/api/maintenance-bulk", editor_only(maintenance_bulk))
    app.router.add_post("/api/resume-bulk", editor_only(resume_bulk))
    app.router.add_post("/api/maintenance/{key}", editor_only(maintenance))
    app.router.add_post("/api/resume/{key}", editor_only(resume))
    app.router.add_get("/api/hosts/{key}/details", host_details)
    app.router.add_get("/api/hosts/{key}/metrics", host_metrics)
    app.router.add_post("/api/hosts/{key}/agent/ignore", editor_only(agent_ignore))
    app.router.add_post("/api/hosts/{key}/agent/sec-filter", editor_only(agent_sec_filter))
    app.router.add_post("/api/hosts/{key}/agent/disk", editor_only(agent_disk))
    app.router.add_post("/api/hosts/{key}/agent/resources", editor_only(agent_resources))
    app.router.add_post("/api/agents/tls", admin_only(agents_tls))
    app.router.add_get("/api/messages", admin_only(messages_list))
    app.router.add_post("/api/messages", admin_only(messages_send))
    app.router.add_post("/api/messages/included", admin_only(messages_included))
    app.router.add_post("/api/messages/{id}/cancel", admin_only(messages_cancel))
    app.router.add_post("/api/hosts/{key}/agent/nic", editor_only(agent_nic))
    app.router.add_post("/api/hosts/{key}/agent/secret-scan", editor_only(agent_secret_scan))
    app.router.add_get("/api/software", software_search)
    app.router.add_post("/api/hosts/{key}/agent/backup-forget", editor_only(agent_backup_forget))
    app.router.add_post("/api/hosts/{key}/agent/ack", editor_only(agent_ack))
    app.router.add_get("/api/agents", editor_only(agents_list))
    app.router.add_post("/api/agents/approve-all", editor_only(agents_approve_all))
    app.router.add_post("/api/agents/approve/{pid}", editor_only(agents_approve))
    app.router.add_post("/api/agents/reject/{pid}", editor_only(agents_reject))
    app.router.add_delete("/api/agents/{aid}", editor_only(agents_revoke))
    app.router.add_post("/api/agents/rotate-key", editor_only(agents_rotate))
    app.router.add_get("/api/agents/script", editor_only(agents_script))
    app.router.add_post("/api/agents/auto-update", editor_only(agents_auto_update))
    app.router.add_post("/api/agents/rollout", editor_only(agents_rollout))
    app.router.add_post("/api/agents/servers", editor_only(agents_servers))
    app.router.add_post("/api/agents/networks", editor_only(agents_networks))
    app.router.add_post("/api/email/test", editor_only(email_test))
    app.router.add_get("/api/log", editor_only(addon_log))
    app.router.add_get("/api/database", editor_only(database_info))
    app.router.add_post("/api/hints/ask", editor_only(hints_ask))
    app.router.add_post("/api/hints/test", admin_only(hints_test))
    app.router.add_post("/api/database/check", editor_only(database_check))
    app.router.add_post("/api/database/compact", admin_only(database_compact))
    app.router.add_post("/api/acks/dismiss", editor_only(acks_dismiss))
    app.router.add_get("/api/agents/msi", editor_only(agents_msi))
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
    "group": {"is", "not"},
    "user": {"contains", "notcontains"},
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
        if not re.match(r"^[a-z0-9]{1,16}$", vid) or vid in ids or vid in ("home", "all", "problems", "windows", "linux", "noagent"):
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
            "agent_settings.json": AGENT_SETTINGS, "views.json": VIEWS_PATH, "imported_options.json": IMPORT_MARK,
            # the key that signs agent updates: restored with everything else, agents keep trusting updates
            "update_key.pem": UPDATE_KEY_PATH,
            # built-in HTTPS: the same key, so agents keep trusting it after a restore
            "agent_tls_key.pem": AGENT_TLS.key_path, "agent_tls_cert.pem": AGENT_TLS.cert_path, "agent_tls.json": AGENT_TLS.state_path}


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
            for k in ("smtp_password", "m365_client_secret", "claude_api_key", "openai_api_key", "gemini_api_key"):  # passwords and keys stay on this install
                raw.pop(k, None)
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


_ONE_SERVER = re.compile(r"^https?://[A-Za-z0-9.\-\[\]:]+$")


def clean_servers(raw: str) -> str | None:
    """One address, or several tried in order (e.g. internal then external), as "a,b"."""
    parts = [p.strip().rstrip("/") for p in re.split(r"[,;\s]+", raw or "") if p.strip()]
    if not parts or len(parts) > 4 or not all(_ONE_SERVER.match(p) for p in parts):
        return None
    return ",".join(dict.fromkeys(parts))


class _ServerRE:  # keeps the old SERVER_RE.match(...) call sites working
    @staticmethod
    def match(v):
        return clean_servers(v) is not None


SERVER_RE = _ServerRE()


def update_public_key() -> str:
    """The public half of the update signing key, or "" if it can't be read (scripts then can't self-update)."""
    try:
        return SIGNER.public()
    except Exception as err:  # noqa: BLE001
        log.warning("Couldn't read the key that signs agent updates: %s", err)
        return ""


def build_agent_script(os_name: str, server: str, enrol_key: str, ignore_cert: bool) -> bytes:
    """The agent script with this add-on's address and enrolment key built in."""
    if os_name == "openwrt":
        text = SH_AGENT_SCRIPT.read_text(encoding="utf-8")
        text = text.replace('SERVER="__PM_SERVER__"', f'SERVER="{server}"', 1)
        text = text.replace('ENROL_KEY="__PM_ENROL_KEY__"', f'ENROL_KEY="{enrol_key}"', 1)
        if ignore_cert:
            text = text.replace("IGNORE_CERT=0", "IGNORE_CERT=1", 1)
        return text.replace("\r\n", "\n").encode("utf-8")
    if os_name == "linux":
        text = LINUX_AGENT_SCRIPT.read_text(encoding="utf-8")
        text = text.replace('SERVER = "__PM_SERVER__"', f'SERVER = "{server}"', 1)
        text = text.replace('ENROL_KEY = "__PM_ENROL_KEY__"', f'ENROL_KEY = "{enrol_key}"', 1)
        text = text.replace('UPDATE_KEY = "__PM_UPDATE_KEY__"', f'UPDATE_KEY = "{update_public_key()}"', 1)
        if AGENT_TLS.on:  # pinned to Rollcall's own HTTPS key from the first report
            text = text.replace('TLS_PIN = "__PM_TLS_PIN__"', f'TLS_PIN = "{AGENT_TLS.pin()}"', 1).replace('TLS_PORT = 0', f'TLS_PORT = {AGENT_HTTPS_PORT}', 1)
        if ignore_cert:
            text = text.replace("IGNORE_CERT = False", "IGNORE_CERT = True", 1)
        return text.encode("utf-8")
    text = AGENT_SCRIPT.read_text(encoding="utf-8")
    text = text.replace("[string]$Server = '__PM_SERVER__'", f"[string]$Server = '{server}'", 1)
    text = text.replace("[string]$EnrolKey = '__PM_ENROL_KEY__'", f"[string]$EnrolKey = '{enrol_key}'", 1)
    text = text.replace("$UpdateKey = '__PM_UPDATE_KEY__'", f"$UpdateKey = '{update_public_key()}'", 1)
    if AGENT_TLS.on:  # pinned to Rollcall's own HTTPS key from the first report
        text = text.replace("$TlsPin = '__PM_TLS_PIN__'", f"$TlsPin = '{AGENT_TLS.pin()}'", 1).replace("$TlsPort = 0", f"$TlsPort = {AGENT_HTTPS_PORT}", 1)
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


def _sh_script_version() -> str | None:
    try:
        m = re.search(r'^AGENT_VERSION="([^"]+)"', SH_AGENT_SCRIPT.read_text(encoding="utf-8"), re.M)
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
        body = None
        if not token:  # the OpenWrt agent sends its token in the report: uclient-fetch can't add headers
            body = await read_json(req)
            token = str(body.get("agent_token") or "")
        state, agent = store.lookup(token)
        if state == "pending":
            return web.json_response({"status": "pending"}, status=202)
        if state != "approved":
            return web.json_response({"error": "unknown agent"}, status=401)
        if body is None:
            body = await read_json(req)
        body.pop("agent_token", None)  # never stored
        # Through a reverse proxy (e.g. the firewall's WAF) the sender is the proxy; it usually passes on the
        # original address. Shown for information only: it's whatever the proxy (or client) says.
        fwd = (req.headers.get("X-Forwarded-For") or "").split(",")[0].strip() or None
        try:
            await monitor.receive_report(agent, body, req.remote, fwd)
        except Exception as err:  # noqa: BLE001
            log.exception("Couldn't process the report from %s: %s", agent["hostname"], err)
            try:  # keep a copy to diagnose with
                (AGENT_REPORTS / f"failed-{agent['id']}.json").write_text(json.dumps(body, indent=1)[:2_000_000])
            except Exception:  # noqa: BLE001
                pass
            return web.json_response({"error": "report could not be processed"}, status=500)
        watch = [str(x) for x in monitor.opts.get("agent_watch_services") or [] if str(x).strip()]
        resp = {"ok": True, "watch_services": watch}
        servers = monitor.agent_servers()
        if servers:
            resp["servers"] = servers  # agents use these from now on (plus the address they were installed with)
        route = monitor.agent_route()
        if route:
            resp["route"] = route  # agents (Windows 1.0.42, Linux 1.0.19 on) pick inside or outside by their own address
        # Signed with Rollcall's own key, so a reply changed on the way can't send agents elsewhere (Windows 1.0.53,
        # Linux 1.0.21 on only use addresses that come with a good signature)
        try:
            resp["config_sig"] = SIGNER.sign(updatesign.config_text(servers or [], route))
        except Exception as err:  # noqa: BLE001
            log.warning("Couldn't sign the agent addresses: %s", err)
        if agent["id"] in monitor.want_apps:
            resp["send_apps"] = True
        resp["secret_scan"] = monitor.secret_scan_config(agent)
        if agent["id"] in monitor.want_secrets:
            resp["send_secrets"] = True
        monitor.rollout_seen(agent, body)
        offer = monitor.agent_update_offer(agent, body)
        if offer:
            resp["agent_update"] = offer
        resp.update(monitor.tls_reply(agent))  # Windows 1.0.54, Linux 1.0.22, router 1.0.3 on move to HTTPS
        shown = monitor.messages_for(agent)
        if shown:
            resp["messages"] = shown  # Windows 1.0.54, Linux 1.0.22 on show them; each is signed
        return web.json_response(resp)

    async def update(req):
        """A newer agent for an approved agent that has been offered one.

        sig=rsa (Windows 1.0.53, Linux 1.0.21 on): JSON with the script and its signature by Rollcall's own key,
        which agents check with the public key built into them. Otherwise (older agents, to move them onto that):
        the script, with an HMAC keyed by the agent's token in a header, as before."""
        auth = req.headers.get("Authorization", "")
        token = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
        state, agent = store.lookup(token)
        if state != "approved":
            return web.json_response({"error": "unknown agent"}, status=401)
        os_name = "linux" if agent.get("os_family") == "linux" else "windows"
        if not monitor.agent_update_offer(agent, {"os_family": os_name, "agent_version": agent.get("agent_version")}):
            return web.json_response({"error": "no update offered"}, status=404)
        server = clean_servers(req.query.get("server") or "")
        if not server:
            raise web.HTTPBadRequest(text="invalid server address")
        server = ",".join(monitor.agent_servers()) or server  # the addresses set under Agents, if any
        body = build_agent_script(os_name, server, store.enrol_key, req.query.get("ignore_cert") == "1")
        log.info("Sending the %s agent update to %s", os_name.capitalize(), agent.get("hostname"))
        monitor.rollout_sent(agent, os_name)
        if req.query.get("sig") == "rsa":
            try:
                signature = await asyncio.to_thread(SIGNER.sign, body)
            except Exception as err:  # noqa: BLE001
                log.warning("Couldn't sign the agent update: %s", err)
                return web.json_response({"error": "no signing key"}, status=503)
            return web.json_response({"script": base64.b64encode(body).decode(), "signature": signature})
        key = bytes.fromhex(agentlib.token_hash(token))
        sig = hmac.new(key, body, hashlib.sha256).hexdigest()
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


class AgentListener:
    """The agent port, which can be switched between HTTP and HTTPS (or given a new
    certificate) without restarting the add-on."""

    def __init__(self, monitor: Monitor):
        self.runner = web.AppRunner(build_agent_app(monitor), access_log=None)
        self.site: web.TCPSite | None = None
        self.ctx: ssl.SSLContext | None = None
        self.tls_site: web.TCPSite | None = None  # built-in HTTPS (agenttls.py), beside the agent port
        self.plain_on = True
        monitor.agent_listener = self

    async def set_builtin(self, on: bool) -> None:
        """Start (or restart, with a new certificate) or stop Rollcall's own HTTPS for agents."""
        if not self.runner.server:
            await self.runner.setup()
        if self.tls_site:
            await self.tls_site.stop()
            self.tls_site = None
        if on:
            site = web.TCPSite(self.runner, "0.0.0.0", AGENT_HTTPS_PORT, ssl_context=AGENT_TLS.context(), reuse_address=True)
            await site.start()
            self.tls_site = site
            log.info("Agent API listening on port %d (HTTPS, Rollcall's own certificate; key %s)", AGENT_HTTPS_PORT, AGENT_TLS.pin()[:12])

    async def set_plain(self, on: bool) -> None:
        """Plain HTTP on the agent port can be turned off once agents use HTTPS (not when the port itself is HTTPS)."""
        if self.ctx is not None or on == self.plain_on:
            return
        if on:
            await self.start(None)
        elif self.site:
            await self.site.stop()
            self.site = None
            log.info("Agent API: plain HTTP on port %d turned off; agents use HTTPS on port %d", AGENT_PORT, AGENT_HTTPS_PORT)
        self.plain_on = on

    @property
    def https(self) -> bool:
        return self.ctx is not None

    async def start(self, ctx: ssl.SSLContext | None) -> None:
        if not self.runner.server:
            await self.runner.setup()
        site = web.TCPSite(self.runner, "0.0.0.0", AGENT_PORT, ssl_context=ctx, reuse_address=True)
        await site.start()
        self.site, self.ctx = site, ctx
        log.info("Agent API listening on port %d (%s)", AGENT_PORT, "HTTPS" if ctx else "HTTP")

    async def restart(self, ctx: ssl.SSLContext | None) -> None:
        """Swap to a new listener. Agents retry anything refused in the moment between the two.
        If the new one can't start, the old settings are put back."""
        old = self.ctx
        if self.site:
            await self.site.stop()
            self.site = None
        try:
            await self.start(ctx)
        except Exception:
            log.exception("Agent API could not restart on port %d; going back to the previous settings", AGENT_PORT)
            await self.start(old)
            raise


async def notification_target(ha: HomeAssistant, opts: dict) -> str:
    """Where tapping a phone notification goes: the notification_url setting, or this dashboard."""
    url = str(opts.get("notification_url") or "").strip()
    if not url:
        slug = await ha.addon_slug() or "local_ping_monitor"
        url = f"/{slug}"
    return url if url.startswith(("/", "http://", "https://")) else "/" + url


class LiveSettings:
    """Changes the add-on's settings from the dashboard and puts them into effect without a restart.

    The settings stay the add-on's options (what the Configuration tab shows): they're saved
    through the Supervisor, so both places always agree and exports keep working. Changes saved
    in the Configuration tab are noticed too, and applied the same way.
    """
    WATCH_SECONDS = 10

    def __init__(self, monitor: Monitor, access: Access, agent_listener: AgentListener | None):
        self.monitor, self.access, self.agent_listener = monitor, access, agent_listener
        self.lock = asyncio.Lock()
        self._mtime = self._options_mtime()

    @staticmethod
    def _options_mtime() -> float:
        try:
            return OPTIONS_PATH.stat().st_mtime
        except OSError:
            return 0.0

    @staticmethod
    def _read_raw() -> dict:
        try:
            raw = json.loads(OPTIONS_PATH.read_text())
            return raw if isinstance(raw, dict) else {}
        except (OSError, ValueError):
            return {}

    def ssl_files(self) -> list[str]:
        try:
            return sorted(p.name for p in SSL_DIR.iterdir() if p.is_file() and not p.name.startswith("."))[:200]
        except OSError:
            return []

    async def check_agent_port(self, merged: dict) -> tuple[str, str] | None:
        """Problem with the agent HTTPS settings, if any (e.g. the certificate file is missing)."""
        for key, dflt in (("agent_certfile", "fullchain.pem"), ("agent_keyfile", "privkey.pem")):
            name = str(merged.get(key) or dflt)
            if not (SSL_DIR / name).is_file():
                return key, f"{name} isn't in Home Assistant's /ssl folder"
        try:
            await asyncio.to_thread(agent_ssl_context, merged)
            return None
        except (ssl.SSLError, OSError, ValueError) as err:
            return "agent_keyfile", f"The certificate and key can't be used together ({err})"

    async def apply(self, changed: dict) -> list[str]:
        """Put changed settings into effect now."""
        notes = self.monitor.apply_options(changed)
        if {"admin_only_changes", "editors"} & changed.keys():
            self.access.update(self.monitor.opts)
            log.info("Who can make changes: %s", "HA admins" + (f" and {', '.join(sorted(self.access.editors))}"
                     if self.access.editors else "") if self.access.enabled else "anyone who can open the panel")
        if "notification_url" in changed:
            self.monitor.click_url = await notification_target(self.monitor.ha, self.monitor.opts)
            log.info("Phone notifications will open %s", self.monitor.click_url)
        if set(settingslib.AGENT_PORT_KEYS) & changed.keys() and self.agent_listener:
            o = self.monitor.opts
            if o.get("agent_ssl") or self.agent_listener.https:
                try:
                    ctx = await asyncio.to_thread(agent_ssl_context, o)
                    await self.agent_listener.restart(ctx)
                    notes.append(f"the agent port now uses {'HTTPS' if ctx else 'HTTP'}; agents keep using the "
                                 f"address they were given, so set {'https' if ctx else 'http'}:// addresses under Agents")
                except Exception as err:  # noqa: BLE001
                    notes.append(f"the agent port couldn't switch ({err}); restart the add-on")
        return notes

    async def save(self, changes: dict, who: str = "") -> dict:
        """Check, save and apply changes from the dashboard. Raises ValueError with
        {key: problem} for anything that isn't allowed."""
        async with self.lock:
            clean, errors = settingslib.clean(changes)
            if errors:
                raise ValueError(errors)
            current = {**DEFAULTS, **self._read_raw()}
            changed = {k: v for k, v in clean.items() if current.get(k) != v}
            if not changed:
                return {"changed": [], "notes": []}
            merged = {**current, **changed}
            if changed.get("agent_ssl") and AGENT_TLS.on:
                raise ValueError({"agent_ssl": "Rollcall's own HTTPS for agents is on (Manage → Agents). Use one or the other: "
                                               "turn it off there first to use your own certificate on the agent port."})
            if set(settingslib.AGENT_PORT_KEYS) & changed.keys() and merged.get("agent_ssl"):
                problem = await self.check_agent_port(merged)
                if problem:
                    raise ValueError({problem[0]: problem[1]})
            saved = {k: v for k, v in merged.items() if k in DEFAULTS}  # only options config.yaml knows
            if self.monitor.ha.enabled:
                err = await self.monitor.ha.write_options(saved)
                if err:
                    raise RuntimeError(err)
            else:  # development, outside Home Assistant
                tmp = OPTIONS_PATH.with_suffix(".tmp")
                tmp.write_text(json.dumps(saved, indent=2))
                tmp.replace(OPTIONS_PATH)
            self._mtime = self._options_mtime()
            notes = await self.apply(changed)
            log.info("Settings changed from the dashboard%s: %s", f" by {who}" if who else "", ", ".join(sorted(changed)))
            return {"changed": sorted(changed), "notes": notes}

    async def watch(self) -> None:
        """Apply settings saved in the Configuration tab (or by the Supervisor) without a restart."""
        while True:
            await asyncio.sleep(self.WATCH_SECONDS)
            try:
                mtime = self._options_mtime()
                if not mtime or mtime == self._mtime:
                    continue
                async with self.lock:
                    self._mtime = mtime
                    raw = self._read_raw()
                    if not raw:
                        continue
                    clean, errors = settingslib.clean({k: v for k, v in raw.items() if k in settingslib.LABELS})
                    for key, problem in errors.items():
                        log.warning("Configuration tab, %s: %s; keeping the current value", key, problem)
                    changed = {k: v for k, v in clean.items() if self.monitor.opts.get(k) != v}
                    if not changed:
                        continue
                    log.info("Configuration tab changes applied without a restart: %s", ", ".join(sorted(changed)))
                    for note in await self.apply(changed):
                        log.info("  %s", note)
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001
                log.exception("Couldn't apply changed settings")


async def main() -> None:
    opts = load_options()
    logging.basicConfig(
        level=getattr(logging, str(opts["log_level"]).upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    logging.getLogger("aiohttp.access").setLevel(logging.WARNING)
    logging.getLogger("aiohttp.server").addFilter(watchdoglib.QuietDisconnects(log))
    logging.getLogger().addHandler(LOG_BUFFER)  # for Manage > Log if the Supervisor's log can't be read
    watchdog = watchdoglib.Watchdog(log)
    watchdog_task = watchdog.start()  # says where the add-on is stuck if something holds it up  # noqa: F841
    apply_pending_restore()
    new_install = not HOSTS_PATH.exists() and not AGENTS_PATH.exists()  # for defaults that differ for new installs
    try:  # made once (the first start of 1.92.1), then kept; a few seconds to make, so not on the first download
        fresh = not UPDATE_KEY_PATH.exists()
        await asyncio.to_thread(SIGNER.public)
        log.info("%s the key that signs agent updates (id %s)", "Made" if fresh else "Using", SIGNER.fingerprint())
    except Exception as err:  # noqa: BLE001
        log.error("Couldn't make or read the key that signs agent updates (%s): agents won't be offered updates", err)
    store = Store(DB_PATH)
    async with ClientSession(timeout=ClientTimeout(total=15)) as session:
        ha = HomeAssistant(session)
        monitor = Monitor(opts, store, ha)
        if monitor.imported:
            await ha.clear_option_hosts()
        monitor.click_url = await notification_target(ha, opts)
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
        monitor._winget_task = asyncio.create_task(monitor.winget_loop())
        monitor._vulns_task = asyncio.create_task(monitor.vulns_loop())
        access = Access(opts, ha)
        if access.enabled:
            log.info("Changes allowed for HA admins%s", f" and {', '.join(sorted(access.editors))}"
                     if access.editors else "")
        else:
            log.info("admin_only_changes is off: anyone who can open the panel can make changes")
        agent_listener: AgentListener | None = AgentListener(monitor)
        if not AGENT_TLS.decided():  # first start of 1.93.0: on for a new install, asked about (dashboard) otherwise
            AGENT_TLS.set(https=new_install, plain_http=True)
            log.info("Built-in HTTPS for agents: %s", "on (a new install)" if new_install else "off until an admin turns it on (Manage → Agents)")
        try:
            plain = not (monitor.tls_builtin() and not AGENT_TLS.plain_http)
            if plain or opts.get("agent_ssl"):
                await agent_listener.start(agent_ssl_context(opts))
            agent_listener.plain_on = plain or bool(opts.get("agent_ssl"))
        except Exception as err:  # noqa: BLE001
            log.error("Windows agent API could not start on port %d: %s", AGENT_PORT, err)
            agent_listener = None
        if agent_listener and monitor.tls_builtin():
            try:
                await asyncio.to_thread(AGENT_TLS.ensure_cert, monitor.tls_hosts())
                await agent_listener.set_builtin(True)
            except Exception as err:  # noqa: BLE001
                log.error("Agent HTTPS could not start on port %d: %s", AGENT_HTTPS_PORT, err)
        live = LiveSettings(monitor, access, agent_listener)
        monitor._settings_watch = asyncio.create_task(live.watch())
        runner = web.AppRunner(build_app(monitor, access, live), access_log=None)
        await runner.setup()
        await web.TCPSite(runner, "0.0.0.0", PORT).start()
        log.info("Dashboard listening on port %d", PORT)
        try:
            loop = asyncio.get_running_loop()
            await loop.create_datagram_endpoint(lambda: sysloglib.Receiver(monitor.on_syslog), local_addr=("0.0.0.0", SYSLOG_PORT))
            net = await ha.addon_network()
            monitor.syslog_port = net.get(f"{SYSLOG_PORT}/udp") if net else None
            if net:  # where agents reach Rollcall's own HTTPS from outside the add-on (None: the port isn't mapped)
                monitor.tls_public_port = net.get(f"{AGENT_HTTPS_PORT}/tcp")
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
