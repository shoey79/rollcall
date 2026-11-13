"""The add-on's settings (the Configuration tab's options) as the dashboard's Settings dialog shows them.

Each field mirrors its entry in config.yaml's `schema:` (types and ranges) and its name and
description in translations/en.yaml; tests/test_settings.py checks they stay in step. `hosts` is
left out on purpose: computers are managed on the dashboard.
"""
from __future__ import annotations

import re

GROUPS = [
    ("checks", "Checking"),
    ("alerts", "Notifications"),
    ("limits", "Certificates, UPS and printers"),
    ("agents", "Agents"),
    ("logs", "Agent log alerts"),
    ("display", "Display and logging"),
    ("agent_port", "Agent port"),
    ("access", "Who can make changes"),
]

# key: (group, type, extra). Types: int (lo, hi), bool, choice (options), str (max length),
# file (a file name in /ssl), strs (list of text), ints (list of whole numbers, lo, hi).
_SPEC: dict[str, tuple] = {
    "interval": ("checks", "int", (30, 3600)),
    "retry_interval": ("checks", "int", (10, 3600)),
    "ping_count": ("checks", "int", (1, 10)),
    "ping_timeout": ("checks", "int", (1, 10)),
    "service_timeout": ("checks", "int", (1, 30)),
    "history_days": ("checks", "int", (1, 90)),
    "maintenance_minutes": ("checks", "int", (1, 1440)),
    "notify_services": ("alerts", "strs", None),
    "persistent_notification": ("alerts", "bool", None),
    "notify_recovery": ("alerts", "bool", None),
    "notification_url": ("alerts", "str", 500),
    "cert_warn_days": ("limits", "int", (1, 365)),
    "cert_crit_days": ("limits", "int", (0, 365)),
    "ups_runtime_warn_minutes": ("limits", "int", (0, 600)),
    "ups_runtime_crit_minutes": ("limits", "int", (0, 600)),
    "ups_load_warn": ("limits", "int", (1, 100)),
    "printer_supply_warn": ("limits", "int", (1, 50)),
    "agent_auto_add": ("agents", "bool", None),
    "agent_stale_minutes": ("agents", "int", (5, 1440)),
    "agent_slow_seconds": ("agents", "int", (0, 3600)),
    "agent_disk_warn": ("agents", "int", (1, 90)),
    "agent_disk_crit": ("agents", "int", (1, 90)),
    "agent_sql_backup_hours": ("agents", "int", (1, 8760)),
    "agent_exchange_queue_warn": ("agents", "int", (1, 1000000)),
    "agent_patch_days": ("agents", "int", (0, 3650)),
    "agent_laps_overdue_days": ("agents", "int", (1, 60)),
    "agent_bitlocker_require": ("agents", "choice", ("off", "workstations", "all")),
    "agent_secret_scan": ("agents", "choice", ("off", "servers", "workstations", "all")),
    "software_updates": ("agents", "bool", None),
    "agent_watch_services": ("agents", "strs", None),
    "agent_ignore": ("agents", "strs", None),
    "agent_event_alerts": ("logs", "bool", None),
    "agent_event_watch": ("logs", "strs", None),
    "agent_security_alerts": ("logs", "bool", None),
    "agent_security_alert_ids": ("logs", "ints", (1, 65535)),
    "agent_failed_logons": ("logs", "int", (1, 100000)),
    "name_line": ("display", "choice", ("auto", "model", "os", "address", "user", "none")),
    "log_level": ("display", "choice", ("debug", "info", "warning", "error")),
    "agent_ssl": ("agent_port", "bool", None),
    "agent_certfile": ("agent_port", "file", None),
    "agent_keyfile": ("agent_port", "file", None),
    "admin_only_changes": ("access", "bool", None),
    "editors": ("access", "strs", None),
}

# Names and descriptions, as in translations/en.yaml (the Configuration tab).
LABELS: dict[str, tuple[str, str]] = {
    "interval": ("Check interval (seconds)", "How often each computer and service is checked, from 30 to 3600 seconds."),
    "retry_interval": ("Re-check after a miss (seconds)", "How soon something that didn't answer is checked again before it goes red. Lower it (e.g. 60) to find out sooner."),
    "ping_count": ("Ping packets per check", "How many pings to send each check. Any reply counts as up."),
    "ping_timeout": ("Ping timeout (seconds)", "How long to wait for each ping reply."),
    "service_timeout": ("Service check timeout (seconds)", "How long to wait for a port, web page, SIP or certificate check to answer."),
    "history_days": ("Keep history for (days)", "How long check results and syslog messages are kept, from 1 to 90 days."),
    "notify_services": ("Phone or other notifications", "Home Assistant notify services to alert, without the \"notify.\" part, e.g. mobile_app_my_phone."),
    "persistent_notification": ("Home Assistant bell notification", "Show a notification in Home Assistant's sidebar while something is down."),
    "notify_recovery": ("Notify when things come back", "Also send a notification when something that was down is working again."),
    "log_level": ("Log level", "How much the add-on writes to its Log tab. \"info\" is right for everyday use; \"debug\" helps when troubleshooting."),
    "maintenance_minutes": ("Default pause length (minutes)", "The time limit offered when you pause a computer for a reboot or maintenance."),
    "notification_url": ("Notification link", "Where tapping a notification goes. Leave blank to open the Rollcall dashboard."),
    "admin_only_changes": ("Only admins can make changes", "Only Home Assistant administrators (and the people listed under Editors) can add, change, pause or delete things. Everyone else can look."),
    "editors": ("Editors", "Home Assistant usernames of people who aren't administrators but may make changes."),
    "cert_warn_days": ("Certificate warning (days before expiry)", "Certificate checks go amber this many days before the certificate expires."),
    "cert_crit_days": ("Certificate alert (days before expiry)", "Certificate checks go red, with a notification, this many days before expiry or once expired."),
    "ups_runtime_warn_minutes": ("UPS runtime warning (minutes)", "A UPS goes amber when its battery would last less than this. 0 turns it off. Each UPS can have its own limits in its details."),
    "ups_runtime_crit_minutes": ("UPS runtime alert (minutes)", "A UPS goes red when its battery would last less than this. 0 turns it off."),
    "ups_load_warn": ("UPS load warning (%)", "A UPS goes amber at this load or more. 95% or more is always red."),
    "agent_stale_minutes": ("Agent not reporting after (minutes)", "An agent goes red when it hasn't reported for this long."),
    "agent_slow_seconds": ("Slow agent run (seconds)", "An agent goes amber when one run takes longer than this. 0 turns it off."),
    "agent_disk_warn": ("Disk space warning (% free)", "Disks go amber at or below this much free space. Each disk can have its own limits in the computer's details."),
    "agent_disk_crit": ("Disk space alert (% free)", "Disks go red at or below this much free space."),
    "agent_failed_logons": ("Failed logons that count as an attack", "This many failed logons in one agent report turns the Security check red."),
    "agent_laps_overdue_days": ("LAPS overdue (days)", "The LAPS check goes red once a password rotation is this many days overdue."),
    "agent_bitlocker_require": ("Require BitLocker on", "Which physical computers with a TPM must use BitLocker. \"workstations\" means Windows 10 and 11. Computers that already use BitLocker are always checked; virtual machines never are."),
    "agent_sql_backup_hours": ("SQL Server backup age (hours)", "A database goes amber when it has had no full or differential backup for this long."),
    "printer_supply_warn": ("Printer supplies warning (%)", "A printer goes amber when a toner, ink or other supply is at or below this level."),
    "software_updates": ("Highlight newer software versions", "Mark installed programs that have a newer version. Windows uses the winget catalogue, downloaded once a day; Linux uses the package manager. Never alerts."),
    "agent_secret_scan": ("Scan for passwords left in files", "Which computers' agents look for passwords saved in plain text (scripts, notes, setup files). Only where each one is reaches Rollcall, never the password. Each computer can be turned on or off in its details."),
    "name_line": ("Line under each name", "What the dashboard shows under each computer's name, unless the computer has its own choice. \"auto\" shows the make and model, or else the operating system."),
    "agent_exchange_queue_warn": ("Exchange queue warning (messages)", "The Exchange check goes amber when this many messages are waiting to be delivered."),
    "agent_patch_days": ("Windows updates overdue (days)", "The Updates check goes amber when nothing has been installed for this long. 0 turns it off."),
    "agent_event_alerts": ("Alert on System log events", "Alert when one of the watched System log events below appears (unexpected shutdowns, crashes, disk errors and so on)."),
    "agent_security_alerts": ("Alert on Security log events", "Alert when one of the watched Security log events below appears (lockouts, new accounts, group changes, cleared logs)."),
    "agent_event_watch": ("Watched System log events", "System log events that alert, written as \"Source:ID\" or just an ID, e.g. Kernel-Power:41."),
    "agent_security_alert_ids": ("Watched Security log event IDs", "Security log event IDs that alert, e.g. 4740 for an account lockout."),
    "agent_watch_services": ("Extra services to watch", "Windows or Linux services to watch on every server, as well as the ones Rollcall picks automatically."),
    "agent_ignore": ("Ignore everywhere", "Things to ignore on every server, e.g. a service, event or disk. Most ignores are easier to add with the Ignore buttons in the dashboard."),
    "agent_auto_add": ("Add approved servers automatically", "When you approve an agent, add its computer to the dashboard straight away."),
    "agent_ssl": ("Agent port uses HTTPS", "Serve the agent port over HTTPS, using the certificate below from Home Assistant's /ssl folder."),
    "agent_certfile": ("Agent HTTPS certificate", "The certificate file in Home Assistant's /ssl folder."),
    "agent_keyfile": ("Agent HTTPS private key", "The certificate's private key file in Home Assistant's /ssl folder."),
}

ACCESS_KEYS = ("admin_only_changes", "editors")      # only real Home Assistant admins may change these
AGENT_PORT_KEYS = ("agent_ssl", "agent_certfile", "agent_keyfile")
MAX_ITEMS, MAX_ITEM_LEN = 500, 200
_FILE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._ -]{0,199}(/[A-Za-z0-9][A-Za-z0-9._ -]{0,199}){0,3}$")


def fields() -> list[dict]:
    """What the dialog needs to draw each field, in order."""
    out = []
    for key, (group, kind, extra) in _SPEC.items():
        name, desc = LABELS[key]
        f = {"key": key, "group": group, "type": kind, "label": name, "help": desc}
        if kind in ("int", "ints"):
            f["min"], f["max"] = extra
        elif kind == "choice":
            f["options"] = list(extra)
        elif kind == "str":
            f["max_length"] = extra
        out.append(f)
    return out


def values(opts: dict) -> dict:
    return {k: opts.get(k) for k in _SPEC}


def _whole(v, lo: int, hi: int) -> int:
    if isinstance(v, bool):
        raise ValueError
    if isinstance(v, str):
        v = v.strip()
        if not re.fullmatch(r"-?\d+", v):
            raise ValueError
    n = int(v)
    if isinstance(v, float) and v != n:
        raise ValueError
    if not lo <= n <= hi:
        raise ValueError
    return n


def clean(changes: dict) -> tuple[dict, dict]:
    """Check the dialog's changes against the schema. Returns (clean values, {key: problem})."""
    out, errors = {}, {}
    for key, v in changes.items():
        if key not in _SPEC:
            errors[key] = "Not a setting"
            continue
        _group, kind, extra = _SPEC[key]
        try:
            if kind == "int":
                lo, hi = extra
                try:
                    out[key] = _whole(v, lo, hi)
                except (TypeError, ValueError):
                    raise ValueError(f"Must be a whole number from {lo} to {hi}") from None
            elif kind == "bool":
                if not isinstance(v, bool):
                    raise ValueError("Must be on or off")
                out[key] = v
            elif kind == "choice":
                if v not in extra:
                    raise ValueError("Must be one of " + ", ".join(extra))
                out[key] = v
            elif kind == "str":
                v = "" if v is None else v
                if not isinstance(v, str) or len(v) > extra or not v.isprintable():
                    raise ValueError(f"Must be up to {extra} ordinary characters")
                out[key] = v.strip()
            elif kind == "file":
                v = v.strip() if isinstance(v, str) else ""
                if not _FILE_RE.match(v) or ".." in v:
                    raise ValueError("Must be a file name in the /ssl folder, e.g. fullchain.pem")
                out[key] = v
            elif kind in ("strs", "ints"):
                if not isinstance(v, list):
                    raise ValueError("Must be a list")
                if len(v) > MAX_ITEMS:
                    raise ValueError(f"Can have up to {MAX_ITEMS} entries")
                items, seen = [], set()
                for item in v:
                    if kind == "ints":
                        lo, hi = extra
                        try:
                            item = _whole(item, lo, hi)
                        except (TypeError, ValueError):
                            raise ValueError(f"Entries must be whole numbers from {lo} to {hi}") from None
                    else:
                        if not isinstance(item, str):
                            raise ValueError("Entries must be text")
                        item = item.strip()
                        if key == "notify_services" and item.lower().startswith("notify."):
                            item = item[7:]
                        if not item:
                            continue
                        if len(item) > MAX_ITEM_LEN or not item.isprintable():
                            raise ValueError(f"Entries must be up to {MAX_ITEM_LEN} ordinary characters")
                    if item not in seen:
                        seen.add(item)
                        items.append(item)
                out[key] = items
        except ValueError as err:
            errors[key] = str(err)
    return out, errors
