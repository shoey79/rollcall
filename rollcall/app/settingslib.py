"""The add-on's settings (the Configuration tab's options) as the dashboard's Settings dialog shows them.

Each field mirrors its entry in config.yaml's `schema:` (types and ranges) and its name and
description in translations/en.yaml; tests/test_settings.py checks they stay in step. `hosts` is
left out on purpose: devices are managed on the dashboard.
"""
from __future__ import annotations

import re

import iprange

# The dialog's tabs, then the titled sections within each, in order: (key, tab, title, a line on what it's for).
GROUPS = [
    ("checks", "Checking"),
    ("alerts", "Alerts"),
    ("agents", "Agents"),
    ("vulns", "Vulnerabilities and software"),
    ("limits", "Device limits"),
    ("hints", "AI hints"),
    ("access", "Dashboard and access"),
]
SECTIONS = [
    ("timing", "checks", "How often", "How often devices and services are checked, and how long a check waits for an answer."),
    ("history", "checks", "History and graphs", "How long check results and readings are kept."),
    ("maint", "checks", "Maintenance", "How long Pause lasts unless you choose otherwise."),
    ("internet", "checks", "Internet access", "For a network without the internet: nothing is downloaded, and nothing warns that it can't be."),
    ("phone", "alerts", "Phone and Home Assistant", "Notifications to your phone through the Home Assistant app, and in Home Assistant itself."),
    ("email", "alerts", "Email", "Alerts by email, through your own mail server or Microsoft 365."),
    ("joining", "agents", "Joining and reporting", "New agents, and when one that's gone quiet or slow counts as a problem."),
    ("port", "agents", "Agent port", "How agents reach Rollcall: plain HTTP, Rollcall's own HTTPS (Manage, Agents), or your own certificate here."),
    ("resources", "agents", "Disks, memory and CPU", "When disks, memory or CPU go amber or red. Each device can have its own disk limits in its details."),
    ("services", "agents", "Services", "Services to watch on every device, and things never to alert on."),
    ("roles", "agents", "Updates and server roles", "Windows updates, SQL Server backups, Exchange queues and time sync."),
    ("events", "agents", "Event and security logs", "Which event log entries and security events alert."),
    ("protect", "agents", "LAPS, BitLocker and system files", "How each device is protected, and whether Windows' own files are intact."),
    ("secrets", "agents", "Passwords left in files", "Which devices look for passwords saved in plain text, and folders whose findings never count."),
    ("messages", "agents", "Messages to users' screens", "Short messages from admins to the screens of agent devices."),
    ("vulnalerts", "vulns", "Vulnerability alerts", "Known vulnerabilities in Windows and Linux, and when they alert."),
    ("eol", "vulns", "End-of-life systems", "Operating systems kept on purpose though out of support: listed, never alerted."),
    ("programs", "vulns", "Other programs", "Programs Windows itself doesn't update: newer versions and known vulnerabilities."),
    ("wordpress", "vulns", "WordPress", "WordPress sites found on IIS servers: updates, closed plugins and, with a key, known vulnerabilities."),
    ("certs", "limits", "Certificates", "When certificates near expiry go amber and red."),
    ("ups", "limits", "UPS", "Runtime and load limits for UPSs read over SNMP."),
    ("printers", "limits", "Printers", "When toner, ink and other supplies count as low."),
    ("hints", "hints", "Hints from AI", "Optional suggestions for errors the built-in hints don't cover."),
    ("display", "access", "Display", "What the dashboard shows under each device's name, and which address ranges are yours."),
    ("logging", "access", "Rollcall's own log", "How much Rollcall writes to its log."),
    ("access", "access", "Who can make changes", "Who can change things in the dashboard, beyond Home Assistant's administrators."),
]
_TAB = {key: tab for key, tab, _t, _i in SECTIONS}


# key: (section, type, extra): the section (SECTIONS) puts it on a tab, under a heading. Types: int (lo, hi), bool, choice (options), str (max length),
# file (a file name in /ssl), strs (list of text), ints (list of whole numbers, lo, hi).
_SPEC: dict[str, tuple] = {
    "interval": ("timing", "int", (30, 3600)),
    "retry_interval": ("timing", "int", (10, 3600)),
    "ping_count": ("timing", "int", (1, 10)),
    "ping_timeout": ("timing", "int", (1, 10)),
    "service_timeout": ("timing", "int", (1, 30)),
    "history_days": ("history", "int", (1, 90)),
    "metrics_days": ("history", "int", (7, 1825)),
    "maintenance_minutes": ("maint", "int", (1, 1440)),
    "notify_services": ("phone", "strs", None),
    "persistent_notification": ("phone", "bool", None),
    "notify_recovery": ("phone", "bool", None),
    "notification_url": ("phone", "str", 500),
    "email_send": ("email", "choice", ("off", "smtp", "microsoft365")),
    "email_to": ("email", "strs", None),
    "email_from": ("email", "str", 200),
    "email_red": ("email", "bool", None),
    "email_recovery": ("email", "bool", None),
    "email_warnings": ("email", "bool", None),
    "email_digest": ("email", "bool", None),
    "email_digest_time": ("email", "str", 5),
    "email_about_devices": ("email", "bool", None),
    "email_about_services": ("email", "bool", None),
    "email_about_network": ("email", "bool", None),
    "email_about_agents": ("email", "bool", None),
    "email_about_backups": ("email", "bool", None),
    "email_about_security": ("email", "bool", None),
    "email_about_updates": ("email", "bool", None),
    "smtp_host": ("email", "str", 200),
    "smtp_port": ("email", "int", (1, 65535)),
    "smtp_security": ("email", "choice", ("starttls", "ssl", "none")),
    "smtp_check_certificate": ("email", "bool", None),
    "smtp_username": ("email", "str", 200),
    "smtp_password": ("email", "password", 200),
    "m365_tenant_id": ("email", "str", 100),
    "m365_client_id": ("email", "str", 100),
    "m365_client_secret": ("email", "password", 200),
    "cert_warn_days": ("certs", "int", (1, 365)),
    "cert_crit_days": ("certs", "int", (0, 365)),
    "ups_runtime_warn_minutes": ("ups", "int", (0, 600)),
    "ups_runtime_crit_minutes": ("ups", "int", (0, 600)),
    "ups_load_warn": ("ups", "int", (1, 100)),
    "printer_supply_warn": ("printers", "int", (1, 50)),
    "agent_auto_add": ("joining", "bool", None),
    "agent_stale_minutes": ("joining", "int", (5, 1440)),
    "agent_slow_seconds": ("joining", "int", (0, 3600)),
    "agent_disk_warn": ("resources", "int", (1, 90)),
    "agent_disk_crit": ("resources", "int", (1, 90)),
    "agent_memory_warn": ("resources", "int", (0, 100)),
    "agent_memory_crit": ("resources", "int", (0, 100)),
    "agent_cpu_warn": ("resources", "int", (0, 100)),
    "agent_cpu_reports": ("resources", "int", (1, 12)),
    "messages": ("messages", "bool", None),
    "agent_sql_backup_hours": ("roles", "int", (1, 8760)),
    "agent_exchange_queue_warn": ("roles", "int", (1, 1000000)),
    "agent_time_warn_seconds": ("roles", "int", (5, 3600)),
    "agent_time_crit_seconds": ("roles", "int", (10, 3600)),
    "agent_patch_days": ("roles", "int", (0, 3650)),
    "agent_laps_overdue_days": ("protect", "int", (1, 60)),
    "agent_bitlocker_require": ("protect", "choice", ("off", "workstations", "all")),
    "agent_secret_scan": ("secrets", "choice", ("off", "servers", "workstations", "all")),
    "secret_ignore_folders": ("secrets", "strs", None),
    "agent_sfc": ("protect", "choice", ("off", "servers", "workstations", "all")),
    "agent_sfc_day": ("protect", "choice", ("monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday")),
    "agent_sfc_hour": ("protect", "int", (0, 23)),
    "agent_sfc_dism": ("protect", "bool", None),
    "offline": ("internet", "bool", None),
    "software_updates": ("programs", "bool", None),
    "vuln_checks": ("vulnalerts", "bool", None),
    "vuln_min_score": ("vulnalerts", "int", (1, 10)),
    "vuln_linux_source": ("vulnalerts", "choice", ("local", "online", "off")),
    "vuln_skip_os": ("eol", "strs", None),
    "vuln_third_party": ("programs", "bool", None),
    "vuln_software_extra": ("programs", "strs", None),
    "wordpress_checks": ("wordpress", "bool", None),
    "wordfence_api_key": ("wordpress", "password", 300),
    "agent_watch_services": ("services", "strs", None),
    "agent_ignore": ("services", "strs", None),
    "agent_event_alerts": ("events", "bool", None),
    "agent_event_watch": ("events", "strs", None),
    "agent_security_alerts": ("events", "bool", None),
    "agent_security_alert_ids": ("events", "ints", (1, 65535)),
    "agent_failed_logons": ("events", "int", (1, 100000)),
    "name_line": ("display", "choice", ("auto", "model", "os", "address", "user", "none")),
    "ip_ranges": ("display", "strs", None),
    "log_level": ("logging", "choice", ("debug", "info", "warning", "error")),
    "agent_ssl": ("port", "bool", None),
    "agent_certfile": ("port", "file", None),
    "agent_keyfile": ("port", "file", None),
    "claude_hints": ("hints", "bool", None),
    # Two columns: the provider beside the daily limit, then each provider's model beside its own key
    "ai_provider": ("hints", "choice", ("anthropic", "openai", "gemini")),
    "claude_hints_per_day": ("hints", "int", (1, 500)),
    "claude_model": ("hints", "str", 100),
    "claude_api_key": ("hints", "password", 300),
    "openai_model": ("hints", "str", 100),
    "openai_api_key": ("hints", "password", 300),
    "gemini_model": ("hints", "str", 100),
    "gemini_api_key": ("hints", "password", 300),
    "admin_only_changes": ("access", "bool", None),
    "editors": ("access", "strs", None),
}

# Names and descriptions, as in translations/en.yaml (the Configuration tab).
LABELS: dict[str, tuple[str, str]] = {
    "interval": ("Check interval (seconds)", "How often each device and service is checked, from 30 to 3600 seconds."),
    "retry_interval": ("Re-check after a miss (seconds)", "How soon something that didn't answer is checked again before it goes red. Lower it (e.g. 60) to find out sooner."),
    "ping_count": ("Ping packets per check", "How many pings to send each check. Any reply counts as up."),
    "ping_timeout": ("Ping timeout (seconds)", "How long to wait for each ping reply."),
    "service_timeout": ("Service check timeout (seconds)", "How long to wait for a port, web page, SIP or certificate check to answer."),
    "history_days": ("Keep history for (days)", "How long check results and syslog messages are kept, from 1 to 90 days."),
    "metrics_days": ("Keep graphs for (days)", "How long disk, network, CPU and memory history from agents is kept for graphs, from 7 to 1825 days (5 years). After two days it's kept as hourly figures, and after a month as daily ones."),
    "notify_services": ("Phone or other notifications", "Home Assistant notify services to alert, without the \"notify.\" part, e.g. mobile_app_my_phone."),
    "persistent_notification": ("Home Assistant bell notification", "Show a notification in Home Assistant's sidebar while something is down."),
    "notify_recovery": ("Notify when things come back", "Also send a notification when something that was down is working again."),
    "email_send": ("Send email with", "\"smtp\": any mail server, such as an internal relay (e.g. an Exchange receive connector that allows Home Assistant's address) or one that needs a user name and password. \"microsoft365\": Microsoft 365 through Microsoft Graph, with an app registration. \"off\": no email."),
    "email_to": ("Send email to", "Addresses that get email alerts and the daily summary."),
    "email_from": ("Send email from", "The sender address. For Microsoft 365, the mailbox the app sends as."),
    "email_red": ("Red alerts", "Problems as they happen: a device down, a check gone red, a failed backup."),
    "email_recovery": ("When things come back", "When something that was red is working again."),
    "email_warnings": ("Amber warnings and events", "As they happen: late backups, log and security events, threats Defender removed. Untick to get them in the daily summary instead."),
    "email_digest": ("Daily summary", "Once a day: everything that's amber or red, plus warnings and events not already emailed."),
    "email_digest_time": ("Daily summary at", "HH:MM in Home Assistant's time zone, e.g. 08:00."),
    "email_about_devices": ("Devices not responding", "A device that stops replying, and when it's back."),
    "email_about_services": ("Service checks", "Ports, websites, certificates, SIP and Home Assistant sensors."),
    "email_about_network": ("SNMP and syslog", "Firewalls, VPNs, switches, iDRACs and syslog alerts."),
    "email_about_agents": ("Agent checks and log events", "Disks, services, Windows updates and the other agent checks, and Windows or Linux log events."),
    "email_about_backups": ("Backups", "Backup jobs that failed, were missed or are overdue."),
    "email_about_security": ("Security", "Security events, Defender, passwords found in files, privileged group changes and agent file changes."),
    "email_about_updates": ("Updates", "A new app version, or an agent update rollout that stopped."),
    "smtp_host": ("SMTP server", "The mail server's name or address, e.g. mail.example.local."),
    "smtp_port": ("SMTP port", "Usually 25 for an internal relay, 587 with STARTTLS, or 465 with SSL."),
    "smtp_security": ("SMTP security", "\"starttls\" (port 587, or 25 if the relay offers it), \"ssl\" (port 465), or \"none\" for a relay on your own network that doesn't offer encryption."),
    "smtp_check_certificate": ("Check the server's certificate", "Turn off for an internal mail server whose certificate Home Assistant doesn't trust, such as Exchange's own self-signed one. The connection is still encrypted."),
    "smtp_username": ("SMTP user name", "Leave blank for a relay that doesn't need signing in."),
    "smtp_password": ("SMTP password", "Only needed with a user name. Stored with the add-on's settings and never shown again."),
    "m365_tenant_id": ("Microsoft 365 tenant ID", "Your directory (tenant) ID, from Microsoft Entra ID."),
    "m365_client_id": ("Microsoft 365 application (client) ID", "From the app registration that has the Mail.Send application permission (with admin consent)."),
    "m365_client_secret": ("Microsoft 365 client secret", "The app registration's client secret. Stored with the add-on's settings and never shown again."),
    "log_level": ("Log level", "How much the add-on writes to its Log tab. \"info\" is right for everyday use; \"debug\" helps when troubleshooting."),
    "maintenance_minutes": ("Default pause length (minutes)", "The time limit offered when you pause a device for a reboot or maintenance."),
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
    "agent_disk_warn": ("Disk space warning (% free)", "Disks go amber at or below this much free space. Each disk can have its own limits in the device's details."),
    "agent_disk_crit": ("Disk space alert (% free)", "Disks go red at or below this much free space."),
    "agent_memory_warn": ("Memory warning (% used)", "The Resources check goes amber at or above this much memory in use. Each device can have its own limits in its details. 0 turns it off."),
    "agent_memory_crit": ("Memory alert (% used)", "The Resources check goes red, and alerts, at or above this much memory in use (two reports in a row). 0 turns it off."),
    "agent_cpu_warn": ("CPU warning (% busy)", "The Resources check goes amber when the CPU is at or above this in several reports in a row (below). Amber only: busy isn't broken. 0 turns it off."),
    "messages": ("Messages to users' screens", "Lets admins send a short message to the screens of agent devices they include (Manage → Messages). Off by default."),
    "agent_cpu_reports": ("CPU warning after (reports in a row)", "How many reports in a row the CPU must be that busy. Agents report every 5 minutes, and each reading is a moment, so one spike doesn't count."),
    "agent_failed_logons": ("Failed logons that count as an attack", "This many failed logons in one agent report turns the Security check red."),
    "agent_laps_overdue_days": ("LAPS overdue (days)", "The LAPS check goes red once a password rotation is this many days overdue."),
    "agent_bitlocker_require": ("Require BitLocker on", "Which physical devices with a TPM must use BitLocker. \"workstations\" means Windows 10 and 11. Devices that already use BitLocker are always checked; virtual machines never are."),
    "agent_sql_backup_hours": ("SQL Server backup age (hours)", "A database goes amber when it has had no full or differential backup for this long."),
    "printer_supply_warn": ("Printer supplies warning (%)", "A printer goes amber when a toner, ink or other supply is at or below this level."),
    "offline": ("Offline (no internet)", "For a network without the internet. Rollcall downloads nothing (vulnerability lists, the winget catalogue, Jellyfin's latest version) and stops warning that it can't; it uses data imported under Manage, Offline data instead, and says how old it is."),
    "software_updates": ("Highlight newer software versions", "Mark installed programs that have a newer version. Windows uses the winget catalogue, downloaded once a day; Linux uses the package manager. Never alerts."),
    "vuln_checks": ('Vulnerability alerts', "Check Windows builds and Linux packages against public lists of known vulnerabilities (CVEs), downloaded daily: Microsoft's security updates, OSV.dev for Linux, and CISA's list of exploited vulnerabilities. Amber when one scores at or above the level below; red when one is known to be exploited."),
    "vuln_min_score": ('Vulnerability score to alert on (CVSS)', 'Vulnerabilities scoring this much or more out of 10 go amber. 9 means "critical"; 7 includes "high" too. Known-exploited ones always count.'),
    "vuln_skip_os": ("End-of-life operating systems (no vulnerability alerts)", "Devices running these operating systems are kept on purpose though out of support (e.g. Windows 10 without ESU): their vulnerabilities are still listed in the device's Vulnerabilities tab, but never alert, known-exploited ones included. In Rollcall's Settings, tick the releases your agents report; others go one per line, matched as whole words against the OS the agent reports (\"Ubuntu 20.04\" matches \"Ubuntu 20.04.6 LTS\", \"Windows 10\" doesn't match Windows 11). LTSC, LTSB and IoT editions are supported for longer, so they're only taken in when named: \"Windows 10\" leaves Windows 10 LTSC alone. A single device can be excluded from its Vulnerabilities tab too."),
    "wordpress_checks": ("WordPress sites", "On servers whose agent finds WordPress sites (Windows with IIS), show each site's WordPress, plugin and theme versions on a WordPress tab, and go amber when updates are waiting or a plugin has been closed on wordpress.org. Read from the site's files only: wp-config.php and the database are never opened. Only plugin and theme names are sent to wordpress.org, never site names or addresses."),
    "wordfence_api_key": ("Wordfence API key (WordPress vulnerabilities)", "Optional. With a free key from wordfence.com (Wordfence Intelligence), the plugins, themes and WordPress versions your sites run are checked against Wordfence's list of known vulnerabilities, downloaded daily; findings show in each server's Vulnerabilities tab. Stored with the add-on's settings and never shown again."),
    "vuln_third_party": ("Vulnerabilities in other programs", "Also check common programs the agents find installed (browsers, 7-Zip, Notepad++, Adobe Reader, VLC, PuTTY, remote-access tools and more; Rollcall keeps the list) against the US National Vulnerability Database, which Microsoft's and the Linux distros' data don't cover. Only the names of the products in use are sent to the NVD, never device names or versions."),
    "vuln_software_extra": ("More programs to check for vulnerabilities", "Programs not on Rollcall's own list, one per line as: program name = vendor:product, where vendor:product is the product's name in the National Vulnerability Database (its CPE), e.g. \"Openfire = igniterealtime:openfire\". The program name is matched as whole words at the start of the name Windows shows."),
    "vuln_linux_source": ('Linux vulnerability data', '"local": download each distro\'s data from OSV.dev daily and match it here, so nothing about your devices is sent anywhere (larger downloads). "online": send OSV.dev one combined list of package names and versions and let it match (small downloads; no device names or addresses). "off": don\'t check Linux.'),
    "agent_secret_scan": ("Scan for passwords left in files", "Which devices' agents look for passwords saved in plain text (scripts, notes, setup files). Only where each one is reaches Rollcall, never the password. Each device can be turned on or off in its details."),
    "secret_ignore_folders": ("Folders whose password findings don't count", "One per line. Anything the password scan finds in these folders, and the folders below them, is listed but never alerts, on every device (for example a folder of daily log files). * stands for any part of a folder's name, and a line starting *\\ can be at any depth: \"*\\Logs\" is every folder called Logs. A single folder can also be ignored on one device with Ignore folder in its details."),
    "agent_sfc": ("System file check (Windows)", "Which Windows devices' agents run a weekly read-only system file check (sfc /verifyonly), which never repairs anything. It takes 10 to 30 minutes of CPU and disk, in the background. Each device can be turned on or off, or run now, in its details."),
    "agent_sfc_day": ("System file check day", "The day of the week the system file check runs, in each device's own time."),
    "agent_sfc_hour": ("System file check hour", "The hour it starts (0 to 23), in each device's own time. A device that's off then runs it the next time it's on."),
    "agent_sfc_dism": ("Also check the component store (DISM)", "After the system file check, run DISM /ScanHealth (also read only), which checks the store Windows repairs system files from. Takes a few more minutes."),
    "ip_ranges": ("Named IP ranges", "Names for parts of your network, shown next to each device's address, e.g. Servers=10.0.1.0/24 or IoT=192.168.20.10-200. A range can be a subnet, a span (10.0.1.10-50) or end in a wildcard (10.0.1.*); separate several with commas. Where ranges overlap, the smallest one wins."),
    "name_line": ("Line under each name", "What the dashboard shows under each device's name, unless the device has its own choice. \"auto\" shows the make and model, or else the operating system."),
    "agent_time_warn_seconds": ("Clock out by (amber, seconds)", "A domain device's Time check goes amber when its clock is this far from its domain controller's."),
    "agent_time_crit_seconds": ("Clock out by (red, seconds)", "The Time check goes red at this. Kerberos sign-ins fail at 300 seconds (5 minutes)."),
    "agent_exchange_queue_warn": ("Exchange queue warning (messages)", "The Exchange check goes amber when this many messages are waiting to be delivered."),
    "agent_patch_days": ("Windows updates overdue (days)", "The Updates check goes amber when nothing has been installed for this long. 0 turns it off."),
    "agent_event_alerts": ("Alert on System log events", "Alert when one of the watched System log events below appears (unexpected shutdowns, crashes, disk errors and so on)."),
    "agent_security_alerts": ("Alert on Security log events", "Alert when one of the watched Security log events below appears (lockouts, new accounts, group changes, cleared logs)."),
    "agent_event_watch": ("Watched System log events", "System log events that alert, written as \"Source:ID\" or just an ID, e.g. Kernel-Power:41."),
    "agent_security_alert_ids": ("Watched Security log event IDs", "Security log event IDs that alert, e.g. 4740 for an account lockout."),
    "agent_watch_services": ("Extra services to watch", "Windows or Linux services to watch on every server, as well as the ones Rollcall picks automatically."),
    "agent_ignore": ("Ignore everywhere", "Things to ignore on every server, e.g. a service, event or disk. Most ignores are easier to add with the Ignore buttons in the dashboard."),
    "agent_auto_add": ("Add approved servers automatically", "When you approve an agent, add its device to the dashboard straight away."),
    "agent_ssl": ("Use your own certificate on the agent port", "Serve the agent port over HTTPS with your own certificate from Home Assistant's /ssl folder, instead of Rollcall's own HTTPS (Manage → Agents)."),
    "agent_certfile": ("Agent HTTPS certificate", "The certificate file in Home Assistant's /ssl folder."),
    "agent_keyfile": ("Agent HTTPS private key", "The certificate's private key file in Home Assistant's /ssl folder."),
    "claude_hints": ("Hints from AI", "Adds an Ask button to amber and red checks, for a few sentences from the AI you choose below on what the error usually means. Off by default. Only the check and its error are sent, with computer, account and domain names and addresses replaced; security events, account lists and password-scan results are never sent. Uses your own API key, so you pay for what's asked (a fraction of a penny each)."),
    "ai_provider": ("AI provider", "Who writes the hints: anthropic (Claude), openai (ChatGPT) or gemini (Google). Each uses its own API key and model below."),
    "claude_api_key": ("Anthropic API key", "For Claude, from console.anthropic.com. Stored with the add-on's settings, never shown again, and only ever sent to Anthropic's API."),
    "claude_model": ("Claude model", "The Claude model that writes the hints. A small, fast one keeps each hint cheap."),
    "openai_api_key": ("OpenAI API key", "For ChatGPT, from platform.openai.com. Stored with the add-on's settings, never shown again, and only ever sent to OpenAI's API."),
    "openai_model": ("OpenAI model", "The OpenAI model that writes the hints. A small, fast one keeps each hint cheap."),
    "gemini_api_key": ("Gemini API key", "For Gemini, from aistudio.google.com. Stored with the add-on's settings, never shown again, and only ever sent to Google's Gemini API."),
    "gemini_model": ("Gemini model", "The Gemini model that writes the hints. A small, fast one keeps each hint cheap."),
    "claude_hints_per_day": ("AI hints per day", "At most this many questions to the AI a day. The same error is only asked about once (answers are kept for 30 days)."),
}

AI_KEYS = ("claude_hints", "ai_provider", "claude_api_key", "claude_model", "openai_api_key", "openai_model", "gemini_api_key",
           "gemini_model", "claude_hints_per_day")
ACCESS_KEYS = ("admin_only_changes", "editors", "messages") + AI_KEYS  # only real Home Assistant admins may change these
AGENT_PORT_KEYS = ("agent_ssl", "agent_certfile", "agent_keyfile")
MAX_ITEMS, MAX_ITEM_LEN = 500, 200
EMAIL_RE = re.compile(r"^[^@\s,;<>]+@[^@\s,;<>]+\.[^@\s,;<>]+$")
_FILE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._ -]{0,199}(/[A-Za-z0-9][A-Za-z0-9._ -]{0,199}){0,3}$")


def sections() -> list[dict]:
    return [{"key": k, "tab": t, "title": title, "intro": intro} for k, t, title, intro in SECTIONS]


def fields() -> list[dict]:
    """What the dialog needs to draw each field, in order: tab by tab, section by section."""
    out = []
    order = {key: n for n, (key, *_rest) in enumerate(SECTIONS)}
    for key, (section, kind, extra) in sorted(_SPEC.items(), key=lambda kv: order[kv[1][0]]):
        name, desc = LABELS[key]
        f = {"key": key, "group": _TAB[section], "section": section, "type": kind, "label": name, "help": desc}
        if kind in ("int", "ints"):
            f["min"], f["max"] = extra
        elif kind == "choice":
            f["options"] = list(extra)
        elif kind in ("str", "password"):
            f["max_length"] = extra
        out.append(f)
    return out


MASK = "••••••••"  # a saved password, as the dialog shows it; sent back unchanged, it's kept


def values(opts: dict) -> dict:
    """The current values, for the dialog. Passwords are never sent: a saved one shows as MASK."""
    return {k: (MASK if opts.get(k) else "") if _SPEC[k][1] == "password" else opts.get(k) for k in _SPEC}


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


# Set only in Home Assistant's Configuration tab, never from Rollcall's own Settings: turning it off from inside the
# dashboard would defeat it (it's what stops anything but Home Assistant from opening the dashboard).
HA_ONLY = {"ingress_only"}


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
            elif kind == "password":
                if v == MASK:
                    continue  # unchanged
                v = "" if v is None else v
                if not isinstance(v, str) or len(v) > extra or not v.isprintable():
                    raise ValueError(f"Must be up to {extra} ordinary characters")
                out[key] = v
            elif kind == "str":
                v = "" if v is None else v
                if not isinstance(v, str) or len(v) > extra or not v.isprintable():
                    raise ValueError(f"Must be up to {extra} ordinary characters")
                v = v.strip()
                if key == "email_digest_time" and v and not re.fullmatch(r"([01]?\d|2[0-3]):[0-5]\d", v):
                    raise ValueError("Must be a time like 08:00, or blank for none")
                if key == "email_from" and v and not EMAIL_RE.match(v):
                    raise ValueError("Must be an email address")
                out[key] = v
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
                        if key == "email_to" and not EMAIL_RE.match(item):
                            raise ValueError(f"{item[:60]} isn't an email address")
                        if key == "ip_ranges":
                            name, _spans = iprange.parse_entry(item)  # raises with what's wrong
                            item = f"{name}={item.partition('=')[2].strip()}"
                    if item not in seen:
                        seen.add(item)
                        items.append(item)
                out[key] = items
        except ValueError as err:
            errors[key] = str(err)
    return out, errors
