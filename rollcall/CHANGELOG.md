# Changelog

## 1.8.0 - 2026-11-02

### Added
- **Storage health check** (Windows agent 1.0.7, Linux agent 1.0.4). Red when a disk in a software RAID fails: Windows mirrored or RAID-5 volumes on dynamic disks with failed redundancy, missing dynamic disks, degraded Storage Spaces, unhealthy physical disks; Linux mdadm arrays that are degraded or have a failed member, and ZFS pools that aren't ONLINE. Amber for a disk predicting failure (SMART) or an array that's rebuilding. Details has a **Storage health** section, and items can be ignored (`storage:E:`).

### Fixed
- Opening a server's Details briefly showed the previous server's name and agent version until the new details loaded.

Update the agents to get the Storage check: download them again from **Agents** (Windows: replace the script on the share or run it again with MECM; Linux: run `--install` again).

## 1.7.0 - 2026-11-02

### Added
- **Monitoring schedules.** A computer can be monitored only at set times (Edit → Monitoring schedule): one or more windows of days and times, which can run past midnight. Outside them it shows as **Off schedule** and nothing alerts; it's still pinged, and the time doesn't count against uptime. When a window opens it shows **Starting up** for an allowance you choose (15 minutes by default) before a down alert. Times follow Home Assistant's time zone and daylight saving.
- Off-schedule computers have their own count at the top and a tab condition (Status is Off schedule). The entity gains `off_schedule` and `schedule` attributes.

## 1.6.2 - 2026-11-02

### Fixed
- Importing an export failed with "Import failed (413)" when the file was more than a few MB. Home Assistant's ingress proxy rejects large uploads, so the dashboard now uploads the file in 1 MB pieces, showing progress, and imports it once it's all there. Existing export files work as they are.

## 1.6.1 - 2026-11-02

### Fixed
- 1.6.0's add-on description contained a colon that made `config.yaml` invalid, so Home Assistant couldn't read the add-on. Fixed.
- Documentation examples use `example.local` instead of a real domain. Install instructions are now for the GitHub repository.

## 1.6.0 - 2026-11-02

### Changed
- **Renamed to Rollcall.** The sidebar, dashboard, notifications and agent messages now say Rollcall. Internal names are unchanged: the add-on ID (`ping_monitor`), entity IDs (`sensor.ping_monitor_*`), agent file names, folders, scheduled task, systemd timer and port 8100, so existing automations and installed agents keep working without changes.
- Phone notifications use a "Rollcall" notification channel; on Android, set its sound or importance again if you'd customised the old "Ping Monitor" channel.
- Exports are named `rollcall-export-<date>.zip`. Exports from Ping Monitor import as before.
- Windows agent 1.0.6 and Linux agent 1.0.3: wording only. No need to redeploy.

## 1.5.0 - 2026-11-02

### Added
- **Export / import** (admins), to move everything to another install of the add-on, e.g. one installed from GitHub. The export is one zip with computers and checks, tabs, pauses, agent approvals and enrolment key, ignores and disk thresholds, last agent reports, uptime history and (optionally restored) the Configuration-tab settings. Import checks the file, replaces the data on that install, keeps what it replaced in `before_import_<date>/`, and restarts the add-on. Agents carry on reporting without being reinstalled.

## 1.4.0 - 2026-11-01

### Added
- **Home Assistant sensor checks.** Any HA sensor can be a check on a computer, e.g. a UniFi access point's CPU and memory from the UniFi Network integration: `CPU=ha:sensor.office_ap_cpu_utilization>90`. The condition describes the problem (`>` `>=` `<` `<=` `=` `!=`); without one, the sensor only needs to be available. The chip shows the current value.
- The Edit dialog can search Home Assistant's sensors and add one with a click, with sensible defaults (CPU and memory above 90%, temperature above 80).

## 1.3.1 - 2026-11-01

### Fixed
- A small vertical scrollbar appeared beside the tabs in Chrome even when they all fit. The tab bar now only scrolls sideways, and only when there are more tabs than fit.

## 1.3.0 - 2026-11-01

### Added
- **Tabs** on the dashboard. Built in: All, Needs attention, and Windows / Linux / No agent when you have a mix. Admins can add their own with **+ New tab**, built from conditions on name (begins with, contains, ends with, is, pattern…), hostname or IP, IP range (CIDR, ranges or wildcards), operating system, status, agent role, service check and 24-hour uptime, matching all or any. A live preview shows what matches.
- Each tab shows how many computers it holds and how many need attention. Tabs are shared by everyone and saved in `views.json`; each browser remembers its last tab.

## 1.2.4 - 2026-10-31

### Fixed
- Linux agent 1.0.2 ignores read errors from virtual floppy and CD drives (`fd0`, `sr0`), which VMs log when the drive is empty. They were being alerted as critical disk I/O errors. Errors on real disks are still alerted.

## 1.2.3 - 2026-10-31

### Added
- **UniFi OS Server** preset (`unifi-os-server`) for the self-hosted UniFi OS Server that replaces the old UniFi Network controller: web interface on https:11443 and device inform on 8080.

### Changed
- The two existing UniFi presets are renamed to make clear which is which: "UniFi Network, old controller (8443)" and "UniFi OS console, e.g. Cloud Key or UDM (443)".

## 1.2.2 - 2026-10-28

### Changed
- Linux agent 1.0.1 re-checks updates as soon as packages are installed or `apt update` runs, instead of waiting up to 6 hours, so the dashboard reflects an upgrade on the next report.

## 1.2.1 - 2026-10-28

### Fixed
- A newly approved Linux server showed "Windows: waiting for first report" until its first report arrived. It now shows "Linux: waiting for first report".
- The Immich API key instructions now list the permissions needed (`server.statistics`, `server.storage` and `job.read` or `queue.read`, on a key made by an admin) instead of "all permissions".

## 1.2.0 - 2026-10-28

### Added
- **Linux agent** (`pingmonitor-agent.py`, 1.0.0) for Ubuntu and other systemd Linux servers, built with Immich in mind. Download it from **Agents**, then `sudo python3 pingmonitor-agent.py --install`. It reports:
  - disk space per mount point, CPU, memory and load
  - Docker containers (stopped, unhealthy or restarting), key systemd services and failed units
  - Immich: API answering and version; with an API key, job queues (failed or paused) and library statistics
  - journal errors, with out-of-memory kills and disk/filesystem errors alerted straight away
  - failed SSH and sudo logins, users created or deleted, users added to groups
  - pending and security updates, last apt run, reboot required
- Details shows Docker containers, an Immich section and journal errors for Linux servers; the dashboard chip reads **Linux ✓**.
- Disk thresholds and Ignore work with Linux mount points (`disk:/srv/photos`).

### Changed
- The **Windows agents** button is now **Agents**, covering both, and the approved list shows each agent's OS.

## 1.1.4 - 2026-10-21

### Added
- Windows agent 1.0.5 times each part of its run and reports the total, CPU time and peak memory. Its log line now reads e.g. "run took 48 s; slowest: update history 41 s".
- Details has an **Agent run** section breaking down where the time went.
- The Agent check shows the run time and turns amber if a run takes longer than `agent_slow_seconds` (default 120; 0 turns this off).

### Changed
- The last-update date (Windows Update history and the installed-updates list, which can be slow, especially on Windows 10/11) is now worked out every 6 hours or after a restart, instead of every run, and reads the latest 100 history entries instead of 300.
- The agent doesn't ask workstations for Windows Server roles.

## 1.1.3 - 2026-10-21

### Fixed
- Pausing a server for maintenance didn't stop the Windows agent's "no report" check. During a reboot longer than `agent_stale_minutes` the Agent check went red, and the server showed as Degraded when the pause ended. The check is now skipped while paused, and after a pause ends (automatically or with Resume) the agent gets a full `agent_stale_minutes` to report again before it's flagged.

## 1.1.2 - 2026-10-20

### Fixed
- Reports from servers with a single disk were rejected (HTTP 500 in the agent log). PowerShell sends a one-item list as a bare object, and the add-on expected a list. The add-on now accepts either shape for every list in a report, so existing agents work without being redeployed.
- Windows agent 1.0.4 sends the disk list as a list even with one disk.
- If a report still can't be processed, the add-on logs the reason and keeps a copy (`agent_reports/failed-<id>.json`) for diagnosis.

## 1.1.1 - 2026-10-20

### Fixed
- IIS FTP sites showed as "Unknown". IIS's site list reports through the web service, which doesn't run FTP sites. Windows agent 1.0.3 reads an FTP-only site's real state from IIS's FTP settings, falling back to whether the FTP service is running.
- A site state of "Unknown" is no longer treated as a fault, so older agents don't raise false alerts.
- Details labels FTP sites as such.

## 1.1.0 - 2026-10-20

### Added
- **Ignore from the dashboard.** In a server's Details, admins can ignore stopped services, stopped IIS app pools and sites, printers, VMs, busy DHCP scopes, event IDs and whole disks, on that server or on all servers. Changes take effect immediately on the latest report and clear any related alert.
- **Per-disk thresholds.** Each disk can have its own amber and red % free levels; 0 turns a level off.
- An **Ignored on this server** list in Details, with **Apply to all servers** and **Stop ignoring**. Ignores from the Configuration tab are listed too.
- Settings are saved in `agent_settings.json` and removed when a server is deleted from the dashboard.

### Changed
- Disk status is worked out per volume against that volume's own thresholds.
- Events that are ignored after they arrive no longer keep the Events chip amber.
- After **Stop ignoring**, something that's still wrong goes red straight away instead of waiting for two more reports.

## 1.0.3 - 2026-10-20

### Fixed
- Windows agent 1.0.2: "last update installed" could be years out on UK-locale servers. The installed-updates list (`Get-HotFix`) stores dates in US format, and they were misread or dropped. The agent now takes the newest of Windows Update history (includes MECM/WSUS installs, excludes Defender definition updates), the Setup event log's servicing entries, and the installed-updates list with its dates parsed correctly.

### Added
- The agent reports the OS build including the update revision (e.g. 10.0.20348.2762), shown in Details and in the Updates check when no date is available.
- Details shows where the last-update date came from.
- `agent_patch_days: 0` turns off the "not updated for N days" warning; a pending reboot is still flagged.

## 1.0.2 - 2026-10-20

### Added
- Windows agent 1.0.1: new `-Action` parameter (`Install`, `Uninstall`, `Report`) for tools that can't pass switch parameters, such as MECM Run Scripts.
- MECM deployment steps in the Windows agents dialog and the README.

### Fixed
- `-Install` now works when the script is run without a file on disk (e.g. as a script block), by writing the script out itself.

## 1.0.1 - 2026-10-20

### Fixed
- After an update, browsers could keep showing the previous version of the dashboard (e.g. no Windows agents button) until a hard refresh. The page and API responses are now marked not to be cached.

## 1.0.0 - 2026-10-20

### Added
- **Windows agent.** One PowerShell script for every server (`PingMonitorAgent.ps1`, downloaded from the dashboard with the address and enrolment key built in). It runs every 5 minutes as a SYSTEM scheduled task, installs itself with `-Install`, and can be deployed by GPO.
  - **Role discovery** on each run: DC, DNS, DHCP, file, DFS, print, IIS, RDS roles, Hyper-V, WSUS, AD CS, AD FS, NPS, SQL Server, Exchange, SharePoint and Veeam. Each role's automatic services are watched.
  - **Checks:** disk space, role services, other stopped automatic services, updates and pending reboot, IIS app pools and sites, AD replication and SYSVOL/NETLOGON, DHCP scope usage, Hyper-V VM state, shared printers, Microsoft Defender, failed-logon bursts, and a stale-agent alarm.
  - **Instant alerts** for account lockouts, account creation and deletion, security group additions, audit policy changes, Security log cleared, unexpected shutdowns and crashes, disk/NTFS errors, Critical events, and Defender detections.
  - **Details** view per server: system info, roles, disks, services, role health, 24 h of errors and (admins only) security events.
  - **Sensors** for every agent check, plus CPU, memory and per-disk free space for HA graphs.
- **Windows agents** admin dialog: download the script, approve or reject servers, revoke, rotate the enrolment key, see the last report and agent version.
- Approved servers are added to the dashboard automatically, or matched to an existing entry by name or IP.
- Agent API on port 8100, with optional HTTPS using Home Assistant's certificates.
- New options: `agent_stale_minutes`, `agent_disk_warn`, `agent_disk_crit`, `agent_failed_logons`, `agent_patch_days`, `agent_event_alerts`, `agent_security_alerts`, `agent_event_watch`, `agent_security_alert_ids`, `agent_watch_services`, `agent_ignore`, `agent_auto_add`, `agent_ssl`, `agent_certfile`, `agent_keyfile`.

### Changed
- Dashboard rows show one "Windows ✓" chip for an agent's healthy checks and list only the ones that need attention.
- The Degraded note lists agent check names; the full reasons are in Details.
- Deleting a computer also revokes its Windows agent.

## 0.9.0 - 2026-10-19

### Added
- The Ping Monitor sidebar panel is now visible to all Home Assistant users, not only admins (`panel_admin: false`).
- **View-only mode for non-admins.** They see status, services and uptime, and can use "Check now", but can't add, edit, delete, pause, resume or reset. The add-on enforces this itself, not just by hiding buttons, because HA doesn't stop non-admins opening an add-on's page by URL.
- Admins are identified from Home Assistant's user list, matched to the signed-in user that HA's ingress passes to the add-on.
- New option `editors`: HA usernames or display names of non-admins who may also make changes.
- New option `admin_only_changes` (default on). Turn it off to let anyone who can open the panel make changes.
- Blocked change attempts are logged with the user's name.

## 0.8.0 - 2026-10-18

### Added
- 59 more service presets, bringing the total to 79, in 11 groups:
  - **Windows & Microsoft:** LDAPS, AD FS, Certificate Services, ConfigMgr/SCCM, KMS, WinRM, Veeam.
  - **Databases:** MySQL/MariaDB, PostgreSQL, MongoDB, Redis, Oracle, Elasticsearch, InfluxDB.
  - **Mail & files:** SMTP, IMAPS, POP3S, FTP, Nextcloud.
  - **Remote access:** VNC, Telnet (SSH moved here).
  - **Virtualisation & storage:** Proxmox VE and Backup Server, ESXi, vCenter, Synology, QNAP, TrueNAS, Unraid, Portainer.
  - **Network & infrastructure:** Pi-hole, AdGuard Home, Nginx Proxy Manager, Squid, network printers, IP cameras/NVRs (RTSP).
  - **Home & automation:** Home Assistant, Node-RED, MQTT, Frigate, Vaultwarden, Paperless-ngx, Uptime Kuma.
  - **Media:** Emby, Audiobookshelf, Navidrome, Tautulli, Overseerr/Jellyseerr.
  - **Downloads:** Sonarr, Radarr, Lidarr, Prowlarr, SABnzbd, qBittorrent, Transmission.
  - **Monitoring & development:** Grafana, Prometheus, Gitea/Forgejo, Jenkins.
  - Apps with a health or status endpoint are checked through it; the rest by their default port.
- Search box in the Add/Edit form to find a preset by name or common alias (e.g. "sccm", "mariadb", "pve").
- A "Selected:" line in the form listing what's ticked, including anything hidden by the search.

### Changed
- Preset descriptions in the form are shorter (e.g. "TCP 1433" rather than "SQL 1433").

## 0.7.1 - 2026-10-18

### Fixed
- HTTPS checks against older devices (e.g. Dell iDRAC 6) showed Degraded even though the web page worked. HTTPS checks now accept TLS 1.0, old ciphers, small (1024-bit) keys and legacy renegotiation.
- The Plex preset failed when Plex is set to require secure connections. `http:PORT` and `https:PORT` checks now try the other protocol when the port answers but not with the expected one, and remember which works ("via https" on the chip).
- Web checks no longer fail on devices that send malformed HTTP headers. Only the status line is read.

### Added
- `idrac` preset (also `ilo`, `bmc`): HTTPS on 443, listed as "Dell iDRAC / server BMC" in the Add/Edit form.
- The Degraded note on the dashboard now shows why each service failed (e.g. "OWA: HTTP 503").

## 0.7.0 - 2026-10-18

### Added
- **Add computer** button and an **Edit** button on each row, opening a form with:
  - name and IP/hostname fields
  - a checkbox for every service preset, grouped and showing the ports each one checks
  - custom check fields, with format hints and a clear error if one isn't valid
  - Delete and Reset uptime for that computer
- Changes take effect immediately, without restarting the add-on.
- Deleting a computer also removes its history, bell notifications and HA sensors.

### Changed
- The computer list is now stored in the add-on's data folder (`hosts.json`) and managed on the dashboard.
- Hosts in the Configuration tab are imported on start (matched by name), then that option is cleared. Hosts already imported are never re-applied, so they can't undo dashboard edits.
- The per-row "Reset" button has moved into the Edit form, making room for "Edit".

## 0.6.0 - 2026-10-18

### Added
- **Service checks.** Each host can have a `checks:` list of presets or custom checks.
  - Presets: `dc`, `dns`, `ldap`, `sql`, `iis`, `iis-https`, `sharepoint`, `exchange`, `wsus`, `fileserver`/`smb`, `rds`/`rdp`, `immich`, `jellyfin`, `plex`, `unifi`, `unifi-os`, `ssh`.
  - Custom: `tcp:PORT`, `http:PORT/path`, `https:PORT/path`, a full URL, and an optional `Label=` prefix.
  - Web checks pass on any response below 500, so a 401 (Windows auth) or a redirect to a login page counts as up. Certificates aren't verified.
- **Degraded** status (orange): the computer pings but a service has failed twice in a row.
- Per-service alerts ("🟠 SQL01: SQL is down" / "🟢 … is back up") and bell notifications, each with its own phone tag.
- Service chips on each dashboard row. Hover for target, error detail, latency and 24h uptime. The filter box also matches service names.
- `sensor.ping_monitor_<host>_<service>` for every service, plus a `services` attribute on each computer sensor.
- `ping_monitor_service_changed` event.
- New option `service_timeout` (default 5 seconds).

### Changed
- When a whole computer goes down you get a single "down" alert. Its services reset and re-check once it's back, instead of each sending its own alert.
- Pausing a computer also pauses its service checks.
- Resetting a computer's uptime also clears its services' history.

## 0.5.0 - 2026-10-18

### Added
- Tapping a phone notification now opens the Ping Monitor dashboard instead of the default HA page. The add-on finds its own sidebar path automatically.
- New option `notification_url` to send taps somewhere else (for example `/lovelace/servers`). Leave it blank for the automatic path.
- Phone notifications are tagged per computer, so a "back up" message replaces that computer's "down" alert instead of stacking.
- Phone notifications are grouped and use their own "Ping Monitor" notification channel on Android, so the sound and priority can be set separately in the phone's notification settings.

### Changed
- Recovery messages show seconds for outages under a minute (previously "after 0m").
- The add-on now requests Supervisor API access (`hassio_api`) to look up its own slug.

### Notes
- Companion app extras are only added for `mobile_app_*` services; other notify services get plain title and message as before.

## 0.4.0 - 2026-10-18

### Added
- **Pause** button on each row (maintenance mode), for reboots and planned work.
  - The host keeps being pinged but shows blue "Paused" and sends no alerts.
  - Monitoring resumes automatically once the host has stopped replying and then replies again, with a "back online" message if `notify_recovery` is on.
  - If it isn't back within the time limit, it goes straight to red and alerts. If it never went down (a quick reboot between checks), it resumes quietly.
  - **Resume** button to end a pause early. The amber/red count starts fresh.
  - Pauses survive an add-on restart.
- New option `maintenance_minutes` (default 30): the default time limit offered when pausing.
- Pause time is left out of the uptime % and shows blue in the 24h strip.
- Sensors report state `maintenance` and a `maintenance_until` attribute.

## 0.3.0 - 2026-10-18

### Added
- "Reset all uptime" button on the dashboard, which clears the check history for every host.
- "Reset" button on each row, which clears history for that host only.
- Both ask for confirmation. Current status is kept; uptime % and the 24h strip start again from the next check, and the HA sensors are updated straight away.

## 0.2.1 - 2026-10-18

### Fixed
- Dashboard header showed the check interval rounded to whole minutes (30 seconds displayed as "1 min"). It now shows the exact interval, plus the retry interval when that differs.

## 0.2.0 - 2026-10-18

### Added
- Sortable columns on the dashboard. Click a header to sort ascending, click again for descending.
  - Names sort naturally (PC2 before PC10) and ignore case.
  - IP addresses sort numerically.
  - Hosts with no value yet (for example, no uptime) always sort last.
- The chosen sort order is remembered between visits.
- A "Sort" dropdown on narrow screens, where column headers are hidden.

## 0.1.0 - 2026-10-18

### Added
- Initial release.
- Pings a configurable list of hosts (IP or hostname) on a schedule. The default is every 5 minutes.
- Status per host: green (up), amber (one missed check), red (two or more missed checks in a row).
- Separate retry interval for the re-check after a miss.
- Ingress dashboard in the HA sidebar showing status, name, IP, 24h uptime %, latency, last check, time since last change, a 24-hour history strip and a "Check now" button.
- `sensor.ping_monitor_<name>` per host, with IP, uptime, latency and timestamps as attributes. Republished every 60 seconds so sensors return quickly after an HA restart.
- Notifications through any `notify` services when a host goes red, and optionally when it recovers.
- Persistent notification in HA while a host is red, cleared on recovery.
- `ping_monitor_status_changed` event on every status change, for use in automations.
- Check history stored in SQLite, kept for a configurable number of days. Last known status is restored on restart without re-sending alerts.
