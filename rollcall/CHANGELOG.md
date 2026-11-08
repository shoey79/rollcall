# Changelog

## 1.33.2 - 2026-11-08

### Fixed
- SNMP: slow switches (e.g. Netgear smart switches) still timed out and sometimes didn't answer at all. Each poll walked every interface, including VLANs and LAGs, column by column: hundreds of requests.
  - Rollcall now finds the physical ports, their names and descriptions, and the PoE ports every 6 hours.
  - Each check fetches only those ports' live values (up/down, speed, errors, PoE state and power), ten per request. A 16-port PoE switch now needs about 15 requests per check instead of about 450.
  - A request a device rejects is retried value by value.

## 1.33.1 - 2026-11-08

### Fixed
- SNMP: PoE information went missing on Netgear switches, and polls took over a minute.
  - Rollcall walked the whole PoE table; it now reads the list of PoE ports, then only the columns it uses, in small batches.
  - After the switch stalled once, the request size stayed at 1 row for good, so every poll took hundreds of requests. It now doubles again after each poll without timeouts, up to the largest size the device has coped with, and tries larger sizes again after 6 hours.

## 1.33.0 - 2026-11-08

### Added
- **Check now**, **Pause** and **Resume** in the Details dialog's footer, so a device opened from the Overview can be paused or resumed straight away. It shows when a pause ends. Pause and Resume are hidden for view-only users.

## 1.32.1 - 2026-11-08

### Fixed
- SNMP: switches could go up and down with "no SNMP reply" (seen on Netgear smart switches). Since 1.20.2, every poll also asked for the device's own uptime (HOST-RESOURCES-MIB). Switches without that MIB can stall their SNMP service when asked for it, so the next poll got no answer. Rollcall now asks once per device, with a short timeout and no retry. A device that doesn't answer isn't asked again, and its SNMP-service uptime is shown instead, as before 1.20.2.

## 1.32.0 - 2026-11-08

### Added
- **Which address each agent uses**:
  - Agents' logs now say where each report went ("Report sent to https://…: …").
  - Rollcall stores the address each agent last reported to and the IP the report came from. For reports through a reverse proxy, such as the firewall's WAF, that's the original IP from `X-Forwarded-For` and the proxy's own IP.
  - Shown under Last report in the Agents list, and in Details → Agent. The add-on log notes when an agent switches address.
- Windows agent 1.0.16 and Linux agent 1.0.10.

## 1.31.0 - 2026-11-08

### Changed
- **Tell it's up by** now defaults to **Automatic**: a computer with an agent counts as up if it answers ping or its agent has reported in the last 10 minutes, so laptops reporting over the internet no longer show as down. Without an agent, it's checked by ping as before.
  - **Ping only** is still available, for the fastest down alerts on always-on servers.
  - **Agent only** is too.
  - Computers that are up only through their agent show **Up (agent)**.

## 1.30.0 - 2026-11-08

### Added
- **Tell it's up by: Its agent reporting in.** For computers that report over the internet and can't be pinged, such as laptops away from the office.
  - Up while reports arrive, amber when a report is late, down with a notification after `agent_stale_minutes`, and up again as soon as it reports.
  - The list shows when it last reported instead of a ping time.

## 1.29.0 - 2026-11-08

### Added
- **Windows installer (.msi)**: **Download installer (.msi)** on the Agents dialog's Windows card builds an MSI with the agent, the addresses and the enrolment key built in.
  - Double-click, accept the administrator prompt, done. It's listed in Installed apps as "Rollcall agent" and uninstalls from there.
  - Upgrades keep the computer's approval, failures roll back, and it supports `msiexec /i ... /qn`.
  - Built in the add-on with msitools, which the add-on image now includes. It isn't code-signed.

## 1.28.0 - 2026-11-08

### Added
- **Agent addresses are saved in the add-on** and sent to every agent with its next report. Change the inside or outside address under Agents and installed agents switch over without a new download. Each agent also keeps the address it was installed with as a last resort.
  - Needs Windows agent 1.0.15 or Linux agent 1.0.9; auto-update installs them.
  - Updates downloaded by agents also carry the saved addresses.

### Fixed
- Windows agent: the address that last worked wasn't read back on the next run, so agents always tried the inside address first. Laptops away from the office therefore waited on it every time.

## 1.27.0 - 2026-11-08

### Added
- **Inside and outside addresses for agents**: set an inside address and, optionally, an outside (internet) one under Agents. Downloads have both built in.
  - Agents try the addresses in order and remember which one worked, so laptops away from the office report through the outside address without waiting.
  - An address that can't be reached is skipped after 3 seconds.
  - The dialog warns if the outside address isn't HTTPS.
- Windows agent 1.0.14 and Linux agent 1.0.8. Agents updating themselves keep their list of addresses.

## 1.26.2 - 2026-11-08

### Changed
- List tabs now wrap onto extra lines, so every tab is visible without scrolling sideways. The selected tab is shown as a box.

## 1.26.1 - 2026-11-08

### Changed
- **Reset all uptime** now shows a random 4-digit number, different each time, which you type to confirm, instead of typing RESET. Anything else, or cancelling, resets nothing.

## 1.26.0 - 2026-11-08

### Changed
- **One Details button**: each device has a single **Details**, with tabs for whatever it has: the agent's tabs, **SNMP** and **Logs**. Before, a NAS had separate Details and Logs buttons.
- **Manage menu**: Add computer, Agents, Export / import and Reset all uptime are now in a **Manage** menu, instead of being separate buttons. Reset all uptime also asks you to type RESET. The menu shows a badge when agents are waiting for approval.
- **At a glance** can be sorted by status, name, uptime, latency, most recently changed or IP address. Your choice is remembered.
- New Rollcall logo at the top of the page and as the browser tab icon. The sidebar icon is now `mdi:list-status`, to match.

### Fixed
- **Needs attention** was empty for alerts on computers that were up but had a check in amber or red, such as a stopped service or a syslog error. It now includes the same computers the Overview lists as alerts, so clicking the **Need attention** tile shows them.

## 1.25.0 - 2026-11-08

### Added
- **Certificate expiry checks**: tick **Certificate expiry on HTTPS (443)**, or add `cert:PORT` or `cert:HOST:PORT`.
  - Any TLS port works, including self-signed and internal certificates. Mail ports (25, 587, 110, 143, 21) use STARTTLS, which covers Exchange SMTP.
  - Amber within `cert_warn_days` (30) of expiry, red with a notification within `cert_crit_days` (7) or once expired.
  - Each check shows the expiry date, days left, the certificate's name and its issuer.

## 1.24.2 - 2026-11-08

### Fixed
- Opening Rollcall briefly showed the list's empty column headings before switching to the Overview. It now starts on the Overview, with placeholder tiles until the data arrives.

## 1.24.1 - 2026-11-08

### Fixed
- A long name or hardware line (e.g. a laptop's full model and serial number) widened the list, pushing the buttons off-screen behind a sideways scroll bar at the bottom of the list. The name column now wraps onto more lines. On narrower screens the buttons wrap too, and the Since, Last check and Latency columns are hidden in turn so the list fits without scrolling sideways.

## 1.24.0 - 2026-11-07

### Added
- **Physical or virtual**: agents now report the manufacturer, model, serial number (e.g. a Dell service tag) and whether the machine is a VM (Hyper-V, VMware, KVM/QEMU/Proxmox, VirtualBox, Xen, cloud) or, on Linux, a container. Computers without an agent count as Hyper-V VMs when a Hyper-V host's VM list includes them.
  - The list shows the hardware under the name, e.g. "Hyper-V VM on HV01".
  - The new tab condition **Physical or virtual**, and the templates Physical machines, Virtual machines and Hyper-V VMs, split the list.
  - VMs get the virtual machine icon automatically.
- Windows agent 1.0.13, Linux agent 1.0.7. Agents set to update automatically pick these up at their next report.

## 1.23.0 - 2026-11-07

### Added
- **Other addresses**: a device can have extra addresses, such as a firewall's WAN and internal IPs. Each one is given a name, pinged while the main address answers, and optionally has ports checked on it. If one stops replying, the device goes degraded. Syslog from any of the addresses is matched to the device. The new checks `ping:HOST` and `tcp:HOST:PORT` also work as custom checks.

## 1.22.1 - 2026-11-07

### Fixed
- The add-on could stop with `RuntimeError: dictionary changed size during iteration`. Its once-a-minute republishing of sensors to Home Assistant broke if a computer was added or deleted while that was running. Loops over the computer list now work on a copy. The monitoring loop also logs any unexpected error and carries on, instead of stopping the add-on.

## 1.22.0 - 2026-11-07

### Added
- **Device icons**: every computer shows an icon in the list and on the Overview. It's picked automatically from its name, agent or checks, or you choose one of 23 device types under **Icon** in Edit (rack/storage/tower server, NAS, switch, router, firewall, access point, cameras, printer, UPS and more). **Upload image** adds your own (PNG, JPEG, WebP or SVG, up to 300 KB), such as a manufacturer's logo or a photo of the hardware. Uploads are included in exports.
- **Make and model** (optional), shown under the computer's name.

## 1.21.1 - 2026-11-07

### Added
- Syslog alerts on the Overview now have their own **Acknowledge** button.

### Fixed
- Syslog: **Acknowledge** in Logs was missing on busy devices. It only counted alerts among the newest 500 messages shown, so an alert followed by many ordinary messages left the check amber or red with no button. Alerts are now counted over the whole 24 hours.

## 1.21.0 - 2026-11-07

### Added
- **SNMP v3**: choose v2c or v3 for each SNMP device. v3 takes a user name plus authentication (MD5, SHA, SHA-224, SHA-256, SHA-384 or SHA-512) and privacy (none, DES, AES-128, AES-192 or AES-256). Requests are signed, replies are checked, and with privacy everything is encrypted. Wrong user names, passwords and protocols are reported in plain words. Passwords aren't shown on the dashboard, and leaving them blank when editing keeps the saved ones.
- The add-on image now includes `py3-cryptography`, which SNMP v3 encryption needs.

## 1.20.2 - 2026-11-07

### Fixed
- SNMP: **Up for** showed how long the device's SNMP service had been running, not the device itself. On Linux-based kit such as a TeraStation, that service restarts whenever the network link drops, for example when a switch reboots. Rollcall now reads the device's own uptime (HOST-RESOURCES-MIB `hrSystemUptime`) when the device provides it, which also stops false **Restarted** warnings. When a device only reports the SNMP service's uptime, Details says so.

## 1.20.1 - 2026-11-06

### Fixed
- SNMP: switches that can't answer large requests in time, such as some Netgear smart switches, lost their PoE information and took around 20 seconds to poll. Rollcall now asks for fewer rows at a time when a request goes unanswered, and remembers that for the device's next poll.
- SNMP Details now says when part of the information didn't arrive, instead of leaving it out silently, and shows how long each part took.

## 1.20.0 - 2026-11-06

### Added
- **Syslog**: the add-on now receives syslog on UDP port 514 (mapped under Configuration → Network). Tick **Syslog** on a device and point the device's syslog at Home Assistant. **Logs** shows its messages with search and a severity filter, kept for `history_days`.
  - Alerts follow the device's setting (critical, errors or warnings and worse, or only chosen words), plus **Always alert** and **Never alert** words. Critical messages and the chosen words go red and notify; the rest go amber.
  - Alerts clear after 24 hours or when you **Acknowledge** them.
  - Messages from devices that aren't set up are listed on the Overview, with a button to add the device.
  - Messages are limited to 100 a second per device.

## 1.19.3 - 2026-11-06

### Changed
- Buffalo TeraStation: an array that reports no space used (e.g. one presented as iSCSI, where the server manages the space) now says the space used isn't reported, instead of showing 0%.

## 1.19.2 - 2026-11-06

### Fixed
- Buffalo TeraStation: SMART showed as a number. It now shows as **OK** (1), and any other number shows as a warning with its code.
- Buffalo TeraStation: polls took around 20 seconds waiting for the NAS's system-information table. It's no longer read, because the model and firmware are already in the device description.

## 1.19.1 - 2026-11-06

### Fixed
- Buffalo TeraStation: a constant amber **NAS: no SNMP reply** even though disks and arrays were coming in. The NAS builds its error list and system information on request and can be slow to send them. They now get longer to answer, the system information is read every 6 hours instead of every check, and if they still don't arrive it's noted in Details rather than raised as an alert. Disk and RAID problems still alert as before.

## 1.19.0 - 2026-11-06

### Added
- **SNMP checks** for switches, NAS units and other network kit: tick **SNMP** when adding or editing a device and enter its community (SNMP v2c, read-only). **Details** shows:
  - every physical port, with its description, speed and errors. Tick **Alert** on the ones that should always be up (uplinks, servers, access points);
  - PoE power against the budget, plus PoE faults, overloads and short circuits, on switches that support the standard PoE MIB, such as the Netgear GS516TP;
  - for a Buffalo TeraStation, disk status, SMART health, RAID arrays and fullness, and the NAS's own errors. A degraded or removed disk goes red;
  - restarts, shown amber for an hour.

  The SNMP client is built in, with no extra dependencies.

### Fixed
- Details tables on phones are now shown as tables that scroll sideways, rather than one value per line.

## 1.18.0 - 2026-11-06

### Added
- Computers outside their monitoring schedule that are switched on now show a half-green, half-grey dot and **On · off schedule**, instead of the same grey as one that's off. They're still not alerted. This shows in the list and in the Overview's At a glance.

## 1.17.1 - 2026-11-06

### Fixed
- Windows agent 1.0.12: reading the Security log could take minutes on computers with a large Security log. The agent asked Windows for "these event IDs since the last run", and because the event log has no index, Windows read the whole log to answer, twice per run. The agent now reads each log (Security, System and Application) backwards from the newest record and stops at the last record it saw, in one pass, so a run only reads what's new. Event descriptions are now only fetched for the events shown, not every match.

## 1.17.0 - 2026-11-06

### Added
- **Pause a whole tab**: in any tab other than All and Overview, **Pause all N in this tab** pauses every computer it shows in one go, with the same time limit and automatic resume as pausing one, e.g. for a site's patch night. With a search typed, it pauses just the computers shown (this also works on All). **Resume N paused** resumes them all early.

## 1.16.0 - 2026-11-06

### Added
- **Overview**: Rollcall now opens on an Overview tab instead of the list. It shows:
  - tiles for computers, up, needing attention, down, paused or off, and agents reporting;
  - an **Alerts** list of everything that isn't green, worst and newest first;
  - an **At a glance** grid of every computer.

  Clicking an agent alert opens that server's Details on the right tab, for example a stopped service on Services, low disk space on Storage, or a failed backup on Backups. Ping and service-check alerts open the list filtered to that computer. Clicking a tile opens the matching list tab. The Overview tab's badge shows how many alerts there are.

### Fixed
- The Agents button showed a red "0" badge when no servers were waiting for approval.

## 1.15.1 - 2026-11-06

### Fixed
- Windows agent 1.0.11: Veeam Backup for Microsoft 365 jobs were missing from Backups most of the time on Windows PowerShell 5.1. They were shown for one report, then lost for the next 30 minutes while the agent reused its cached copy.
- Windows agent: a problem reading Microsoft 365 jobs (module not found, or `Get-VBOJob` failing) now shows as an agent error in Details instead of the jobs silently not appearing, and no longer affects Backup & Replication jobs. If the module isn't found by name, the agent also looks for it under `Program Files\Veeam`.

## 1.15.0 - 2026-11-06

### Added
- **Automatic agent updates** (Windows agent 1.0.10, Linux agent 1.0.6). Turn on **Update Windows/Linux agents automatically** under Agents, or use **Update** next to one server. At its next report an older agent downloads the add-on's copy, checks it is signed with its own token, is the version offered and newer, and parses, then replaces itself, keeping the old copy as `.old`. Off by default; agents never downgrade.

### Changed
- `-Install` / `--install` no longer replaces an installed agent with an older copy (e.g. a Group Policy startup script pointing at an old file on a share).

## 1.14.1 - 2026-11-06

### Changed
- Microsoft Defender's status moved from the Roles tab to the Security tab in Details, alongside Defender detections, failed logons and security events. The Defender check card on the Overview now jumps there.

## 1.14.0 - 2026-11-06

### Added
- **Veeam backups** (Windows agent 1.0.9). A **Backups** check and Details tab for Veeam Backup & Replication (every job's result from the Veeam Backup event log) and Veeam Backup for Microsoft 365 (job status from its PowerShell module, every 30 minutes). A failed job is red with one notification per failed run; warnings and retried failures are amber; a job that hasn't succeeded for well over its usual interval is amber with one "backup overdue" notification; a Microsoft 365 job past its scheduled run is amber. Jobs can be ignored individually.

### Fixed
- Windows agent: dates kept in its state file could be read back in the wrong format under PowerShell 7 (AMD RAID "since" times).

## 1.13.0 - 2026-11-05

### Added
- **"Whenever it's switched on"** monitoring mode, for computers that are usually off (cold storage, monthly backups). Off is normal: shown as **Off**, never alerted, and not counted against uptime. While it's on, it and its checks and agent are monitored as usual.
- **Never alert for this computer**: no notifications of any kind for it, while the dashboard, entities and events still show its real status. Marked 🔕 on the dashboard. Works with any schedule.

## 1.12.0 - 2026-11-05

### Added
- **Immich update alerts** (Linux agent 1.0.5). When a newer Immich release is out, the Immich check turns amber and you get one notification per release with a link to its release notes. The newest version comes from Immich's own version check (API key with `systemMetadata.read`), or from GitHub every 6 hours. Details shows "vX available" next to the running version; Ignore there stops flagging Immich updates (`update:immich`).

Update the Linux agent to get this: download it again from **Agents** and run `--install` again.

## 1.11.0 - 2026-11-04

### Added
- **Acknowledge** for the Events and Security checks' 24-hour amber. It turns them green without ignoring anything: acknowledged items stay listed (greyed), and anything new afterwards turns the check amber again. Available on the check's card in Details → Overview and at the top of the Events and Security tabs, with who acknowledged it and when, and Undo. Admins only.

## 1.10.3 - 2026-11-04

### Fixed
- On phones, scrolling past the end of a window (Details, Edit, Agents and the others) carried on scrolling the server list behind it. The page behind a window now stays still while it's open.

## 1.10.2 - 2026-11-04

### Fixed
- In server Details, scrolled content showed above the tab bar. The tabs now sit outside the scrolling area, under the server's name, and the Details window keeps one size so it doesn't jump when you switch tabs.

## 1.10.1 - 2026-11-04

### Changed
- **Server Details has tabs**: Overview (checks, system, roles), Storage (disks, storage health, hardware), Services (services, IIS, containers), Roles (AD, DHCP, Hyper-V, printers, RDS, Defender, Immich; "Apps" on Linux), Events ("Journal" on Linux), Security and Agent (ignored items, run timings, warnings). Tabs only appear when they have something in them, and show a badge for checks needing attention. The open tab is kept when you refresh.
- The check cards on the Overview are clickable: each opens its tab and scrolls to its section.
- The Hardware Log row in Details no longer looks like a fault, and RAID controllers are labelled as such.

## 1.10.0 - 2026-11-04

### Added
- **Dell PERC and server hardware via OpenManage** (Windows agent 1.0.8). Where OMSA's `omreport` is installed, the Storage check covers every PERC controller, virtual disk and physical disk (degraded or failed is red; rebuilding or predicted failure is amber), and a new **Hardware** check covers OMSA's chassis health: power supplies, fans, temperatures, voltages, memory, batteries and intrusion. Both show in Details.
- **AMD RAIDXpert2 arrays** (Windows agent 1.0.8), worked out from its "AMD RAID API" events in the System log: critical is red, rebuilding amber with progress, and recent disk drop-outs, timeouts and bad-sector remaps amber. The array state is kept between runs.

Update the Windows agent to get these.

## 1.9.3 - 2026-11-02

### Fixed
- An agent could attach to the wrong dashboard entry when the server also holds another monitored address, such as an Exchange DAG or failover-cluster IP on whichever node owns it: the agent's checks showed on the DAG entry and not on the server. Agents are now matched by name before IP (and, by IP, their primary address first). An agent already attached by IP to an entry that isn't its server moves to the entry with its name at the next start or report, and the leftover agent sensors on the other entry are removed.
- Log messages say "agent" rather than "Windows agent", since they cover Linux agents too.

## 1.9.2 - 2026-11-02

### Changed
- **Security rating 8 (second attempt).** Adds an AppArmor profile based on Home Assistant's example for add-ons that start with s6-overlay, so start-up is allowed this time. It keeps Rollcall within its container: no mounting, no tracing other processes, no extra capabilities beyond ordinary file ownership. If the add-on doesn't start after this update, install 1.9.1 again (it has no profile).

## 1.9.1 - 2026-11-02

### Fixed
- 1.9.0 wouldn't start: its new AppArmor profile blocked the container's start-up program (s6-overlay, `/run/s6/basedir/bin/init: Permission denied`). The profile is removed for now; the security rating is 7 instead of 8. Dropping the `NET_RAW` privilege (the other part of 1.9.0's change) stays.

## 1.9.0 - 2026-11-02

### Changed
- **Agents page** reorganised: the address agents report to, then side-by-side Windows and Linux sections with the same layout (requirements, download, install, options, update, remove, troubleshoot).
- **Security rating up from 6 to 8.** The add-on no longer asks for the `NET_RAW` privilege (ping uses unprivileged ICMP sockets) and now has its own AppArmor profile, which limits what it can run and where it can write.

### Added
- If a system doesn't allow unprivileged ping, Rollcall logs it, says so on the dashboard, and checks hosts over TCP instead (up if any common port, or one of the host's service-check ports, answers or refuses).

## 1.8.1 - 2026-11-02

### Fixed
- For a moment after the page loaded, view-only users could see and click admin buttons (Agents, Export / import, Add computer, Reset all uptime) until their permissions arrived. The page now starts view-only and only shows admin controls once the add-on confirms the user can make changes; if that check fails, it stays view-only. Any admin dialog that's open is closed if the user turns out to be view-only. The add-on already refused those actions for view-only users (HTTP 403), so no data or settings were exposed.

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
