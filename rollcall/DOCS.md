# Rollcall (Home Assistant add-on)

*Who's up, and how are they doing?* (Formerly **Ping Monitor**.)

Rollcall pings your computers and devices on a schedule and checks the services running on them. It can also:

- read switches, NAS units and UPSs over **SNMP**;
- collect their **syslog** messages;
- show what Home Assistant already knows about a device, through a **linked Home Assistant device**;
- look inside Windows and Linux servers with an **agent**: disks, services, containers, backups, logs, security and more.

Every computer gets one of these states:

| Status | Meaning |
|---|---|
| 🟢 Up | Answers, and all its checks pass |
| 🟡 Unresponsive | Missed one check |
| 🟠 Degraded | Answers, but a service, device or agent check has failed. You're notified |
| 🔴 Down | Missed two checks in a row. You're notified |
| 🔵 Paused | Maintenance mode: still checked, but no alerts |
| ⚪ Off / Off schedule | Outside its monitoring times, or a computer that's usually off |

You get a dashboard in the Home Assistant sidebar, a sensor for every computer and check, and phone notifications.

## Contents

1. [Quick start](#quick-start)
2. [Using the dashboard](#using-the-dashboard): Overview, tabs, Details, adding computers, discovering devices, icons
3. [Checks](#checks): how status works, presets, custom checks, certificates, SIP, other addresses, Home Assistant sensors
4. [Watching devices](#watching-devices): SNMP, syslog, linked Home Assistant devices
5. [Windows agent](#windows-agent)
6. [Linux agent](#linux-agent)
7. [Agent addresses and updates](#agent-addresses-and-updates)
8. [Alerts and quiet times](#alerts-and-quiet-times): notifications, acknowledging, pausing, schedules
9. [Administration](#administration): settings, who can change things, export and import, security
10. [Reference](#reference): every option, ports, sensors and events, files
11. [Troubleshooting](#troubleshooting)

---

## Quick start

1. In Home Assistant, go to **Settings → Add-ons → Add-on Store → ⋮ → Repositories**, add `https://github.com/shoey79/rollcall` and close.
2. Find **Rollcall** in the store, choose **Install** then **Start**, and turn on **Show in sidebar**.
3. Open **Rollcall** from the sidebar and choose **Manage → Add computer**. Give it a name and an IP address or hostname, tick any services to check, and save.
4. In the add-on's **Configuration** tab, add your phone under `notify_services` (e.g. `mobile_app_your_phone`) to get alerts.

**Updates** appear on the add-on's page in Home Assistant, or use **⋮ → Check for updates** in the store. Turn on **Auto update** to install them automatically.

**Moving from a local copy** (one installed by copying the folder into `/addons`): Home Assistant treats the store version as a separate add-on, so bring your data across with [Export and import](#export-and-import).

---

## Using the dashboard

### The Overview

![The Overview: totals, alerts and every computer at a glance](https://raw.githubusercontent.com/shoey79/rollcall/main/docs/images/dashboard.png)
*Screenshots in this guide show made-up computers.*

Rollcall opens on the **Overview**:

- **Tiles** show how many computers are up, need attention, are down or are paused, and whether the agents are reporting. Click one to open a list of just those computers, as a temporary tab with **×** to go back to All.
- **Alerts** lists everything that isn't green, worst and newest first. That includes computers not responding, failing checks, and agent problems such as stopped services, low disks, failed backups or security events. Click an alert to open the computer's Details on the right tab.
- **At a glance** shows every computer as a tile. Click one for its Details. The tiles can be sorted, and grouped with **group by**:
  - **Group** (the default): one section per group. A computer's group is the one typed in its Edit form, or else its icon's type (Computers and servers, Network, Lighting, Smart home, Heating and climate, Security and access, and so on). Your own groups come first.
  - **Your tabs**: one section per custom tab, in tab order, plus "Not in a tab". A computer in two tabs appears in both.
  - **Monitoring schedule**: one section per schedule, plus "Always monitored".
  - **Nothing**: all the tiles together.

  Each section shows how many are down, need attention, paused or up. Click its heading to collapse it. Your choices are remembered in this browser.
- **Syslog from unknown devices** appears when something sends syslog that isn't set up in Rollcall (see [Syslog](#syslog)).

### Tabs

Tabs split a long list. Each is a saved filter, so it updates by itself as computers are added or change. The number on a tab is how many computers it shows. The coloured badge is how many of those need attention (red if any are down).

- **Built in:** **All**, **Needs attention** (down, degraded or missed a check), and **Windows**, **Linux** and **No agent**, which appear once you have a mix.
- **Your own (admins):** choose **+ New tab**, name it and add conditions. It shows computers that match *all* or *any* of them, and lists what matches as you type. **Start from** offers ready-made starting points: name, IP range, Windows, Linux, domain controllers, web servers, low uptime, physical machines, virtual machines and Hyper-V VMs.

| Condition | Options | Example |
|---|---|---|
| Name | begins with, contains, ends with, is, is not, doesn't contain, matches pattern | begins with `SQL` · pattern `^RDS0[1-4]$` |
| Hostname or IP | same as Name | ends with `.example.local` |
| IP range | is in, is not in | `10.0.1.0/24`, `10.0.1.10-50`, `10.0.1.10-10.0.2.20`, `10.0.1.*` (separate several with commas) |
| Operating system | is, is not | Windows, Linux, No agent |
| Status | is, is not | Needs attention, Down, Degraded, Paused, Off schedule… |
| Server role (agent) | includes, doesn't include | `Domain controller`, `IIS`, `Immich` (comma-separated means any of them) |
| Service check | includes, doesn't include | `SQL`, `HTTPS`, `32400` |
| Physical or virtual | is | Physical, Virtual (any), Hyper-V VM, VMware VM, KVM / QEMU / Proxmox VM, Container, Not known |
| Signed-in user (agent) | includes, doesn't include | One or more user names, separated by commas, e.g. `jsmith`. Handy for finding which computer someone is on |
| Group | is, is not | One or more groups, separated by commas, e.g. `Lighting, Smart home`. Matches typed groups and the automatic ones from the icon |
| Uptime (24 h) | is below / above % | below `99` |

The ✎ on the open tab edits it, deletes it or moves it left or right. Tabs are shared: everyone who opens the panel sees the same ones. The tab bar wraps onto more lines rather than scrolling. The search box filters within the open tab.

**Pause all in this tab** pauses every computer in the tab at once, e.g. for a site's patch night. If something is typed in the search box, only the computers shown are paused. **Resume N paused** ends the pause early for all of them. See [Pausing](#pausing-for-reboots-maintenance-mode).

### Details

![Details of a Windows server with the agent: its checks and system information](https://raw.githubusercontent.com/shoey79/rollcall/main/docs/images/details.png)

**Details** on a row, or the computer's name, opens everything Rollcall knows about that computer, in tabs:

- **Overview** (computers without an agent). The whole device on one page:
  - tiles for status, 24-hour uptime with its history bar (each segment is a half hour on the clock, e.g. 16:00 – 16:30, and the last runs up to now; hover over one to see its times and how it went), and ping time;
  - device tiles: a UPS's power, battery, runtime and load; a NAS's disks and how full each array is; a switch's ports and PoE; readings from its logs; a linked Pi-hole's figures;
  - a **Needs attention** list of failing checks, SNMP problems, log alerts and readings over their limits. Click an item to jump to its detail;
  - every check with its uptime, the latest warnings and errors from its logs, and the device's model, serial, firmware and location.
- **Agent details** (computers with an agent): the agent's own tabs. See [Windows agent](#windows-agent).
- **SNMP**, **Logs** and **Home Assistant**, when those are set up for the computer.

Along the bottom are **Check now**, **Pause** / **Resume** and **Edit**. Edit opens on top of Details, and Details refreshes when you save or cancel. It closes if you delete the computer.

### Adding and editing computers

![Adding a computer: name, address and the services to check](https://raw.githubusercontent.com/shoey79/rollcall/main/docs/images/add.png)

- **Manage → Add computer** opens a form with the name, the IP address or hostname, a checkbox for each service preset (showing the ports it checks), custom checks, SNMP, syslog, a linked Home Assistant device, other addresses and the monitoring schedule.
- **Edit** on a row, or at the bottom of Details, opens the same form. **Delete** and **Reset uptime** for that computer are in the form too.
- Changes apply straight away, with no add-on restart.
- The list is saved in the add-on's data folder (`hosts.json`), which is included in Home Assistant backups.

**Hostnames** are resolved on every check, so the IP shown follows DNS changes. A name that can't be resolved counts as a failed ping. For `.local` names, see [Troubleshooting](#troubleshooting).

**Bulk import.** You can list computers under `hosts:` in the add-on's Configuration tab:

```yaml
hosts:
  - name: DC01
    host: 10.0.1.10
    checks: [dc]
  - name: SQL01
    host: 10.0.1.20
    checks: [sql]
  - name: Printer
    host: 10.0.1.90        # no checks = ping only
```

On the next start they're merged into the dashboard list. They're matched by name, so an existing computer is updated rather than duplicated. The add-on then clears the option, so the dashboard stays the one place to manage them. If Home Assistant doesn't let it clear the option, entries already imported are ignored on later starts. That way they can't overwrite your changes or bring back a computer you deleted.

### Discovering devices

![Discover devices: what a network scan found, with a guess at each device](https://raw.githubusercontent.com/shoey79/rollcall/main/docs/images/discovery.png)

**Manage → Discover devices** scans your network for devices that aren't in Rollcall yet (admins and editors only).

1. **Addresses to scan:** the networks to look at, e.g. `192.168.1.0/24`, `10.0.1.1-200` or single addresses, separated by commas. Rollcall suggests the network Home Assistant is on and the ones your computers are on. Only private addresses can be scanned, up to 1,024 per range (a /22) and 4,096 in all.
2. **SNMP community:** used to read switches, NAS boxes and UPS cards (`public` unless you've changed it).
3. **Scan.** A /24 usually takes under a minute. You can close the window and come back; the last scan is kept.

For each address, Rollcall:
- pings it and checks about 40 common ports (SSH, RDP, SMB, HTTP/HTTPS, LDAP, SQL, printing, and others). Addresses that don't answer ping get a quick port check too, since Windows often blocks ping.
- looks up the device's DNS name, its NetBIOS name, workgroup or domain and MAC address (Windows and Samba), its SNMP name and description, whether SIP answers (phones and ATAs), and its web page's title.

From that it guesses what the device is: domain controller, Exchange, SQL Server, Windows computer, Linux, NAS (Synology, QNAP, Buffalo, TrueNAS), printer, UPS, switch or router, VoIP phone or ATA, camera, Pi-hole, Proxmox, ESXi, server management card or UniFi. It also suggests the matching checks.

- **Add** opens the Add form with the name, address (the DNS name when there is one), make and model, and suggested checks filled in. Check it and save. For Windows and Linux servers, the [agent](#windows-agent) gives far more detail than port checks.
- **Hide** takes a device off the list (e.g. phones, TVs, guests). **Show hidden** brings them back.
- Devices already in Rollcall are left out unless you tick **Show devices already in Rollcall**; then they link to their Details.
- **Doesn't answer ping:** Rollcall checks by ping, so once added it would show as down. Allow ping (ICMP echo) in its firewall, or install the Windows agent, as a computer counts as up while its agent reports.

#### Networks Rollcall uses

If Home Assistant has more than one network interface (e.g. one for your smart-home devices and one for your servers), **Networks Rollcall uses** at the top of Discover devices lists each one with its subnet. Untick the ones Rollcall shouldn't use:
- Discovery only suggests and scans the networks that are ticked. A scan that includes an address on another network is refused.
- When you add or edit a device, the form says which interface it will be reached through, with a warning if that isn't one of Rollcall's networks.
- Each device's Details shows **Reached through**, e.g. `eth1 (10.0.1.0/24)`, or the default route for addresses on no directly attached subnet. It's marked ⚠ if that isn't one of Rollcall's networks.

Rollcall doesn't choose the interface itself: Home Assistant's host sends each check out of the interface on the device's subnet, or the one with the default route. So this setting keeps discovery inside the networks you pick and shows you where each check goes, rather than redirecting traffic. Home Assistant's own adapter choice under Settings → System → Network is for integrations' discovery (Zeroconf and similar) and doesn't affect Rollcall.

The add-on runs in Home Assistant's container network, so it can't read MAC addresses from the ARP table; the MAC shown comes from the NetBIOS reply. A scan sends a ping and a few connection attempts to every address, so intrusion detection on your network may notice it. Each scan is logged with who started it.

### Icons and make/model

Each computer has an icon, in the list and on the Overview. By default it's picked from the computer's name or make (e.g. "AP1", "NAS01", "SQL01", "NVR01", "Kitchen plug", "Tapo P110", "Landing light", "Tapo L530", "Hall thermostat", "Back door sensor", "Zappi", "Solis inverter"), its agent (Windows Server or desktop, Linux) or its checks (printer, RTSP camera, SNMP, SIP, Home Assistant, Pi-hole). In the form, *Automatic* shows which icon that gives, and follows the checks as you tick them.

To choose one yourself, choose **Icon** in Edit. The picker has about 75 icons in groups, with a search box (try "light" or "sensor"):

| Group | Icons |
|---|---|
| Computers and servers | Rack, storage and tower servers, NAS, server rack, desktop, laptop, VM, database, single-board computer, web service, cloud |
| Network | Switch, router, firewall, access point, mesh Wi-Fi, modem/ONT, DNS/ad blocker |
| Lighting | Light bulb, ceiling light, spotlight/downlight, lamp, wall/porch light, floodlight, garden/path light, LED strip, light switch/dimmer, remote/button |
| Smart home | Smart home hub, home automation, smart plug, temperature, water leak, motion and door/window sensors, blinds, robot vacuum, sprinkler, weather station |
| Heating and climate | Thermostat, radiator valve (TRV), radiator/heater, underfloor heating, boiler, fan, air conditioning/heat pump, air purifier |
| Security and access | CCTV and dome cameras, video doorbell, smart lock, alarm panel, siren, smoke/CO alarm, garage door |
| Phones and entertainment | VoIP phone/ATA, mobile phone, tablet, TV, smart speaker, smart display, projector, games console |
| Appliances | Washing machine, fridge/freezer, kitchen appliance, printer, 3D printer, car |
| Power and energy | UPS, battery storage, inverter, solar panels, EV charger, energy meter |

They're generic and drawn for Rollcall, with no company logos.

For a manufacturer's logo or a photo of the hardware, choose **Upload image** in the icon picker:

- PNG, JPEG, WebP or SVG, up to 300 KB each and 200 images in total.
- Uploaded images can be used for any computer and are included in exports.
- Deleting an image from the picker returns computers that used it to an automatic icon.
- Only use images you have the right to use.

**Make and model** (optional) is shown under the name, e.g. "Dell PowerEdge R720xd", and helps choose the automatic icon.

**Group** (optional) puts the computer in a section of the Overview, e.g. *Servers* or *Home automation*. Leave it blank to group it by its icon's type; the field shows which group that is.

**Line under the name** chooses what the list shows under the computer's name:

| Choice | Shows |
|---|---|
| Add-on default | Whatever the `name_line` option says (Automatic unless you change it) |
| Automatic | The make and model you typed, or what the agent reports. With neither, the operating system |
| Make and model | Only the make and model |
| Operating system | The operating system from the agent, e.g. *Windows 11 Pro*. Devices without an agent show their make and model |
| Signed-in user | Who is signed in, from the agent, e.g. *CONTOSO\\jsmith*, *jsmith + 2 others* or *Nobody signed in* (hover for the full list). Shown to Home Assistant admins only |
| Address | The address, plus the IP when the address is a name |
| Nothing | A blank line |

### Physical or virtual

Agents (Windows 1.0.13 and Linux 1.0.7 or later) report the machine's manufacturer, model and serial number (a Dell service tag, for instance), and whether it's a virtual machine: Hyper-V, VMware, KVM/QEMU (including Proxmox), VirtualBox, Xen or a cloud VM, or a container (LXC, Docker) on Linux.

- A computer without an agent counts as a Hyper-V VM when a Hyper-V host's agent lists a VM with the same name.
- You can also type "VM" or "Hyper-V" in **Make and model**.
- The list shows this under the name (e.g. *Hyper-V VM on HV01*, or *Dell Inc. PowerEdge R720xd · ABC1234*), unless you've typed a make and model.
- **Custom-built PCs** often leave placeholders such as "System manufacturer", "System Product Name" or "To Be Filled By O.E.M." in the BIOS. These are ignored, along with dummy serial numbers. From Windows agent 1.0.30, the agent then reports the motherboard instead (e.g. *ASUSTeK COMPUTER INC. PRIME B660M-A*), and hovering over it says so.
- To split the list, make a tab with the **Physical or virtual** condition.

---

## Checks

### How status works

- **Ping** decides whether a computer is up. One miss turns it amber; a second miss in a row turns it red and notifies. The re-check after a miss comes `retry_interval` seconds later.
- **Every other check** runs only while the computer answers. Each has its own count: one failure turns its chip amber, two in a row turn it red.
- **A red check** makes the computer **Degraded** and sends an alert naming it, e.g. "🟠 SQL01: SQL is down". Recovery sends "🟢 SQL01: SQL is back up" if `notify_recovery` is on.
- **When the whole computer stops answering**, you get one "down" alert, not one per check. Its checks start counting again once it's back, which gives services time to start after a reboot.
- **Pausing** a computer pauses its checks too.
- **Uptime %** is time-weighted over the last 24 hours. Amber time counts as down. Gaps when the add-on wasn't running are left out rather than guessed. The row shows ping uptime; each check's own uptime shows when you hover over its chip, and in its sensor.

For computers that can't be pinged, such as laptops reporting over the internet, see [Computers that report over the internet](#computers-that-report-over-the-internet).

### Presets

Tick presets in the Add/Edit form. They're grouped as below, with a search box. In the Configuration tab, use the preset's name in a `checks:` list, e.g. `[dc, fileserver, tcp:5985]`. Ports are each product's defaults; if yours differs, use a [custom check](#custom-checks). A target listed twice is only checked once.

| Preset | Name | Checks |
|---|---|---|
| **Windows & Microsoft** | | |
| `dc` (or `domain`) | Domain controller | DNS 53 · Kerberos 88 · LDAP 389 · SMB 445 · GC 3268 |
| `dns` | DNS server | TCP 53 |
| `ldap` | LDAP | TCP 389 |
| `ldaps` | LDAPS (secure LDAP) | TCP 636 |
| `fileserver` (or `smb`, `file`) | File server (SMB) | TCP 445 |
| `rds` (or `rdp`, `terminal`) | Remote Desktop / Terminal Server | TCP 3389 |
| `sql` (or `mssql`) | SQL Server | TCP 1433 |
| `iis` | IIS (HTTP) | http:80/ |
| `iis-https` | IIS (HTTPS) | https:443/ |
| `sharepoint` | SharePoint | https:443/ |
| `exchange` (or `owa`) | Exchange | OWA https:443/owa · SMTP 25 |
| `wsus` | WSUS | TCP 8530 |
| `adfs` | AD FS | https:443/FederationMetadata/2007-06/FederationMetadata.xml |
| `adcs` (or `certsrv`) | Certificate Services (web enrolment) | http:80/certsrv/ |
| `configmgr` (or `sccm`, `mecm`) | ConfigMgr / SCCM management point | http:80/sms_mp/.sms_aut?mplist |
| `kms` | KMS activation | TCP 1688 |
| `winrm` | WinRM / PowerShell remoting | TCP 5985 |
| `veeam` | Veeam Backup & Replication | TCP 9392 |
| **Databases** | | |
| `mysql` (or `mariadb`) | MySQL / MariaDB | TCP 3306 |
| `postgres` (or `postgresql`, `pgsql`) | PostgreSQL | TCP 5432 |
| `mongodb` (or `mongo`) | MongoDB | TCP 27017 |
| `redis` | Redis | TCP 6379 |
| `oracle` | Oracle | TCP 1521 |
| `elasticsearch` (or `elastic`) | Elasticsearch | http:9200/ |
| `influxdb` (or `influx`) | InfluxDB | http:8086/ping |
| **Mail & files** | | |
| `smtp` | SMTP relay / mail server | TCP 25 |
| `imap` | IMAP (secure) | TCP 993 |
| `pop3` | POP3 (secure) | TCP 995 |
| `ftp` | FTP | TCP 21 |
| `nextcloud` | Nextcloud | https:443/status.php |
| **Remote access** | | |
| `ssh` (or `sftp`) | SSH / SFTP | TCP 22 |
| `vnc` | VNC | TCP 5900 |
| `telnet` | Telnet (switches, old kit) | TCP 23 |
| **Virtualisation & storage** | | |
| `proxmox` (or `pve`) | Proxmox VE | https:8006/ |
| `pbs` | Proxmox Backup Server | https:8007/ |
| `esxi` (or `vmware`) | VMware ESXi | https:443/ |
| `vcenter` | VMware vCenter | https:443/ui/ |
| `synology` (or `dsm`) | Synology DSM | https:5001/ |
| `qnap` | QNAP QTS | http:8080/ |
| `truenas` | TrueNAS | https:443/ |
| `unraid` | Unraid | http:80/ |
| `portainer` | Portainer | https:9443/ |
| **Network & infrastructure** | | |
| `unifi` | UniFi Network, old controller (8443) | UniFi https:8443/ · Inform 8080 |
| `unifi-os` | UniFi OS console, e.g. Cloud Key or UDM (443) | https:443/ |
| `unifi-os-server` | UniFi OS Server, self-hosted (11443) | UniFi https:11443/ · Inform 8080 |
| `idrac` (or `ilo`, `bmc`, `ipmi`) | Dell iDRAC / server BMC | https:443/ |
| `pihole` (or `pi-hole`) | Pi-hole | DNS 53 · Pi-hole http:80/admin/ |
| `adguard` | AdGuard Home | DNS 53 · AdGuard http:80/ |
| `npm` | Nginx Proxy Manager | http:81/ |
| `squid` | Squid / web proxy | TCP 3128 |
| `printer` | Network printer | TCP 9100 |
| `camera` (or `nvr`, `rtsp`) | IP camera / NVR (RTSP) | TCP 554 |
| `voip` (or `sip`, `ata`, `pbx`) | VoIP phone, ATA or PBX | SIP UDP 5060 |
| `ata2` (or `spa112`, `spa122`) | Two-line ATA, e.g. Cisco SPA112/122 | Line 1 SIP 5060 · Line 2 SIP 5061 |
| **Home & automation** | | |
| `homeassistant` (or `ha`) | Home Assistant | http:8123/ |
| `nodered` (or `node-red`) | Node-RED | http:1880/ |
| `mqtt` (or `mosquitto`) | MQTT broker (Mosquitto) | TCP 1883 |
| `frigate` | Frigate NVR | http:5000/api/version |
| `vaultwarden` (or `bitwarden`) | Vaultwarden | http:80/alive |
| `paperless` | Paperless-ngx | http:8000/ |
| `uptimekuma` (or `kuma`) | Uptime Kuma | http:3001/ |
| **Media** | | |
| `plex` | Plex | http:32400/identity |
| `jellyfin` | Jellyfin | http:8096/health |
| `emby` | Emby | http:8096/emby/System/Info/Public |
| `immich` | Immich | http:2283/api/server/ping |
| `audiobookshelf` | Audiobookshelf | http:13378/ |
| `navidrome` | Navidrome | http:4533/ |
| `tautulli` | Tautulli | http:8181/ |
| `overseerr` (or `jellyseerr`) | Overseerr / Jellyseerr | http:5055/api/v1/status |
| **Downloads** | | |
| `sonarr` | Sonarr | http:8989/ping |
| `radarr` | Radarr | http:7878/ping |
| `lidarr` | Lidarr | http:8686/ping |
| `prowlarr` | Prowlarr | http:9696/ping |
| `sabnzbd` | SABnzbd | http:8080/ |
| `qbittorrent` | qBittorrent | http:8080/ |
| `transmission` | Transmission | http:9091/transmission/web/ |
| **Monitoring & development** | | |
| `grafana` | Grafana | http:3000/api/health |
| `prometheus` | Prometheus | http:9090/-/healthy |
| `gitea` (or `forgejo`) | Gitea / Forgejo | http:3000/api/healthz |
| `jenkins` | Jenkins | http:8080/login |
| **Other** | | |
| `http` | Web server (HTTP) | http:80/ |
| `https` | Web server (HTTPS) | https:443/ |

**SNMP**, **Syslog** and **Certificate expiry on HTTPS (443)** are also under Network in the form; see [Watching devices](#watching-devices) and [Certificate expiry](#certificate-expiry).

### Custom checks

| Form | Example | Checks |
|---|---|---|
| `tcp:PORT` | `tcp:5985` | The port accepts a connection |
| `http:PORT/path` | `http:8080/status` | A web request to this computer |
| `https:PORT/path` | `https:443/owa` | The same over HTTPS |
| Full URL | `https://mail.example.local/owa` | A specific URL, e.g. a virtual host or load-balanced name |
| `cert:…` | `cert:8443` | A certificate's expiry; see [Certificate expiry](#certificate-expiry) |
| `sip`, `sip:PORT` | `sip:5062` | A SIP service; see [VoIP](#voip-phones-atas-and-pbxs-sip) |
| `ping:HOST`, `tcp:HOST:PORT` | `ping:203.0.113.5` | Another address of this device; see [Other addresses](#other-addresses) |
| `ha:ENTITY` | `ha:sensor.ap_cpu>90` | A Home Assistant sensor; see [Home Assistant sensors](#home-assistant-sensors) |
| `Label=` prefix | `SQL Reporting=tcp:50123` | Any of the above with your own label |

**Web checks** pass on any response below 500:

- A 401 from Windows authentication, or a 302 redirect to a login page, still means the app is answering.
- A 5xx (such as the 503 from a stopped IIS app pool), a timeout or a refused connection fails.
- Redirects aren't followed. Only the status line is read, so devices that send untidy headers are fine.
- HTTPS checks only test whether the service answers, so they accept self-signed or expired certificates, 1024-bit keys, TLS 1.0 and old ciphers. That covers older kit such as Dell iDRAC 6.
- For `http:PORT/…` and `https:PORT/…` checks (including presets), if the port answers but not with that protocol, the other one is tried and used from then on. The chip then shows "via https". For example, Plex set to "Secure connections: Required" only answers HTTPS on 32400. Full-URL checks always use exactly the scheme you gave.

**SQL named instances** usually listen on a dynamic port. Use `tcp:<port>` with the instance's actual port instead of the `sql` preset.

### Certificate expiry

Tick **Certificate expiry on HTTPS (443)** under Network, or add custom checks:

- `cert:8443`: the certificate on another port of this computer.
- `SMTP=cert:25`: mail ports use STARTTLS (25 and 587 SMTP, 110 POP3, 143 IMAP, 21 FTP), so mail servers' SMTP certificates can be checked.
- `cert:mail.example.com:443`: a certificate on another name or address. The name is also sent as SNI, so the right certificate is picked on a server that has several.

The check reads whatever certificate the service presents; internal and self-signed ones count. It's green while more than `cert_warn_days` (30) are left, amber within that, and red within `cert_crit_days` (7) or once expired. Red notifies, and so does renewal if `notify_recovery` is on. The chip shows the expiry date, days left, the name on the certificate and who issued it. If the certificate can't be read (port closed, not TLS), the check goes amber and says why.

### VoIP phones, ATAs and PBXs (SIP)

Tick **VoIP phone, ATA or PBX** to check a device's SIP service on UDP 5060. For two-line adapters such as the Cisco SPA112/122, tick **Two-line ATA**: Line 1 is UDP 5060 and Line 2 is UDP 5061. For another port, use `sip:PORT`, e.g. `Line 3=sip:5062`, or `sip:HOST:PORT` for another address.

![A two-line ATA with both SIP lines answering](https://raw.githubusercontent.com/shoey79/rollcall/main/docs/images/sip.png)

Each check sends a SIP OPTIONS request, the standard "are you there?" message, and any SIP reply counts as up:

- Replies such as 404 Not Found or 401 Unauthorized are normal, because the request isn't addressed to a real number. The chip says e.g. `SIP answering (404 Not Found, normal for this probe) · Cisco/SPA122-1.4.1(SR5)`.
- No reply goes red (after two checks, like other checks). A 5xx error from the device is amber.
- **"Nothing listening on UDP 5060 (refused)"** means the device answered, but SIP isn't on that port. Rollcall then tries the common SIP ports (5061–5065, 5070, 5080, 5160, 5161) and says where SIP answers, e.g. "change this check to sip:5062". Providers that use high, non-standard ports need the port setting by hand. On Cisco ATAs it's under **Voice → Line 1 → SIP Port**.
- **"No SIP reply"**: the device may only accept SIP from its provider ("Restrict Source IPs" on Cisco ATAs), or use TCP/TLS. Turn the restriction off, or rely on ping and syslog.
- A line with no account set up may not listen at all, so only tick the lines you use.

This shows the SIP service is running, not that the line is registered with your provider. For registration alerts, send the device's syslog to Rollcall; see [SIP line registration](#sip-line-registration-cisco-spa-atas). SNMP on SPA112/122 adapters gives only uptime, restarts and the network port.

### Other addresses

A firewall, router or multi-homed server can have more than one address worth watching, e.g. a WAN IP and an internal IP. Under **Other addresses** in Edit, add each one with a name (e.g. *WAN*), the IP address or hostname, and optionally ports to check there (e.g. `443, 4444`).

- The main address still decides whether the device is up or down. The other addresses are checked while it answers, each with its own chip. One that stops replying turns the device **Degraded** (amber at the first miss, red if it's still missing at the next check).
- Syslog from any of the device's addresses is matched to it.
- They're stored as checks, so you can also type them as custom checks: `WAN=ping:203.0.113.5` and `WAN 443=tcp:203.0.113.5:443`. IPv6 addresses go in brackets: `ping:[2001:db8::1]`.

### Home Assistant sensors

Any Home Assistant sensor can be a check on a computer. For example, the UniFi Network integration's CPU and memory sensors for an access point can sit alongside its ping. The chip shows the current value, e.g. **CPU 12%**.

In **Edit**, search under **Home Assistant sensors** (the search starts with the computer's name) and choose **Add**. CPU and memory are added as "problem above 90%", temperatures above 80; anything else just needs to be available. Edit the line under **Custom checks** to change it:

| Check | Meaning |
|---|---|
| `CPU=ha:sensor.office_ap_cpu_utilization>90` | Amber, then red (two checks in a row) while CPU is over 90 |
| `Memory=ha:sensor.office_ap_memory_utilization>=85` | The same for memory at 85% or more |
| `ha:sensor.office_ap_state!=Connected` | Red when the state is anything but Connected |
| `ha:binary_sensor.nas_status` | Only needs to exist and not be unavailable |

The condition describes the problem. Operators are `>` `>=` `<` `<=` `=` `!=`. A sensor that's `unavailable` or missing also counts as failing. Sensor checks run with the ping, and pause while the computer is down or paused. Some UniFi sensors are disabled by default in Home Assistant; enable them on the device's page first.

To bring in *all* of a device's entities at once, link its Home Assistant device instead; see [Linked Home Assistant devices](#linked-home-assistant-devices).

---

## Watching devices

### SNMP

![A UPS read over SNMP: battery, runtime, load and its network port](https://raw.githubusercontent.com/shoey79/rollcall/main/docs/images/snmp.png)

For network kit you can't install an agent on, tick **SNMP** (under Network) when adding or editing the device, and choose the version:

- **v3** (recommended where supported): create a read-only SNMP v3 user on the device and enter its user name, authentication protocol and password, and privacy (encryption) protocol and password.
  - Authentication: MD5, SHA, SHA-224, SHA-256, SHA-384 or SHA-512. Privacy: DES, AES-128, AES-192 or AES-256. SHA with AES-128 is the most widely supported pair.
  - AES-192 and AES-256 use the same key extension as Net-SNMP (Blumenthal). Devices using Cisco's variant aren't supported.
  - Passwords are 8 characters or more. Requests are signed, replies are checked, and with privacy everything is encrypted.
- **v2c**: turn on SNMP v2c on the device with a read-only community and enter the same name here. It's case-sensitive; a TeraStation's default is `TeraStation`. The community travels unencrypted.
- **v1**: for older kit that ignores v2c requests, such as first-generation APC Network Management Cards (AP9606, AP9617, AP9618, AP9619). It's set up like v2c. If a device answers `snmpwalk -v1` but not `-v2c`, choose this.

Whichever version you use, the device must allow Home Assistant's IP address. APC cards call this the *NMS IP*: use Home Assistant's address, or `0.0.0.0` for any.

Rollcall reads the device at every check while it answers ping. The **SNMP** tab in Details shows what it found:

- **Ports** (any switch): every physical port, with its description, speed and error counts. Tick **Alert** for ports that should always be up (uplinks, servers, access points): they go red if they drop, and amber if someone disables them. Other ports are just shown, so desktops going off at night don't alert.
- **PoE** (switches with the standard PoE MIB, e.g. Netgear GS516TP): power used against the budget, amber at the switch's own alert threshold. A port in a PoE fault is red. A port's overload, short-circuit or power-denied count going up is amber. A PoE supply that's off or faulty is red.
- **Buffalo TeraStation** (detected automatically): each disk's status and SMART health, RAID arrays and how full they are (amber at 90%, red at 97%), and the errors the NAS reports itself. A degraded or removed disk is red; a removed hot spare or a SMART warning is amber.
- **UPS**: APC Network Management Cards are detected automatically. Other makes' network cards (Eaton, CyberPower, Riello, Socomec, Vertiv, Tripp Lite…) are read through the standard UPS-MIB. It shows output status, battery charge, runtime left, load, input and output voltage, battery temperature, when the battery was last replaced, the last self-test and runtime calibration, model, serial and firmware.
  - **Red:** on battery (with how long and the runtime left), output off, battery low or faulty, battery needs replacing, a failed self-test, under `ups_runtime_crit_minutes` (5) of runtime, or load at 95% or more.
  - **Amber:** under `ups_runtime_warn_minutes` (15) of runtime, load at or over `ups_load_warn` (80%), on bypass (the load isn't protected), or a battery over 40 °C.
  - Other makes' alarms (fan or fuse failure, charger failed, overload…) are shown, and the serious ones go red.
  - **Limits for one UPS:** under the UPS section in its SNMP details, **Change** sets that UPS's own runtime and load limits, e.g. a longer runtime warning for a large battery bank. Blank goes back to the add-on's setting, and 0 minutes turns a level off. It applies straight away, without restarting the add-on. Only Home Assistant admins can change it.
- **Printers** (most network printers, through the standard Printer MIB; detected from the maker or description, e.g. HP, Brother, Canon, Epson, Kyocera, Lexmark, Ricoh, Xerox, Konica Minolta). It shows each toner or ink cartridge with its colour and level, plus drums, fusers and waste toner boxes. It also shows the paper trays, the page count, the printer's status and error flags, what its front-panel display says, and its own alerts.
  - **Amber:** a supply at `printer_supply_warn` (10%) or less, a waste toner box nearly full, or the printer reporting no paper, door open, offline, service requested, a missing supply, or an output tray full.
  - **Red:** a paper jam.
  - Some printers report only "some left" for third-party cartridges, so those can't alert on level.

  ![A colour laser printer read over SNMP: toner levels, drum, waste box, trays and its display](https://raw.githubusercontent.com/shoey79/rollcall/main/docs/images/printer.png)
  - A power cut goes red at the check after it's seen. If you need to know about power cuts quickly, shorten `interval`.
- **Restarts**: amber for an hour after the device restarts. If it was planned or expected, choose **Acknowledge** next to it (SNMP tab or Overview, admins and editors). That clears the warning for that restart only; a later restart still shows. Devices that don't report their own uptime (many switches, APC cards) count a restart of their SNMP service or management card too.

Problems go red, and notify, only if they're still there at the next check, so a port bouncing once doesn't alert. Warnings stay amber and don't notify. If the device stops answering SNMP (wrong community, SNMP turned off), the SNMP check goes red but the device stays up while it answers ping.

Communities and v3 passwords aren't shown on the dashboard; leaving them blank when editing keeps the saved ones. They are included in exports, so keep export files safe.

### Syslog

Rollcall receives syslog on **UDP port 514** of the Home Assistant machine. You can change or turn off the port under the add-on's **Configuration → Network**.

1. Tick **Syslog** (under Network) on the device in Rollcall.
2. Set the device to send its logs to Home Assistant's IP address on that port.

Messages are matched to the device by the address they come from, including its [other addresses](#other-addresses).

- **Logs** in Details shows its messages, newest first, with search and a severity filter. They're kept for `history_days`, up to 20,000 per device.
- **Alert on** (in Edit) sets which messages alert: critical and worse, errors and worse (the default), warnings and worse, or only your words.
  - Critical, alert and emergency messages, and any message containing one of your **Always alert on these words**, go red and notify. Others you alert on go amber.
  - Messages containing one of the **Never alert on these words** are kept but never alert. Use this for harmless noise a device logs at error level.
- **Alerts last 24 hours.** **Acknowledge**, in Logs or on the Overview, clears them now; a new message that alerts sets it off again.
- **Unknown devices.** Messages from devices that aren't in Rollcall, or don't have Syslog ticked, are listed on the Overview under **Syslog from unknown devices**, with a button to add the device or tick Syslog for it. Once you do, the entry goes and its recent messages (up to 200 from the last hour) are filed in the device's log. Older ones aren't kept.
- **Rate limit.** Each device can send up to 100 messages a second, with bursts up to 200. Anything above that is dropped, so a chatty device can't fill the database.
- **Trust.** Syslog over UDP isn't authenticated, so anything on your network can send messages that appear to come from a device. Treat syslog alerts as a prompt to look, not as proof.

#### Readings from its logs

Some devices report readings in their routine log messages. Rollcall picks these out and shows them at the top of the **Logs** tab, and as tiles on the Overview: the latest value, the range and a small graph over 24 hours, and when it was last reported.

![A NAS's Logs tab: temperatures, fan, time sync and firmware picked out of its syslog](https://raw.githubusercontent.com/shoey79/rollcall/main/docs/images/syslog.png)

| Device | Readings |
|---|---|
| Buffalo TeraStation and LinkStation | Temperatures (`temp0`, `temp1`…, as the NAS names them) and fan speed and mode, from `fanctld.sh`; whether the last time sync (NTP) worked; the last firmware check that found it up to date |
| Small Linux devices logging `MemFree:` / `MemTotal:` (e.g. Cisco SPA ATAs) | Memory free, against the total |
| Anything logging a kernel boot banner (`Linux version …`, or `System started:` on Cisco SPA ATAs) | When it last started |
| Cisco SPA ATAs with voice debug on | Each line's SIP registration (see below) |

The readings are worked out from the stored messages, so nothing extra is kept. They only show while the device keeps sending them.

**Name / alert** (admins and editors) gives a reading a name and alert limits. For example, call `temp0` "CPU" and make it amber over 85 and red over 95.

- Temperatures alert above their limits; fan speed and free memory alert below theirs.
- A reading over its limit shows on the device's **Syslog** check, its tile and **Needs attention**. Red notifies.
- It clears by itself once the reading is back within the limit, so it doesn't need acknowledging.
- A reading that hasn't been reported for an hour isn't judged. Without limits, readings don't alert.

#### SIP line registration (Cisco SPA ATAs)

To track whether each phone line is registered with your provider:

1. On the adapter, set **Voice → System → Debug Server** to Home Assistant's IP (port 514), and **Debug Level** to 3.
2. Set **Voice → Line N → SIP Debug Option** to `1-line` for each line in use.
3. Tick **Syslog** for the device in Rollcall.

The adapter then logs each registration (`[0]RegOK. NextReg in 594`) and each failure (`RegFail`). Each line shows in the Logs tab and Overview, e.g. "Line 1 registration (sip.provider.example): registered".

The **Syslog** check goes red, and notifies, when:

- a registration fails and the adapter hasn't recovered within a minute; or
- a line hasn't registered again well after it was due, while the adapter is still logging. If the adapter goes silent altogether, ping and the SIP check catch that instead.

It turns green again when the line registers. Tip: add `getOptRdata` to the adapter's **Never alert on these words**, because its mDNS service logs that harmless error constantly.

### Linked Home Assistant devices

If Home Assistant already has an integration for a device, link its Home Assistant device and Rollcall reads all of the integration's entities, with no extra passwords. In **Edit → Home Assistant device**, search (e.g. `pi-hole`) and choose **Link**. To remove it, choose **Unlink**.

![A Pi-hole linked to its Home Assistant device, with its readings and controls](https://raw.githubusercontent.com/shoey79/rollcall/main/docs/images/ha.png)

This adds a **Home Assistant** check and a **Home Assistant** tab in Details, including for computers with an agent. On computers without an agent, the Overview shows it too:

- **Readings:** every entity and its state. Diagnostic and configuration entities are folded away.
- **Controls:** the device's buttons and switches, in their own list. Admins and editors can **Press**, **Turn on** or **Turn off**. Each one asks you to confirm first and is logged with who did it. Only that device's own controls can be used. A button shows when it was last pressed; until then Home Assistant reports its state as "unknown".
- **Any device:** goes red if every entity is unavailable (Home Assistant has lost touch with it), and amber for a "problem" binary sensor that's on. Updates available are noted.
- **Pi-hole** (the built-in Pi-hole integration, or **Pi-hole V6** from HACS):
  - tiles for ad blocking on or off, DNS queries today, blocked today and the percentage blocked, clients, domains on blocklists, and (V6) CPU and memory;
  - ad blocking turned off is amber;
  - Pi-hole's own diagnostic messages and updates are noted;
  - the chip reads e.g. "Pi-hole: blocking on, 85,710 queries today, 21.4% blocked".

Keep the **Pi-hole** preset ticked as well. It checks DNS and the admin page directly, so you still hear about a dead Pi-hole even if Home Assistant is down.

---

## Windows agent

One PowerShell script, the same on every server. Every 5 minutes it works out what the server does and reports what matters for it. Servers appear on the dashboard by themselves once you approve them.

**Requirements:** Windows Server 2012 R2 or later (Windows PowerShell 4.0+), and port 8100 open from the servers to Home Assistant. Workstations work too; they just have no server roles.

### Setting it up

![Manage → Agents: where agents report to, and the downloads](https://raw.githubusercontent.com/shoey79/rollcall/main/docs/images/agents.png)

1. In the dashboard, open **Manage → Agents** and download **PingMonitorAgent.ps1**. Check the address first: it's what your servers use to reach Home Assistant on port 8100 (use the IP if they can't resolve the name). The script has the address and the enrolment key built in.
2. Copy it to `\\your-domain\NETLOGON`, or any share the servers can read.
3. Run it on the servers, by one of these:
   - **Group Policy** for the servers' OU: *Computer Configuration → Policies → Windows Settings → Scripts → Startup*, script `powershell.exe`, parameters `-NoProfile -ExecutionPolicy Bypass -File \\your-domain\NETLOGON\PingMonitorAgent.ps1 -Install`.
   - **By hand:** run that command once as an administrator on a server to start straight away.
   - **MECM (Run Scripts):** *Software Library → Scripts → Create Script*, import the script and have it approved (by default an author can't approve their own). Right-click a device collection → **Run Script**, choose it, set **Action** to `Install` and leave the rest at their defaults. It runs as SYSTEM straight away. MECM warns about the switch parameters; that's expected, and it's why `Action` exists. If it fails with a signing error, your client settings' PowerShell execution policy is *All Signed*: sign the script, or use *Bypass* for that collection.
   - **The installer**, for computers looked after by people outside IT; see below.
4. Within 5 minutes each server shows under **Waiting for approval**. Check the name and address, then **Approve** (or **Approve all**).
5. Approved servers that aren't on the dashboard yet are added automatically, by IP, unless `agent_auto_add` is off. Existing entries are matched by name or IP.

**What `-Install` does:** copies the script to `C:\ProgramData\PingMonitor` and creates a scheduled task, **Ping Monitor Agent**, that runs every 5 minutes as SYSTEM. Running it again is safe, and is one way to update. The task keeps its old name so existing installs update in place.

| Switch | Does |
|---|---|
| `-Install` (`-Action Install`) | Installs or updates the agent |
| `-Uninstall` (`-Action Uninstall`) | Removes it |
| `-ShowReport` (`-Action Report`) | Prints what it would send, for troubleshooting |

The agent logs to `C:\ProgramData\PingMonitor\agent.log`. To keep agents current without redeploying, see [Updating agents automatically](#updating-agents-automatically).

#### Windows installer (.msi)

For computers looked after by people who aren't in IT, use **Download installer (.msi)** on the Windows card. It has the agent, the addresses and the enrolment key built in, so they only need to double-click it and accept the administrator prompt. It:

- copies the agent to `C:\Program Files\Rollcall` and runs its install as SYSTEM, which creates the scheduled task;
- shows in *Installed apps* as **Rollcall agent**; removing it there uninstalls the agent, its task and data;
- lets a newer .msi replace an older one, keeping the computer's approval;
- rolls back and shows an error if the agent couldn't be installed.

The computer then appears under Agents for approval as usual. For silent installs (Intune, MECM, Group Policy software installation): `msiexec /i RollcallAgent-<version>.msi /qn`.

The installer isn't code-signed, so Windows SmartScreen may say "Windows protected your PC" (choose **More info → Run anyway**). You can sign it yourself after downloading, with `signtool`. Many email systems block .msi attachments, so share it with a link instead.

### What it checks

| Check | Goes amber | Goes red (and alerts) |
|---|---|---|
| **Agent** | A run took longer than `agent_slow_seconds` (120) | No report for `agent_stale_minutes` (15) |
| **Disk** | A volume under `agent_disk_warn` (15%) free | Under `agent_disk_crit` (5%) free |
| **Services** | Another automatic-start service isn't running | A service for one of the server's roles has stopped (two reports in a row) |
| **Updates** | Reboot pending, or no update installed for `agent_patch_days` (60; `0` turns this off). The details say what asked for the restart (Windows Update, component servicing, Configuration Manager, files waiting to be replaced) and what was installed since the last one | |
| **IIS** | | An app pool or site stopped (two reports) |
| **Storage** | A disk predicting failure, or a RAID volume rebuilding | A failed disk, a degraded mirror, RAID-5 or Storage Space, a missing dynamic disk, or an unhealthy disk (two reports) |
| **Hardware** (Dell OMSA) | Non-Critical chassis health | Critical chassis health |
| **AD** (domain controllers) | | Replication failing, or SYSVOL/NETLOGON not shared (two reports) |
| **DHCP** | A scope 85% or more used | 95% or more used |
| **Hyper-V** | | A VM in a critical state |
| **Printers** (print servers) | A shared printer not ready (paper jam, offline…) | |
| **Backups** (Veeam) | A warning, a failure Veeam will retry, or a job overdue | A failed job |
| **Defender** | Definitions over 7 days old | Real-time protection off, or malware not removed |
| **Security** | Notable events in the last 24 h | `agent_failed_logons` (20) or more failed logons in one report |
| **LAPS** (where a LAPS policy applies) | Rotation more than a day overdue, the last LAPS run failed, the managed account missing, or LAPS set but not working | Rotation more than `agent_laps_overdue_days` (3) overdue (two reports) |
| **BitLocker** (physical computers that use it, and Windows 10/11 with a TPM by default) | A fixed drive not encrypted, protection suspended, encryption paused or being removed, a drive locked, or no recovery password on the Windows drive | |
| **Domain security** (the PDC emulator) | For 24 h after someone is added to a privileged group; KRBTGT password over 180 days old; an enabled account that doesn't require a password | |
| **Exchange** (Exchange servers) | Back pressure Medium, `agent_exchange_queue_warn` (250) or more messages waiting, anything in the poison queue, maintenance mode or a component inactive, a copy suspended or behind | Back pressure High, or a database copy failed or dismounted (two reports) |
| **Group Policy** (domain members) | Failing, and not applied for 3 hours | |
| **SYSVOL replication** (domain controllers) | A partner unreachable for over an hour, initial sync or recovery, or still using FRS | Replication stopped (dirty shutdown, offline too long, or in error; two reports) |
| **SQL Server** (SQL servers) | A database with no backup for `agent_sql_backup_hours` (36), in full recovery with its log not backed up, or offline; a SQL Agent job failed; can't connect or read | A database suspect or recovery pending (two reports) |
| **Scheduled tasks** (servers) | A task's last run failed, or a timed task missed its run | |
| **Certificates** | A certificate in the computer's own stores within `cert_warn_days` (30) of expiry | Within `cert_crit_days` (7) of expiry, or expired (two reports) |
| **Network** (adapters you tick) | A ticked adapter disabled, or its link slower than when it was ticked (e.g. 1 Gb/s down to 100 Mb/s) | A ticked adapter disconnected or gone (two reports) |
| **Events** | Alert-worthy events in the last 24 h | |

**Installed software:** the **Software** tab in Details lists every installed program with its version, publisher, install date and size, plus a filter box. **Recent changes** shows what was installed, removed, updated or downgraded in the last 30 days (the add-on keeps 180 days).
- On Windows the list matches **Apps & features**: the machine's Uninstall entries (64- and 32-bit) and those of signed-in users. Windows updates and hidden system components are left out. It doesn't use `Win32_Product`, which is slow and can make MSI packages repair themselves.
- On Linux it's the package list from `dpkg` or `rpm`.
- The agent checks every run but only sends the list when something has changed, so reports stay small. If the add-on hasn't got a computer's list (e.g. after a restore), it asks for it.
- **Newer versions** are highlighted (never alerted) with *Newer: …* under the installed version, and **Only the N with a newer version** filters to them. Find software shows them too.
  - **Windows:** the add-on downloads Microsoft's winget catalogue once a day (a few MB from `cdn.winget.microsoft.com`) and matches programs the way winget does: by their Uninstall key (MSI product code), then by name and publisher. Nothing runs on the servers, so it works on every Windows version, including Server 2016 and 2019. Programs that aren't in the catalogue (most line-of-business software) aren't checked.
  - **Linux:** the newer versions the package manager already knows about (`apt list --upgradable` or `dnf check-update` from its cache).
  - Turn it off with the `software_updates` option. Newer versions need Windows agent 1.0.34 or Linux agent 1.0.15.
- **Manage → Find software** searches every computer's list by program or publisher, e.g. *TeamViewer*, and shows which computers have it and which versions. Click a computer to open its Software tab.
- This needs Windows agent 1.0.33 or Linux agent 1.0.14.

**Signed-in users:** the Details Overview shows who is signed in. Where there's more than one session, or a Remote Desktop or SSH session, a table lists each one: user, session (console, Remote Desktop or SSH), active or disconnected, idle time and when they signed in. On Windows this comes from `quser`, so disconnected Remote Desktop sessions are included; Windows Home editions only show the console user. On Linux it comes from `who`. Like security events, user names are only shown to Home Assistant admins. This needs Windows agent 1.0.32 or Linux agent 1.0.13.

**Network adapters:** the **Network** tab in Details lists each adapter with its status, link speed, addresses, MAC address, traffic (the average since the previous report) and error counts. Like the ports on an SNMP switch, nothing alerts until you tick **Alert** for an adapter that should always be connected, such as a second LAN, a team member, iSCSI or a backup network. The link speed when you tick it is remembered, so a cable or switch port that drops to a slower speed shows amber. Virtual adapters (Hyper-V vEthernet and the like) are labelled. This needs Windows agent 1.0.31 or Linux agent 1.0.12; the Linux agent leaves out loopback and Docker's own interfaces.

**Roles** are found from the server's installed Windows roles and services: domain controller, DNS, DHCP, file server, DFS, print server, IIS, Remote Desktop (Session Host, Broker, Gateway, Licensing), Hyper-V, WSUS, Certificate Services, AD FS, NPS, SQL Server, Exchange, SharePoint and Veeam. Each role's services are watched if they're set to start automatically. Roles added or removed later are picked up on the next run.

**Updates.** The last update date is the newest of Windows Update history (which includes MECM and WSUS installs), the Setup event log (every package Windows installs, even with the Windows Update service disabled), and the installed-updates list. Details shows which source it came from, and the OS build. It's re-checked every 6 hours or after a restart, because it can be slow to find. To leave patch compliance to MECM, set `agent_patch_days: 0`; a pending reboot is still flagged.

**Storage health** covers Windows' own RAID (mirrored and RAID-5 volumes on dynamic disks, read with `diskpart`), Storage Spaces, and each physical disk's health, including SMART predicted failures. It also reads two vendors' RAID, which Windows sees only as one healthy-looking disk:

- **Dell PERC, through OpenManage Server Administrator (OMSA).** If `omreport` is installed, each run reads every controller, virtual disk and physical disk. A degraded or failed virtual disk, a failed disk or a controller fault is red; a rebuild or a disk predicting failure is amber. OMSA's chassis health (power supplies, fans, temperatures, voltages, memory, batteries, intrusion) becomes the **Hardware** check. "Hardware Log" (how full the server's own event log is) is shown but doesn't alert.
- **AMD RAIDXpert2.** Its events in the System log ("AMD RAID API") give each array's state. "Goes critical" is red until a rebuild starts; a rebuild in progress is amber with its percentage; "completed" or "goes online" is healthy. The state is remembered, so an array that has been critical for a long time stays red. Disks dropping out, timeouts and remapped bad sectors in the last 24 hours are amber.

Other hardware RAID controllers aren't covered; use the vendor's own alerting.

**Veeam backups.** On a Veeam server the agent adds a **Backups** check and tab:

- **Backup & Replication** (v12/13): every job's result is read from the *Veeam Backup* event log (backup, replication, backup copy, agent jobs and others).
  - A failed job is red, with one notification per failed run giving Veeam's reason. A failure Veeam will retry, or a warning, is amber.
  - **Backup copy jobs** that copy several source jobs log each copy as `<copy job>\<source job>`, and the copy job itself only logs when one of its own sessions ends. So a failed result for the copy job itself (e.g. a failed retry) counts as superseded once copies have finished since it and none of them failed. Its row then shows *Last run failed; N copy sessions have succeeded since*.
  - **Retired a job on purpose?** **Forget** on its row removes it from the list and its alerts straight away, which is tidier than **Ignore** when you're reorganising jobs. If a job with the same Veeam ID runs again, it comes back on its own. Forgotten jobs are listed under the table with **Bring back**. Jobs that haven't run for 60 days are forgotten automatically.
  - A copy job like that is also judged by its copies for being overdue: its **Last success** is the latest successful copy, and each copy has its own overdue check, so the copy job's own occasional entries don't make it look overdue.
  - Rollcall learns how often each job runs. A job with no successful run for more than about 1½ times its usual gap (at least 26 hours, or 8 days until it has a few runs of history) is amber, with one "backup overdue" notification. That catches a job that has been disabled or silently stopped.
  - Jobs with no run for 60 days are dropped.
- **Backup for Microsoft 365:** each job's last status, from its PowerShell module, every 30 minutes (loading the module is slow). Failed is red; Warning, Stopped or Disconnected is amber; an enabled job more than 2 hours past its next scheduled run is amber ("missed"). Disabled jobs are listed but not checked.
- **Ignore** on a job in the Backups tab (`backup:<job name>`) leaves it out, e.g. a weekly test job.

**Alerted as they happen** (a notification for each):

- **Security log:** account locked out (4740), account created or deleted (4720/4726), member added to a security group (4728/4732/4756, e.g. Domain Admins), audit policy changed (4719), Security log cleared (1102). The IDs are in `agent_security_alert_ids`. Group members that are local accounts are named from their SID, and changes made by the computer itself (LAPS, Group Policy) show as `SYSTEM`.
- **System log:** unexpected shutdowns and crashes (Kernel-Power 41, EventLog 6008, BugCheck 1001), disk and NTFS errors, and any Critical-level event. The list is in `agent_event_watch`, as `Source:ID` or just an ID.
- **Microsoft Defender:** every detection, saying whether it was removed.

**Failed logons** are grouped by account and source. Each group shows Windows' reason (e.g. "user name doesn't exist", "wrong password", "account locked out"), the logon type, the method (NTLM, Kerberos) and the client's computer name. A user name sent with the domain already in it reads e.g. `contoso\svc_backup (with domain CONTOSO)`, which usually means a saved credential is typed wrongly.

**Details** shows system info, CPU and memory, roles, disk bars, role services, other stopped services, IIS app pools, AD replication partners, DHCP scopes, Hyper-V VMs, printers, RDS sessions, Defender status, the last 24 hours of System and Application errors, and how long each agent run takes (**Agent run**: total time, CPU, peak memory and a breakdown by step). Failed logons, security events, LAPS, BitLocker, certificates and the Administrators group are on the **Security** tab. Security events and the Administrators group are shown to admins only.

### LAPS

On computers where a LAPS policy applies (agent 1.0.18 or later), Rollcall checks that the managed local admin password is being rotated on the schedule the policy sets. It covers Windows LAPS (from Group Policy, Intune or local configuration, backing up to AD or Entra ID) and legacy Microsoft LAPS (AdmPwd), including Windows LAPS' legacy emulation mode.

- **The policy** is read the way Windows reads it: Intune, then Group Policy, then local configuration, then legacy. That includes the password age and the managed account.
- **The due date** comes from the password's expiry on the computer's own AD object (`msLAPS-PasswordExpirationTime`, or `ms-Mcs-AdmPwdExpirationTime` for legacy LAPS), which is what LAPS itself works from. The computer can read the expiry; the password itself is never read. The lookup happens at most hourly.
- **Without AD** (Entra ID backup, or a laptop away from the office), the due date is the last rotation plus the policy's password age. The last rotation comes from the managed account's password-last-set time and Windows LAPS' own events (10018/10029 backed up, 10020 account updated).
- **Alerts:** amber once rotation is more than a day overdue, red once it's more than `agent_laps_overdue_days` (3) overdue. Also amber when the latest LAPS run failed (event 10005, with its error), the managed account doesn't exist, there's no password in AD yet, backup is disabled in the policy, or a legacy policy is set with no LAPS client installed.
- **Domain controllers:** Windows LAPS manages the DSRM password there, if *Enable password backup for DSRM accounts* is on.
- **Computers without LAPS** don't get the check. To leave it off one server, use **Ignore** (`laps:laps`).

The Security tab shows the product, where the policy comes from, where it backs up to, how often it rotates, the managed account, when the password was last set and when it expires, the last backup and the last LAPS run.

### BitLocker

Rollcall checks BitLocker on each fixed drive of physical computers (agent 1.0.21 or later; the TPM check needs 1.0.22). It reads the state from Windows (WMI), the same as `manage-bde -status`, and never reads the keys or recovery passwords.

- **Which computers:**
  - **Virtual machines** (Hyper-V, VMware, VirtualBox and others) aren't checked; their drives are still listed.
  - A physical computer with a BitLocker-encrypted drive is always checked.
  - One that doesn't use BitLocker is only expected to when it has a TPM, and `agent_bitlocker_require` covers it: `workstations` (Windows 10/11, the default), `all` (servers too) or `off`. No TPM, no warning. A TPM that's turned off still counts as present, and the alert says it's turned off.
  - Computers without BitLocker installed (servers without the feature) don't get the check.
- **The TPM** is read from Windows (`Win32_Tpm`), the same as `Get-Tpm`: its version, maker, and whether it's turned on. The Security tab shows it, and why a computer isn't checked when it isn't.
- **Amber** when a fixed drive isn't encrypted, protection is suspended, encryption is paused, the drive is being decrypted, a drive is locked, or the Windows drive has no recovery password (so it couldn't be recovered if the TPM failed). It never goes red: an unencrypted drive isn't an outage.
- **Suspended protection** is often deliberate: Windows Update and firmware updates suspend it until the next restart. When a restart is pending the alert says so, and it clears once the computer restarts and protection resumes.
- **Encrypting** shows the percentage and stays green.
- Removable drives (BitLocker To Go) and drives without a letter aren't checked.

The Security tab shows each drive with its state, protection, encryption method and what unlocks it (TPM, PIN, recovery password, password…). To leave out one drive, use **Ignore** on its row (`bitlocker:D:`); to leave the check off a computer, **Ignore** the whole check (`bitlocker:bitlocker`).

### Exchange

On Exchange servers (agent 1.0.27 or later), Rollcall checks mail flow and the databases. It's on the **Roles** tab.

- **Queues**, from Exchange transport's performance counters: waiting for delivery, submission, retrying, unreachable and poison. **Amber** at `agent_exchange_queue_warn` (250) or more waiting for delivery, 10 or more unreachable, or anything in the poison queue.
- **Back pressure**, from transport's events (15004–15007). **Red** when it's High, because transport has stopped accepting mail (often a full disk on the queue database's drive). **Amber** at Medium.
- **Server components**, from the state Exchange keeps in the registry. **Amber** in maintenance mode (ServerWideOffline inactive) or when a component such as HubTransport is inactive. ForwardSyncDaemon and ProvisioningRps are normally inactive and don't count.
- **Database copies** (mounted, healthy, copy and replay queues, search index), read every 15 minutes with the Exchange snap-in. **Red** when a copy has failed or is dismounted; **amber** when one is suspended, disconnected or over 10 logs behind, or its search index has failed. The agent runs as the computer's account. If Exchange doesn't let it read database copies, Details says so and everything else is still checked.
- Exchange's certificates, including the Auth certificate, are covered by the [Certificates](#certificates) check.

To leave the check off a server, ignore it (`exchange:exchange`).

### Group Policy and SYSVOL replication

**Group Policy** is checked on every domain-joined computer (agent 1.0.26 or later), from Group Policy's own results in the System log.

- **Amber** when the latest result is a failure and policy hasn't applied for 3 hours. Policy refreshes every 90 minutes or so, so a failure at start-up (before the network is up) that the next refresh fixes doesn't alert.
- Failures are explained, e.g. *Couldn't read a policy from SYSVOL* (1058), *Couldn't find a domain controller* (1054), *No network connection to a domain controller* (1129), *A settings extension failed* (1085), with Windows' own message.

**SYSVOL replication** is checked on domain controllers, using DFS-R's state for the SYSVOL folder and its event log over the last 7 days.

- **Red** when DFS-R has stopped replicating SYSVOL: after an unclean shutdown (event 2213, which needs resuming with the command in the event), because the DC was offline longer than DFS-R allows (4012, which needs a non-authoritative sync), or the folder is in error.
- **Amber** while it can't reach a partner for over an hour (5002/5008/5014 with no 5004 since), during initial sync or recovery, or while SYSVOL still replicates with FRS. FRS isn't supported from Windows Server 2019; migrate with `dfsrmig`.

Both are on the **Roles** tab. Each can be ignored on a computer (`gpo:gpo`, `sysvol:sysvol`).

### SQL Server

On servers running SQL Server (agent 1.0.25 or later), Rollcall checks each running instance. It's on the **Roles** tab.

- **Databases:** each one's state, recovery model, last full or differential backup, last log backup, and log size and use. **Red** when a database is suspect, recovery pending or in emergency mode. **Amber** when it's offline.
- **Backups:** **amber** when a database has had no full or differential backup for `agent_sql_backup_hours` (36). Any backup that SQL Server records counts, including Veeam's application-aware backups. Not checked: system databases, databases created since, snapshots, availability group databases that are backed up on another replica, and databases their own application protects (Veeam's configuration database, WSUS's SUSDB).
- **Logs:** **amber** when a database is in full (or bulk-logged) recovery, its log is waiting for a log backup, and there hasn't been one for a day. In that state the log keeps growing until the disk fills. Either back the log up, or switch the database to simple recovery if point-in-time restores aren't needed.
- **SQL Agent jobs:** **amber** when an enabled job's last run (in the last 30 days) failed, with SQL Server's message.

**Permissions.** The agent connects as the computer's own account, `NT AUTHORITY\SYSTEM`, with read-only queries. On SQL Server 2012 and later that account can see the databases, but often not the backup history or SQL Agent jobs. When it can't, the check goes amber and Details shows this script, which grants read-only access:

```sql
USE [master];
GRANT VIEW SERVER STATE TO [NT AUTHORITY\SYSTEM];
USE [msdb];
IF USER_ID('NT AUTHORITY\SYSTEM') IS NULL CREATE USER [NT AUTHORITY\SYSTEM] FOR LOGIN [NT AUTHORITY\SYSTEM];
ALTER ROLE [db_datareader] ADD MEMBER [NT AUTHORITY\SYSTEM];   -- backup history
ALTER ROLE [SQLAgentReaderRole] ADD MEMBER [NT AUTHORITY\SYSTEM];   -- SQL Agent jobs
```

If the agent can't log in at all, create the login first: `CREATE LOGIN [NT AUTHORITY\SYSTEM] FROM WINDOWS;`.

**Windows Internal Database** (WID, `MICROSOFT##WID`) is the cut-down SQL Server that Windows roles install for themselves: WSUS, AD FS, the RD Connection Broker and IPAM. The agent connects to it through its local pipe and lists its databases. Only their state is checked: red if one is suspect, amber if it's offline. There are no backup, log or job alerts, because each role looks after its own data. A WID the agent can't reach doesn't alert. Microsoft doesn't support changing WID's logins or settings, so no permissions are needed or recommended.

To leave out a database, use **Ignore** on its row (`sqldb:<name>`, or `sqldb:<instance>\<name>`); a whole instance, **Ignore** by its name (`sqldb:<instance>\*`, e.g. `sqldb:MICROSOFT##WID\*`); a job, `sqljob:<name>`; the whole check, `sqldb:sql`.

### Scheduled tasks

The agent (1.0.24 or later) lists the scheduled tasks outside Task Scheduler's **Microsoft** folder: your own scripts and jobs, and other vendors' tasks. Each one shows the account it runs as, when it last ran, its result, and when it's next due. They're on the **Services** tab.

- **Amber** when a task's last run failed, or a timed task (daily, weekly, monthly, one-off) missed a run or is over an hour past its due time. The result code is explained where it's a common one, e.g. `0x1` (script error), `0x8007052E` (the account's password is wrong), `0x80070569` (the account isn't allowed to log on as a batch job).
- **Not alerted on:** disabled tasks; tasks that are running; results that just mean "ready" or "hasn't run yet"; and other vendors' updaters that fail routinely (Edge, Google, OneDrive, Adobe, Mozilla, Intel, NVIDIA and similar), which show as *Not watched*.
- **Servers only.** Windows 10/11 PCs list their tasks but don't alert, as they're full of vendor tasks.
- It clears once the task next runs successfully. To leave one out, use **Ignore** on its row (`task:<name>`); to leave the check off a server, ignore the whole check (`task:tasks`).

### Certificates

The agent (1.0.23 or later) lists the certificates with a private key in the computer's **Personal**, **Remote Desktop** and **Web Hosting** stores, and when each expires. That covers certificates the network check can't see, such as LDAPS on domain controllers, SQL Server, RD Connection Broker and internal services. Keys are never read.

- **Amber** within `cert_warn_days` (30) of expiry, **red** within `cert_crit_days` (7) or once expired. These are the same options as the network certificate check.
- **Renewals don't alert.** When a newer certificate with the same name is valid, the old one is marked *Replaced*. A certificate that expired over 30 days ago and isn't bound to anything is marked *Old, not in use*. Neither counts.
- **Used by** shows what a certificate is bound to: HTTPS bindings (IIS, RD Gateway, WinRM, ADFS), from `netsh http show sslcert`, and the Remote Desktop listener. Services such as LDAPS and SQL Server pick a certificate themselves, so every certificate counts, bound or not.
- Windows' own self-signed Remote Desktop certificate isn't checked, because Windows renews it.
- To leave one out, use **Ignore** on its row (`cert:<thumbprint>`, or `cert:<name>`); to leave the check off a computer, ignore the whole check (`cert:certs`).

### Domain security

The domain-wide checks run on one domain controller only: the one holding the **PDC emulator** role (agent 1.0.28 or later). They're read from Active Directory once an hour, as the DC's own account, and are on its **Security** tab. Like security events, they're shown to admins and editors only.

- **Privileged groups:** the members of Domain Admins, Enterprise Admins, Schema Admins, Administrators, Account Operators, Server Operators, Backup Operators, Print Operators, DnsAdmins and Group Policy Creator Owners. Rollcall remembers who was there; anyone added later is highlighted with the time, and the check is **amber for 24 hours**. Removals are listed too. Members there when Rollcall first looked show as *before monitoring*. The DC's security log still reports each change as it happens (events 4728/4732/4756); this check covers changes made on any DC and gives the full picture.
- **KRBTGT:** **amber** once its password is over 180 days old. Reset it twice, some hours apart, so tickets issued with the old key expire in between.
- **Accounts that don't require a password** (enabled, with *password not required* set): **amber**. To accept one, use **Ignore** on its row (`aduser:<name>`).
- **For review, without alerting:** enabled accounts whose password never expires, and enabled users and computers with no logon for 90 days. *Last logon* is AD's replicated value (`lastLogonTimestamp`), which can be up to 14 days behind.

To leave the check off, ignore it (`domain:domain`).

### Administrators group

The Security tab (admins only, agent 1.0.17 or later) lists every direct member of the computer's built-in Administrators group, with its type (user or group), where it's from (Local, Domain, Azure AD, Built-in) and its SID.

- The built-in Administrator and disabled local accounts are marked. A SID Windows can't name shows as "Unknown (deleted?)", usually an account that has since been deleted. An Azure AD (Entra ID) SID is labelled as such.
- Groups in the list (e.g. Domain Admins) are listed, not expanded into their members.
- On a domain controller, this is the domain's built-in Administrators group.
- Rollcall remembers the list. Anyone added after it first looked shows the date they appeared and is highlighted for 30 days. Additions and removals are listed under **Changes**, at the agent's next report. Additions also raise the usual 4732 security-event alert.

### Tuning

**From Details (admins):**

- **Ignore** appears next to anything that's flagged: stopped services (role or otherwise), stopped IIS app pools and sites, printers, VMs in a critical state, busy DHCP scopes, event IDs, whole disks and backup jobs. It applies to that server straight away and clears the alert.
- **Ignored on this server** (at the bottom of Details) lists everything ignored there. **Apply to all servers** makes an item global; **Stop ignoring** undoes it, and anything still wrong goes red again immediately.
- **Disks → Change** sets that disk's own amber and red levels (% free), e.g. amber below 8% and red below 3% for a large data volume. Leave a box blank to use the default, or enter 0 to turn that level off. **Use defaults** removes the override.
- **Acknowledge**: the Events and Security checks stay amber for 24 hours after something alert-worthy. **Acknowledge** (on the check's card in the Overview, or at the top of the Events or Security tab) turns them green without ignoring anything. The items stay listed, greyed out, and anything new turns the check amber again. On the Security tab it also covers a burst of failed logons, which turns Security red: acknowledging it turns the check green until a later report has another burst. It records who acknowledged it and when; **Undo** puts it back. To stop a recurring event alerting at all, use **Ignore** on it instead.

- **Security filters**: for security events that are expected and low-risk, so they stop alerting. See below.

These settings are kept in the add-on's data folder (`agent_settings.json`), across restarts and agent updates.

#### Security filters

Some account and group changes are routine: LAPS recreating its managed account, a deployment tool adding a service account to a group, a helpdesk group that changes every week. A filter stops events like these from alerting, while everything else of the same kind still does.

![Making a security filter from an event on the Security tab](https://raw.githubusercontent.com/shoey79/rollcall/main/docs/images/security-filter.png)

On the **Security** tab, choose **Filter…** next to an event (admins and editors). The form is filled in from that event, and an event has to match every part you leave in:

| Part | Matches | Example |
|---|---|---|
| The event | That event type. Untick it to match any security event | User account created (4720) |
| Account | The account the event is about | `*\LAPSAdmin`, `svc_*`, `CONTOSO\svc_deploy` |
| Group | The group it was added to or removed from | `Builtin\Administrators`, `CONTOSO\Helpdesk*` |
| Done by | Who made the change | `SYSTEM*` (Windows itself, e.g. LAPS or Group Policy), `CONTOSO\svc_deploy` |
| Applies to | This server, or all servers | |
| Note | Why it's expected; shown next to filtered events | "LAPS manages this account" |

- `*` stands for any run of characters and `?` for any one. Matching ignores upper and lower case. An empty box matches anything.
- For a local account on the computer the event came from, the account is suggested as `*\name`, so one filter covers that account on every computer.
- The form says how many of the listed events the filter matches before you save it, and warns if it would hide every event of a type.
- **What a filter does:** matching events don't notify and don't turn the Security check amber. They're still listed, greyed out, with the note. It applies straight away, including to events from the last 24 hours, so an alert it covers clears now.
- **Security filters**, under the events, lists every filter for this server and for all servers, with who added it and when. **Apply to all servers** widens one; **Remove** deletes it, and matching events from the last 24 hours count again.
- A filter needs at least an event type or one pattern. Each add and removal is logged with who did it.

Keep filters narrow. "Added to Administrators, by anyone" would hide exactly the change you want to hear about; "LAPSAdmin added to Administrators by SYSTEM" doesn't. Filters work for the Linux agent's security events too.

**From the Configuration tab (all servers):**

- `agent_disk_warn` / `agent_disk_crit`: the default disk thresholds.
- `agent_ignore`: known noise. A service name (`MapsBroker`), or `event:10016` (the DCOM permission errors), `apppool:OldTestPool`, `site:Default Web Site`, `disk:E:`, `dhcp:10.0.6.0`, `printer:Old MFP`, `vm:TEST01`, `storage:E:` (a volume, disk or array), `backup:<job>`, `laps:laps`, `bitlocker:D:` (one drive) or `bitlocker:bitlocker` (the whole check), `cert:<thumbprint>` or `cert:certs`, `task:<name>` or `task:tasks`, `sqldb:<name>`, `sqljob:<name>` or `sqldb:sql`, `gpo:gpo`, `sysvol:sysvol`, `exchange:exchange`, `domain:domain`, `aduser:<name>`, `update:immich`.
- `agent_watch_services`: services to watch on every server, even manual-start ones (e.g. `AcmeBackupAgent`).
- `agent_event_alerts` / `agent_security_alerts`: turn those alert types off.

Pausing a computer silences its agent alerts too.

### Passwords left in files

The agents can look for passwords saved in plain text: in scripts, configuration files, notes, spreadsheets, setup answer files and command histories. It's off unless you turn it on.

> **Passwords never leave the computer.** The agent reads the files on the computer itself. For each password it finds, it sends Rollcall only:
> - the file's path
> - the line number (for Word files, the paragraph number)
> - what kind of thing it is, e.g. *Password in a database connection string*
> - the name of the setting, e.g. `DbPassword` (letters, digits and `._-` only)
> - how many characters the password has
>
> It never sends the password, any part of it, a hash of it, or the text around it. The agent measures the value and then drops it; nothing it stores between runs holds it either. Rollcall keeps only those five details, whatever an agent sends, and only Home Assistant admins and Rollcall editors can see them. File and folder names are sent as they are, so you can find the file.

**Turning it on**

- The `agent_secret_scan` option picks which computers scan by default: `off` (the default), `servers`, `workstations` (Windows 10 and 11) or `all`.
- To change one computer, open its Details → **Security** → **Passwords left in files** → **Scan settings for this computer**. Choose **On** or **Off**, add extra folders (one per line, e.g. `D:\Shares\IT` or `/etc/myapp`), and choose how often a full scan runs (every 24 hours by default).
- It needs Windows agent 1.0.36 or Linux agent 1.0.17.

**Where it looks**

- **Windows:**
  - users' folders (Desktop, Documents, Downloads, OneDrive and so on, but not AppData);
  - PowerShell command histories;
  - Windows setup answer files (`unattend.xml`);
  - `C:\inetpub`, `C:\Scripts`, `C:\Temp`, `C:\Install` and `C:\Deploy`;
  - SYSVOL on domain controllers;
  - the automatic sign-in password (`DefaultPassword`) in the registry.
- **Linux:** `/home`, `/root`, `/opt`, `/srv` and `/var/www`, including shell histories, `.env`, `.netrc`, `.pgpass` and SSH keys.
- Plus any extra folders you add.
- It reads text files up to 2 MB (scripts, configuration, notes, CSV) and Word and Excel files (`.docx`, `.xlsx`) up to 10 MB. Older `.doc` and `.xls` files and PDFs are only checked by name.
- It skips program and system folders, `node_modules`, `.git`, the recycle bin, links and junctions, and cloud-only OneDrive files, so it never downloads anything.

**What it finds**

- Group Policy Preferences passwords (`cpassword`), which any domain user can decrypt.
- Passwords in setup answer files, the automatic sign-in password, and `ConvertTo-SecureString ... -AsPlainText`.
- Passwords on command lines: `-Password "..."`, `net use`, `net user ... /add`, `mysql -p...`, `sshpass -p`, `curl -u user:...`.
- Connection strings, `<add key="...Password" value="...">` settings, XML elements, and settings such as `password=`, `api_key:` or `client_secret`.
- User names and passwords in web addresses (`https://user:password@...`).
- AWS access keys, GitHub and Slack tokens, and Azure storage keys.
- Private keys with no passphrase (PEM, OpenSSH and PuTTY).
- "password: ..." written in notes and documents.
- Spreadsheets and CSV files with a password column (such as a browser's password export), and files with names like *Passwords.xlsx*.

Placeholders aren't counted, such as `${DB_PASS}`, `%PASSWORD%`, `$env:API_KEY`, `*****`, `null`, empty values and settings like `PasswordExpiryDays`. In program code (Python, JavaScript, C# and so on) only quoted text counts, so `password = get_password()` isn't flagged.

**How it runs and alerts**

- **It runs after each report**, so reports aren't slowed down. It spends up to 45 seconds per agent run at low priority and carries on where it left off. A full pass can take several runs on a big file server.
- After the first pass, only changed files are re-read.
- Findings go to Rollcall with the next report, and only when they've changed.
- **The check is amber at most** (*Passwords in files*) and never sends a notification.
- **Fix:** move the password into a password manager or the program's protected store, then remove it from the file. The finding clears after the next scan.
- **Ignore:** use **Ignore** on a row for a finding you've accepted (e.g. a test password). It stays ignored until that file, setting or kind of finding changes.
- **Ignore all:** accepts everything found so far on that computer, e.g. after checking a first scan's false positives. Anything found later turns it amber again, marked **New**, and **Ignore all** accepts those too. A finding that only moves because lines were added or removed above it isn't new. **Undo** brings them all back.
- **Turning it off** for a computer removes its check and Rollcall's findings straight away. The agent deletes its own scan files on its next run.
- To try it on a folder without sending anything:
  - Windows: `PingMonitorAgent.ps1 -SecretTest D:\Shares`
  - Linux: `python3 pingmonitor-agent.py --secret-test /srv`

  Each prints what would be reported.

### Agent security

- **The password scan never sends passwords**, only where each one is (see [Passwords left in files](#passwords-left-in-files)).
- **Nothing runs on the servers at the add-on's request**, apart from an agent update you've turned on, which is signed (see [Updating agents automatically](#updating-agents-automatically)).
- **Each server has its own token**, generated on the server and stored in `C:\ProgramData\PingMonitor` (readable only by SYSTEM and Administrators). The add-on keeps only a hash of it.
- **The enrolment key only lets a server ask to join.** Nothing is accepted until an admin approves it, so a leaked key can't feed data in. **Rotate key** under Agents if needed; approved servers keep working.
- **Revoke** stops a server's reports. Deleting a computer from the dashboard also revokes its agent. A revoked or rejected copy can't ask again; to re-add the server, run `-Uninstall` then `-Install` on it.
- **Reports go over HTTP by default**, so they're readable on your network. To use HTTPS, turn on **Agent port uses HTTPS** (`agent_ssl`) under **Manage → Settings → Agent port**, with a certificate in Home Assistant's `/ssl` folder (`agent_certfile`, `agent_keyfile`), and download the script with an `https://` address. Tick **Accept a self-signed certificate** if yours is self-signed.

---

## Linux agent

One Python file (`pingmonitor-agent.py`, Python 3.8+, standard library only, so nothing to install on Ubuntu 20.04 or newer). It uses the same enrolment, approval, alerts, Details, Ignore buttons and disk thresholds as the Windows agent, and shows as **Linux ✓** on the dashboard.

### Setting it up

1. In the dashboard, open **Manage → Agents** and use **Download pingmonitor-agent.py**. It uses the same address as the Windows script, so check that first.
2. Copy it to the server, e.g. `scp pingmonitor-agent.py admin@server:`
3. On the server, run `sudo python3 pingmonitor-agent.py --install`.
   - For Immich's job queues and statistics, add an API key created by an Immich admin with the `server.statistics`, `server.storage`, `job.read` (or `queue.read`) and `systemMetadata.read` permissions (Immich → Account Settings → API Keys; Immich before 1.138 needs `all`): `sudo python3 pingmonitor-agent.py --install --immich-api-key YOUR_KEY`.
   - If Immich isn't in a local container, add `--immich-url http://host:2283`.
4. Approve it under **Agents → Waiting for approval**.

It installs to `/usr/local/lib/pingmonitor/` and adds a systemd timer (`pingmonitor-agent.timer`, every 5 minutes, at low CPU and disk priority). Its token and log are in `/var/lib/pingmonitor/`, and its settings, including the API key, in `/etc/pingmonitor/agent.conf` (all root only).

| Command | Does |
|---|---|
| `--install` | Installs or updates the agent |
| `--uninstall` | Removes it |
| `--report` | Prints what it would send |

`systemctl status pingmonitor-agent` and `/var/lib/pingmonitor/agent.log` show what it's doing.

### What it checks

| Check | Goes amber | Goes red (and alerts) |
|---|---|---|
| **Agent** | A run slower than `agent_slow_seconds` | No report for `agent_stale_minutes` |
| **Disk** | A mount point under its amber level | Under its red level (per mount, e.g. `/` or `/srv/photos`) |
| **Services** | A failed systemd unit | A Docker container that should be up is stopped, unhealthy or restarting, or docker, containerd, ssh or cron stopped (two reports in a row) |
| **Storage** | An array rebuilding | A degraded software RAID (mdadm, from `/proc/mdstat`) array or ZFS pool, or a failed member |
| **Updates** | Reboot required, security updates waiting with nothing installed for a week, or nothing installed for `agent_patch_days` | |
| **Immich** | A job queue paused or with failed jobs, or a newer Immich release out | Immich's API not answering (two reports) |
| **Security** | Notable events in 24 h | `agent_failed_logons` or more failed SSH/sudo logins in one report |
| **Network** (adapters you tick) | A ticked adapter disabled, or its link slower than when it was ticked (e.g. 1 Gb/s down to 100 Mb/s) | A ticked adapter disconnected or gone (two reports) |
| **Journal** | Alert-worthy errors in 24 h | |

- **Containers:** every container that's running, has a restart policy, or belongs to a Compose stack is watched (Immich's server, machine learning, Postgres and Redis/Valkey included). A one-off container that exited cleanly isn't. Containers can be ignored like services.
- **Updates:** the last apt run (from apt's history), packages waiting and how many are security updates, and whether a reboot is required. Re-checked every 6 hours, after a restart, or straight after apt installs anything.
- **Immich:** found from its container (port 2283 unless mapped elsewhere). It always checks the API answers and reports the version. With an API key it also shows each job queue (active, waiting, failed, paused), the photo and video counts, and storage use.
- **Immich updates:** when a newer release is out, the Immich check turns amber ("update available: v2.2.3 (running v2.1.0)"), with one notification per release linking to its release notes. The newest release comes from Immich's own version check if the API key can read it (`systemMetadata.read`, and **Version check** on in Immich's Administration → Settings), otherwise from GitHub, at most every 6 hours. To stop flagging them, use **Ignore** next to the version in Details (`update:immich`).
- **Alerted as they happen:** out-of-memory kills, disk I/O and filesystem (ext4/XFS/btrfs) errors, any critical journal entry, users created or deleted, and users added to groups such as `sudo` or `docker`. SSH logins are listed in Details but not alerted.
- **Administrators** (Security tab, admins only, agent 1.0.11 or later): who can act as root. That's members of the `sudo`, `wheel` and `admin` groups (including users whose main group it is), other accounts with uid 0, and users and `%groups` given rules in sudoers (marked "some commands" if a rule doesn't allow everything). Additions and removals are tracked as on Windows.

---

## Agent addresses and updates

### Inside and outside addresses

Under **Agents → Where the agents report to** there are two addresses: **Inside your network** (e.g. `http://192.168.1.5:8100`) and, optionally, **From outside** (e.g. `https://rollcall.example.com:8100`).

- Downloads have both built in. Agents try them in order and remember which one worked, so a laptop away from the office goes straight to the outside address next time, and back to the inside one when it returns. An address that can't be reached is skipped after 3 seconds.
- Changes are saved straight away and sent to every agent with its next report (Windows agent 1.0.15 and Linux agent 1.0.9 or later), so installed agents follow them without a new download. Each agent also keeps the address it was installed with as a last resort, so a mistake here can't cut it off.
- Each report records which address it was sent to and where it came from, shown in the agent's Details.

For the outside address to work, forward its port on your firewall to Home Assistant's agent port, or publish it through a reverse proxy, and use HTTPS (`agent_ssl`). Otherwise reports and each server's token cross the internet unencrypted. Servers still have to be approved, and every report is checked against that server's own token.

### Computers that report over the internet

A computer that reports through the outside address usually can't be pinged from Home Assistant. **Tell it's up by** (in Edit) handles this:

- **Automatic** (the default): it's up while it answers ping or, if it has an agent, while the agent has reported in the last 10 minutes. The status then says **Up (agent)**, and the list shows "report 2 min ago" instead of a ping time. It's only treated as down when both fail: no ping reply and no report for over 10 minutes.
- **Ping only**: the fastest down alerts, for servers that are always on the network. With Automatic, a crashed server with an agent can take up to about 10 minutes to show as down.
- **Agent only**: never pinged. It's up while reports arrive, amber ("Report late") once a report is over about 11 minutes old, and down with a notification after `agent_stale_minutes` (at least 12).

In each case it's up again as soon as a report arrives. Port, web and certificate checks still have to reach the computer from Home Assistant, so leave those off for computers only reachable over the internet.

### Updating agents automatically

Each add-on release carries the latest agents. Under **Agents → Download and install**, tick **Update Windows agents automatically** and/or **Update Linux agents automatically**. At its next report, any agent older than the add-on's copy downloads it and replaces itself; the new version runs from the report after that. To update just one server, use **Update** next to it in the Approved list. Both are off by default, and the Agent column shows which servers are out of date.

**New versions go to one computer first.** With automatic updates on, a new agent version is sent to one computer first, preferably a server. Every other agent only gets it once that computer has reported on the new version, usually within 5–10 minutes. If it hasn't reported within 20 minutes of fetching the update, the rollout stops: no other agent is updated, you get a notification, and Agents shows the computer concerned with two choices:
- **Retry** tries it on a different computer first.
- **Update the rest** sends it to every agent anyway.

If the first computer is switched off before it fetches the update, another one is chosen after an hour. With only one agent of a kind, it's updated straight away as before; if it goes quiet afterwards you're still told why. **Update** next to a single server always sends it straight away.

An agent only installs an update if all of these pass; otherwise it keeps its current version and logs why:

- It's signed (HMAC-SHA256) with that server's own token, which only the server and the add-on know. A copy changed on the way, or sent by anything other than your add-on, is refused.
- It's the version offered, and newer than the one running. Agents never downgrade.
- It parses (PowerShell) or compiles (Python).

The previous copy is kept next to it (`PingMonitorAgent.ps1.old`, `pingmonitor-agent.py.old`). Only installed agents update themselves; a copy run by hand from a share doesn't. A Group Policy startup script pointing at an older copy won't undo an update, because `-Install` never replaces a newer installed copy with an older one.

---

## Alerts and quiet times

### Notifications

- **Phone and other notifications** go to each service in `notify_services` (without the `notify.` prefix, e.g. `mobile_app_your_phone`). Tapping one opens the dashboard, or `notification_url` if set.
- **A bell notification** in Home Assistant stays while something is down, if `persistent_notification` is on.
- **Recovery** ("back up") notifications are sent if `notify_recovery` is on.
- **Red notifies; amber doesn't.** Most problems go red only if they're still there at the next check, so a single blip doesn't alert.

### Acknowledging

Some amber states clear themselves after a while. **Acknowledge** clears them now. A new occurrence still alerts.

- **Syslog alerts**: in the Logs tab or on the Overview.
- **Agent Events and Security**: on the check's card or at the top of its tab, including Security's red for a burst of failed logons. **Undo** puts it back. For security events that are expected every time, use a [security filter](#security-filters) instead.
- **An SNMP device's restart**: in the SNMP tab or on the Overview.

Problems that clear themselves once fixed, such as a reading over its limit or a SIP line not registered, can't be acknowledged; they turn green when they're resolved. To stop something alerting at all, use **Ignore** (agents), a [security filter](#security-filters) (security events) or **Never alert on these words** (syslog).

### Pausing for reboots (maintenance mode)

Choose **Pause** on a row, or in Details, before rebooting or working on a machine. You're asked for a time limit (default `maintenance_minutes`, 30). While paused, the machine is still pinged but shows blue **Paused** and sends no alerts:

- When it has gone down and replies again, monitoring resumes by itself, with a "back online" message if `notify_recovery` is on.
- If it isn't back by the time limit, it goes red and you're alerted.
- While it's waiting for the machine to go down, it's checked every 5 seconds, so a quick reboot isn't missed.
- A computer with an agent normally counts as up for 10 minutes after each report, even if ping fails. While it's paused, if it usually answers ping, a missed ping counts as it going down, and it's back when ping answers again.
- A restart is also spotted from the agent's uptime: if the computer booted after the pause began, it counts as having gone down and come back. This covers computers that don't answer ping. The Windows agent (1.0.37 or later) also runs a minute after Windows starts, so this is noticed straight away rather than up to 5 minutes later.
- If it never appeared to go down or restart, it resumes quietly at the time limit.
- **Resume** ends the pause early.

Paused time doesn't count towards uptime, and pauses survive an add-on restart. An agent isn't flagged for not reporting while its server is paused, and gets a full `agent_stale_minutes` after the pause ends. To pause a whole tab at once, see [Tabs](#tabs).

### Monitoring schedules

By default every computer is monitored all the time. For one that's only meant to be on at certain times, open **Edit → Monitoring schedule**, choose **Only at set times** and add one or more windows, each with its days and times, e.g. Mon–Fri 07:00–19:00, or Sat 22:00–06:00 for an overnight job. A window can run past midnight; it belongs to the day it starts.

- **Outside its windows** the computer shows as **Off schedule** (grey), with when monitoring resumes. It's still pinged: if it's on anyway, the dot turns half green, half grey and it shows **On · off schedule**. Nothing alerts either way, and off-schedule time doesn't count against uptime.
- **When a window opens** it shows **Starting up** until it replies, for up to the allowance you set (15 minutes by default, 0–240). If it hasn't replied by then, you get the usual down alert.
- **When a window closes**, it goes back to Off schedule without an alert.
- **Problems its agent reported stay on the Overview.** A failed backup, a full disk or a stopped service from the last report is still listed outside the window, marked *off schedule; from the report …*, and the tile says how many checks need attention. They clear when a later report says they're fixed.
- **Backup results still notify.** A failed or overdue Veeam job is sent even if the report arrives outside the window (e.g. a backup server that's only on overnight). Only a manual **Pause** holds them back.

Times are in Home Assistant's time zone (Settings → System → General) and follow daylight saving. The schedule shows under the computer's name, and its sensor has `off_schedule` and `schedule` attributes. A manual **Pause** still works on a scheduled computer and takes priority while it lasts.

**Computers that are usually off.** For something that's only switched on now and then (cold storage, a monthly backup target), choose **Whenever it's switched on**. Being off is then normal: it shows as **Off** (grey), never alerts for it, and off time doesn't count against uptime. While it's on, it's monitored like any other computer, so a failed disk or stopped service still alerts during that monthly run.

**Never alert.** **Never alert for this computer** (Edit → Monitoring schedule) turns off every notification for it: down, checks, agent, events and updates. The dashboard still shows its real status, it still counts in tabs such as Needs attention, and its entities and events still update, so your own automations keep working. A 🔕 next to its name shows it's set. It can be combined with any schedule.

**Critical alerts.** **Critical** (Edit → Monitoring schedule) is for computers that should wake you, such as a mail server. When it goes down, one of its checks goes red, or a Veeam backup job fails, the notification sent to the Home Assistant app is a critical alert:
- **iPhone:** a critical alert, which plays a sound even when the phone is muted or on Do Not Disturb. iOS asks you to allow critical alerts for the Home Assistant app the first time.
- **Android:** a high-priority notification on the `alarm_stream` channel, which plays as an alarm even on vibrate or silent. To get through Do Not Disturb too, allow that channel to override it in Android's notification settings for the Home Assistant app.

"Back up" messages, amber warnings, certificate reminders and syslog alerts stay normal. Only `mobile_app_…` notify services get critical alerts; others get the normal message. Pauses and monitoring schedules still apply. A 🚨 next to its name shows it's set, and it can't be combined with **Never alert**.

---

## Administration

### Settings

**Manage → Settings** (admins and editors) changes the add-on's settings from the dashboard: check intervals, notifications, alert limits, agent options, the agent port and who can make changes. They're the same settings as the add-on's **Configuration** tab, grouped into tabs with a search box, and saved to the same place, so the two always agree.

- **No restart.** Changes take effect as soon as you save. A shorter check interval starts straight away; new limits apply from each computer's next check or agent report; turning **Agent port uses HTTPS** on or off switches the agent port over at once.
- **Checked as you type.** A value out of range is marked and **Save** waits until it's fixed. If Home Assistant turns a change down, nothing is changed and the reason is shown.
- **Who can make changes** (`admin_only_changes`, `editors`) can only be changed by Home Assistant admins, not by editors.
- **The Configuration tab still works.** Settings saved there are picked up within about 10 seconds without a restart, even though Home Assistant offers to restart the add-on.
- Computers aren't listed here; add and edit them on the dashboard.

### Who can see and change things

The **Rollcall** sidebar panel is visible to every Home Assistant user.

- **Admins** (and the owner) can do everything: add, edit and delete computers, pause and resume, acknowledge, approve agents, use linked devices' controls and reset uptime.
- **Everyone else** gets a **View only** dashboard, with status, checks, uptime and **Check now**. The editing buttons are hidden, and the add-on itself refuses changes from non-admins, so typing the URLs directly doesn't get around it.
- **`editors`**: Home Assistant usernames (or display names) of non-admins who may also make changes, e.g. `editors: [sam]`.
- **`admin_only_changes: false`** lets anyone who can open the panel make changes.

The add-on reads Home Assistant's user list to find out who's an admin. If it can't (the log will say so), only names in `editors` can make changes. If `editors` is empty too, everyone can, so you're never locked out of your own add-on.

To hide the panel from some non-admins, remove it from their sidebar under their **Profile → Change the order and hide items from the sidebar**. That only hides it; anyone who can sign in could still open the view-only page by URL.

### Export and import

**Manage → Export / import** (admins) moves everything to another install of the add-on, for example from a local copy to one installed from GitHub.

- **Export** downloads one zip: computers and their checks, tabs, pauses, agent approvals and the enrolment key, ignores and thresholds, uploaded icons, each agent's last report, uptime history and the Configuration-tab settings. Keep it safe: it contains the enrolment key and any SNMP passwords.
- **Import** on the new install replaces everything there with the export and restarts the add-on. Tick **Also restore the Configuration-tab settings** to bring notifications, thresholds and agent options across too. The data it replaced is kept in a `before_import_<date>` folder in the add-on's data folder.

Agents keep reporting without being reinstalled, as long as they reach the new install on the same address and port. Stop the old copy once the new one is running, since both can't use port 8100.

**Reset all uptime** (Manage menu) clears the uptime history for every computer. It asks you to type a 4-digit code first, so it can't be clicked by accident.

### Add-on security

Rollcall runs with the least access it needs, which gives it Home Assistant's top security rating of 8:

- **No extra privileges.** Ping uses unprivileged ICMP sockets, which Docker allows by default, so the add-on doesn't need `NET_RAW`. If a system doesn't allow them, Rollcall says so in its log and on the dashboard, and checks whether each host is up over TCP instead: a host counts as up if any common port (or one of its check ports) answers, even by refusing the connection.
- **AppArmor profile** (`apparmor.txt`): no mounting, no tracing other processes, and no capabilities beyond ordinary file ownership.
- **Ingress:** the dashboard is only reachable through Home Assistant, with Home Assistant's login.
- **Supervisor API** with the default (lowest) role, only to read the add-on's own details, restart it after an import, and update its own options (from **Manage → Settings**).
- **Home Assistant API:** reading states, devices and users, sending notifications, and pressing a linked device's buttons or switches when an admin asks.

---

## Reference

### Options

Set these under **Manage → Settings** on the dashboard, or in the add-on's **Configuration** tab. Either way they apply without a restart.

| Option | Default | What it does |
|---|---|---|
| **Checking** | | |
| `interval` | 300 | Seconds between checks (30–3600) |
| `retry_interval` | 300 | Seconds until the re-check after a miss. Lower it (e.g. 60) to go red faster |
| `ping_count` | 3 | Ping packets per check; any reply means up |
| `ping_timeout` | 2 | Seconds to wait for each packet |
| `service_timeout` | 5 | Seconds to wait for a port, web, SIP or certificate check |
| `history_days` | 7 | How long results and syslog messages are kept (1–90) |
| **Notifications** | | |
| `notify_services` | `[]` | `notify.*` services to alert, without the `notify.` prefix |
| `persistent_notification` | true | A bell notification in Home Assistant while something is down |
| `notify_recovery` | true | Also notify when something comes back |
| `notification_url` | blank | Where tapping a notification goes; blank opens this dashboard |
| `maintenance_minutes` | 30 | Default time limit when pausing a computer |
| **Certificates and UPSs** | | |
| `cert_warn_days` | 30 | Certificate checks go amber this many days before expiry |
| `cert_crit_days` | 7 | …and red (with a notification) this many days before, or once expired |
| `ups_runtime_warn_minutes` | 15 | UPS runtime below this is amber |
| `ups_runtime_crit_minutes` | 5 | …and below this is red |
| `ups_load_warn` | 80 | UPS load (%) that's amber; 95% or more is red |
| **Access** | | |
| `admin_only_changes` | true | Only admins and `editors` can make changes |
| `editors` | `[]` | Home Assistant usernames of non-admins who may make changes |
| **Agents** | | |
| `agent_stale_minutes` | 15 | Red if an agent hasn't reported for this long |
| `agent_slow_seconds` | 120 | Amber if an agent run takes longer (0 turns it off) |
| `agent_disk_warn` | 15 | Default amber level, % free |
| `agent_disk_crit` | 5 | Default red level, % free |
| `agent_failed_logons` | 20 | Failed logons in one report that count as an attack |
| `agent_laps_overdue_days` | 3 | LAPS goes red once rotation is this many days overdue |
| `agent_bitlocker_require` | workstations | Which physical computers with a TPM must use BitLocker: `workstations` (Windows 10/11), `all` or `off`. Physical computers that use it are always checked; virtual machines never are |
| `agent_sql_backup_hours` | 36 | SQL Server: amber when a database has had no full or differential backup for this long |
| `agent_exchange_queue_warn` | 250 | Exchange: amber when this many messages are waiting for delivery |
| `printer_supply_warn` | 10 | Printers (SNMP): amber when a toner, ink or other supply is at this % or less |
| `software_updates` | true | Highlight programs with a newer version: from the winget catalogue (downloaded daily) for Windows, and the package manager for Linux |
| `agent_secret_scan` | off | Which computers look for passwords left in files by default: `off`, `servers`, `workstations` or `all`. Only where each one is reaches Rollcall, never the password (see [Passwords left in files](#passwords-left-in-files)) |
| `name_line` | auto | What the list shows under each name, unless a computer has its own choice: `auto`, `model`, `os`, `address` or `none` (see **Line under the name** in the Edit form) |
| `agent_patch_days` | 60 | Amber if no update installed for this long (0 turns it off) |
| `agent_event_alerts` | true | Alert on watched System-log events |
| `agent_security_alerts` | true | Alert on watched Security-log events |
| `agent_event_watch` | Kernel-Power:41, EventLog:6008, BugCheck:1001, disk:7/51/153, Ntfs:55/98 | System-log events that alert, as `Source:ID` or an ID |
| `agent_security_alert_ids` | 4740, 4720, 4726, 4728, 4732, 4756, 1102, 4719 | Security-log event IDs that alert |
| `agent_watch_services` | `[]` | Extra services to watch on every server |
| `agent_ignore` | `[]` | Things to ignore on every server; see [Tuning](#tuning) |
| `agent_auto_add` | true | Add approved servers to the dashboard automatically |
| `agent_ssl` | false | Serve the agent port over HTTPS |
| `agent_certfile` | fullchain.pem | Certificate in Home Assistant's `/ssl` folder |
| `agent_keyfile` | privkey.pem | Its private key |
| **Other** | | |
| `log_level` | info | debug, info, warning or error |
| `hosts` | `[]` | Optional bulk import; see [Adding and editing computers](#adding-and-editing-computers) |

### Ports

| Port | Used for | Change it under |
|---|---|---|
| TCP 8100 | Agent reports | Configuration → Network |
| UDP 514 | Syslog | Configuration → Network |

The dashboard itself uses Home Assistant's ingress, with no port of its own.

### What it creates in Home Assistant

**Computer sensors:** `sensor.ping_monitor_<name>`, with state `green` / `amber` / `degraded` / `red` / `maintenance`, and attributes `ip`, `host`, `uptime_24h`, `latency_ms`, `consecutive_failures`, `last_check`, `last_change`, `maintenance_until`, `services` (each check's status), `off_schedule` and `schedule`.

**Check sensors:** `sensor.ping_monitor_<name>_<check>` (e.g. `sensor.ping_monitor_sql01_sql`), with state `green` / `amber` / `red` / `unknown`, and attributes `target`, `detail` (e.g. `HTTP 503`, `connection refused`), `uptime_24h`, `latency_ms`, `last_check` and `last_change`.

**Agent sensors:** each agent check as `sensor.ping_monitor_<name>_agent_<check>` (e.g. `sensor.ping_monitor_dc01_agent_disk`), plus graphable numbers: `sensor.ping_monitor_<name>_cpu`, `_memory` and `_disk_<letter>_free` (Linux: `_disk_root_free`, `_disk_srv_photos_free`; all %).

All sensors are refreshed every 60 seconds, so they come back within a minute of a Home Assistant restart. They're pushed through the API, so they can't be renamed or given an area in the UI.

**Events:** `ping_monitor_status_changed` on every computer status change (`name`, `host`, `ip`, `old_status`, `new_status`, `entity_id`), and `ping_monitor_service_changed` on every check change (adds `service`, `target`, `detail`, `host_entity_id`). For example:

```yaml
automation:
  - alias: Server down - flash office light
    trigger:
      - platform: event
        event_type: ping_monitor_status_changed
        event_data:
          new_status: red
    action:
      - service: light.turn_on
        target: { entity_id: light.office }
        data: { color_name: red, flash: long }
```

**Dashboard card (optional).** The add-on's own page is the main dashboard, but this Markdown card lists the computers on any Home Assistant dashboard:

```yaml
type: markdown
title: Computers
content: >
  | | Name | IP | Uptime 24h | Checks down |
  |---|---|---|---|---|
  {% for s in states.sensor
       | selectattr('entity_id', 'search', '^sensor\.ping_monitor_')
       | selectattr('attributes.services', 'defined')
       | sort(attribute='name') -%}
  | {{ {'green':'🟢','amber':'🟡','degraded':'🟠','red':'🔴','maintenance':'🔵'}.get(s.state, '⚪') }}
  | {{ s.name }} | {{ s.attributes.ip or '—' }}
  | {{ s.attributes.uptime_24h if s.attributes.uptime_24h is not none else '—' }}%
  | {{ s.attributes.services | dictsort | selectattr(1, 'eq', 'red') | map(attribute=0) | join(', ') or '—' }} |
  {% endfor %}
```

### Files

In the add-on's data folder (included in Home Assistant backups):

| File | Holds |
|---|---|
| `hosts.json` | Computers and their checks |
| `views.json` | Tabs |
| `agents.json` | Agent approvals, token hashes and the enrolment key |
| `agent_settings.json` | Ignores, thresholds, acknowledgements, agent addresses |
| `secrets/` | Where each agent's password scan found passwords: path, line, kind, setting name and length (never the passwords) |
| `icons/` | Uploaded icons |
| SQLite database | Uptime history and syslog messages |

In the repository:

```
rollcall/              the add-on (its internal ID is ping_monitor)
├── config.yaml        add-on manifest, options and schema
├── build.yaml, Dockerfile, run.sh, apparmor.txt
├── CHANGELOG.md
├── DOCS.md            this documentation (the add-on's Documentation tab)
├── icon.png, logo.png
└── app/
    ├── main.py        scheduler, checks, history, Home Assistant API, web server
    ├── agents.py      agent enrolment, tokens and report evaluation
    ├── snmp.py        SNMP client and device readers
    ├── syslogrx.py, syslogreadings.py   syslog receiver and readings
    ├── certcheck.py, sipcheck.py, hadevice.py, msi.py
    ├── agent/PingMonitorAgent.ps1       the Windows agent
    ├── agent/pingmonitor-agent.py       the Linux agent
    └── web/index.html dashboard (served through ingress)
```

### The name change

Rollcall was called Ping Monitor until 1.6.0. Only the visible name changed, so nothing already set up breaks:

- The add-on's ID is still `ping_monitor`, so entities keep their `sensor.ping_monitor_*` names, and automations and cards carry on working.
- The agents keep their file names (`PingMonitorAgent.ps1`, `pingmonitor-agent.py`), folders (`C:\ProgramData\PingMonitor`, `/var/lib/pingmonitor`), scheduled task, systemd timer and port (8100). Installed agents carry on reporting and updating; there's no need to redeploy them.

---

## Languages

Rollcall's dashboard, notifications and Home Assistant entities are in English. Dates and times follow the browser's own settings, e.g. 11.11.2026 14:05 in a German browser.

The agents work on Windows and Linux in any language:
- Text that comes from the system, such as Windows event messages, service names and program names, is shown as the system wrote it, so it may be in another language.
- Anything the agents read to make decisions doesn't depend on the system's language. Linux commands run in the C locale. On Windows, the agents use IDs and values rather than translated labels, and the signed-in user check understands the common languages' words for an active session.

## Troubleshooting

**A computer shows down but it's on.**
Checks come from the Home Assistant machine, so remote sites must be routable from it, and firewalls must allow ICMP echo and the ports you check. For a computer that can't be pinged, use an agent with **Tell it's up by: Automatic** or **Agent only**.

**A hostname doesn't resolve.**
Home Assistant's DNS treats `.local` as mDNS, so Active Directory names like `server.example.local` may not resolve from the add-on. Use the IP address instead.

**"No SNMP reply".**
Check that SNMP is on, the community (or v3 user) is right, and the device allows Home Assistant's address. Older kit may only speak v1: if `snmpwalk -v1` answers but `-v2c` doesn't, choose v1. The SNMP tab shows how long each part of the last poll took and how many requests it needed. A slow or overloaded switch adapts by asking for fewer rows at a time.

**A server's agent doesn't appear under Waiting for approval.**
Check the server can reach Home Assistant on port 8100 at the address in **Agents** (`Test-NetConnection <address> -Port 8100`), and look at `C:\ProgramData\PingMonitor\agent.log` (Windows) or `/var/lib/pingmonitor/agent.log` (Linux). `-ShowReport` / `--report` shows what it would send.

**An agent run is slow.**
**Agent run** in Details breaks a run down by step. The Agent check turns amber above `agent_slow_seconds`.

**Syslog messages don't show up.**
Make sure **Syslog** is ticked on the device in Rollcall and it's sending to Home Assistant's IP on the syslog port. Messages are matched by the address they come from: if it sends from a different address, they'll appear under **Syslog from unknown devices** on the Overview, with a button to add it.

**SIP: "refused" or "no SIP reply".**
See [VoIP](#voip-phones-atas-and-pbxs-sip).

**Windows blocks the .msi.**
See [Windows installer](#windows-installer-msi). Choose **More info → Run anyway**, sign it yourself, or share it with a link instead of an email attachment.

**The add-on can't ping at all.**
If unprivileged ping isn't allowed on your system, the log and dashboard say so, and Rollcall checks over TCP instead (see [Add-on security](#add-on-security)).
