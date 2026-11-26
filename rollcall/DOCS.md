# Rollcall (Home Assistant add-on)

*Who's up, and how are they doing?* (Formerly **Ping Monitor**.)

Rollcall pings your devices on a schedule and checks the services running on them. It can also:

- read switches, NAS units and UPSs over **SNMP**;
- collect their **syslog** messages;
- show what Home Assistant already knows about a device, through a **linked Home Assistant device**;
- look inside Windows and Linux servers with an **agent**: disks, services, containers, backups, logs, security and more.

Every device gets one of these states:

| Status | Meaning |
|---|---|
| 🟢 Up | Answers, and all its checks pass |
| 🟡 Unresponsive | Missed one check |
| 🟠 Degraded | Answers, but a service, device or agent check has failed. You're notified |
| 🔴 Down | Missed two checks in a row. You're notified |
| 🔵 Paused | Maintenance mode: still checked, but no alerts |
| ⚪ Off / Off schedule | Outside its monitoring times, or a device that's usually off |

You get a dashboard in the Home Assistant sidebar, a sensor for every device and check, and phone notifications.

## Contents

1. [Quick start](#quick-start)
2. [Using the dashboard](#using-the-dashboard): Overview, tabs, Details, adding devices, discovering devices, icons
3. [Checks](#checks): how status works, presets, custom checks, certificates, SIP, other addresses, Home Assistant sensors
4. [Watching devices](#watching-devices): SNMP (Cisco and Juniper too), syslog, HPE iLO, VMware, OPNsense, Jellyfin, Plex, Starlink, linked Home Assistant devices (Pi-hole, myenergi), upstream devices
5. [Windows agent](#windows-agent)
6. [Linux agent](#linux-agent) (with Proxmox), [OpenWrt agent](#openwrt-agent) and [pfSense, OPNsense and FreeBSD agent](#pfsense-opnsense-and-freebsd-agent)
7. [Known vulnerabilities](#known-vulnerabilities): CVE alerts for Windows and Linux, and [offline use](#offline-use)
8. [Agent addresses and updates](#agent-addresses-and-updates): HTTPS, updates, messages to users' screens
9. [Alerts and quiet times](#alerts-and-quiet-times): notifications, email, acknowledging, pausing, schedules
10. [Administration](#administration): settings, what's new, who can change things, the database, export and import, hints for errors, security
11. [Reference](#reference): every option, ports, sensors and events, files
12. [Troubleshooting](#troubleshooting)

---

## Quick start

1. In Home Assistant, go to **Settings → Add-ons → Add-on Store → ⋮ → Repositories**, add `https://github.com/shoey79/rollcall` and close.
2. Find **Rollcall** in the store, choose **Install** then **Start**, and turn on **Show in sidebar**.
3. Open **Rollcall** from the sidebar and choose **Manage → Add device**. Give it a name and an IP address or hostname, tick any services to check, and save.
4. In the add-on's **Configuration** tab, add your phone under `notify_services` (e.g. `mobile_app_your_phone`) to get alerts.

**Updates** appear on the add-on's page in Home Assistant, or use **⋮ → Check for updates** in the store. Turn on **Auto update** to install them automatically.

**Moving from a local copy** (one installed by copying the folder into `/addons`): Home Assistant treats the store version as a separate add-on, so bring your data across with [Export and import](#export-and-import).

---

## Using the dashboard

### The Overview

![The Overview: totals, alerts and every device at a glance](https://raw.githubusercontent.com/shoey79/rollcall/main/docs/images/dashboard.png)
*Screenshots in this guide show made-up devices.*

Rollcall opens on the **Overview**:

- **Tiles** show how many devices are up, need attention, are down or are paused, and whether the agents are reporting. Click one to open a list of just those devices, as a temporary tab with **×** to go back to All. The **Rollcall** tile is Rollcall itself: its database's size and health, and the free space on Home Assistant's disk. Click it for [the database](#the-database).
- **Alerts** lists everything that isn't green, worst and newest first. That includes devices not responding, failing checks, and agent problems such as stopped services, low disks, failed backups or security events. Click an alert to open the device's Details on the right tab. **💡** shows what a well-known error usually means and what to try (see [Hints for errors](#hints-for-errors)).
- **At a glance** shows every device as a tile. Click one for its Details. The tiles can be sorted, and grouped with **group by**:
  - **Group** (the default): one section per group. A device's group is the one typed in its Edit form, or else its icon's type (Servers and PCs, Network, Lighting, Smart home, Heating and climate, Security and access, and so on). Your own groups come first.
  - **Your tabs**: one section per custom tab, in tab order, plus "Not in a tab". A device in two tabs appears in both.
  - **Monitoring schedule**: one section per schedule, plus "Always monitored".
  - **Nothing**: all the tiles together.

  Each section shows how many are down, need attention, paused or up. Click its heading to collapse it. Your choices are remembered in this browser.
- **Syslog from unknown devices** appears when something sends syslog that isn't set up in Rollcall (see [Syslog](#syslog)).

### Tabs

Tabs split a long list. Each is a saved filter, so it updates by itself as devices are added or change. The number on a tab is how many devices it shows. The coloured badge is how many of those need attention (red if any are down).

- **Built in:** **All**, **Needs attention** (down, degraded or missed a check), and **Windows**, **Linux** and **No agent**, which appear once you have a mix.
- **Your own (admins):** choose **+ New tab**, name it and add conditions. It shows devices that match *all* or *any* of them, and lists what matches as you type. **Start from** offers ready-made starting points: name, IP range, Windows, Linux, domain controllers, web servers, low uptime, physical machines, virtual machines and Hyper-V VMs.

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
| Signed-in user (agent) | includes, doesn't include | One or more user names, separated by commas, e.g. `jsmith`. Handy for finding which device someone is on |
| Group | is, is not | One or more groups, separated by commas, e.g. `Lighting, Smart home`. Matches typed groups and the automatic ones from the icon |
| Uptime (24 h) | is below / above % | below `99` |

The ✎ on the open tab edits it, deletes it or moves it left or right. **A–Z** (next to **+ New tab**) puts your own tabs in alphabetical order once; until then they stay in the order they were made. Tabs are shared: everyone who opens the panel sees the same ones. The tab bar wraps onto more lines rather than scrolling. The search box filters within the open tab, and lists matches in other tabs below it (*N more in other tabs*, grouped by tab; **In** *tab name* goes there, keeping the search). Searching from the **Overview** opens a temporary **Search** tab with every matching device; clear the box, or choose × on the tab, to go back to the Overview.

**Pause all in this tab** pauses every device in the tab at once, e.g. for a site's patch night. If something is typed in the search box, only the devices shown are paused. **Resume N paused** ends the pause early for all of them. See [Pausing](#pausing-for-reboots-maintenance-mode).

### Details

![Details of a Windows server with the agent: its checks and system information](https://raw.githubusercontent.com/shoey79/rollcall/main/docs/images/details.png)

**Details** on a row, or the device's name, opens everything Rollcall knows about that device, in tabs:

- **Overview** (devices without an agent). The whole device on one page:
  - tiles for status, 24-hour uptime with its history bar (each segment is a half hour on the clock, e.g. 16:00 – 16:30, and the last runs up to now; hover over one to see its times and how it went), and ping time;
  - device tiles: a UPS's power, battery, runtime and load; a NAS's disks and how full each array is; a switch's ports and PoE; readings from its logs; a linked Pi-hole's figures;
  - a **Needs attention** list of failing checks, SNMP problems, log alerts and readings over their limits. Click an item to jump to its detail;
  - every check with its uptime, the latest warnings and errors from its logs, and the device's model, serial, firmware and location.
- **Agent details** (devices with an agent): the agent's own tabs. See [Windows agent](#windows-agent).
- **SNMP**, **Logs** and **Home Assistant**, when those are set up for the device.

Along the bottom are **Check now**, **Pause** / **Resume** and **Edit**. Edit opens on top of Details, and Details refreshes when you save or cancel. It closes if you delete the device.

### Adding and editing devices

![Adding a device: name, address and the services to check](https://raw.githubusercontent.com/shoey79/rollcall/main/docs/images/add.png)

- **Manage → Add device** opens a form with the name, the IP address or hostname, a checkbox for each service preset (showing the ports it checks), custom checks, SNMP, syslog, a linked Home Assistant device, other addresses and the monitoring schedule.
- **Edit** on a row, or at the bottom of Details, opens the same form. **Delete** and **Reset uptime** for that device are in the form too.
- The **i** next to a setting explains it: hover over it, tap it or tab to it. The Home Assistant parts are tick boxes: **Link a Home Assistant device** and **Add Home Assistant sensors as checks** open their searches when ticked; unticking the device unlinks it.
- Changes apply straight away, with no add-on restart.
- The list is saved in the add-on's data folder (`hosts.json`), which is included in Home Assistant backups.

**Hostnames** are resolved on every check, so the IP shown follows DNS changes. A name that can't be resolved counts as a failed ping. For `.local` names, see [Troubleshooting](#troubleshooting).

**Bulk import.** You can list devices under `hosts:` in the add-on's Configuration tab:

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

On the next start they're merged into the dashboard list. They're matched by name, so an existing device is updated rather than duplicated. The add-on then clears the option, so the dashboard stays the one place to manage them. If Home Assistant doesn't let it clear the option, entries already imported are ignored on later starts. That way they can't overwrite your changes or bring back a device you deleted.

### Discovering devices

![Discover devices: what a network scan found, with a guess at each device](https://raw.githubusercontent.com/shoey79/rollcall/main/docs/images/discovery.png)

**Manage → Discover devices** scans your network for devices that aren't in Rollcall yet (admins and editors only).

1. **Addresses to scan:** the networks to look at, e.g. `192.168.1.0/24`, `10.0.1.1-200` or single addresses, separated by commas. Rollcall suggests the network Home Assistant is on and the ones your devices are on. Only private addresses can be scanned, up to 1,024 per range (a /22) and 4,096 in all.
2. **SNMP community:** used to read switches, NAS boxes and UPS cards (`public` unless you've changed it).
3. **Scan.** A /24 usually takes under a minute. You can close the window and come back; the last scan is kept.

For each address, Rollcall:
- pings it and checks about 40 common ports (SSH, RDP, SMB, HTTP/HTTPS, LDAP, SQL, printing, and others). Addresses that don't answer ping get a quick port check too, since Windows often blocks ping.
- looks up the device's DNS name, its NetBIOS name, workgroup or domain and MAC address (Windows and Samba), its SNMP name and description, whether SIP answers (phones and ATAs), and its web page's title.

From that it guesses what the device is: domain controller, Exchange, SQL Server, Windows computer, Linux, NAS (Synology, QNAP, Buffalo, TrueNAS), printer, UPS, switch or router, VoIP phone or ATA, camera, Pi-hole, Proxmox, ESXi, server management card or UniFi. It also suggests the matching checks.

- **Add** opens the Add form with the name, address (the DNS name when there is one), make and model, and suggested checks filled in. Check it and save. For Windows and Linux servers, the [agent](#windows-agent) gives far more detail than port checks.
- **Hide** takes a device off the list (e.g. phones, TVs, guests). **Show hidden** brings them back.
- Devices already in Rollcall are left out unless you tick **Show devices already in Rollcall**; then they link to their Details.
- **Doesn't answer ping:** Rollcall checks by ping, so once added it would show as down. Allow ping (ICMP echo) in its firewall, or install the Windows agent, as a device counts as up while its agent reports.

#### Networks Rollcall uses

If Home Assistant has more than one network interface (e.g. one for your smart-home devices and one for your servers), **Networks Rollcall uses** at the top of Discover devices lists each one with its subnet. Untick the ones Rollcall shouldn't use:
- Discovery only suggests and scans the networks that are ticked. A scan that includes an address on another network is refused.
- When you add or edit a device, the form says which interface it will be reached through, with a warning if that isn't one of Rollcall's networks.
- Each device's Details shows **Reached through**, e.g. `eth1 (10.0.1.0/24)`, or the default route for addresses on no directly attached subnet. It's marked ⚠ if that isn't one of Rollcall's networks.

Rollcall doesn't choose the interface itself: Home Assistant's host sends each check out of the interface on the device's subnet, or the one with the default route. So this setting keeps discovery inside the networks you pick and shows you where each check goes, rather than redirecting traffic. Home Assistant's own adapter choice under Settings → System → Network is for integrations' discovery (Zeroconf and similar) and doesn't affect Rollcall.

The add-on runs in Home Assistant's container network, so it can't read MAC addresses from the ARP table; the MAC shown comes from the NetBIOS reply. A scan sends a ping and a few connection attempts to every address, so intrusion detection on your network may notice it. Each scan is logged with who started it.

### Icons and make/model

Each device has an icon, in the list and on the Overview. By default it's picked from the device's name or make (e.g. "AP1", "NAS01", "SQL01", "NVR01", "Kitchen plug", "Tapo P110", "Landing light", "Tapo L530", "Hall thermostat", "Back door sensor", "Zappi", "Solis inverter"), its agent (Windows Server or desktop, Linux) or its checks (printer, RTSP camera, SNMP, SIP, Home Assistant, Pi-hole). In the form, *Automatic* shows which icon that gives, and follows the checks as you tick them.

To choose one yourself, choose **Icon** in Edit. The picker has about 75 icons in groups, with a search box (try "light" or "sensor"):

| Group | Icons |
|---|---|
| Servers and PCs | Rack, storage and tower servers, NAS, server rack, desktop, laptop, VM, database, single-board computer, web service, cloud |
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
- Uploaded images can be used for any device and are included in exports.
- Deleting an image from the picker returns devices that used it to an automatic icon.
- Only use images you have the right to use.

**Make and model** (optional) is shown under the name, e.g. "Dell PowerEdge R720xd", and helps choose the automatic icon.

**Group** (optional) puts the device in a section of the Overview, e.g. *Servers* or *Home automation*. Leave it blank to group it by its icon's type; the field shows which group that is.

**Line under the name** chooses what the list shows under the device's name:

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

- A device without an agent counts as a Hyper-V VM when a Hyper-V host's agent lists a VM with the same name.
- You can also type "VM" or "Hyper-V" in **Make and model**.
- The list shows this under the name (e.g. *Hyper-V VM on HV01*, or *Dell Inc. PowerEdge R720xd · ABC1234*), unless you've typed a make and model.
- **Custom-built PCs** often leave placeholders such as "System manufacturer", "System Product Name" or "To Be Filled By O.E.M." in the BIOS. These are ignored, along with dummy serial numbers. From Windows agent 1.0.30, the agent then reports the motherboard instead (e.g. *ASUSTeK DEVICE INC. PRIME B660M-A*), and hovering over it says so.
- To split the list, make a tab with the **Physical or virtual** condition.

---

## Checks

### How status works

- **Ping** decides whether a device is up. One miss turns it amber; a second miss in a row turns it red and notifies. The re-check after a miss comes `retry_interval` seconds later.
- **Every other check** runs only while the device answers. Each has its own count: one failure turns its chip amber, two in a row turn it red.
- **Agent checks** fold into one chip while they're fine: **Windows ✓ all 14 OK** (or Linux). Any that need attention get their own chip, and the summary says how many of the total are OK, e.g. **Windows: 14 of 16 OK** next to the two problem chips.
- **A red check** makes the device **Degraded** and sends an alert naming it, e.g. "🟠 SQL01: SQL is down". Recovery sends "🟢 SQL01: SQL is back up" if `notify_recovery` is on.
- **When the whole device stops answering**, you get one "down" alert, not one per check. Its checks start counting again once it's back, which gives services time to start after a reboot.
- **Pausing** a device pauses its checks too.
- **Uptime %** is time-weighted over the last 24 hours. Amber time counts as down. Gaps when the add-on wasn't running are left out rather than guessed. The row shows ping uptime; each check's own uptime shows when you hover over its chip, and in its sensor.

For devices that can't be pinged, such as laptops reporting over the internet, see [Devices that report over the internet](#computers-that-report-over-the-internet).

### Presets

Tick presets in the Add/Edit form. They're grouped as below, with a search box. In the Configuration tab, use the preset's name in a `checks:` list, e.g. `[dc, fileserver, tcp:5985]`. Ports are each product's defaults; if yours differs, use a [custom check](#custom-checks). A target listed twice is only checked once.

| Preset | Name | Checks |
|---|---|---|
| **Windows & Microsoft** | | |
| `dc` (or `domain`) | Domain controller: DNS, Kerberos, LDAP, SMB and Global Catalog | DNS 53 · Kerberos 88 · LDAP 389 · SMB 445 · GC 3268 |
| `dns` | DNS server | TCP 53 |
| `ldap` | LDAP | TCP 389 |
| `ldaps` | LDAPS (secure LDAP) | TCP 636 |
| `fileserver` (or `smb`, `file`) | File server: File server (SMB) | TCP 445 |
| `rds` (or `rdp`, `terminal`) | Remote Desktop: Remote Desktop / Terminal Server | TCP 3389 |
| `sql` (or `mssql`) | SQL Server | TCP 1433 |
| `iis` | IIS (HTTP) | http:80/ |
| `iis-https` | IIS (HTTPS) | https:443/ |
| `sharepoint` | SharePoint | https:443/ |
| `exchange` (or `owa`) | Exchange | OWA https:443/owa · SMTP 25 |
| `wsus` | WSUS | TCP 8530 |
| `adfs` | AD FS | https:443/FederationMetadata/2007-06/FederationMetadata.xml |
| `adcs` (or `certsrv`) | Certificate Services: Certificate Services web enrolment (/certsrv) | http:80/certsrv/ |
| `configmgr` (or `sccm`, `mecm`) | ConfigMgr management point: ConfigMgr / SCCM management point | http:80/sms_mp/.sms_aut?mplist |
| `kms` | KMS: KMS activation | TCP 1688 |
| `winrm` | WinRM: WinRM / PowerShell remoting | TCP 5985 |
| `veeam` | Veeam Backup & Replication | TCP 9392 |
| `rdweb` | RD Web Access: Remote Desktop Web Access page (/RDWeb) | https:443/RDWeb/ |
| `rdgateway` (or `rdgw`) | RD Gateway: Remote Desktop Gateway (HTTPS 443) | TCP 443 |
| **Databases** | | |
| `mysql` (or `mariadb`) | MySQL / MariaDB | TCP 3306 |
| `postgres` (or `postgresql`, `pgsql`) | PostgreSQL | TCP 5432 |
| `mongodb` (or `mongo`) | MongoDB | TCP 27017 |
| `redis` | Redis | TCP 6379 |
| `oracle` | Oracle | TCP 1521 |
| `elasticsearch` (or `elastic`) | Elasticsearch | http:9200/ |
| `influxdb` (or `influx`) | InfluxDB | http:8086/ping |
| **Mail & files** | | |
| `smtp` | SMTP: SMTP relay or mail server | TCP 25 |
| `imap` | IMAPS: IMAP over TLS | TCP 993 |
| `pop3` | POP3S: POP3 over TLS | TCP 995 |
| `ftp` | FTP | TCP 21 |
| `nextcloud` | Nextcloud | https:443/status.php |
| **Remote access** | | |
| `ssh` (or `sftp`) | SSH / SFTP | TCP 22 |
| `vnc` | VNC | TCP 5900 |
| `telnet` | Telnet: Telnet (switches, old kit) | TCP 23 |
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
| `unifi` | UniFi controller (8443): UniFi Network, old self-hosted controller | UniFi https:8443/ · Inform 8080 |
| `unifi-os` | UniFi OS console: UniFi OS console, e.g. Cloud Key or UDM | https:443/ |
| `unifi-os-server` | UniFi OS Server: UniFi OS Server, self-hosted | UniFi https:11443/ · Inform 8080 |
| `idrac` (or `ilo`, `bmc`, `ipmi`) | iDRAC / BMC: Dell iDRAC or another server management controller | https:443/ |
| `hpilo` (or `ilo3`, `ilo4`) | HPE iLO health: HPE iLO 3 or iLO 4: drives, fans, temperatures and power supplies (needs an iLO login) | health, with an iLO login (see [HPE iLO](#hpe-ilo)) |
| `pihole` (or `pi-hole`) | Pi-hole | DNS 53 · Pi-hole http:80/admin/ |
| `adguard` | AdGuard Home | DNS 53 · AdGuard http:80/ |
| `npm` | Nginx Proxy Manager | http:81/ |
| `squid` | Web proxy: Squid or another web proxy | TCP 3128 |
| `printer` | Printer: Network printer (raw printing on 9100) | TCP 9100 |
| `omada` | TP-Link Omada controller: TP-Link Omada software controller | https:8043/ |
| `mikrotik` (or `winbox`) | MikroTik (Winbox): MikroTik router or switch (Winbox port) | TCP 8291 |
| `openfire` (or `xmpp`, `jabber`) | Openfire / XMPP chat: Openfire or another XMPP chat server, and Openfire's admin console | XMPP 5222 · Openfire admin http:9090/ |
| `snmp` | SNMP: Switch ports and PoE, NAS disks and RAID, UPS battery and power, printer supplies (e.g. Netgear, Buffalo, APC) | snmp:device |
| `cert` | Certificate expiry: Warns before the HTTPS certificate on 443 expires | cert:443 |
| `syslog` | Syslog: Keep this device's log messages and alert on errors | syslog:device |
| `camera` (or `nvr`, `rtsp`) | Camera / NVR: IP camera or NVR (RTSP) | TCP 554 |
| `onvif` (or `tapo`) | ONVIF camera: IP camera with RTSP and ONVIF, e.g. TP-Link Tapo | RTSP 554 · ONVIF 2020 |
| `voip` (or `sip`, `ata`, `pbx`, `phone`, `asterisk`, `freepbx`, `3cx`) | VoIP / SIP: VoIP phone, ATA or PBX (SIP on UDP 5060) | sip:5060 |
| `ata2` (or `spa112`, `spa122`) | Two-line ATA: Two-line ATA, e.g. Cisco SPA112/122 (SIP lines 1 and 2) | Line 1 sip:5060 · Line 2 sip:5061 |
| `starlink` (or `dishy`, `satellite`) | Starlink dish: online, outages, obstructions, latency, drops, throughput and the dish's own alerts; see [Starlink](#starlink) | starlink:device |
| **Home & automation** | | |
| `homeassistant` (or `ha`) | Home Assistant | http:8123/ |
| `nodered` (or `node-red`) | Node-RED | http:1880/ |
| `mqtt` (or `mosquitto`) | MQTT broker: MQTT broker, e.g. Mosquitto | TCP 1883 |
| `frigate` | Frigate NVR | http:5000/api/version |
| `zigbee2mqtt` (or `zigbee`) | Zigbee2MQTT: Zigbee2MQTT web interface | http:8080/ |
| `zwavejs` (or `zwave`) | Z-Wave JS UI: Z-Wave JS UI web interface | http:8091/ |
| `esphome` | ESPHome dashboard | http:6052/ |
| `hue` | Philips Hue bridge | http:80/api/config |
| `shelly` | Shelly device: Shelly relay, plug or sensor | http:80/shelly |
| `neohub` (or `heatmiser`, `neostat`) | Heatmiser neoHub: Heatmiser neoHub local API (secure WebSocket on 4243, always on) | TCP 4243 |
| `vaultwarden` (or `bitwarden`) | Vaultwarden | http:80/alive |
| `paperless` | Paperless-ngx | http:8000/ |
| `uptimekuma` (or `kuma`) | Uptime Kuma | http:3001/ |
| **Media** | | |
| `plex` | Plex | http:32400/identity |
| `jellyfin` | Jellyfin | http:8096/health |
| `jellyfin-api` | Jellyfin health (API key) | version, restart, updates, failed tasks and streams; see [Jellyfin](#jellyfin) |
| `plex-api` | Plex (token) | version, updates and what's playing, by whom; see [Plex](#plex) |
| `emby` | Emby | http:8096/emby/System/Info/Public |
| `immich` | Immich | http:2283/api/server/ping |
| `audiobookshelf` | Audiobookshelf | http:13378/ |
| `navidrome` | Navidrome | http:4533/ |
| `tautulli` | Tautulli | http:8181/ |
| `overseerr` (or `jellyseerr`) | Overseerr / Jellyseerr | http:5055/api/v1/status |
| `ombi` | Ombi | http:5000/ |
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
| `http:PORT/path` | `http:8080/status` | A web request to this device |
| `https:PORT/path` | `https:443/owa` | The same over HTTPS |
| Full URL | `https://mail.example.local/owa` | A specific URL, e.g. a virtual host or load-balanced name |
| `cert:…` | `cert:8443` | A certificate's expiry; see [Certificate expiry](#certificate-expiry) |
| `sip`, `sip:PORT` | `sip:5062` | A SIP service; see [VoIP](#voip-phones-atas-and-pbxs-sip) |
| `ping:HOST`, `tcp:HOST:PORT` | `ping:203.0.113.5` | Another address of this device; see [Other addresses](#other-addresses) |
| `ha:ENTITY` | `ha:sensor.ap_cpu>90` | A Home Assistant sensor; see [Home Assistant sensors](#home-assistant-sensors) |
| `reading:SOURCE.READING` | `reading:starlink.latency>100` | One of an integration's readings as its own chip; see [Readings as chips](#readings-as-chips) |
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

- `cert:8443`: the certificate on another port of this device.
- `SMTP=cert:25`: mail ports use STARTTLS (25 and 587 SMTP, 110 POP3, 143 IMAP, 21 FTP), so mail servers' SMTP certificates can be checked.
- `cert:mail.example.com:443`: a certificate on another name or address. The name is also sent as SNI, so the right certificate is picked on a server that has several.

The check reads whatever certificate the service presents; internal and self-signed ones count. It's green while more than `cert_warn_days` (30) are left, amber within that, and red within `cert_crit_days` (7) or once expired. Red notifies, and so does renewal if `notify_recovery` is on. The chip shows the expiry date, days left, the name on the certificate and who issued it. If the certificate can't be read (port closed, not TLS), the check goes amber and says why.

### VoIP phones, ATAs and PBXs (SIP)

Tick **VoIP / SIP** to check a device's SIP service on UDP 5060. For two-line adapters such as the Cisco SPA112/122, tick **Two-line ATA**: Line 1 is UDP 5060 and Line 2 is UDP 5061. For another port, use `sip:PORT`, e.g. `Line 3=sip:5062`, or `sip:HOST:PORT` for another address.

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

Any Home Assistant sensor can be a check on a device. For example, the UniFi Network integration's CPU and memory sensors for an access point can sit alongside its ping. The chip shows the current value, e.g. **CPU 12%**.

In **Edit**, search under **Home Assistant sensors** (the search starts with the device's name) and choose **Add**. CPU and memory are added as "problem above 90%", temperatures above 80; anything else just needs to be available. Edit the line under **Custom checks** to change it:

| Check | Meaning |
|---|---|
| `CPU=ha:sensor.office_ap_cpu_utilization>90` | Amber, then red (two checks in a row) while CPU is over 90 |
| `Memory=ha:sensor.office_ap_memory_utilization>=85` | The same for memory at 85% or more |
| `ha:sensor.office_ap_state!=Connected` | Red when the state is anything but Connected |
| `ha:binary_sensor.nas_status` | Only needs to exist and not be unavailable |

The condition describes the problem. Operators are `>` `>=` `<` `<=` `=` `!=`. A sensor that's `unavailable` or missing also counts as failing. Sensor checks run with the ping, and pause while the device is down or paused. Some UniFi sensors are disabled by default in Home Assistant; enable them on the device's page first.

To bring in *all* of a device's entities at once, link its Home Assistant device instead; see [Linked Home Assistant devices](#linked-home-assistant-devices).

### Readings as chips

Any reading from a device's integrations can be its own chip on the row, with its value (e.g. **Latency 31.5 ms**), and optionally a limit that makes it a problem. Past the limit it's amber, then red (two checks in a row), and alerts like any other check. Readings come from the integration's own check on the same device, so nothing extra is asked of it.

In **Edit**, tick **Add readings as chips**: it lists what this device's integrations read now, with their current values, and **Add** puts one under **Custom checks** with a suggested limit, where you can change or remove it. (It's there once the device is saved and its integration has been read.)

| Source | Readings |
|---|---|
| Starlink | latency, pings dropped, download, upload, obstructed (% of the time), sky blocked (% of the sky seen, from the obstruction map), uptime, rotation off and elevation off (degrees from where the dish wants to point), Ethernet speed, signal, update waiting |
| Jellyfin, Plex | streams, transcoding, users watching, failed tasks (Jellyfin), update available |
| iLO | power (W), each temperature, each fan's speed |
| UPS (SNMP) | battery charge, runtime, load, battery temperature, input voltage, on battery |
| Fire TV | CPU, memory free, storage free, Wi-Fi signal and link speed, uptime, temperature, disabled apps, apps installed, sideloaded apps and how many aren't running, screen, app in front, Fire OS version, security patch age |
| Linked Home Assistant devices | their sensors, added as [Home Assistant sensor](#home-assistant-sensors) checks |

| Check | Meaning |
|---|---|
| `Rotation=reading:starlink.rotation_off>15` | Alerts when the dish is more than 15° off the direction it wants to face (knocked, or the mount moved) |
| `Latency=reading:starlink.latency>100` | Alerts while latency is over 100 ms |
| `Download=reading:starlink.download<20` | Alerts while download is under 20 Mb/s |
| `reading:ups.runtime<10` | Alerts when the UPS has under 10 minutes left |
| `reading:jellyfin.streams` | Just shows the number of streams |

The condition describes the problem, with the same operators as Home Assistant sensors. A reading the integration hasn't read yet isn't a problem in itself: the integration's own check says why.

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

- **Ports** (any switch): every physical port, with its description, speed and error counts. Tick **Alert** for ports that should always be up (uplinks, servers, access points): they go red if they drop, and amber if someone disables them. Other ports are just shown, so desktops going off at night don't alert. The list of ports, with their names and descriptions, is re-read every 6 hours (each check only fetches the live values, which older switches cope with better); after renaming or describing a port on the switch, press **Check now** in Details to see it straight away.
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
- **Sophos Firewall VPNs** (SFOS: XG and XGS; detected automatically): each IPsec connection with its type and status. A connection switched on in the firewall goes red if it's down, and amber if it's only partly up (some of its networks are down). Connections switched off in the firewall are just shown. Untick **Alert** for one that's only up when it's needed (e.g. a supplier's on-demand tunnel), so it never alerts.
  - On the firewall, turn on SNMP under **Administration → SNMP** (an agent with v3, or a v2c community), and allow SNMP from Home Assistant's address on the zone it uses (**Administration → Device access**).
  - If a second connection drops while the firewall is already red, it gets its own alert, and with `notify_recovery` on you hear when each comes back.
  - Sophos UTM isn't supported: it's end of life and doesn't have this table.
- **Dell iDRAC** (detected automatically): the server's overall health from the iDRAC, under **System**. A non-critical problem is amber; critical or non-recoverable is red. iDRAC7 and later also give storage health and whether the server is powered on (powered off is amber). An iDRAC6 only reports overall health and has no network interfaces to list, so it shows no Ports.
- **Sophos RED** (Remote Ethernet Device): each RED shows in **Ports** as `reds1`, `reds2` and so on, marked RED. The firewall always reports a RED's interface as up, even with the RED unplugged, so Rollcall goes by what it receives instead. A connected RED sends a keepalive every 15 seconds, so a RED interface that has received nothing since the previous check (at least 45 seconds earlier) shows **Disconnected**. Tick **Alert** on it to go red and be told when that happens, and when it's back. It takes up to two checks to notice (about 10 minutes with the default 5-minute interval).

![A Sophos firewall over SNMP: its IPsec connections, one down and one partly up, and its RED connected](https://raw.githubusercontent.com/shoey79/rollcall/main/docs/images/firewall.png)
- **Restarts**: amber for an hour after the device restarts. If it was planned or expected, choose **Acknowledge** next to it (SNMP tab or Overview, admins and editors). That clears the warning for that restart only; a later restart still shows. Devices that don't report their own uptime (many switches, APC cards) count a restart of their SNMP service or management card too.
- **Acknowledging a problem:** any other problem SNMP finds can be acknowledged from **Checks** in the SNMP details, e.g. a server that's meant to be powered off, or a known non-critical fault waiting for a part. It's greyed out and stops counting, so the device can go green, for as long as it stays the same or better (its figures may change, e.g. a UPS's runtime). If it gets worse (amber to red, e.g. non-critical to critical) it shows and alerts again, and the acknowledgement is dropped. If it clears and later comes back, it alerts again too. **Undo** takes an acknowledgement back.
- **Ignoring a problem on one device:** for something that's normal for that device every time, e.g. **Server: powered off** on the iDRAC of a server that's only on some of the time, choose **Ignore** next to it in **Checks**. It never alerts on that device again, whether or not it clears and comes back, and the device stays green. It stays listed, greyed out ("ignored on this device"), and while it isn't showing, **Checks** lists it under **Ignored on this device**. **Stop ignoring** makes it alert again. Other devices aren't affected, and other problems on the same device still alert.

Problems go red, and notify, only if they're still there at the next check, so a port bouncing once doesn't alert. Warnings stay amber and don't notify. If the device stops answering SNMP (wrong community, SNMP turned off), the SNMP check goes red but the device stays up while it answers ping.

Communities and v3 passwords aren't shown on the dashboard; leaving them blank when editing keeps the saved ones. They are included in exports, so keep export files safe.

#### Cisco and Juniper

Any switch or router gets the standard SNMP readings (ports, traffic, errors, PoE). Cisco and Juniper kit, recognised by its SNMP object ID, also gets what its own MIBs say about the box, in a **Cisco** or **Juniper** section of the SNMP tab:

- **Cisco:** CPU (1 and 5 minutes) and memory pools; fans, power supplies and temperatures (CISCO-ENVMON, or ENTITY-SENSOR on Nexus and newer IOS XE); a stack's members, their roles and whether the stack ring is redundant; whether the running configuration has changed since it was saved; and an ASA's failover state.
- **Juniper:** CPU, memory and temperature for each component (routing engines, FPCs), routing engine redundancy, the chassis's yellow and red alarms, and its parts (FRUs).
- **Both:** BGP and OSPF neighbours and their state.
- **Red:** a fan, power supply or temperature critical or shut down, a stack member not ready, an ASA pair with no active unit, a Juniper component down, or a red chassis alarm. **Amber:** a warning from any of those, a stack ring that isn't redundant, unsaved configuration changes, a failover unit in another state, a yellow alarm, a part (FRU) with a problem, a BGP neighbour that isn't established, or CPU or memory over 90%.
- Problems can be acknowledged or ignored like other SNMP problems, and readings added as chips.
- Cisco's `%LINK`, `%LINEPROTO` and `%SYS` log messages get hints (see [Syslog](#syslog)).

This was built from Cisco's and Juniper's MIBs and tested against a stand-in, not real kit. If something reads wrongly, `snmpwalk` output from the device (with names and addresses blanked) on a GitHub issue helps.

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
- **Trust.** Syslog over UDP isn't authenticated, so anything on your network can send messages that appear to come from a device. Treat syslog alerts as a prompt to look, not as proof. Messages from addresses that aren't devices in Rollcall are only listed, never alerted. If you don't use syslog, turn the port off under the add-on's **Configuration → Network**; if you do, allow UDP 514 at your firewall only from the devices that send it.

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

### HPE iLO

For HPE servers with **iLO 3** or **iLO 4**, Rollcall can log in to the iLO and read the server's health: each drive, fans, temperatures and power supplies. Add the iLO as a device, using the iLO's own address, tick **HPE iLO health** (`hpilo`) and enter an iLO user name and password. In the iLO, create a user with only the **Login** privilege: Rollcall only reads.

- It's read every 5 minutes over HTTPS, using HPE's RIBCL interface (an HTTPS POST to `/ribcl`), which both iLO 3 and iLO 4 have. The iLO's self-signed certificate and older TLS are accepted, and Rollcall uses TLS 1.2 at most with it, which older iLO firmware needs.
- An **iLO** tab in Details shows the power state, inlet temperature, each problem found, then:
  - **Storage:** each Smart Array controller with its cache, each logical drive with its RAID level, and each physical drive. iLO 4 reports drives when HPE's Agentless Management Service is installed on the server (it comes with HPE's Service Pack for ProLiant). iLO 3 lists drive bays on servers that have a drive backplane.
  - power supplies, fans and temperature sensors with their limits, and the iLO's own **Health at a glance**.
- **Red:** a failed drive, fan or power supply, a controller or other part that has failed, or a temperature at its critical limit. Like SNMP, a new failure is read again at the next check and goes red (and notifies) only if it's still there.
- **Amber:** a drive predicting failure or rebuilding, a degraded logical drive, a temperature over its caution limit, fans or power supplies no longer redundant, memory or processors degraded, and the server powered off. A server with a single power supply is never counted as not redundant.
- **Acknowledge** and **Ignore** work as for SNMP: acknowledged, a problem stops counting while it's there and no worse; ignored, it never alerts on that server.
- If the iLO turns the user name or password down, the check goes amber and Rollcall waits 30 minutes before trying again, so the iLO's log doesn't fill with failed logins.
- iLO 2 and earlier, and iLO 5 and later, aren't supported by this check. The `idrac` preset (or `ilo`) still checks that any management controller's web page answers.

### VMware

ESXi hosts, vCenter Server and the Aria appliances, read with a read-only account. Choose the **VMware ESXi / vCenter health** preset (or one of the **VMware Aria** ones) and enter the account under **Edit**.

1. Make a user for Rollcall and give it the **Read-only** role: on ESXi under *Host → Actions → Permissions*; on vCenter under *Administration → Access Control → Global Permissions*, with **Propagate to children**.
2. Add the device by the ESXi host's or vCenter's address, tick the preset, and enter the user (e.g. `rollcall@vsphere.local`) and password. Leave **Address** blank for `https://` on the device's address.

Rollcall only reads, every 5 minutes, over HTTPS, and logs out each time. Whether it's an ESXi host or a vCenter is found from its answer.

- **ESXi and vCenter** (the vSphere API): each host's connection, maintenance mode, power, uptime, CPU and memory use, hardware health sensors (temperatures, fans, power supplies, voltages and the overall state), memory, CPU and storage hardware status; each datastore's free space; VMs on, off and suspended (templates left out); clusters with HA and DRS on or off; and triggered alarms.
- **vCenter 7.0 U2 and later** also have a REST API, from which Rollcall reads the appliance's own health (system, load, memory, storage, swap, database storage, software packages), its services, its file-based backup schedule and latest backups, and whether an update is waiting. Older vCenters, or an account that can't use it, just leave that part out.
- **Aria Operations:** the node's status (online), the version, and how many critical and immediate alerts are active. **Aria Automation:** its `/health` page, the version, and that the account can log in. **Aria Operations for Logs:** the version and that the account can log in.
- **The certificate** each one presents is checked for expiry, like the certificate check (`cert_warn_days`, `cert_crit_days`).

| | Amber | Red (and alerts) |
|---|---|---|
| **Hosts** | A yellow sensor or hardware status | A host not responding or disconnected from vCenter; a red sensor or hardware status |
| **Datastores** | Under 10% free | Under 5% free, or not accessible |
| **Alarms** | A yellow alarm | A red alarm. Alarms acknowledged in vSphere don't count |
| **vCenter appliance** | Health yellow or orange; a service set to start automatically that isn't running, or unhealthy | Health red; the latest file-based backup failed |
| **Aria** | Critical alerts in Aria Operations | Aria Operations' node not online; Aria Automation's health page not answering |
| **Certificate** | Expiring within `cert_warn_days` | Within `cert_crit_days`, or expired |

Maintenance mode and a waiting update are shown, never alerted. **Ignore** on a problem's row in the **VMware** tab stops it counting on that device (e.g. a datastore of ISOs that's always nearly full); ignored ones are listed under the table with **Stop ignoring**. If the account is turned down the check goes amber and Rollcall waits 30 minutes before trying again, so it can't lock the account out. VMs, hosts in maintenance, alarms, datastores' free space, temperatures and fans, and the certificate's days left can be added as chips. vSAN's own health checks need VMware's separate vSAN API and aren't read; a vSAN datastore's free space is.

The password is only ever sent to the address it was entered for, and isn't shown again. Built and tested against VMware's own simulator (vcsim) and VMware's documented answers: if something reads wrongly on yours, say so on GitHub.

### OPNsense

OPNsense can be read without an agent, through its own API (the **OPNsense health (API key, no agent)** preset). For pfSense, or to also see disks, interfaces and traffic, use the [pfSense, OPNsense and FreeBSD agent](#pfsense-opnsense-and-freebsd-agent) instead.

1. In OPNsense, add a user for Rollcall (*System → Access → Users*) with only these privileges: **Lobby: Dashboard**, **System: Gateways** and **System: Firmware**, plus **Interfaces: Virtual IPs: Status**, **Status: IPsec** and **Status: OpenVPN** if you use them.
2. Under that user, add an API key. OPNsense downloads a file with the key and its secret.
3. Tick the preset on the device and enter the key and secret under **Edit**. Leave **Address** blank for `https://` on the device's address.

Rollcall reads it at each check, only with GET requests. It's judged like the agent's report: a gateway down is red; packet loss or high delay, an IPsec tunnel or OpenVPN client down, a CARP address in INIT, or the state table over 90% full are amber; a CPU temperature from 85 °C is amber and from 95 °C red. An update waiting is shown, not alerted. A section the key isn't allowed to read is left out, not an error. The **OPNsense** tab shows uptime, memory, load, the version and updates, gateways, CARP, IPsec and OpenVPN. The key and secret are only ever sent to the address they were entered for, and aren't shown again.

### Jellyfin

The `jellyfin` preset only checks that Jellyfin's `/health` page answers. For more, tick **Jellyfin health (API key)** (`jellyfin-api`) and enter an API key, made in Jellyfin under **Dashboard → API Keys**. Rollcall itself reads Jellyfin at each check (no agent needed):

- **Red, with an alert:** Jellyfin doesn't answer, says it's *Unhealthy*, or is shutting down. Like a port check, it's amber at the first miss and red if it's still failing at the next check.
- **Amber, never an alert:** a **restart pending**, an **update available**, a **failed scheduled task** (e.g. *Scan Media Library*: its last run *Failed* or was *Aborted*), or health *Degraded*. Run the task again in Jellyfin to clear it. A pending restart names the plugin behind it when there is one, e.g. *restart pending (LDAP Authentication: failed to load)*.
- It always shows the **version** and how many **streams** are playing (and how many are being transcoded), e.g. *Jellyfin 10.10.7; 2 streams (1 transcoding)*. Transcoding never alerts.
- **The Jellyfin tab** in Details (for any device with this check, with or without an agent) shows, updating as it's checked:
  - **Now playing:** who, on which app and device, what (a series' episode, a film and its year, a song and artist), how far through and whether it's paused, and whether it's played directly or **transcoded**: if so, to what and Jellyfin's reasons (e.g. *video codec not supported*);
  - **Server:** version, health, how many users were active in the last 15 minutes, a pending restart or update;
  - **Plugins** that aren't active (needing a restart, failed to load, not supported by this version), which are usually why Jellyfin asks for a restart;
  - **Library:** how many movies, series, episodes, albums, songs and books it has;
  - **Scheduled tasks** whose last run failed, with when they ended and their error.
- **Updates:** Jellyfin 10.9 and later no longer check for updates themselves, so Rollcall also looks up Jellyfin's latest release on GitHub every 12 hours. That request carries nothing about your server.
- **The address** is `http://<the device's address>:8096` unless you set another, e.g. `https://media.example.local` behind a reverse proxy.
- **The key** is stored with the device in `hosts.json`, never shown on the dashboard again, and **only ever sent to that address**, in Jellyfin's `Authorization: MediaBrowser Token="…"` header. Redirects aren't followed, so it can't be passed on. Change the address to a different server and the key is cleared, so it has to be entered again. If Jellyfin turns the key down, the check goes amber and says so.
- Endpoints used: `/health`, `/System/Info`, `/ScheduledTasks` and `/Sessions` (all read-only).

### Plex

The `plex` preset only checks that Plex's `/identity` page answers. For more, tick **Plex (token)** (`plex-api`) and enter a Plex token. To find it:
- **In Plex Web:** open any film or episode, choose **Get Info → View XML**, and look at the very end of the **address** of the tab that opens: `…&X-Plex-Token=xxxxxxxxxxxxxxxxxxxx`. It isn't in the XML itself.
- **On the Plex server:** it's `PlexOnlineToken` in Plex's `Preferences.xml` (Linux: `/var/lib/plexmediaserver/Library/Application Support/Plex Media Server/`; Docker: the same path under its config folder), or on Windows in the registry under `HKEY_CURRENT_USER\Software\Plex, Inc.\Plex Media Server` (for the account Plex runs as).

 Leave the address blank for port 32400 on the device itself, or enter e.g. `https://plex.example.local:32400`.

- **Secure connections:** if Plex's *Secure connections* setting is *Required*, it drops plain HTTP, so the check tries HTTPS on the same port and keeps using it.
- **Red, with an alert:** Plex doesn't answer. Like a port check, it's amber at the first miss and red if it's still failing at the next check. A refused token is amber.
- **Amber, never an alert:** an **update available** (Plex's own updater says so).
- It always shows the **version** and how many **streams** are playing (and how many are being transcoded), e.g. *Plex 1.41.2.9200; 3 streams (1 transcoding)*. Transcoding never alerts.
- **The Plex tab** in Details (for any device with this check, with or without an agent) shows, updating as it's checked:
  - **Now playing:** who, on which app and device (and *remote* when they're outside your network), what, how far through and whether it's paused, and whether it's played directly, direct streamed or **transcoded**: if so, what's converted (e.g. *video hevc to h264, audio copied, 1080p, hardware*);
  - **Server:** version, how many people are watching, an update waiting;
  - **Busy with:** what Plex is doing in the background, such as a library scan, and how far it's got;
  - **Libraries:** each one's size (films, series and their episodes, artists...).
- **The token** is stored with the device in `hosts.json`, never shown on the dashboard again, and **only ever sent to that address**, in Plex's `X-Plex-Token` header (not the address, so it doesn't end up in logs). Redirects aren't followed. Moving the address to another machine needs it entering again; switching to https, changing the port, or using the server's name instead of its IP keeps it.

### Fire TV and Android TV

Tick **Fire TV / Android TV** (`firetv`, under Media) to watch a Fire TV stick or an Android TV box. Nothing is installed on it: Rollcall talks to it over **network ADB** (Android's debugging connection, port 5555) with a key of its own, and runs a fixed set of commands that only read. It never presses keys, installs or removes anything, or changes a setting.

**Setting it up:** on the stick, turn on **Settings → My Fire TV → Developer options → ADB debugging** (on Android TV, Developer options too). The first time Rollcall connects, the TV shows **Allow USB debugging?** for Rollcall's key: tick **Always allow from this computer** and choose **Allow**. Until then the check is amber and says so; Rollcall waits about 45 seconds for Allow at each check. The Fire TV tab shows the key's fingerprint as the TV's prompt shows it. Another port: use the check `firetv:5556`.

**What it shows** (the **Fire TV** tab, and tiles on the Overview):
- Model, Fire OS version (e.g. 6.7.1.1) and Android version, build and security patch; how long it's been up and how many times it has started.
- CPU use over 2 seconds (Fire OS's load average counts waiting kernel tasks, so it reads 5 or 6 on an idle 4-core stick and isn't used), memory and storage free, Wi-Fi signal, band and link speed, and temperature where the TV lets ADB read it (Fire TV sticks don't: it says so).
- The screen (on, standby or screensaver) and the app in front.
- The apps you've installed, with versions and where they came from (Appstore, Google Play or **sideloaded**). Each sideloaded app shows whether it's running and how many services it has, e.g. a custom launcher's Home-button helper.
- How many apps are **disabled**: if that drops, an update has turned debloated apps back on.

**Amber, never an alert:** storage below 10% or 500 MB free, CPU at 90% or more in 3 checks in a row (a video makes it jump, so one busy check means nothing), disabled apps turned back on, a sideloaded app that was running having stopped, and a Wi-Fi signal below −80 dBm. **Red:** the stick doesn't answer on its ADB port. Every value can also be its own chip with a limit of your choosing ([Readings as chips](#readings-as-chips)).

**Security:** network ADB gives **full control** of the stick to anything on the network that the TV has allowed, and anything at all can ask (the TV then shows the prompt). Keep sticks on a network of their own if you can, turn ADB debugging off on sticks you don't monitor, and only ever allow keys you recognise. Rollcall's key is kept in its data folder (`firetv/adbkey`); a fresh install makes a new one, and the TV asks again.

### Starlink

Tick **Starlink dish** (`starlink`, under Network) to watch a Starlink dish. Rollcall reads the dish's own status, the same figures the Starlink app shows, in one of two ways, chosen under **Edit**:

- **From the dish, on the local network** (the default, no sign-in). The dish always answers on **192.168.100.1**, port **9200** (gRPC, the same local API Home Assistant's own Starlink integration uses). Leave the address blank to use that, or enter another if your router maps the dish somewhere else.
- **Through the Starlink account**, for a dish Home Assistant can't reach, such as at another site. See [Through the Starlink account](#through-the-starlink-account) below.

What it shows, at each check:
- **Red, with an alert:** the dish reports an **outage** (with the reason Starlink gives: obstructed, no satellites, starting up, stowed, too hot...), it has **shut down because it's too hot**, its **service is disabled** (e.g. no active account), or it can't be reached at all. Like a port check, it's amber at the first miss and red if it's still failing at the next check.
- **Amber, never an alert:** the dish's own warnings: **motors stuck**, **mast not vertical**, **too hot, slowed down**, **slow Ethernet link**, a weaker signal than expected, water detected; **obstructions** cutting it off for more than 1% of the time; **stowed**; **out of alignment** (20° or more off the direction it wants to face, or 10° off the elevation it wants: usually it's been knocked or the mount has moved; it says which way to turn or tilt it); and, through the account, the sign-in having expired.
- **Shown only:** heating (melting snow), power-save idle, roaming, and an update downloading or installed (the dish restarts itself for updates).
- Green says what it's doing, e.g. *Starlink online, 31.5 ms, 0.2% drops, ↓ 48.2 Mb/s ↑ 5.1 Mb/s*; the latency also goes in the device's response-time chart.
- **The Starlink tab** in Details: status and how long it's been up, latency and pings dropped, throughput now, how much of the time it's been obstructed, anything that needs attention, then the hardware and software versions, an update waiting, when and why it last restarted, the Ethernet link speed, the signal, and how much of the sky is blocked. The same tiles appear on the device's Overview.
- **Alignment** on the Starlink tab: a compass with where the dish faces now (solid line) and where it would like to (dashed), e.g. *160° SSE, wants 165° SSE*, and a gauge with how high it points (0° the horizon, 90° straight up), where it would like to, and how far the panel is tilted. Dishes report this from their status; older ones that don't simply leave it out.
- **Obstruction map** on the Starlink tab: the sky as the dish sees it, straight up in the middle and the horizon at the edge, north at the top. Clear is grey, partly blocked amber, blocked red, and sky it hasn't seen yet faint. Beside it, in words: how much of the sky it has seen is blocked, mostly in which directions and how high (*mostly to the north-east and east, low, near the horizon*), and how much of the sky it has seen so far. The dish builds the map up as satellites pass and starts again when it restarts, so it's sparse for the first day or so. It's read when the tab opens (at most every 5 minutes; **Read again** for a fresh one), not at each check.
- Rollcall only reads: it never asks the dish to restart, stow, clear its obstruction map or change anything.

**Reaching the dish's address.** With the Starlink router in its normal mode, devices on its network reach 192.168.100.1 directly. With the router in **bypass mode** (your own router or firewall doing the routing), your router needs to send 192.168.100.1 out of its Starlink connection, with that connection's address as the source (NAT/masquerade), which most do already for anything not on the local network. Then allow Home Assistant to reach 192.168.100.1 on TCP 9200. To test from Home Assistant's terminal: `curl -v telnet://192.168.100.1:9200` should connect.

- **If one of your own networks is 192.168.100.0/24**, it clashes with the dish's address: your router sends 192.168.100.1 to that network instead. Either renumber that network, or, if nothing there uses .1 (its gateway is another address), add a **host route** for 192.168.100.1/32 out of the Starlink connection, with NAT on that connection. A /32 is more specific than the /24, so only the dish's address is sent to Starlink. On some firewalls, VPN routes are used before static routes (on Sophos Firewall, see `system route_precedence show` on the console): put static routes first, or use a policy route for 192.168.100.1 instead.
- **A dish at another site**: reach it over a site-to-site VPN with a route to 192.168.100.1 at that site (and the same care if 192.168.100.0/24 is used anywhere), or read it through the account.

#### Through the Starlink account

For a dish Home Assistant can't reach. Rollcall reads the same status through starlink.com, signed in as you, the way the community integration *ha-starlink-remote* does:

1. Open a **private (incognito) window** and sign in at **starlink.com**.
2. Open the browser's developer tools (**F12**), choose **Network**, and click any request to `starlink.com`.
3. Under **Request headers**, copy the whole value of **cookie** (it includes `Starlink.Com.Sso`).
4. In Rollcall, **Edit** the device, choose **Through the Starlink account**, paste it, choose **Find dishes** and pick the dish.
5. Close the private window; don't sign out, which would end this sign-in too.

- **The cookie** is stored with the device in `hosts.json`, never shown on the dashboard again, and **only ever sent to starlink.com** (redirects aren't followed). Parts of it that starlink.com renews are kept. Rollcall only reads; nothing it sends can restart or stow the dish.
- **Rollcall keeps the session alive** the way an open browser tab does: at each check it visits the account pages, keeps the cookies starlink.com renews there and drops the ones it deletes, then asks for a short-lived token.
- **It expires** if you sign in again in the same browser, or if starlink.com ends the session: the check turns amber with *Starlink sign-in expired: paste a new cookie under Edit*, without an alert. A private window, closed straight after copying, avoids the first. When it happens, the add-on's log says what starlink.com answered at each step (status codes and cookie names, never their values), which helps if it keeps happening.
- **This is starlink.com's unofficial API**, used by its own website, so it may change without notice; if it stops working, Rollcall says so rather than guessing. Starlink Business accounts also have an official API with service accounts, which Rollcall doesn't use (yet).

### Upstream devices

A device can have an **Upstream device** (Edit, under Other addresses): what it's reached through, such as the router at a branch office, a switch, or a VPN firewall. While the upstream device is down, the devices behind it show as **Unreachable** (a striped dot) rather than Down, and don't alert on their own: you get **one** alert, for the upstream device, that lists what's behind it, e.g. *Branch router is DOWN … Devices behind it may also be affected (3): PC01, PC02, Switch.*

**Many devices at once:** open the router, switch or VPN firewall's **Edit** and expand **Devices behind it**: tick every device reached through it, and untick any that aren't. A device already behind something else says so, and ticking it moves it here; devices this one is behind aren't offered (that would be a loop). Filter the list by name, address or group.

- It works through several levels, e.g. PC → switch → router: everything behind the router that's down counts as unreachable, and says which device is the cause.
- The devices behind it don't have to be checked after the upstream device. If one goes red first, its alert waits (*Checking Branch router before alerting*) while Rollcall checks the upstream device straight away. If that's fine, the alert goes out, saying the upstream device is answering; if it's down too, the device becomes Unreachable. It never waits more than 3 minutes.
- When the upstream device comes back, the devices behind it are checked again at once. Those that never alerted don't send a "back up" either. One that's still down then gets its own down alert.
- An upstream device that's paused, or off schedule, and not answering counts as down for this.
- Unreachable devices are listed last on the Overview, counted separately in the summary (**Unreachable**), and still count as down for uptime. Their sensors keep the state `red`, with `unreachable: true` and `upstream_device` attributes, and the `ping_monitor_status_changed` event has `unreachable` and `upstream`, so automations can tell them apart.
- A device can't be upstream of something that's upstream of it. Deleting an upstream device clears it from the devices behind it.

### Linked Home Assistant devices

If Home Assistant already has an integration for a device, link its Home Assistant device and Rollcall reads all of the integration's entities, with no extra passwords. In **Edit**, tick **Link a Home Assistant device**, search (e.g. `pi-hole`) and choose **Link**. To remove it, choose **Unlink**.

Some integrations split one thing into several Home Assistant devices, such as myenergi's Zappi, hub and Harvi. Link each of them to the same Rollcall device: the first is the main one, and the others' readings show alongside it, each under its own heading, with tiles and alerts drawn from all of them.

![A Pi-hole linked to its Home Assistant device, with its readings and controls](https://raw.githubusercontent.com/shoey79/rollcall/main/docs/images/ha.png)

This adds a **Home Assistant** check and a **Home Assistant** tab in Details, including for devices with an agent. On devices without an agent, the Overview shows it too:

- **Readings:** every entity and its state. Diagnostic and configuration entities are folded away.
- **Controls:** the device's buttons and switches, in their own list. Admins and editors can **Press**, **Turn on** or **Turn off**. Each one asks you to confirm first and is logged with who did it. Only that device's own controls can be used. A button shows when it was last pressed; until then Home Assistant reports its state as "unknown".
- **Any device:** goes red if every entity is unavailable (Home Assistant has lost touch with it), and amber for a "problem" binary sensor that's on. Updates available are noted.
- **Pi-hole** (the built-in Pi-hole integration, or **Pi-hole V6** from HACS):
  - tiles for ad blocking on or off, DNS queries today, blocked today and the percentage blocked, clients, domains on blocklists, and (V6) CPU and memory;
  - ad blocking turned off is amber;
  - Pi-hole's own diagnostic messages and updates are noted;
  - the chip reads e.g. "Pi-hole: blocking on, 85,710 queries today, 21.4% blocked".

- **myenergi** (the `myenergi` integration from HACS): link the Zappi, and the hub and any Harvi too, to one device:
  - tiles for the Zappi's status and plug, its charge mode, charging power now (from the Zappi's own clamp), energy added this session and charged today (with the green part), and locked or unlocked;
  - from the hub: grid now (importing or exporting), what the home is using, the supply's voltage and frequency, and today's imports, exports and generation;
  - **generation** is shown as myenergi measures it, and never alerts: a "generation" clamp can also see a home battery discharging, so it isn't necessarily solar. With the hub linked its total is used; without it, the clamps on the Zappi and Harvi are added up;
  - a Zappi fault (plug status *Fault/Restart*) is **red** and alerts; a firmware update, or the supply outside the UK's limits (216–253 V, 49.5–50.5 Hz), is amber;
  - the integration reads myenergi's cloud, so if Home Assistant loses touch, Rollcall says it may be myenergi's servers rather than the charger.
  Readings are found by what they measure, so renaming the devices in Home Assistant doesn't matter.

Keep the **Pi-hole** preset ticked as well. It checks DNS and the admin page directly, so you still hear about a dead Pi-hole even if Home Assistant is down.

---

## Windows agent

One PowerShell script, the same on every server. Every 5 minutes it works out what the server does and reports what matters for it. Servers appear on the dashboard by themselves once you approve them.

**Requirements:** Windows Server 2012 R2 or later (Windows PowerShell 4.0+), and port 8100 open from the servers to Home Assistant. Workstations work too; they just have no server roles.

### Setting it up

![Manage → Agents: where agents report to, and the downloads](https://raw.githubusercontent.com/shoey79/rollcall/main/docs/images/agents.png)

1. In the dashboard, open **Manage → Agents** and download **RollcallAgent.ps1**. Check the address first: it's what your servers use to reach Home Assistant on port 8100 (use the IP if they can't resolve the name). The script has the address and the enrolment key built in.
2. Copy it to `\\your-domain\NETLOGON`, or any share the servers can read.
3. Run it on the servers, by one of these:
   - **Group Policy** for the servers' OU: *Computer Configuration → Policies → Windows Settings → Scripts → Startup*, script `powershell.exe`, parameters `-NoProfile -ExecutionPolicy Bypass -File \\your-domain\NETLOGON\RollcallAgent.ps1 -Install`.
   - **By hand:** run that command once as an administrator on a server to start straight away.
   - **MECM (Run Scripts):** *Software Library → Scripts → Create Script*, import the script and have it approved (by default an author can't approve their own). Right-click a device collection → **Run Script**, choose it, set **Action** to `Install` and leave the rest at their defaults. It runs as SYSTEM straight away. MECM warns about the switch parameters; that's expected, and it's why `Action` exists. If it fails with a signing error, your client settings' PowerShell execution policy is *All Signed*: sign the script, or use *Bypass* for that collection.
   - **The installer**, for devices looked after by people outside IT; see below.
4. Within 5 minutes each server shows under **Waiting for approval**. Check the name and address, then **Approve** (or **Approve all**).
5. Approved servers that aren't on the dashboard yet are added automatically, by IP, unless `agent_auto_add` is off. Existing entries are matched by name or IP.

   **Address changed?** If a device is monitored on an IP address its agent no longer reports (DHCP gave it a new one), the list shows *agent reports …* under its address, and its details ask whether to **Use** the new address (checks naming the old one move with it) or **Keep** the current one, which may still be right: a second network card, a VPN or a dock. One notification per new address. Devices monitored by name aren't asked: their name follows DHCP.

   If the same device has two entries, e.g. one you added for ping and another the agent linked to, the one without the agent says **This looks like the same device as …** at the top of its details. **Merge into this entry** moves the agent onto it, with the other entry's checks, agent settings (ignores, filters, acknowledgements) and graphs, and removes the other entry. The entry you merge into keeps its name, address, history and Home Assistant sensors, and nothing re-alerts.

**What `-Install` does:** copies the script to `C:\ProgramData\Rollcall` and creates a scheduled task, **Rollcall Agent**, that runs every 5 minutes as SYSTEM. After its first report it adds a second task, **Rollcall Agent (start-up)**, that runs a minute after Windows starts, so a restart shows straight away. From agent 1.0.47 that start-up run waits up to 3 minutes for Rollcall to be reachable (DHCP, the domain network or a VPN can take longer than a minute), rather than giving up until the next 5-minute run. Running it again is safe, and is one way to update.

**Agents installed before 1.0.60** used Rollcall's old name: `PingMonitorAgent.ps1` in `C:\ProgramData\PingMonitor`, task **Ping Monitor Agent**. At its first run as 1.0.60 or later, an agent in the old place copies itself, its token and its state to `C:\ProgramData\Rollcall` and creates the **Rollcall Agent** task. The old task stays as the fallback until the new one has reported; only then are the old task and folder removed. If the move fails, the old one carries on and its next report says why (it tries again a day later). Running the new script with `-Install` over an old install does the same. Nothing needs redeploying, but a Group Policy startup script can be pointed at `RollcallAgent.ps1` at your convenience; one still running the old file is harmless.

| Switch | Does |
|---|---|
| `-Install` (`-Action Install`) | Installs or updates the agent |
| `-Uninstall` (`-Action Uninstall`) | Removes it |
| `-ShowReport` (`-Action Report`) | Prints what it would send, for troubleshooting |

The agent logs to `C:\ProgramData\Rollcall\agent.log`. To keep agents current without redeploying, see [Updating agents automatically](#updating-agents-automatically).

#### Windows installer (.msi)

For devices looked after by people who aren't in IT, use **Download installer (.msi)** on the Windows card. It has the agent, the addresses and the enrolment key built in, so they only need to double-click it and accept the administrator prompt. It:

- copies the agent to `C:\Program Files\Rollcall` and runs its install as SYSTEM, which creates the scheduled task;
- shows in *Installed apps* as **Rollcall agent**; removing it there uninstalls the agent, its task and data;
- lets a newer .msi replace an older one, keeping the device's approval;
- rolls back and shows an error if the agent couldn't be installed.

When installed by double-clicking, it ends on a **Rollcall agent installed** screen saying the device will appear in Rollcall within a minute or two (or, if something went wrong, a screen saying how to get an install log). The device then appears under Agents for approval as usual. For silent installs (Intune, MECM, Group Policy software installation), which show no screens: `msiexec /i RollcallAgent-<version>.msi /qn`.

The installer isn't code-signed, so Windows SmartScreen may say "Windows protected your PC" (choose **More info → Run anyway**). You can sign it yourself after downloading, with `signtool`. Many email systems block .msi attachments, so share it with a link instead.

### What it checks

| Check | Goes amber | Goes red (and alerts) |
|---|---|---|
| **Agent** | A run took longer than `agent_slow_seconds` (120) | No report for `agent_stale_minutes` (15) |
| **Disk** | A volume under `agent_disk_warn` (15%) free | Under `agent_disk_crit` (5%) free |
| **Resources** | Memory at `agent_memory_warn` (90%) used or more; the CPU at `agent_cpu_warn` (90%) or more in the last `agent_cpu_reports` (3) reports; on a router, the 15-minute load above its number of CPU cores | Memory at `agent_memory_crit` (95%) used or more (two reports in a row) |
| **Services** | Another automatic-start service isn't running | A service for one of the server's roles has stopped (two reports in a row). Automatic (Delayed Start) services, which Windows starts a couple of minutes after it starts, don't count as stopped until it's been up 5 minutes; Details marks them *delayed start* |
| **Updates** | Reboot pending, or no update installed for `agent_patch_days` (60; `0` turns this off). The details say what asked for the restart (Windows Update, component servicing, Configuration Manager, files waiting to be replaced) and what was installed since the last one | |
| **Vulnerabilities** | A known vulnerability in Windows scoring `vuln_min_score` (9) or more that a later Windows update fixes (see [Known vulnerabilities](#known-vulnerabilities)) | One that's known to be exploited |
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
| **BitLocker** (physical devices that use it, and Windows 10/11 with a TPM by default) | A fixed drive not encrypted, protection suspended, encryption paused or being removed, a drive locked, or no recovery password on the Windows drive | |
| **Domain security** (the PDC emulator) | For 24 h after someone is added to a privileged group; KRBTGT password over 180 days old; an enabled account that doesn't require a password | |
| **Exchange** (Exchange servers) | Back pressure Medium, `agent_exchange_queue_warn` (250) or more messages waiting, anything in the poison queue, maintenance mode or a component inactive, a copy suspended or behind | Back pressure High, or a database copy failed or dismounted (two reports) |
| **Group Policy** (domain members) | Failing, and not applied for 3 hours | |
| **Time** (domain members) | Clock `agent_time_warn_seconds` (60) out from its domain controller, or Windows Time not syncing; on the PDC emulator, running on its own clock | `agent_time_crit_seconds` (240) out (two reports) |
| **SYSVOL replication** (domain controllers) | A partner unreachable for over an hour, initial sync or recovery, or still using FRS | Replication stopped (dirty shutdown, offline too long, or in error; two reports) |
| **DFS Replication** (DFS Replication role) | Recovering its database after an unclean shutdown, a folder in initial sync or recovery, or a partner unreachable for over an hour | Replication stopped (dirty shutdown, offline too long, database not recovered, a folder in error, or the service stopped; two reports) |
| **SQL Server** (SQL servers) | A database with no backup for `agent_sql_backup_hours` (36), in full recovery with its log not backed up, or offline; a SQL Agent job failed; can't connect or read | A database suspect or recovery pending (two reports) |
| **Scheduled tasks** (servers) | A task's last run failed, or a timed task missed its run | |
| **Certificates** | A certificate in the device's own stores within `cert_warn_days` (30) of expiry | Within `cert_crit_days` (7) of expiry, or expired (two reports) |
| **Network** (adapters you tick) | A ticked adapter disabled, or its link slower than when it was ticked (e.g. 1 Gb/s down to 100 Mb/s) | A ticked adapter disconnected or gone (two reports) |
| **Events** | Alert-worthy events in the last 24 h | |

**Installed software:** the **Software** tab in Details lists every installed program with its version, publisher, install date and size, plus a filter box. **Recent changes** shows what was installed, removed, updated or downgraded in the last 30 days (the add-on keeps 180 days).
- On Windows the list matches **Apps & features**: the machine's Uninstall entries (64- and 32-bit) and those of signed-in users. Windows updates and hidden system components are left out. It doesn't use `Win32_Product`, which is slow and can make MSI packages repair themselves.
- On Linux it's the package list from `dpkg` or `rpm`.
- The agent checks every run but only sends the list when something has changed, so reports stay small. If the add-on hasn't got a device's list (e.g. after a restore), it asks for it.
- **Newer versions** are highlighted (never alerted) with *Newer: …* under the installed version, and **Only the N with a newer version** filters to them. Find software shows them too.
  - **Windows:** the add-on downloads Microsoft's winget catalogue once a day (a few MB from `cdn.winget.microsoft.com`) and matches programs the way winget does: by their Uninstall key (MSI product code), then by name and publisher. Nothing runs on the servers, so it works on every Windows version, including Server 2016 and 2019. Programs that aren't in the catalogue (most line-of-business software) aren't checked.
  - **Linux:** the newer versions the package manager already knows about (`apt list --upgradable` or `dnf check-update` from its cache).
  - Turn it off with the `software_updates` option. Newer versions need Windows agent 1.0.34 or Linux agent 1.0.15.
- **Manage → Find software** searches every device's list by program or publisher, e.g. *TeamViewer*, and shows which devices have it and which versions. Click a device to open its Software tab.
- This needs Windows agent 1.0.33 or Linux agent 1.0.14.

**Signed-in users:** the Details Overview shows who is signed in. Where there's more than one session, or a Remote Desktop or SSH session, a table lists each one: user, session (console, Remote Desktop or SSH), active or disconnected, idle time and when they signed in. On Windows this comes from `quser`, so disconnected Remote Desktop sessions are included; Windows Home editions only show the console user. On Linux it comes from `who`. Like security events, user names are only shown to Home Assistant admins. This needs Windows agent 1.0.32 or Linux agent 1.0.13.

**Network adapters:** the **Network** tab in Details lists each adapter with its status, link speed, addresses, MAC address, traffic (the average since the previous report) and error counts. Like the ports on an SNMP switch, nothing alerts until you tick **Alert** for an adapter that should always be connected, such as a second LAN, a team member, iSCSI or a backup network. The link speed when you tick it is remembered, so a cable or switch port that drops to a slower speed shows amber. Virtual adapters (Hyper-V vEthernet and the like) are labelled. This needs Windows agent 1.0.31 or Linux agent 1.0.12; the Linux agent leaves out loopback and Docker's own interfaces.

**Acknowledging alerts.** Most alerts on the Overview have an **Acknowledge** button, so you don't need to open each device. The same button is on each amber or red check in a device's details. What it does depends on the alert:

- **Something that happened** (alert-worthy events, security alerts, passwords found in files, changes to the agent's files, and additions to privileged groups such as Domain Admins): everything up to now is acknowledged, so it's green again straight away instead of after 24 hours. Anything new turns it amber again. Security events and failed-logon bursts don't time out at all: they stay until someone acknowledges them.
- **Something that's still the case** (a pending reboot, a stopped app pool, a backup that hasn't run, a disk filling up, an SNMP warning): it counts as OK while it stays as it is or better. If it gets worse (amber to red) it alerts again, and if it clears and later comes back it alerts again too.
- **Not responding**, or a service check that fails (a port or web page): nothing to acknowledge. Pause the device instead.
- **Defender:** a threat is cleared on the device itself; the next agent report then clears the alert. There's no Acknowledge for it.

Acknowledging doesn't send a notification. **N acknowledged**, under the alerts, lists what's acknowledged, who did it and when, each with **Undo**. Event-type acknowledgements drop off that list after 24 hours. Ones you don't need to see, e.g. passwords in files that have to stay, can be **Dismiss**ed (or **Dismiss all**): they stay acknowledged but disappear from the Overview. If the problem comes back or gets worse, it alerts again as usual. Only Home Assistant admins and Rollcall editors can acknowledge.

**Graphs over time.** Rollcall keeps the disk space, network traffic, CPU and memory from each agent report, so you can see how they change, e.g. for capacity planning. **Graph** opens a graph under the item, with ranges of 24 hours, 7 days, 30 days, 90 days and a year. Hover for the figures at that time.

![A server's D: drive over a year: used space against its size, with when it'll be full at that rate](https://raw.githubusercontent.com/shoey79/rollcall/main/docs/images/graphs.png)

- **Disks** (Storage tab): used space against the disk's size. Underneath, how fast it's growing and, if it is, roughly when it'll be full at that rate. The rate is worked out from the daily averages over the last 30 days, or the range shown if that's longer, once there are at least 3 days of history.
- **Network adapters** (Network tab): received and sent traffic for each connected adapter that carries traffic. That's physical adapters, and virtual ones with an address, such as a Hyper-V host's vEthernet: up to 6 per device. **Peak** shows the busiest figure in each period instead of the average. Each figure is the average between two agent reports (every few minutes), so a short burst reads lower than it was.
- **CPU and memory** (**Graph** next to CPU on the Overview tab). CPU is the reading at each report, so it shows how busy the device usually is rather than every spike.
- **History builds up from the update onwards.** Nothing is filled in from before. The traffic graph starts at the second report after the add-on starts, because it's worked out from two reports.
- **Storage:** every report is kept for two days, then as hourly figures for a month, then as daily figures (average, lowest and highest) for `metrics_days`, 365 by default. That's a few MB per device for a year. Deleting a device removes its graphs; **Reset uptime** doesn't touch them.

**Roles** are found from the server's installed Windows roles and services: domain controller, DNS, DHCP, file server, DFS, print server, IIS, Remote Desktop (Session Host, Broker, Gateway, Licensing), Hyper-V, WSUS, Certificate Services, AD FS, NPS, SQL Server, Exchange, SharePoint and Veeam. Each role's services are watched if they're set to start automatically. Roles added or removed later are picked up on the next run.

**Updates.** The last update date is the newest of Windows Update history (which includes MECM and WSUS installs), the Setup event log (every package Windows installs, even with the Windows Update service disabled), and the installed-updates list. Details shows which source it came from, and the OS build. It's re-checked every 6 hours or after a restart, because it can be slow to find. To leave patch compliance to MECM, set `agent_patch_days: 0`; a pending reboot is still flagged.

**Storage health** covers Windows' own RAID (mirrored and RAID-5 volumes on dynamic disks, read with `diskpart`), Storage Spaces, and each physical disk's health, including SMART predicted failures. It also reads two vendors' RAID, which Windows sees only as one healthy-looking disk:

- **Dell PERC, through OpenManage Server Administrator (OMSA).** If `omreport` is installed, each run reads every controller, virtual disk and physical disk. A degraded or failed virtual disk, a failed disk or a controller fault is red; a rebuild or a disk predicting failure is amber. OMSA's chassis health (power supplies, fans, temperatures, voltages, memory, batteries, intrusion) becomes the **Hardware** check. "Hardware Log" (how full the server's own event log is) is shown but doesn't alert.
- **AMD RAIDXpert2.** Its events in the System log ("AMD RAID API") give each array's state. "Goes critical" is red until a rebuild starts; a rebuild in progress is amber with its percentage; "completed" or "goes online" is healthy. The state is remembered, so an array that has been critical for a long time stays red. Disks dropping out, timeouts and remapped bad sectors in the last 24 hours are amber.

Other hardware RAID controllers aren't covered; use the vendor's own alerting.

**Veeam backups.** On a Veeam server, or a device backed up by Veeam Agent, the agent adds a **Backups** check and tab:

- **Backup & Replication** (v12/13): every job's result is read from the *Veeam Backup* event log (backup, replication, backup copy, agent backup jobs managed by the backup server, and others).
  - A failed job is red, with one notification per failed run giving Veeam's reason. A failure Veeam will retry, or a warning, is amber.
  - **Why?** on a job that warned or failed shows what went wrong in its latest run: each VM or item with its result, Veeam's reason and its own warning lines (e.g. *Cannot use CBT…* for a disk), and the run's warning and error lines. Well-known reasons get a 💡 explaining them. On the backup server it's read from Veeam's own record of the run (Veeam's PowerShell module, installed with the console). Backup & Replication 13's module needs PowerShell 7.6, so the agent (Windows agent 1.0.55+) runs the lookup in PowerShell 7 when it's installed; without it, the agent's log says so. Otherwise, and for Veeam Agent jobs, it comes from the warnings and errors in the Veeam event log during the run, which say that a VM warned but not why. Each run is looked up once.
  - **Backup copy jobs** that copy several source jobs log each copy as `<copy job>\<source job>`, and the copy job itself only logs when one of its own sessions ends. So a failed result for the copy job itself (e.g. a failed retry) counts as superseded once copies have finished since it and none of them failed. Its row then shows *Last run failed; N copy sessions have succeeded since*.
  - **A warning you've looked at?** **Acknowledge** on a job that finished with warnings turns it green until the job runs again. If that run warns or fails too, it's back; **Undo** takes the acknowledgement back.
  - **Retired a job on purpose?** **Forget** on its row removes it from the list and its alerts straight away, which is tidier than **Ignore** when you're reorganising jobs. If a job with the same Veeam ID runs again, it comes back on its own. Forgotten jobs are listed under the table with **Bring back**. Jobs that haven't run for 60 days are forgotten automatically.
  - A copy job like that is also judged by its copies for being overdue: its **Last success** is the latest successful copy, and each copy has its own overdue check, so the copy job's own occasional entries don't make it look overdue.
  - Rollcall learns how often each job runs. A job with no successful run for more than about 1½ times its usual gap (at least 26 hours, or 8 days until it has a few runs of history) is amber, with one "backup overdue" notification. That catches a job that has been disabled or silently stopped.
  - Jobs with no run for 60 days are dropped.
- **Agent policies** (Veeam Agents managed by the backup server, *Agent Policy* jobs): the policy's own run only sends its settings to the computers, so on its own it would look overdue while they back up every night. Each computer's backups are listed under the policy as `<policy>\<computer>`, like a copy job's sources, each judged and checked for being overdue on its own, and the policy itself isn't judged by its age. On the backup server the agent (Windows agent 1.0.56+) reads each computer's sessions with Veeam's PowerShell, once an hour (in PowerShell 7 for Backup & Replication 13), or, if there are none, when each computer's latest restore point was made. When the server can't list them, the computers that have their own Rollcall agent fill them in, marked *reported by PC01's own agent*. Reading them through Veeam's PowerShell is built from Veeam's documentation and checked with a stand-in; if it lists nothing on your server, the computers' own agents still fill the policy in.
- **Veeam Agent for Microsoft Windows** on the device itself: each session's result, from the *Veeam Agent* event log. It works whether the agent is standalone or managed by a backup server, through an agent backup job or a backup policy. A failure Veeam Agent will retry is amber; one it won't is red. Overdue runs are spotted the same way as above.
- **Backup for Microsoft 365:** each job's last status, from its PowerShell module, every 30 minutes (loading the module is slow). Failed is red; Warning, Stopped or Disconnected is amber; an enabled job more than 2 hours past its next scheduled run is amber ("missed"). Disabled jobs are listed but not checked.
- **Ignore** on a job in the Backups tab (`backup:<job name>`) leaves it out, e.g. a weekly test job.

**Other backup products** (Windows agent 1.0.56+) go in the same **Backups** check and tab, with the same red, amber, overdue and **Why?**:

- **Veritas NetBackup**, on the primary (master) server: the job list from `bpdbjobs -report -all_columns`. Each policy and client is a job (`Servers / srv01.example.local`), from its finished backups: status 0 is a success, status 1 (partly successful) amber, anything else red, with the status code and what it means (e.g. *status 58: can't connect to client*). Catalog backups are listed too. NetBackup keeps its job list for a few days; the agent keeps each job's history itself, so one that stops running is spotted as overdue.
- **HPE / OpenText Data Protector**, on the Cell Manager: the last week's sessions from `omnirpt -report list_sessions -tab`. Each backup specification is a job: *Completed* is a success, *Completed/Errors* and *Completed/Failures* amber (with the error and warning counts and how many disk agents failed), *Failed* and *Aborted* red.
- Both only list jobs; nothing is changed. Common NetBackup status codes and Data Protector's partial failures get a 💡 hint.
- **Not tested on real installs yet**: neither product is available to test with, so both are built from the vendors' documentation and checked against sample output in that format. If you use one, a sample of the command's output (with names replaced) in a GitHub issue would let it be confirmed.

**Alerted as they happen** (a notification for each):

- **Security log:** account locked out (4740), account created or deleted (4720/4726), member added to a security group (4728/4732/4756, e.g. Domain Admins), audit policy changed (4719), Security log cleared (1102). The IDs are in `agent_security_alert_ids`. Group members that are local accounts are named from their SID, and changes made by the device itself (LAPS, Group Policy) show as `SYSTEM`.
- **System log:** unexpected shutdowns and crashes (Kernel-Power 41, EventLog 6008, BugCheck 1001), disk and NTFS errors, and any Critical-level event. The list is in `agent_event_watch`, as `Source:ID` or just an ID.
- **Microsoft Defender:** every detection, saying whether it was removed.

**Failed logons** are grouped by account and source. Each group shows Windows' reason (e.g. "user name doesn't exist", "wrong password", "account locked out"), the logon type, the method (NTLM, Kerberos) and the client's device name. A user name sent with the domain already in it reads e.g. `contoso\svc_backup (with domain CONTOSO)`, which usually means a saved credential is typed wrongly.

**Details** shows system info, CPU and memory, roles, disk bars, role services, other stopped services, IIS app pools, AD replication partners, DHCP scopes, Hyper-V VMs, printers, RDS sessions, Defender status, the last 24 hours of System and Application errors, and how long each agent run takes (**Agent run**: total time, CPU, peak memory and a breakdown by step). Hyper-V VMs show their uptime, CPU, memory and checkpoints (agent 1.0.58 on; checkpoints older than a week are highlighted). Failed logons and security events are at the top of the **Security** tab, with BitLocker, certificates and the Administrators group; LAPS is on the **Domain** tab, and known vulnerabilities on the **Vulnerabilities** tab. Security events and the Administrators group are shown to admins only.

In Details, **Group Policy** and **Time** are on their own **Domain** tab (and, from 1.94.2, **Domain security** on the PDC emulator). **Microsoft Defender** (Security tab) shows when the last quick and full scans finished (agent 1.0.52 or later). While a device is down, off schedule or its agent has stopped reporting, **Signed in** says nobody (it's off) or not known (no recent report), rather than showing who was signed in at its last report; the same goes for the **Signed-in user** line under the name.

### LAPS

On devices where a LAPS policy applies (agent 1.0.18 or later), Rollcall checks that the managed local admin password is being rotated on the schedule the policy sets. It covers Windows LAPS (from Group Policy, Intune or local configuration, backing up to AD or Entra ID) and legacy Microsoft LAPS (AdmPwd), including Windows LAPS' legacy emulation mode.

- **The policy** is read the way Windows reads it: Intune, then Group Policy, then local configuration, then legacy. That includes the password age and the managed account.
- **The due date** comes from the password's expiry on the computer's own AD object (`msLAPS-PasswordExpirationTime`, or `ms-Mcs-AdmPwdExpirationTime` for legacy LAPS), which is what LAPS itself works from. The device can read the expiry; the password itself is never read. The lookup happens at most hourly.
- **Without AD** (Entra ID backup, or a laptop away from the office), the due date is the last rotation plus the policy's password age. The last rotation comes from the managed account's password-last-set time and Windows LAPS' own events (10018/10029 backed up, 10020 account updated).
- **Alerts:** amber once rotation is more than a day overdue, red once it's more than `agent_laps_overdue_days` (3) overdue. Also amber when the latest LAPS run failed (event 10005, with its error), the managed account doesn't exist, there's no password in AD yet, backup is disabled in the policy, or a legacy policy is set with no LAPS client installed.
- **Away from the domain network:** a laptop that can't reach a domain controller can't rotate or back up its password, so LAPS failing there isn't news. When the LAPS error says it couldn't find a domain controller, or Group Policy and time sync can't reach one either, or Group Policy hasn't applied for over two days, the check says *Hasn't been on the domain network since 9 Nov* (the last time Group Policy applied) instead of the bare error, and stays amber: no alert for LAPS alone. It catches up once the device is back on the network. A device started less than two hours ago is amber rather than red too, since LAPS normally catches up within an hour.
- **Domain controllers:** Windows LAPS manages the DSRM password there, if *Enable password backup for DSRM accounts* is on.
- **Devices without LAPS** don't get the check. To leave it off one server, use **Ignore** (`laps:laps`).

The Domain tab shows the product, where the policy comes from, where it backs up to, how often it rotates, the managed account, when the password was last set and when it expires, the last backup and the last LAPS run.

### BitLocker

Rollcall checks BitLocker on each fixed drive of physical devices (agent 1.0.21 or later; the TPM check needs 1.0.22). It reads the state from Windows (WMI), the same as `manage-bde -status`, and never reads the keys or recovery passwords.

- **Which devices:**
  - **Virtual machines** (Hyper-V, VMware, VirtualBox and others) aren't checked; their drives are still listed.
  - A physical device with a BitLocker-encrypted drive is always checked.
  - One that doesn't use BitLocker is only expected to when it has a TPM, and `agent_bitlocker_require` covers it: `workstations` (Windows 10/11, the default), `all` (servers too) or `off`. No TPM, no warning. A TPM that's turned off still counts as present, and the alert says it's turned off.
  - Devices without BitLocker installed (servers without the feature) don't get the check.
- **The TPM** is read from Windows (`Win32_Tpm`), the same as `Get-Tpm`: its version, maker, and whether it's turned on. The Security tab shows it, and why a device isn't checked when it isn't.
- **Amber** when a fixed drive isn't encrypted, protection is suspended, encryption is paused, the drive is being decrypted, a drive is locked, or the Windows drive has no recovery password (so it couldn't be recovered if the TPM failed). It never goes red: an unencrypted drive isn't an outage.
- **Suspended protection** is often deliberate: Windows Update and firmware updates suspend it until the next restart. When a restart is pending the alert says so, and it clears once the device restarts and protection resumes.
- **Encrypting** shows the percentage and stays green.
- Removable drives (BitLocker To Go) and drives without a letter aren't checked.

The Security tab shows each drive with its state, protection, encryption method and what unlocks it (TPM, PIN, recovery password, password…). To leave out one drive, use **Ignore** on its row (`bitlocker:D:`); to leave the check off a device, **Ignore** the whole check (`bitlocker:bitlocker`).

### Exchange

On Exchange servers (agent 1.0.27 or later), Rollcall checks mail flow and the databases. It's on the **Roles** tab.

- **Queues**, from Exchange transport's performance counters: waiting for delivery, submission, retrying, unreachable and poison. **Amber** at `agent_exchange_queue_warn` (250) or more waiting for delivery, 10 or more unreachable, or anything in the poison queue.
- **Back pressure**, from transport's events (15004–15007). **Red** when it's High, because transport has stopped accepting mail (often a full disk on the queue database's drive). **Amber** at Medium.
- **Server components**, from the state Exchange keeps in the registry. **Amber** in maintenance mode (ServerWideOffline inactive) or when a component such as HubTransport is inactive. ForwardSyncDaemon and ProvisioningRps are normally inactive and don't count.
- **Database copies** (mounted, healthy, copy and replay queues, search index), read every 15 minutes with the Exchange snap-in. **Red** when a copy has failed or is dismounted; **amber** when one is suspended, disconnected or over 10 logs behind, or its search index has failed. The agent runs as the computer's account. If Exchange doesn't let it read database copies, Details says so and everything else is still checked.
- Exchange's certificates, including the Auth certificate, are covered by the [Certificates](#certificates) check.

To leave the check off a server, ignore it (`exchange:exchange`).

### Time

On every domain-joined Windows device (agent 1.0.46 or later), the agent measures how far its clock is from the domain with `w32tm /stripchart`, the same as running it by hand. It's on the **Domain** tab.

- **Domain members** are compared with the domain controller they use; **other domain controllers** with the PDC emulator, which the rest of the domain takes its time from.
- **Amber** when the clock is `agent_time_warn_seconds` (60) or more out, or Windows Time isn't syncing from anything ("Local CMOS Clock", "Free-running System Clock" or NoSync). **Red** at `agent_time_crit_seconds` (240) on two reports in a row: Kerberos refuses sign-ins at 5 minutes, so that's a warning before people can't log on.
- **The PDC emulator** has nothing to compare with, so it's checked for a real time source instead: amber when it runs on its own clock, since the whole domain then drifts with it. Point it at an NTP server (`w32tm /config /manualpeerlist:"pool.ntp.org" /syncfromflags:manual /reliable:yes /update`).
- If the domain controller can't be reached for the comparison, the check says so and stays green, rather than alerting for something the time isn't to blame for.
- Can be ignored on a device (`time:time`).

### Resources (memory and CPU)

Every agent (Windows, Linux and the OpenWrt router agent) is checked for memory and CPU:

- **Memory** is amber at `agent_memory_warn` (90%) used and red, with an alert, at `agent_memory_crit` (95%) for two reports in a row. Memory used is worked out from what the system reports as available (`MemAvailable` on Linux and routers, free physical memory on Windows), the same figure as in Details.
- **CPU** is amber when it's at `agent_cpu_warn` (90%) or more in each of the last `agent_cpu_reports` (3) reports, about 15 minutes. Each report's reading is a moment, so one spike doesn't count, and a missed report starts the count again. CPU is never red: busy isn't broken.
- **Routers** (router agent 1.0.2 or later) are also amber when the 15-minute load is above the number of CPU cores, a sign the router can't keep up.
- **SQL Server and Exchange** keep most of a server's memory for themselves by design, so memory isn't checked on those servers unless you give the device its own memory limits.
- **Each device can have its own limits**: in Details, under **System**, choose **Change** next to the Resources line. Blank uses the add-on's setting, 0 turns that one off, and **Don't check memory or CPU on this device** turns the check off.

### Group Policy and SYSVOL replication

**Group Policy** is checked on every domain-joined device (agent 1.0.26 or later), from Group Policy's own results in the System log.

- **Amber** when the latest result is a failure and policy hasn't applied for 3 hours. Policy refreshes every 90 minutes or so, so a failure at start-up (before the network is up) that the next refresh fixes doesn't alert.
- Failures are explained, e.g. *Couldn't read a policy from SYSVOL* (1058), *Couldn't find a domain controller* (1054), *No network connection to a domain controller* (1129), *A settings extension failed* (1085), with Windows' own message.

**SYSVOL replication** is checked on domain controllers, using DFS-R's state for the SYSVOL folder and its event log over the last 7 days.

- **Red** when DFS-R has stopped replicating SYSVOL: after an unclean shutdown (event 2213, which needs resuming with the command in the event), because the DC was offline longer than DFS-R allows (4012, which needs a non-authoritative sync), or the folder is in error.
- **Amber** while it can't reach a partner for over an hour (5002/5008/5014 with no 5004 since), during initial sync or recovery, or while SYSVOL still replicates with FRS. FRS isn't supported from Windows Server 2019; migrate with `dfsrmig`.

Group Policy is on the **Domain** tab, with Time; SYSVOL replication is on the **Roles** tab, as part of the domain controller role. Each can be ignored on a device (`gpo:gpo`, `sysvol:sysvol`).

### DFS Replication

**DFS Replication** is checked on servers with the DFS Replication role (agent 1.0.44 or later), for every replicated folder except SYSVOL (checked above on domain controllers). It uses DFS-R's state for each folder and its event log over the last 7 days, and is on the **Roles** tab with each folder's state and the recent DFS-R events.

- **Red** when replication has stopped: after an unclean shutdown (event 2213, which needs resuming with the command in the event), because the server was offline longer than DFS-R allows (4012, which needs a non-authoritative sync), its database couldn't be recovered (2104), a folder is in error, or the DFS Replication service isn't running. Like other serious agent checks, it turns red on the second report in a row.
- **Amber** while DFS-R recovers its database after an unclean shutdown (2212, until 2214 or every folder is back to normal). This is often a long scan of the volume, during which files can be slow or unavailable even though the server answers. Also amber while a folder is in initial sync or auto recovery, or when it can't reach a partner for over an hour (5002/5008/5014 with no 5004 since).
- **Any other DFS-R error** in its event log in the last 24 hours also turns it amber, e.g. **6404** (a replicated folder's local path is invalid or can't be reached), until that folder has been back to normal for an hour or the error hasn't recurred for a day. They're listed under **Other errors and warnings** with how many times each happened; common ones are named (6404, sharing violations 4302/4304, staging space 4202/4206) and the rest show Windows' own first line. Warnings are listed but don't alert (agent 1.0.46).
- A folder that's expected to be out of step can be ignored with **Ignore** next to it (`dfsr:Folder name`); an error by its ID (`dfsr:event:6404`); the whole check with `dfsr:dfsr`.

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
- **Runs missed while the computer was off don't count.** Windows counts those as missed too, so a server started in the morning would otherwise report every overnight run it slept through. Rollcall compares them with when the computer started: runs missed before then show as *Missed while off* and don't alert. A task that then still hasn't run a day after start-up (a week for weekly tasks) is amber again, and so is one that hasn't run for over a week because its runs always fall while the computer is off (Rollcall suggests ticking *Run task as soon as possible after a scheduled start is missed*).
- **Rollcall's own agent task** (*Rollcall Agent*, every 5 minutes) isn't watched here: the agent's reports already show whether it runs.
- **Not alerted on:** disabled tasks; tasks that are running; results that just mean "ready" or "hasn't run yet"; and other vendors' updaters that fail routinely (Edge, Google, OneDrive, Adobe, Mozilla, Intel, NVIDIA and similar), which show as *Not watched*.
- **Servers only.** Windows 10/11 PCs list their tasks but don't alert, as they're full of vendor tasks.
- It clears once the task next runs successfully. To leave one out, use **Ignore** on its row (`task:<name>`); to leave the check off a server, ignore the whole check (`task:tasks`).

### Certificates

The agent (1.0.23 or later) lists the certificates with a private key in the device's **Personal**, **Remote Desktop** and **Web Hosting** stores, and when each expires. That covers certificates the network check can't see, such as LDAPS on domain controllers, SQL Server, RD Connection Broker and internal services. Keys are never read.

- **Amber** within `cert_warn_days` (30) of expiry, **red** within `cert_crit_days` (7) or once expired. These are the same options as the network certificate check.
- **Renewals don't alert.** When a newer certificate with the same name is valid, the old one is marked *Replaced*. A certificate that expired over 30 days ago and isn't bound to anything is marked *Old, not in use*. Neither counts.
- **Used by** shows what a certificate is bound to: HTTPS bindings (IIS, RD Gateway, WinRM, ADFS), from `netsh http show sslcert`, and the Remote Desktop listener. Services such as LDAPS and SQL Server pick a certificate themselves, so every certificate counts, bound or not.
- Windows' own self-signed Remote Desktop certificate isn't checked, because Windows renews it.
- To leave one out, use **Ignore** on its row (`cert:<thumbprint>`, or `cert:<name>`); to leave the check off a device, ignore the whole check (`cert:certs`).

### Domain security

The domain-wide checks run on one domain controller only: the one holding the **PDC emulator** role (agent 1.0.28 or later). They're read from Active Directory once an hour, as the DC's own account, and are on its **Domain** tab, with Group Policy and Time. Like security events, they're shown to admins and editors only.

- **Privileged groups:** the members of Domain Admins, Enterprise Admins, Schema Admins, Administrators, Account Operators, Server Operators, Backup Operators, Print Operators, DnsAdmins and Group Policy Creator Owners. Rollcall remembers who was there; anyone added later is highlighted with the time, and the check is **amber for 24 hours**. Removals are listed too. Members there when Rollcall first looked show as *before monitoring*. The DC's security log still reports each change as it happens (events 4728/4732/4756); this check covers changes made on any DC and gives the full picture.
- **KRBTGT:** **amber** once its password is over 180 days old. Reset it twice, some hours apart, so tickets issued with the old key expire in between.
- **Accounts that don't require a password** (enabled, with *password not required* set): **amber**. To accept one, use **Ignore** on its row (`aduser:<name>`).
- **For review, without alerting:** enabled accounts whose password never expires, and enabled users and devices with no logon for 90 days. *Last logon* is AD's replicated value (`lastLogonTimestamp`), which can be up to 14 days behind.

To leave the check off, ignore it (`domain:domain`).

### Administrators group

The Security tab (admins only, agent 1.0.17 or later) lists every direct member of the device's built-in Administrators group, with its type (user or group), where it's from (Local, Domain, Azure AD, Built-in) and its SID.

- The built-in Administrator and disabled local accounts are marked. A SID Windows can't name shows as "Unknown (deleted?)", usually an account that has since been deleted. An Azure AD (Entra ID) SID is labelled as such.
- Groups in the list (e.g. Domain Admins) are listed, not expanded into their members.
- On a domain controller, this is the domain's built-in Administrators group.
- Rollcall remembers the list. Anyone added after it first looked shows the date they appeared and is highlighted for 30 days. Additions and removals are listed under **Changes**, at the agent's next report. Additions also raise the usual 4732 security-event alert.

### System file check

An optional weekly `sfc /verifyonly` (agent 1.0.59 or later): Windows' own check that its system files are as they should be. It's read only, the `/verifyonly` form, which never repairs or changes anything.

- **Turning it on:** `agent_sfc` chooses which devices run it (`off`, `servers`, `workstations` or `all`; off by default). Each device can also be turned on or off in its details, under **System files**, whatever the setting.
- **When:** weekly, on `agent_sfc_day` at `agent_sfc_hour`, in each device's own time. A device that's off then runs it the next time it's on. **Run now** in its details starts one at the agent's next report.
- **It takes 10 to 30 minutes of CPU and disk**, so it runs in the background at low priority, separately from the agent's 5-minute run, which carries on as usual.
- **The result** is read from Windows' own log of the check (`CBS.log`), not sfc's screen output, which is unreliable. **System files** goes amber when files don't match what Windows expects, naming them, with what to run to repair them (`DISM /Online /Cleanup-Image /RestoreHealth`, then `sfc /scannow`). It's never red: nothing is down because of it. It says so when it couldn't run (another update or repair in progress, or a restart pending).
- **DISM too:** with `agent_sfc_dism` on, `DISM /Online /Cleanup-Image /ScanHealth` (also read only) follows it, which checks the component store that Windows repairs system files from.

### Tuning

**From Details (admins):**

- **Ignore** appears next to anything that's flagged: stopped services (role or otherwise), stopped IIS app pools and sites, printers, VMs in a critical state, busy DHCP scopes, event IDs, whole disks and backup jobs. It applies to that server straight away and clears the alert.
- **Ignored on this server** (at the bottom of Details) lists everything ignored there. **Apply to all servers** makes an item global; **Stop ignoring** undoes it, and anything still wrong goes red again immediately.
- **Disks → Change** sets that disk's own amber and red levels (% free), e.g. amber below 8% and red below 3% for a large data volume. Leave a box blank to use the default, or enter 0 to turn that level off. **Use defaults** removes the override.
- **Acknowledge**: the Events and Security checks stay amber for 24 hours after something alert-worthy. **Acknowledge** (on the check's card in the Overview, or at the top of the Events or Security tab) turns them green without ignoring anything. The items stay listed, greyed out, and anything new turns the check amber again. On the Security tab it also covers a burst of failed logons, which turns Security red: acknowledging it turns the check green until a later report has another burst. It records who acknowledged it and when; **Undo** puts it back. To stop a recurring event alerting at all, use **Ignore** on it instead.

- **Security filters**: for security events and failed logons that are expected and low-risk, so they stop alerting. See below.

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
- For a local account on the device the event came from, the account is suggested as `*\name`, so one filter covers that account on every device.
- The form says how many of the listed events the filter matches before you save it, and warns if it would hide every event of a type.
- **What a filter does:** matching events don't notify and don't turn the Security check amber. They're still listed, greyed out, with the note. It applies straight away, including to events from the last 24 hours, so an alert it covers clears now.
- **Security filters**, under the events, lists every filter for this server and for all servers, with who added it and when. **Apply to all servers** widens one; **Remove** deletes it, and matching events from the last 24 hours count again.
- A filter needs at least an event type or one pattern. Each add and removal is logged with who did it.

**Failed logons** can be filtered the same way, for ones that are expected every time, such as a service that tries the wrong account, or a Remote Desktop Gateway that signs in to its own Remote Desktop service as the server's name and gets "user name doesn't exist" for each user who logs in. Choose **Filter…** next to a line in **Failed logons**:

| Part | Matches | Example |
|---|---|---|
| Account | The account in the failed logon | `CONTOSO\SRV01`, `*\scanner` |
| From | The address or device it came from | `::1` (the server itself), `192.168.1.*` |
| Reason | Windows' reason | `user name doesn't exist`, `wrong password` |

Matching failed logons stay listed, greyed out with the note, and the count shows how many were filtered. They don't count towards `agent_failed_logons`, so they no longer turn Security red; failed logons that don't match still do, and the Security check names only those. They're listed under **Security filters** with the event filters.

The agent sends the five busiest groups of failed logons in each report, plus the total, so a filter works on those five. That suits expected noise, which is always among the busiest.

Keep filters narrow. "Added to Administrators, by anyone" would hide exactly the change you want to hear about; "LAPSAdmin added to Administrators by SYSTEM" doesn't. Filters work for the Linux agent's security events too.

**From the Configuration tab (all servers):**

- `agent_disk_warn` / `agent_disk_crit`: the default disk thresholds.
- `agent_ignore`: known noise. A service name (`MapsBroker`), or `event:10016` (the DCOM permission errors), `apppool:OldTestPool`, `site:Default Web Site`, `disk:E:`, `dhcp:10.0.6.0`, `printer:Old MFP`, `vm:TEST01`, `storage:E:` (a volume, disk or array), `backup:<job>`, `laps:laps`, `bitlocker:D:` (one drive) or `bitlocker:bitlocker` (the whole check), `cert:<thumbprint>` or `cert:certs`, `task:<name>` or `task:tasks`, `sqldb:<name>`, `sqljob:<name>` or `sqldb:sql`, `gpo:gpo`, `sysvol:sysvol`, `exchange:exchange`, `domain:domain`, `aduser:<name>`, `update:immich`.
- `agent_watch_services`: services to watch on every server, even manual-start ones (e.g. `AcmeBackupAgent`).
- `agent_event_alerts` / `agent_security_alerts`: turn those alert types off.

Pausing a device silences its agent alerts too.

### Passwords left in files

The agents can look for passwords saved in plain text: in scripts, configuration files, notes, spreadsheets, setup answer files and command histories. It's off unless you turn it on.

> **Passwords never leave the device.** The agent reads the files on the device itself. For each password it finds, it sends Rollcall only:
> - the file's path
> - the line number (for Word files, the paragraph number)
> - what kind of thing it is, e.g. *Password in a database connection string*
> - the name of the setting, e.g. `DbPassword` (letters, digits and `._-` only)
> - how many characters the password has
>
> It never sends the password, any part of it, a hash of it, or the text around it. The agent measures the value and then drops it; nothing it stores between runs holds it either. Rollcall keeps only those five details, whatever an agent sends, and only Home Assistant admins and Rollcall editors can see them. File and folder names are sent as they are, so you can find the file.

**Turning it on**

- The `agent_secret_scan` option picks which devices scan by default: `off` (the default), `servers`, `workstations` (Windows 10 and 11) or `all`.
- To change one device, open its Details → **Security** → **Passwords left in files** → **Scan settings for this device**. Choose **On** or **Off**, add extra folders (one per line, e.g. `D:\Shares\IT` or `/etc/myapp`), and choose how often a full scan runs (every 24 hours by default).
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
- **Ignore all:** accepts everything found so far on that device, e.g. after checking a first scan's false positives. Anything found later turns it amber again, marked **New**, and **Ignore all** accepts those too. A finding that only moves because lines were added or removed above it isn't new. **Undo** brings them all back.
- **Turning it off** for a device removes its check and Rollcall's findings straight away. The agent deletes its own scan files on its next run.
- To try it on a folder without sending anything:
  - Windows: `RollcallAgent.ps1 -SecretTest D:\Shares`
  - Linux: `python3 rollcall-agent.py --secret-test /srv`

  Each prints what would be reported.

### Agent security

- **The agents keep their own files locked down.** Each run, the Windows agent checks that its folder (`C:\ProgramData\Rollcall`) and everything in it still belong to SYSTEM or Administrators, give nobody else access and don't take permissions from the folder above. The Linux agent checks its script, settings, data folder and systemd units are root's and not open to others. Anything changed, e.g. someone giving themselves access to read the log, is put back. Rollcall's **Agent files** check then says who changed it and when it was put back, e.g. *Its folder's permissions were changed by CONTOSO\admin; the agent reset them at 14:32 on 19 Nov* (Windows doesn't record who changes permissions, so the "who" is whoever took ownership to change them; otherwise it names the accounts given access). The full list is under **What the agent found** in Details. It's amber for 24 hours or until you press **Acknowledge** (on the check, or in the Security tab), and visible to admins and editors only. A later change turns it amber again. The first check after the agent updates only tidies up, without the amber, as hand-installed agents on Windows 10/11 are owned by whoever installed them.
- **The password scan never sends passwords**, only where each one is (see [Passwords left in files](#passwords-left-in-files)).
- **Nothing runs on the servers at the add-on's request**, apart from an agent update you've turned on, signed with a key only Rollcall has (see [Updating agents automatically](#updating-agents-automatically)), and messages to users' screens if you turn them on (see [Messages to users' screens](#messages-to-users-screens)).
- **Limit who can reach the agent ports.** Allow TCP 8100 (and 8101 with HTTPS on) at your firewall only from the networks your agents report from.
- **Each server has its own token**, generated on the server and stored in `C:\ProgramData\Rollcall` (readable only by SYSTEM and Administrators). The add-on keeps only a hash of it.
- **The enrolment key only lets a server ask to join.** Nothing is accepted until an admin approves it, so a leaked key can't feed data in. **Rotate key** under Agents if needed; approved servers keep working.
- **Revoke** stops a server's reports. Deleting a device from the dashboard also revokes its agent. A revoked or rejected copy can't ask again; to re-add the server, run `-Uninstall` then `-Install` on it.
- **Reports can go over HTTPS with Rollcall's own certificate** (see [HTTPS for agents](#https-for-agents)). Without it they go over plain HTTP, readable on your network. Using your own certificate on the agent port instead (`agent_ssl`, with `agent_certfile` and `agent_keyfile` in Home Assistant's `/ssl` folder) still works; **Accept a self-signed certificate** then makes agents accept any certificate, so it keeps reports private but doesn't stop something else standing in for Rollcall. Rollcall's own HTTPS does.

---

## Linux agent

One Python file (`rollcall-agent.py`, Python 3.8+, standard library only, so nothing to install on Ubuntu 20.04 or newer). It uses the same enrolment, approval, alerts, Details, Ignore buttons and disk thresholds as the Windows agent, and shows as **Linux ✓** on the dashboard.

### Setting it up

1. In the dashboard, open **Manage → Agents** and use **Download rollcall-agent.py**. It uses the same address as the Windows script, so check that first.
2. Copy it to the server, e.g. `scp rollcall-agent.py admin@server:`
3. On the server, run `sudo python3 rollcall-agent.py --install`.
   - For Immich's job queues and statistics, add an API key created by an Immich admin with the `server.statistics`, `server.storage`, `job.read` (or `queue.read`) and `systemMetadata.read` permissions (Immich → Account Settings → API Keys; Immich before 1.138 needs `all`): `sudo python3 rollcall-agent.py --install --immich-api-key YOUR_KEY`. To keep the key out of the process list while it installs, use `--immich-api-key -` and paste it when asked, or set `RC_IMMICH_API_KEY` (e.g. `sudo RC_IMMICH_API_KEY=… python3 rollcall-agent.py --install`).
   - If Immich isn't in a local container, add `--immich-url http://host:2283`.
4. Approve it under **Agents → Waiting for approval**.

It installs to `/usr/local/lib/rollcall/` and adds a systemd timer (`rollcall-agent.timer`, every 5 minutes, at low CPU and disk priority). Its token and log are in `/var/lib/rollcall/`, and its settings, including the API key, in `/etc/rollcall/agent.conf` (all root only).

Agents installed before 1.0.25 used the old name (`pingmonitor-agent.py`, `/var/lib/pingmonitor`, `/etc/pingmonitor`, unit `pingmonitor-agent`). They move themselves when they update, as the Windows agent does: the new unit has to report before the old one is removed, and a failed move leaves the old one running and says why.

| Command | Does |
|---|---|
| `--install` | Installs or updates the agent |
| `--uninstall` | Removes it |
| `--report` | Prints what it would send |

`systemctl status rollcall-agent` and `/var/lib/rollcall/agent.log` show what it's doing.

### What it checks

| Check | Goes amber | Goes red (and alerts) |
|---|---|---|
| **Agent** | A run slower than `agent_slow_seconds` | No report for `agent_stale_minutes` |
| **Disk** | A mount point under its amber level | Under its red level (per mount, e.g. `/` or `/srv/photos`) |
| **Services** | A failed systemd unit | A Docker container that should be up is stopped, unhealthy or restarting, or docker, containerd, ssh or cron stopped (two reports in a row) |
| **Storage** | An array rebuilding | A degraded software RAID (mdadm, from `/proc/mdstat`) array or ZFS pool, or a failed member |
| **Updates** | Reboot required, security updates waiting with nothing installed for a week, or nothing installed for `agent_patch_days` | |
| **Vulnerabilities** | A known vulnerability scoring `vuln_min_score` (9) or more in a package that a newer version fixes (Debian, Ubuntu, AlmaLinux and Rocky Linux; agent 1.0.20 or later; see [Known vulnerabilities](#known-vulnerabilities)) | One that's known to be exploited |
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

### Proxmox VE and Backup Server

On a Proxmox VE host (agent 1.0.24 or later) the Linux agent adds a **Proxmox VE** check and section; on a Proxmox Backup Server, a **Proxmox Backup Server** one. Nothing to set up: it's found from `pvesh` and `proxmox-backup-manager`, and only read (`get`, never `set`).

- **The cluster:** quorum and each node online or not (a standalone host says so).
- **VMs and containers** on the cluster: state, node, uptime, CPU and memory, and HA state.
- **Storage** (enabled, active, how full, what it holds) and **ZFS pools** (health and how full).
- **Replication jobs**, **HA resources**, **Ceph**'s health if it's there, and the **subscription** and pending updates (from apt, like any Linux host).
- **Backups:** each vzdump job's result goes on the **Backups** tab, like Veeam's: a failed backup is red, with its log, and **Acknowledge** works the same.
- **Proxmox Backup Server:** each datastore's use, and the last verify, prune, garbage collection and sync jobs (shown with their results; only the datastores alert).

| | Amber | Red (and alerts) |
|---|---|---|
| **Proxmox VE** | A node offline (fewer than half); storage not active or 90% full; a ZFS pool DEGRADED; a replication job failing; Ceph HEALTH_WARN | Quorum lost; half the nodes or more offline; storage 97% full; a ZFS pool FAULTED or worse; an HA resource in error, fence or recovery; Ceph HEALTH_ERR |
| **Proxmox Backup Server** | A datastore 90% full | A datastore 97% full or with an error |

Install the agent on each node you want watched; a cluster's guests, storage and quorum show on every node that has it.

## OpenWrt agent

For routers and other small Linux that can't run Python: one shell script (`rollcall-agent.sh`) using only what OpenWrt has built in (BusyBox, `ubus`, `jsonfilter`, `uclient-fetch`), so there's nothing to install. It uses the same enrolment, approval, alerts, Details and Ignore buttons as the other agents ([#12](https://github.com/shoey79/rollcall/issues/12)).

### Setting it up

1. In the dashboard, open **Manage → Agents** and use **Download rollcall-agent.sh** on the OpenWrt card.
2. Copy it to the router, e.g. `scp -O rollcall-agent.sh root@192.168.1.1:/tmp/` (`-O` for routers without SFTP).
3. On the router run `sh /tmp/rollcall-agent.sh --install`.
4. Approve it under **Agents → Waiting for approval**.

It copies itself to `/etc/rollcall/` (with its token), adds that folder to `/etc/sysupgrade.conf` so it's kept through firmware upgrades, and adds a cron job that runs it every 5 minutes. Its log is `/tmp/rollcall-agent.log`, which is in memory and cleared on restart; once it passes 32 KB only the latest 16 KB is kept, so it can't fill a small router's memory. After joining it writes nothing to flash: what it keeps between runs is in `/tmp`. Only one run goes at a time: if a run is still going when cron starts the next, the new one is skipped, and a run stuck for 10 minutes is stopped. Each `ubus` call gives up after 10 seconds. The router agent doesn't update itself: to update it, download it again and repeat steps 2 and 3 (it keeps its token). For an HTTPS address the router needs `ca-bundle` and an SSL library for `uclient-fetch`, which recent OpenWrt includes; if `curl` is installed it's used instead. OpenWrt's `uclient-fetch` can't add request headers, so the router sends its token inside each report rather than in a header; as with the other agents, use an HTTPS address for routers that report over the internet.

It doesn't update itself: to update, download it again and run `--install` again. Approval is kept.

| Command | Does |
|---|---|
| `--install` | Installs or updates the agent |
| `--uninstall` | Removes it, its cron job and its `/etc/sysupgrade.conf` line |
| `--report` | Prints what it would send |

### What it checks

| Check | Goes amber | Goes red (and alerts) |
|---|---|---|
| **Agent** | A run slower than `agent_slow_seconds` | No report for `agent_stale_minutes` |
| **Disk** | A mount point under its amber level | Under its red level (the overlay, i.e. the router's free flash, and any USB or other storage) |
| **Services** | | An OpenWrt service that's enabled to start isn't running (two reports in a row) |
| **Internet (WAN)** | Only an IPv6 connection (e.g. `wan6`) down: many ISPs don't provide IPv6, so ignore it if yours doesn't | An internet connection (e.g. `wan` over DHCP or PPPoE) that's set to start is down (two reports), with OpenWrt's reason, e.g. `AUTH_FAILED` |
| **Security** | | `agent_failed_logons` or more failed SSH (dropbear) or LuCI sign-ins in one report |
| **Network** (adapters you tick) | A ticked interface disabled, or its link slower than when it was ticked | A ticked interface disconnected or gone (two reports) |

- **Resources:** memory and CPU are checked as on other agents (see [Resources](#resources-memory-and-cpu)), and the router is amber when its 15-minute load is above its number of CPU cores (router agent 1.0.2 or later).
- **Details** shows the model and OpenWrt version, uptime, CPU, memory and load, each interface's addresses, traffic, errors and drops, and the internet connections (protocol, address, gateway, DNS servers, how long they've been up) on the **Roles** tab.
- **Internet connections** are the interfaces named `wan…` or with a default route. One can be ignored by its name with **Ignore** in Details (`wan:wan6`).
- **Failed sign-ins** come from the system log (`logread`): who, from where and how many times, each counted once.
- Updates, vulnerabilities and the journal aren't checked: OpenWrt is updated by flashing new firmware.

## pfSense, OPNsense and FreeBSD agent

One shell script (`rollcall-agent-freebsd.sh`) for pfSense, OPNsense and plain FreeBSD, using only what they have built in, plus `curl` (pfSense and OPNsense include it; on FreeBSD, `pkg install curl`). Read only: it never changes the firewall's settings. For OPNsense without installing anything, see [OPNsense](#opnsense).

### Setting it up

1. In the dashboard, open **Manage → Agents** and use **Download rollcall-agent-freebsd.sh** on the pfSense / OPNsense / FreeBSD card.
2. Copy it to the firewall, e.g. `scp rollcall-agent-freebsd.sh admin@192.168.1.1:/tmp/` (pfSense: enable SSH under *System → Advanced*).
3. On the firewall, as root (pfSense: shell option 8), run `sh /tmp/rollcall-agent-freebsd.sh --install`.
4. Approve it under **Agents → Waiting for approval**.

It copies itself to `/usr/local/etc/rollcall/` (with its token) and adds a cron entry in `/usr/local/etc/cron.d/`, both under `/usr/local`, which pfSense and OPNsense keep through upgrades. Its log is `/var/log/rollcall-agent.log`. It doesn't update itself: to update, download it again and run `--install` again (approval is kept). After a major pfSense or OPNsense upgrade, check it's still reporting. With HTTPS on, reports go over HTTPS from the start, checked against Rollcall's own certificate authority built into the download.

| Command | Does |
|---|---|
| `--install` | Installs or updates the agent |
| `--uninstall` | Removes it and its cron entry |
| `--report` | Prints what it would send |

### What it checks

| Check | Goes amber | Goes red (and alerts) |
|---|---|---|
| **Agent** | A run slower than `agent_slow_seconds` | No report for `agent_stale_minutes` |
| **Disk** | A filesystem under its amber level | Under its red level |
| **Storage** | | A ZFS pool that isn't ONLINE |
| **Firewall** (pfSense, OPNsense) | Packet loss or high delay on a gateway; an IPsec tunnel or OpenVPN client down; a CARP address in INIT; the state table over 90% full | A gateway down (two reports) |
| **Temperature** | A sensor at 85 °C or more | 95 °C or more |
| **Network** (adapters you tick) | A ticked interface disabled or slower | A ticked interface down or gone (two reports) |

- **Gateways** come from the firewall's own monitoring (dpinger): delay, its variation and loss for each. One can be ignored by its name with **Ignore** in Details.
- **IPsec:** tunnels that are up, and site-to-site ones that aren't. Mobile-client (road warrior) connections aren't expected to be up, so they're counted but never alerted.
- **Updates** (pfSense) are checked once a day, because the check takes several seconds: shown, never alerted.
- **Temperatures:** a firewall in a virtual machine has no sensors, and the Details say so.
- Memory and CPU are checked as on other agents, and interfaces show their traffic and errors.

---

## Known vulnerabilities

Devices with an agent get a **Vulnerabilities** check: known vulnerabilities (CVEs) in what's installed, from public data the add-on downloads once a day. Only vulnerabilities that an update fixes count, so each one has something to do about it.

- **Amber:** a vulnerability scoring `vuln_min_score` or more out of 10 (its CVSS base score; 9 by default, which is "critical"). Amber isn't notified, like other amber checks.
- **Red, and notified:** any vulnerability, whatever its score (so it's listed even below `vuln_min_score`), on CISA's [Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) list, or that Microsoft says is being exploited, whatever its score.
- The **Software** tab in Details lists each one, worst first: the CVE (linked to cve.org), its score, what it's in, the installed version and the version or Windows build that fixes it. Vulnerable packages are marked in the list, with **Only the N with known vulnerabilities** to filter, and **Find software** marks them too.
- **Acknowledge** keeps it green while the list stays the same; a new vulnerability alerts again. It clears by itself once the update is installed.
- **End-of-life systems kept on purpose** (e.g. Windows 10 without extended security updates): list their OSes in `vuln_skip_os` (Settings, **End-of-life operating systems**), one per line, or tick **Treat this device as end of life** in one device's Vulnerabilities tab. Their vulnerabilities are still listed there, with a note saying why, but never turn the device amber or red or notify, known-exploited ones included. An entry is matched as whole words against the OS the agent reports: `Windows 10` doesn't match Windows 11 (but does match Windows 10 Enterprise LTSC), `Ubuntu 20.04` matches `Ubuntu 20.04.6 LTS`, and `Windows Server 2012` includes 2012 R2.
- Like other security details, the list is only shown to Home Assistant admins and editors; others see the check's colour.
- Turn it off with `vuln_checks`. Its alerts are emailed under **Security**.

**Windows** (any agent version): Microsoft publishes, for each CVE, the Windows build that fixes it, e.g. `10.0.17763.6414`. Rollcall downloads the last 12 months of Microsoft's security update data (the MSRC API, `api.msrc.microsoft.com`) and compares each device's build, which the agent already reports with its update revision. Desktop Windows and Windows Server are compared separately: some share a build number (Windows 11 24H2 and Server 2025 are both 26100; Windows 10 1809 and Server 2019 are both 17763) but are updated separately, with their own revisions. A device further behind than 12 months is flagged by the **Updates** check anyway; a Windows version Microsoft hasn't updated in that time is shown as probably out of support. Only Windows itself is checked: other programs (including Office, SQL Server and Exchange) aren't yet. Devices that get hotpatch updates are compared with the monthly updates, so they may show fixes as missing until their next baseline update.

**Linux** (Linux agent 1.0.20 or later, which sends each package's source package and the distro's release): Debian, Ubuntu (not the Pro or FIPS streams), AlmaLinux and Rocky Linux, using [OSV.dev](https://osv.dev)'s data. A package counts when a newer version fixes a vulnerability, not for issues the distro hasn't fixed. Where several versions of a package are installed (e.g. an old kernel left beside the running one), the newest counts. Scores come from the CVSS 3 vector in OSV's record; a vulnerability without one counts only if it's known to be exploited. `vuln_linux_source` chooses where the matching is done:

- `local` (the default): the add-on downloads OSV's data for each distro your agents run, once a day (`storage.googleapis.com`), and matches it itself. Nothing about your devices is sent anywhere. These downloads are larger, and building the index takes a little while on slow hardware.
- `online`: the add-on sends OSV.dev's API (`api.osv.dev`) one combined list of the package names and versions across all your Linux devices, once a day and when a list changes, and fetches the details of what applies. No device names, addresses or which device has which package are sent. Downloads are small.
- `off`: Linux devices aren't checked.

The add-on needs to reach `api.msrc.microsoft.com`, `www.cisa.gov`, and `storage.googleapis.com` or `api.osv.dev`. If one can't be reached, the Vulnerabilities tab says so, and the data already downloaded is used until it can.

## Offline use

For a network without the internet (an airgapped one), turn on `offline` (**Offline (no internet)** in Settings). Rollcall then downloads nothing and doesn't warn that it can't:

- **Vulnerability data** (Microsoft, CISA, OSV.dev) and **the winget catalogue** (for software updates on Windows) come from a bundle you import instead.
- Jellyfin's latest release isn't looked up, so its "update available" can't show. (Immich's is looked up by the Linux agent on the Immich server, not by the add-on; without the internet it simply finds nothing.)
- Hints from AI need the internet, so leave them off.
- Nothing else changes: checks, agents, alerts and the dashboard need no internet.

**Getting the data in:** on a Rollcall that has the internet, open **Manage → Offline data** and **Download offline data**. That file holds only the vulnerability lists and the winget catalogue: no devices, settings, keys or anything about that network. Take it to the offline Rollcall and **Import** it under the same menu. Devices are checked against it straight away. The Vulnerabilities and Software tabs say the data is offline and how old it is, so refresh it as often as you'd like it to be current.

**Installing the add-on without the internet:** the add-on is built from Home Assistant's base image and a few Alpine packages (`python3`, `py3-aiohttp`, `py3-cryptography`, `py3-regex`, `iputils`, `tzdata`, `msitools`), so a Home Assistant with no internet needs those from a local mirror, or the add-on's image copied in. Once it's running it needs nothing from outside.

---

## Agent addresses and updates

### Inside and outside addresses

Under **Agents → Where the agents report to** there are two addresses: **Inside your network** (e.g. `http://192.168.1.5:8100`) and, optionally, **From outside** (e.g. `https://rollcall.example.com:8100`).

- Downloads have both built in. Agents try them in order and remember which one worked, so a laptop away from the office goes straight to the outside address next time. An address that can't be reached is skipped after 3 seconds.
- **Internal networks** (recommended when you use both addresses): list your internal subnets, e.g. `10.0.1.0/24, 192.168.1.0/24`. If none are set yet, Rollcall offers Home Assistant's own networks. Each agent then chooses at every report, going by its own IPv4 addresses: on one of those networks, the inside address first; anywhere else, the outside one first. If that doesn't answer, it uses the other, and goes back to its usual one at the next report. Without them, one failed attempt at the inside address (e.g. during a restart) can leave an agent on the outside address until that stops working. Needs Windows agent 1.0.42 or Linux agent 1.0.19.
- The **Approved** list shows which address each agent last reported through, **internal** or **external**. With internal networks set, it's marked ⚠ when that doesn't match the agent's own address (an older agent, or one that had to fall back).
- Changes are saved straight away and sent to every agent with its next report (Windows agent 1.0.15 and Linux agent 1.0.9 or later), so installed agents follow them without a new download. Each agent also keeps the address it was installed with as a last resort, so a mistake here can't cut it off.
- Each report records which address it was sent to and where it came from, shown in the agent's Details.

For the outside address to work, forward its port on your firewall to Home Assistant's agent port, or publish it through a reverse proxy, and use HTTPS (`agent_ssl`). Otherwise reports and each server's token cross the internet unencrypted. Servers still have to be approved, and every report is checked against that server's own token.

### HTTPS for agents

Rollcall can secure agent reports itself, with nothing to buy or install. Under **Agents → Where the agents report to → HTTPS**, choose **Turn on HTTPS** (admins only). New installs start with it on; existing ones are offered it on the dashboard.

- **Rollcall makes its own key and certificate** (a P-256 key, kept in its data folder and in exports) and listens for agents over HTTPS on **port 8101**, beside plain HTTP on 8100. Nothing goes into Windows' certificate store.
- **Agents trust exactly that key** ("pinning"), not names or certificate authorities, so a certificate for the right name from anyone else is refused, before anything, the token included, is sent. That's stronger than **Accept a self-signed certificate**, which accepts any certificate.
- **Agents move across by themselves.** At its next report each agent gets the port and the key's fingerprint, signed with the key that signs updates (so even that hand-over can't be changed on the way), and from the run after it reports to `https://<the same address>:8101`. The address it had stays as the fallback. Agents downloaded while HTTPS is on have it built in and use it from their first report. Needs Windows agent 1.0.54, Linux agent 1.0.22 or router agent 1.0.3. **Routers need TLS support** for HTTPS: `curl` built with TLS, or `uclient-fetch` with its TLS library (`libustream-mbedtls`, `-openssl` or `-wolfssl`), which many routers don't have room for. Without it a router can only use plain HTTP, so leave plain HTTP on; router agent 1.0.4 and later doesn't try HTTPS then, and tells Rollcall, which lists it under **Manage → Agents** and asks before plain HTTP is turned off.
- **Routers** can't check a key or a signature: the router agent is given Rollcall's certificate and trusts only that (`uclient-fetch --ca-certificate`, or curl), so the certificate lists every address agents use; Rollcall adds new ones as agents report from them. It's kept on the router's flash, written only when it changes. A router without TLS support for uclient-fetch (the `libustream-*` package) stays on HTTP.
- **Plain HTTP stays on** until you choose **Turn off plain HTTP**. Rollcall judges each agent by the port its reports actually arrive on, so an agent behind a reverse proxy that forwards to plain HTTP counts as plain HTTP, whatever address it was given. The HTTPS section lists agents still reaching Rollcall over plain HTTP, ones that haven't reported since Rollcall started checking, and ones quiet for over 2 days; turning plain HTTP off asks first if any active agent isn't on HTTPS. Once every agent that reported in the last 2 days did so over HTTPS, admins see a reminder on the Overview with a button to turn it off. If agents that were reporting stop for half an hour after it's turned off, the Overview names them with a button to turn plain HTTP back on. Off stays off across restarts and updates, and **Settings → Agent port** shows it. Leave it on if a reverse proxy forwards to port 8100 over plain HTTP: agents that reach Rollcall through one with its own certificate (e.g. Let's Encrypt on a firewall) carry on as they are.
- **Port 8101** must be open under the add-on's **Configuration → Network** (it is by default). If it's closed, the HTTPS section says so and agents stay on HTTP.

### Devices that report over the internet

A device that reports through the outside address usually can't be pinged from Home Assistant. **Tell it's up by** (in Edit) handles this:

- **Automatic** (the default): it's up while it answers ping or, if it has an agent, while the agent has reported in the last 10 minutes. The status then says **Up (agent)**, and the list shows "report 2 min ago" instead of a ping time. It's only treated as down when both fail: no ping reply and no report for over 10 minutes.
- **Ping only**: the fastest down alerts, for servers that are always on the network. With Automatic, a crashed server with an agent can take up to about 10 minutes to show as down.
- **Agent only**: never pinged. It's up while reports arrive, amber ("Report late") once a report is over about 11 minutes old, and down with a notification after `agent_stale_minutes` (at least 12).

In each case it's up again as soon as a report arrives. Port, web and certificate checks still have to reach the device from Home Assistant, so leave those off for devices only reachable over the internet.

### Updating agents automatically

Each add-on release carries the latest agents. Under **Agents → Download and install**, tick **Update Windows agents automatically** and/or **Update Linux agents automatically**. At its next report, any agent older than the add-on's copy downloads it and replaces itself; the new version runs from the report after that. To update just one server, use **Update** next to it in the Approved list. Both are off by default, and the Agent column shows which servers are out of date.

**New versions go to one device first.** With automatic updates on, a new agent version is sent to one device first, preferably a server. Every other agent only gets it once that device has reported on the new version, usually within 5–10 minutes. If it hasn't reported within 20 minutes of fetching the update, the rollout stops: no other agent is updated, you get a notification, and Agents shows the device concerned with two choices:
- **Retry** tries it on a different device first.
- **Update the rest** sends it to every agent anyway.

If the first device is switched off before it fetches the update, another one is chosen after an hour. With only one agent of a kind, it's updated straight away as before; if it goes quiet afterwards you're still told why. **Update** next to a single server always sends it straight away.

An agent only installs an update if all of these pass; otherwise it keeps its current version and logs why:

- It's signed with Rollcall's own key (RSA, 3072-bit). The add-on makes the key the first time it starts, keeps it in its data folder, and never sends it anywhere; each agent script carries only the public half, built in when you download it. So nothing on the network can sign an update, even someone able to read and change plain-HTTP reports (Windows agent 1.0.53, Linux agent 1.0.21 or later).
- Before those versions, updates were signed with the agent's own token, which goes with every report. Over plain HTTP, someone able to read and change that traffic could have captured it and signed an update of their own. Agents older than those versions move to the new ones the old way once, so update them while they report over your own network or a VPN, not over the internet on plain HTTP.
- It's the version offered, and newer than the one running. Agents never downgrade.
- It parses (PowerShell) or compiles (Python).

The addresses Rollcall tells agents to report to (under **Agents → Where the agents report to**) are signed the same way, so a changed reply can't send an agent somewhere else. An agent that gets addresses without a good signature keeps the ones it has, and says so in its log. A failed check never stops an agent reporting.

The previous copy is kept next to it (`RollcallAgent.ps1.old`, `rollcall-agent.py.old`). Only installed agents update themselves; a copy run by hand from a share doesn't. A Group Policy startup script pointing at an older copy won't undo an update, because `-Install` never replaces a newer installed copy with an older one.

### Messages to users' screens

Admins can put a short message on the screens of agent devices, e.g. *The file server restarts at 6pm today: please save your work.* It's **off by default**: turn on **Messages to users' screens** (`messages`) under **Manage → Settings → Agents** (admins only). Off by default because anyone who could get into Home Assistant could otherwise put a message on your users' screens.

- **Manage → Messages** (admins only). Under **Who can receive messages**, choose **Choose…** and tick the devices that may get them; only those can, whoever sends.
- Write the message (plain text, up to 500 characters and 12 lines), choose who it goes to (every included device, a tab, or one device) and how long it stays (1 hour to 3 days), and **Send**.
- It's shown at each device's next report, within about 5 minutes, under the heading **Message from the Rollcall Administrator**, which the sender can't change. Each message is signed with Rollcall's own key, so a reply changed on the way can't put words on anyone's screen.
- **Windows** shows it as a message box in every signed-in session, console and Remote Desktop alike, as `msg *` does. **Linux** sends it to terminals and SSH sessions (`wall`), so a desktop user without a terminal open won't see it. Routers can't receive messages.
- Each device shows it once. With nobody signed in, it waits and shows it at a later report, until the message stops being shown.
- **Sent** lists each message with who sent it and, for each device, whether it was shown and to how many sessions. **Withdraw** stops devices that haven't shown it yet. Sending, withdrawing and changing who can receive are in Rollcall's log.
- Needs Windows agent 1.0.54 or Linux agent 1.0.22.

For a message every user sees when they sign in, Group Policy's *Interactive logon: Message text for users attempting to log on* is the better tool.

---

## Alerts and quiet times

### Notifications

- **Phone and other notifications** go to each service in `notify_services` (without the `notify.` prefix, e.g. `mobile_app_your_phone`). Tapping one opens the dashboard, or `notification_url` if set.
- **A bell notification** in Home Assistant stays while something is down, if `persistent_notification` is on.
- **Recovery** ("back up") notifications are sent if `notify_recovery` is on.
- **Red notifies; amber doesn't.** Most problems go red only if they're still there at the next check, so a single blip doesn't alert.

### Email alerts

Set up under **Manage → Settings → Email alerts**. One list of addresses gets everything. Alerts that arrive within a minute of each other come in one email.

**What to email** (tick any):

- **Red alerts** (on): problems as they happen, such as a device down, a check gone red, a failed backup or a Defender threat that wasn't removed.
- **When things come back** (on): when something that was red works again.
- **Amber warnings and events** (off): as they happen, e.g. a late or missed backup, Windows log and security events, or a threat Defender removed. Left off, these go in the daily summary instead.
- **Daily summary** (on), at **Daily summary at** (08:00 by default, in Home Assistant's time zone): everything that isn't responding, red, amber or paused, plus the warnings and events not already emailed. If Home Assistant was off at that time, it's sent when it starts, up to an hour late; after that, that day is skipped.

**Email about** (all on to start with): untick any you don't want emailed. Phone notifications aren't affected.

| Tick | Covers |
|---|---|
| Devices not responding | A device that stops replying, and when it's back |
| Service checks | Ports, websites, certificates, SIP and Home Assistant sensors |
| SNMP and syslog | Firewalls, VPNs and REDs, switches, iDRACs and syslog alerts |
| Agent checks and log events | Disks, services, Windows updates and the other agent checks, and Windows or Linux log events |
| Backups | Backup jobs that failed, were missed or are overdue |
| Security | Security events, Defender, passwords found in files, privileged group changes and agent file changes |
| Updates | A new app version (e.g. Immich), or an agent update rollout that stopped |

These also decide what's in the daily summary.

**Pauses, schedules and "never alert"** apply to email the same as to notifications. **Send a test email** tries the settings on the screen before you save them; it says what you'll get with the ticks as they are, or shows the mail server's answer if it fails.

Choose how Rollcall sends with **Send email with**:

**An internal relay** (`smtp`, no user name). For example, an Exchange receive connector that allows Home Assistant's address to relay. Set **SMTP server** and **SMTP port** (usually 25). Leave **SMTP security** on `starttls` if the relay offers it, or `none` if it doesn't. If the relay uses Exchange's own self-signed certificate, turn off **Check the server's certificate**; the connection is still encrypted.

**A mail server that needs signing in** (`smtp` with a user name). Usually port 587 with `starttls`, or 465 with `ssl`. Fill in **SMTP user name** and **SMTP password**. For a mailbox with multi-factor sign-in, use an app password if the provider offers one, or use Microsoft 365 below.

**Microsoft 365** (`microsoft365`). Sends through Microsoft Graph, so no SMTP sign-in or relay is needed:

1. In the Microsoft Entra admin center, go to **App registrations → New registration**. Name it (e.g. `Rollcall`), single tenant, no redirect URI.
2. **API permissions → Add a permission → Microsoft Graph → Application permissions → Mail.Send**, then **Grant admin consent**.
3. **Certificates & secrets → New client secret**. Copy the secret's **Value** (not its ID) straight away; it's only shown once.
4. In Rollcall, fill in **Microsoft 365 tenant ID** (Directory (tenant) ID on the app's Overview page), **Microsoft 365 application (client) ID** and **Microsoft 365 client secret**.
5. Set **Send email from** to the mailbox Rollcall sends as, e.g. `rollcall@example.local`. A shared mailbox works and needs no licence.

Mail.Send lets the app send as any mailbox in the organisation. To limit it to Rollcall's mailbox, add an [application access policy](https://learn.microsoft.com/en-us/graph/auth-limit-mailbox-access) in Exchange Online PowerShell. Client secrets expire (up to 24 months); when one does, the test email says so, and you add a new one.

**Passwords and secrets** are stored with the add-on's other settings, shown as "Saved" afterwards and never sent back to the browser. **Export** leaves them out, so enter them again after an import.

### Acknowledging

Some amber states clear themselves after a while. **Acknowledge** clears them now. A new occurrence still alerts.

- **Syslog alerts**: in the Logs tab or on the Overview.
- **Agent Events and Security**: on the check's card or at the top of its tab, including Security's red for a burst of failed logons. **Undo** puts it back. For security events that are expected every time, use a [security filter](#security-filters) instead.
- **An SNMP device's restart**: in the SNMP tab or on the Overview.

Problems that clear themselves once fixed, such as a reading over its limit or a SIP line not registered, can't be acknowledged; they turn green when they're resolved. To stop something alerting at all, use **Ignore** (agents), a [security filter](#security-filters) (security events and failed logons) or **Never alert on these words** (syslog).

### Pausing for reboots (maintenance mode)

Choose **Pause** on a row, or in Details, before rebooting or working on a machine. You're asked for a time limit (default `maintenance_minutes`, 30). While paused, the machine is still pinged but shows blue **Paused** and sends no alerts:

- When it has gone down and replies again, monitoring resumes by itself, with a "back online" message if `notify_recovery` is on.
- If it isn't back by the time limit, it goes red and you're alerted.
- While it's waiting for the machine to go down, it's checked every 5 seconds, so a quick reboot isn't missed.
- A device with an agent normally counts as up for 10 minutes after each report, even if ping fails. While it's paused, if it usually answers ping, a missed ping counts as it going down, and it's back when ping answers again.
- A restart is also spotted from the agent's uptime: if the device booted after the pause began, it counts as having gone down and come back. This covers devices that don't answer ping. The Windows agent (1.0.37 or later) also runs a minute after Windows starts, so this is noticed straight away rather than up to 5 minutes later.
- If it never appeared to go down or restart, it resumes quietly at the time limit.
- **Resume** ends the pause early.

Paused time doesn't count towards uptime, and pauses survive an add-on restart. An agent isn't flagged for not reporting while its server is paused, and gets a full `agent_stale_minutes` after the pause ends. To pause a whole tab at once, see [Tabs](#tabs).

### Monitoring schedules

By default every device is monitored all the time. For one that's only meant to be on at certain times, open **Edit → Monitoring schedule**, choose **Only at set times** and add one or more windows, each with its days and times, e.g. Mon–Fri 07:00–19:00, or Sat 22:00–06:00 for an overnight job. A window can run past midnight; it belongs to the day it starts.

- **Outside its windows** the device shows as **Off schedule** (grey), with when monitoring resumes. It's still pinged: if it's on anyway, the dot turns half green, half grey and it shows **On · off schedule**. Nothing alerts either way, and off-schedule time doesn't count against uptime.
- **When a window opens** it shows **Starting up** until it replies, for up to the allowance you set (15 minutes by default, 0–240). If it hasn't replied by then, you get the usual down alert. Its services and agent checks get the same allowance: one that fails while it's starting shows as *starting up* (blue) and doesn't alert. Anything still failing when the allowance ends alerts straight away.
- **When a window closes**, it goes back to Off schedule without an alert.
- **Problems its agent reported stay on the Overview.** A failed backup, a full disk or a stopped service from the last report is still listed outside the window, marked *off schedule; from the report …*, and the tile says how many checks need attention. They clear when a later report says they're fixed.
- **Backup results still notify.** A failed or overdue Veeam job is sent even if the report arrives outside the window (e.g. a backup server that's only on overnight). Only a manual **Pause** holds them back.

Times are in Home Assistant's time zone (Settings → System → General) and follow daylight saving. The schedule shows under the device's name, and its sensor has `off_schedule` and `schedule` attributes. A manual **Pause** still works on a scheduled device and takes priority while it lasts.

**Devices that are usually off.** For something that's only switched on now and then (cold storage, a monthly backup target), choose **Whenever it's switched on**. Being off is then normal: it shows as **Off** (grey), never alerts for it, and off time doesn't count against uptime. While it's on, it's monitored like any other device, so a failed disk or stopped service still alerts during that monthly run.
- **Start-up allowance:** each time it's switched on, its services and agent checks get time to start before anything alerts (**Allow … minutes**, 15 by default, 0–240). Until then a failed check shows as *starting up* and the device as **Starting up**, with the time the allowance ends. Anything still failing after that alerts straight away. Restarting the add-on while it's on doesn't start a new allowance.

**Never alert.** **Never alert for this device** (Edit → Monitoring schedule) turns off every notification for it: down, checks, agent, events and updates. The dashboard still shows its real status, it still counts in tabs such as Needs attention, and its entities and events still update, so your own automations keep working. A 🔕 next to its name shows it's set. It can be combined with any schedule.

**Critical alerts.** **Critical** (Edit → Monitoring schedule) is for devices that should wake you, such as a mail server. When it goes down, one of its checks goes red, or a Veeam backup job fails, the notification sent to the Home Assistant app is a critical alert:
- **iPhone:** a critical alert, which plays a sound even when the phone is muted or on Do Not Disturb. iOS asks you to allow critical alerts for the Home Assistant app the first time.
- **Android:** a high-priority notification on the `alarm_stream` channel, which plays as an alarm even on vibrate or silent. To get through Do Not Disturb too, allow that channel to override it in Android's notification settings for the Home Assistant app.

"Back up" messages, amber warnings, certificate reminders and syslog alerts stay normal. Only `mobile_app_…` notify services get critical alerts; others get the normal message. Pauses and monitoring schedules still apply. A 🚨 next to its name shows it's set, and it can't be combined with **Never alert**.

---

## Administration

### Settings

**Manage → Settings** (admins and editors) changes the add-on's settings from the dashboard: check intervals, notifications, alert limits, agent options, the agent port and who can make changes. They're the same settings as the add-on's **Configuration** tab, grouped into tabs with a search box, and saved to the same place, so the two always agree.

- **No restart.** Changes take effect as soon as you save. A shorter check interval starts straight away; new limits apply from each device's next check or agent report; turning **Use your own certificate on the agent port** on or off switches the agent port over at once.
- **Checked as you type.** A value out of range is marked and **Save** waits until it's fixed. If Home Assistant turns a change down, nothing is changed and the reason is shown.
- **Who can make changes** (`admin_only_changes`, `editors`), **Messages to users' screens** and **Error hints** can only be changed by Home Assistant admins, not by editors.
- **The Configuration tab still works.** Settings saved there are picked up within about 10 seconds without a restart, even though Home Assistant offers to restart the add-on.
- Devices aren't listed here; add and edit them on the dashboard.

### What's new

After Rollcall is updated, each admin gets a short pop-up the first time they open it, listing what changed since the version they last saw: each change's headline, newest first, covering every version they skipped, with **Full changelog** to read the details in the dashboard (or on GitHub). It shows once per admin, wherever they sign in, because the version each admin last saw is kept by the add-on, not in the browser. It isn't shown to other users, or at all after a fresh install. **What's new** under the version in the menu opens it again.

### Who can see and change things

The **Rollcall** sidebar panel is visible to every Home Assistant user.

- **Admins** (and the owner) can do everything: add, edit and delete devices, pause and resume, acknowledge, approve agents, use linked devices' controls and reset uptime.
- **Everyone else** gets a **View only** dashboard, with status, checks, uptime and **Check now**. The editing buttons are hidden, and the add-on itself refuses changes from non-admins, so typing the URLs directly doesn't get around it.
- **`editors`**: Home Assistant usernames (or display names) of non-admins who may also make changes, e.g. `editors: [sam]`.
- **`admin_only_changes: false`** lets anyone who can open the panel make changes.

The add-on reads Home Assistant's user list to find out who's an admin. If it can't (the log will say so), only names in `editors` can make changes until it can, and the dashboard shows **View only for now**. Before 1.92.1 everyone could make changes then if `editors` was empty; the panel is open to every Home Assistant user, so that's no longer allowed. To make changes while the list can't be read, add your Home Assistant username to `editors` in the add-on's **Configuration** tab (outside Rollcall, so you can't be locked out).

To hide the panel from some non-admins, remove it from their sidebar under their **Profile → Change the order and hide items from the sidebar**. That only hides it; anyone who can sign in could still open the view-only page by URL.

### The database

**Manage → Database** (admins and editors), or the **Rollcall** tile on the Overview, shows how much room Rollcall takes and whether its database is healthy.

- **Sizes:** the database, Rollcall's whole data folder, and the free space on Home Assistant's disk.
- **What takes the room:** check history, agent readings (for the graphs) and syslog messages, each with its size, how many entries, the oldest, and how long it's kept. History and syslog follow **History (days)** (`history_days`); agent readings are kept for every report for 2 days, hourly for a month and daily for **Agent graphs (days)** (`metrics_days`). Below that, every file and folder in the data folder with its size, biggest first. A `before_import_<date>` folder is what an import replaced, kept in case it was needed; you can delete it once you're happy.
- **Health:** SQLite's integrity check (`quick_check`) runs once a day in the early hours, and on **Check now**. Damage is red, with an alert: restore from a Rollcall export (**Export / import**) or a Home Assistant backup of the add-on. Free space on Home Assistant's disk below 10% is amber, below 5% red with an alert (Home Assistant and Rollcall stop saving history once the disk is full; old Home Assistant backups are the usual culprit).
- **Compact now** (admins only) rewrites the database without the free space that old history leaves behind, which SQLite otherwise keeps for reuse. It needs free space of about twice the database's size, and Rollcall holds its writes while it runs (seconds for most databases, a minute or so for a big one). Nothing is deleted. Usually it isn't needed: the space is reused.

### Export and import

**Manage → Export / import** (Home Assistant admins only, not editors: an export holds private keys) moves everything to another install of the add-on, for example from a local copy to one installed from GitHub.

- **Export** downloads one zip: devices and their checks, tabs, pauses, agent approvals and the enrolment key, ignores and thresholds, uploaded icons, each agent's last report, uptime history and the Configuration-tab settings. Keep it safe: it contains the enrolment key, any SNMP and iLO passwords, and the key that signs agent updates (so agents go on accepting updates from the install you import it into). Anyone with the export could sign an agent update, so keep it as safe as a password. That's why export and import are for Home Assistant admins only (since 1.97.0; before that, editors named in `editors` could use them too). The keys have to be in it: without them, agents wouldn't trust updates or HTTPS from the install you import into. The email password and Microsoft 365 client secret are left out.
- **Import** on the new install replaces everything there with the export and restarts the add-on. Tick **Also restore the Configuration-tab settings** to bring notifications, thresholds and agent options across too. The data it replaced is kept in a `before_import_<date>` folder in the add-on's data folder.

Agents keep reporting without being reinstalled, as long as they reach the new install on the same address and port. Stop the old copy once the new one is running, since both can't use port 8100.

**Reset all uptime** (Manage menu) clears the uptime history for every device. It asks you to type a 4-digit code first, so it can't be clicked by accident.

### Hints for errors

Amber and red checks with a well-known error show **💡**: on the Overview next to the alert, and in Details under the check. It explains what the error usually means and what to try.

**Built-in hints** cover common codes and messages: finding or signing in to the domain (`0x8007054B`, `0x8007051F`, `0x800706BA`, wrong or expired passwords, locked or disabled accounts, access denied), Group Policy failures, LAPS (no password in AD, overdue rotation), the clock and the PDC emulator, Windows Update and WSUS (`0x80244022`, `0x8024401C`, `0x80073712`, `0x800F081F` and others), certificates, DFS Replication (4012, 2213) and backups (VSS). They're part of Rollcall: free, and nothing leaves your network.

**Hints from AI** are optional and **off by default**. An admin turns them on under **Manage → Settings → Error hints**, chooses who answers, and enters their own API key for it:

| Provider (`ai_provider`) | Key from | Default model |
|---|---|---|
| Claude (`anthropic`) | console.anthropic.com | `claude-haiku-5-5` |
| ChatGPT (`openai`) | platform.openai.com | `gpt-5.4-mini` |
| Gemini (`gemini`) | aistudio.google.com | `gemini-3.5-flash-lite` |

Then **💡** also offers **Ask Claude** (or ChatGPT, or Gemini) for any amber or red check, including errors the built-in table doesn't know. **Test the saved key and model** sends one tiny question to check they work; model names change over time, so if a default stops working, enter the provider's current small model.

- **On request only.** Nothing is sent until someone who can make changes clicks **Ask**. The answer is marked as a suggestion from that provider and model: advice only. It can't change anything.
- **What's sent:** the check's name, what it looks at (e.g. *a reading from a Starlink satellite dish: Obstructed, the share of the time something blocked the dish's view of the satellites, in %*), the limit you set if it has one, whether it's amber or red, its error text, the related check's state for a reading (e.g. the Starlink check's), the kind of device (e.g. *Microsoft Windows 11 Pro (workstation)*), whether it's on a domain, and how long ago its agent reported. **What's sent?** shows exactly that before you ask, and each answer keeps a copy.
- **Names and addresses are replaced first:** every device name Rollcall knows, the domain's names, signed-in users, `DOMAIN\account` names, email addresses, IPv4 and IPv6 addresses, host names, UNC paths, SIDs, MAC addresses and user profile folders become stand-ins such as `PC01`, `CONTOSO\user1` and `192.0.2.1`. Windows' own names (`NT AUTHORITY\SYSTEM`, `C:\Windows\...`) and error codes are kept, since they're what the answer depends on.
- **Never sent:** security events, domain security (privileged groups and accounts), agent file changes, known vulnerabilities and anything from password scanning. Those checks don't offer **Ask** at all.
- **Cost:** a small, fast model answers in a few sentences, a fraction of a penny each, on your account with that provider. The same error is only asked about once per provider (answers are kept for 30 days in `claude_hints.json`), and **AI hints per day** (`claude_hints_per_day`, 30) caps the rest.
- **The keys** are stored with the add-on's settings like the email password: never shown again, left out of exports, and each only ever sent to its own provider's API (Gemini's in a header, not the address).

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
| `metrics_days` | 365 | How long agents' disk, network, CPU and memory history is kept for graphs (7–1825) |
| **Notifications** | | |
| `notify_services` | `[]` | `notify.*` services to alert, without the `notify.` prefix |
| `persistent_notification` | true | A bell notification in Home Assistant while something is down |
| `notify_recovery` | true | Also notify when something comes back |
| `notification_url` | blank | Where tapping a notification goes; blank opens this dashboard |
| `maintenance_minutes` | 30 | Default time limit when pausing a device |
| **Email alerts** | | |
| `email_send` | off | `off`, `smtp` or `microsoft365` |
| `email_to` | `[]` | Addresses that get email alerts and the daily summary |
| `email_from` | blank | Sender address; for Microsoft 365, the mailbox the app sends as |
| `email_red` | true | Email red alerts as they happen |
| `email_recovery` | true | Also email when something that was red works again |
| `email_warnings` | false | Email amber warnings and events as they happen, instead of in the daily summary |
| `email_digest` | true | Send the daily summary |
| `email_digest_time` | 08:00 | When to send the daily summary (HH:MM) |
| `email_about_devices`, `_services`, `_network`, `_agents`, `_backups`, `_security`, `_updates` | true | What to email about; see [Email alerts](#email-alerts) |
| `smtp_host` | blank | Mail server name or address |
| `smtp_port` | 25 | 25 for a relay, 587 with STARTTLS, 465 with SSL |
| `smtp_security` | starttls | `starttls`, `ssl` or `none` |
| `smtp_check_certificate` | true | Turn off for a server with a self-signed certificate |
| `smtp_username` / `smtp_password` | blank | Only for a server that needs signing in |
| `m365_tenant_id` / `m365_client_id` / `m365_client_secret` | blank | Microsoft 365 app registration with Mail.Send |
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
| `agent_memory_warn` | 90 | Resources: amber at this much memory used, % (0 turns it off) |
| `agent_memory_crit` | 95 | Resources: red, and an alert, at this much memory used, % (two reports in a row; 0 turns it off) |
| `agent_cpu_warn` | 90 | Resources: amber when the CPU is this busy, %, in each of the last `agent_cpu_reports` reports (0 turns it off) |
| `agent_cpu_reports` | 3 | How many reports in a row (5 minutes apart) the CPU must be that busy |
| `messages` | false | Lets admins send short messages to the screens of agent devices they include (Manage → Messages) |
| `agent_failed_logons` | 20 | Failed logons in one report that count as an attack |
| `agent_laps_overdue_days` | 3 | LAPS goes red once rotation is this many days overdue |
| `agent_bitlocker_require` | workstations | Which physical devices with a TPM must use BitLocker: `workstations` (Windows 10/11), `all` or `off`. Physical devices that use it are always checked; virtual machines never are |
| `agent_sql_backup_hours` | 36 | SQL Server: amber when a database has had no full or differential backup for this long |
| `agent_exchange_queue_warn` | 250 | Exchange: amber when this many messages are waiting for delivery |
| `agent_time_warn_seconds` | 60 | Time: amber when a domain device's clock is this far from its domain controller's |
| `agent_time_crit_seconds` | 240 | Time: red at this (Kerberos sign-ins fail at 300) |
| `printer_supply_warn` | 10 | Printers (SNMP): amber when a toner, ink or other supply is at this % or less |
| `software_updates` | true | Highlight programs with a newer version: from the winget catalogue (downloaded daily) for Windows, and the package manager for Linux |
| `offline` | false | For a network without the internet: download nothing, and use imported data instead (see [Offline use](#offline-use)) |
| `vuln_skip_os` | `[]` | End-of-life operating systems whose vulnerabilities are listed but never alert (see [Known vulnerabilities](#known-vulnerabilities)) |
| `vuln_checks` | true | The **Vulnerabilities** check on devices with an agent (see [Known vulnerabilities](#known-vulnerabilities)) |
| `vuln_min_score` | 9 | Vulnerabilities scoring this much or more (CVSS, out of 10) go amber; known-exploited ones are always red |
| `vuln_linux_source` | local | Linux data: `local` (download each distro's data and match in the add-on; nothing is sent), `online` (send OSV.dev one combined list of package names and versions) or `off` |
| `agent_secret_scan` | off | Which devices look for passwords left in files by default: `off`, `servers`, `workstations` or `all`. Only where each one is reaches Rollcall, never the password (see [Passwords left in files](#passwords-left-in-files)) |
| `ip_ranges` | `[]` | Names for parts of your network, shown next to each device's address and in Details, e.g. `Servers=10.0.1.0/24`, `IoT=192.168.20.10-200`, `Workstations=10.0.2.*`. Several ranges can share a name (`Servers=10.0.1.0/24, 10.0.3.0/24`); where they overlap, the smallest wins. The search box matches them too |
| `name_line` | auto | What the list shows under each name, unless a device has its own choice: `auto`, `model`, `os`, `address` or `none` (see **Line under the name** in the Edit form) |
| `agent_patch_days` | 60 | Amber if no update installed for this long (0 turns it off) |
| `agent_sfc` | off | Which Windows devices run the weekly read-only system file check: `off`, `servers`, `workstations` or `all` (see [System file check](#system-file-check)) |
| `agent_sfc_day` | sunday | The day it runs, in each device's own time |
| `agent_sfc_hour` | 3 | The hour it starts (0–23) |
| `agent_sfc_dism` | false | Also run DISM `/ScanHealth` (read only) on the component store |
| `agent_event_alerts` | true | Alert on watched System-log events |
| `agent_security_alerts` | true | Alert on watched Security-log events |
| `agent_event_watch` | Kernel-Power:41, EventLog:6008, BugCheck:1001, disk:7/51/153, Ntfs:55/98 | System-log events that alert, as `Source:ID` or an ID |
| `agent_security_alert_ids` | 4740, 4720, 4726, 4728, 4732, 4756, 1102, 4719 | Security-log event IDs that alert |
| `agent_watch_services` | `[]` | Extra services to watch on every server |
| `agent_ignore` | `[]` | Things to ignore on every server; see [Tuning](#tuning) |
| `agent_auto_add` | true | Add approved servers to the dashboard automatically |
| `agent_ssl` | false | Serve the agent port over HTTPS with your own certificate, instead of Rollcall's own HTTPS. Not while Rollcall's own HTTPS is on (Manage → Agents); **Settings → Agent port** says which is in use |
| `agent_certfile` | fullchain.pem | Certificate in Home Assistant's `/ssl` folder |
| `agent_keyfile` | privkey.pem | Its private key |
| **Error hints** (admins only) | | |
| `claude_hints` | false | Offer **Ask** (hints from AI) on amber and red checks; see [Hints for errors](#hints-for-errors) |
| `ai_provider` | anthropic | Who answers: `anthropic` (Claude), `openai` (ChatGPT) or `gemini` |
| `claude_api_key` | | Anthropic API key; never shown again, only sent to Anthropic |
| `claude_model` | claude-haiku-5-5 | The Claude model |
| `openai_api_key` | | OpenAI API key; never shown again, only sent to OpenAI |
| `openai_model` | gpt-5.4-mini | The OpenAI model |
| `gemini_api_key` | | Gemini API key; never shown again, only sent to Google |
| `gemini_model` | gemini-3.5-flash-lite | The Gemini model |
| `claude_hints_per_day` | 30 | At most this many questions to the AI a day (1 to 500) |
| **Other** | | |
| `log_level` | info | debug, info, warning or error |
| `hosts` | `[]` | Optional bulk import; see [Adding and editing devices](#adding-and-editing-computers) |

### Ports

| Port | Used for | Change it under |
|---|---|---|
| TCP 8100 | Agent reports | Configuration → Network |
| TCP 8101 | Agent reports over HTTPS (Rollcall's own certificate) | Configuration → Network |
| UDP 514 | Syslog | Configuration → Network |

The dashboard itself uses Home Assistant's ingress, with no port of its own.

### What it creates in Home Assistant

**Device sensors:** `sensor.ping_monitor_<name>`, with state `green` / `amber` / `degraded` / `red` / `maintenance`, and attributes `ip`, `ip_range`, `host`, `upstream_device`, `unreachable`, `uptime_24h`, `latency_ms`, `consecutive_failures`, `last_check`, `last_change`, `maintenance_until`, `services` (each check's status), `off_schedule` and `schedule`.

**Check sensors:** `sensor.ping_monitor_<name>_<check>` (e.g. `sensor.ping_monitor_sql01_sql`), with state `green` / `amber` / `red` / `unknown`, and attributes `target`, `detail` (e.g. `HTTP 503`, `connection refused`), `uptime_24h`, `latency_ms`, `last_check` and `last_change`.

**Agent sensors:** each agent check as `sensor.ping_monitor_<name>_agent_<check>` (e.g. `sensor.ping_monitor_dc01_agent_disk`), plus graphable numbers: `sensor.ping_monitor_<name>_cpu`, `_memory` and `_disk_<letter>_free` (Linux: `_disk_root_free`, `_disk_srv_photos_free`; all %).

All sensors are refreshed every 60 seconds, so they come back within a minute of a Home Assistant restart. They're pushed through the API, so they can't be renamed or given an area in the UI.

**Events:** `ping_monitor_status_changed` on every device status change (`name`, `host`, `ip`, `old_status`, `new_status`, `entity_id`, `unreachable`, `upstream`), and `ping_monitor_service_changed` on every check change (adds `service`, `target`, `detail`, `host_entity_id`). For example:

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

**Dashboard card (optional).** The add-on's own page is the main dashboard, but this Markdown card lists the devices on any Home Assistant dashboard:

```yaml
type: markdown
title: Devices
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
| `hosts.json` | Devices and their checks |
| `views.json` | Tabs |
| `agents.json` | Agent approvals, token hashes and the enrolment key |
| `agent_settings.json` | Ignores, thresholds, acknowledgements, agent addresses |
| `vulns/` | Downloaded vulnerability data (Microsoft, CISA, OSV.dev), refreshed daily |
| `secrets/` | Where each agent's password scan found passwords: path, line, kind, setting name and length (never the passwords) |
| `icons/` | Uploaded icons |
| `db_health.json` | The last database check and compaction |
| `claude_hints.json` | Hints from AI: answers (30 days) and today's count; never the API keys |
| SQLite database | Uptime history, agent readings and syslog messages (see [The database](#the-database)) |

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
    ├── ilo.py         HPE iLO health over RIBCL
    ├── vmware.py      ESXi, vCenter and Aria, read only
    ├── opnsense.py    OPNsense through its API, read only
    ├── netvendor.py   Cisco and Juniper over SNMP
    ├── offline.py, whatsnew.py   offline data bundles; the What's new pop-up
    ├── vulns.py       known vulnerabilities: Microsoft, OSV.dev and CISA data
    ├── dbhealth.py    Manage > Database: sizes, integrity check, compacting
    ├── hints.py       hints for errors: the built-in table, and Claude (optional)
    ├── certcheck.py, sipcheck.py, hadevice.py, msi.py
    ├── agent/RollcallAgent.ps1          the Windows agent
    ├── agent/rollcall-agent.py          the Linux agent
    ├── agent/rollcall-agent.sh          the OpenWrt agent
    ├── agent/rollcall-agent-freebsd.sh  the pfSense, OPNsense and FreeBSD agent
    └── web/index.html dashboard (served through ingress)
```

### The name change

Rollcall was called Ping Monitor until 1.6.0. Only the visible name changed, so nothing already set up breaks:

- The add-on's ID is still `ping_monitor`, so entities keep their `sensor.ping_monitor_*` names, and automations and cards carry on working.
- The agents kept their old file names, folders and tasks until 1.99.0 (Windows agent 1.0.60, Linux agent 1.0.25), which renamed them: `RollcallAgent.ps1` in `C:\ProgramData\Rollcall` with the task **Rollcall Agent**, and `rollcall-agent.py` with `/var/lib/rollcall` and the unit `rollcall-agent`. Installed agents move themselves safely when they update (see [Setting it up](#setting-it-up)); there's no need to redeploy them. The port (8100) is unchanged.

---

## Languages

Rollcall's dashboard, notifications and Home Assistant entities are in English. Dates and times follow the browser's own settings, e.g. 11.11.2026 14:05 in a German browser.

The agents work on Windows and Linux in any language:
- Text that comes from the system, such as Windows event messages, service names and program names, is shown as the system wrote it, so it may be in another language.
- Anything the agents read to make decisions doesn't depend on the system's language. Linux commands run in the C locale. On Windows, the agents use IDs and values rather than translated labels, and the signed-in user check understands the common languages' words for an active session.

## Rollcall's own log

**Manage → Log** (admins and editors) shows the add-on's log, the same one as Home Assistant's **Settings → Apps → Rollcall → Log**, including lines from before the last restart. Choose **Warnings and errors** or **Errors only** (an error's traceback stays with it), search, and **Download** what's loaded as a text file. **Follow** reloads it every 5 seconds while it's open.

Anything that looks like a password, token, key or SNMP community is masked before it leaves the add-on. If Home Assistant's copy can't be read, it shows the lines logged since Rollcall last started, and says so.

## Troubleshooting

**A device shows down but it's on.**
Checks come from the Home Assistant machine, so remote sites must be routable from it, and firewalls must allow ICMP echo and the ports you check. For a device that can't be pinged, use an agent with **Tell it's up by: Automatic** or **Agent only**.

**A hostname doesn't resolve.**
Home Assistant's DNS treats `.local` as mDNS, so Active Directory names like `server.example.local` may not resolve from the add-on. Use the IP address instead.

**"No SNMP reply".**
Check that SNMP is on, the community (or v3 user) is right, and the device allows Home Assistant's address. Older kit may only speak v1: if `snmpwalk -v1` answers but `-v2c` doesn't, choose v1. The SNMP tab shows how long each part of the last poll took and how many requests it needed. A slow or overloaded switch adapts by asking for fewer rows at a time.

**A server's agent doesn't appear under Waiting for approval.**
Check the server can reach Home Assistant on port 8100 at the address in **Agents** (`Test-NetConnection <address> -Port 8100`), and look at `C:\ProgramData\Rollcall\agent.log` (Windows) or `/var/lib/rollcall/agent.log` (Linux); agents not yet moved to the new name log to `C:\ProgramData\PingMonitor\agent.log` or `/var/lib/pingmonitor/agent.log`. `-ShowReport` / `--report` shows what it would send.

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
