# Rollcall (Home Assistant add-on)

*Who's up, and how are they doing?* Formerly **Ping Monitor**.


Pings a list of computers on a schedule and, optionally, checks the services running on them (TCP ports and web apps). A Windows agent and a Linux agent can also report what's happening inside each server: disk space, services, Docker containers, event/journal and security logs, and role health (including Immich). Each computer is shown as:

| Status | Meaning |
|---|---|
| 🟢 Up | Replied to ping, and all its service checks pass |
| 🟡 Unresponsive | Missed one ping |
| 🟠 Degraded | Pings fine, but a service check or agent check has failed. Notification sent |
| 🔴 Down | Missed two pings in a row. Notification sent |
| 🔵 Paused | Maintenance mode; still checked, but no alerts |

You get a dashboard in the HA sidebar (status, name, service chips, IP, 24h uptime %, latency, a 24h history strip, Check now / Pause / Reset), sensors for every computer and service, and phone notifications.

## Install

1. In Home Assistant: **Settings → Add-ons → Add-on Store → ⋮ → Repositories**, add `https://github.com/shoey79/rollcall` and close.
2. Find **Rollcall** in the store, **Install**, then **Start**, and turn on **Show in sidebar**.
3. Open **Rollcall** from the sidebar and click **+ Add computer**.

Updates appear on the add-on's page in Home Assistant (or **⋮ → Check for updates** in the store). Turn on **Auto update** to install them automatically.

**Moving from an earlier local copy** (installed by copying the folder into `/addons`): Home Assistant treats the store version as a separate add-on, so use **Export / import** to bring your data across. See [Export and import](#export-and-import).

## Tabs

Rollcall opens on the **Overview**. Tiles at the top show how many computers are up, need attention, are down or are paused, and whether the agents are reporting; click one to open the matching list. **Alerts** lists everything that isn't green (computers not responding or missing checks, failing service checks, and agent checks such as stopped services, low disks, failed backups or security events), worst and newest first. Click an agent alert to open that server's Details on the relevant tab; other alerts open the list filtered to that computer. **At a glance** shows every computer as a tile; click one for its Details, or its row in the list if it has no agent.

The dashboard has tabs to split a long list. Each tab is a saved filter, so it updates by itself as computers are added or change. The number on a tab is how many computers it shows; the coloured badge is how many of them need attention (red if any are down).

**Built in:** **All**, **Needs attention** (down, degraded or missed a check), and **Windows**, **Linux** and **No agent**, which appear once you have a mix.

**Your own (admins):** **+ New tab**, give it a name and add conditions. Show computers that match *all* or *any* of them. The box at the bottom lists what matches as you type.

| Condition | Options | Example |
|---|---|---|
| Name | begins with, contains, ends with, is, is not, doesn't contain, matches pattern | begins with `SQL` · pattern `^RDS0[1-4]$` |
| Hostname or IP | same as Name | ends with `.example.local` |
| IP range | is in, is not in | `10.0.1.0/24`, `10.0.1.10-50`, `10.0.1.10-10.0.2.20`, `10.0.1.*` (several separated by commas) |
| Operating system | is, is not | Windows, Linux, No agent |
| Status | is, is not | Needs attention, Down, Degraded, Paused… |
| Server role (agent) | includes, doesn't include | `Domain controller`, `IIS`, `Immich` (comma-separated means any of them) |
| Service check | includes, doesn't include | `SQL`, `HTTPS`, `32400` |
| Uptime (24 h) | is below / above % | below `99` |

**Start from** has ready-made starting points (name, IP range, Windows, Linux, domain controllers, web servers, low uptime). The ✎ on the open tab edits it, deletes it or moves it left or right. Tabs are shared: everyone who opens the panel sees the same ones, and they're saved in the add-on's data folder (`views.json`). The search box filters within the open tab.

**Pause all in this tab** pauses every computer in the open tab at once, e.g. for a site's patch night. Each one works like pausing it on its own: it keeps being pinged, resumes by itself once it has gone down and come back, and alerts if it isn't back within the time limit. If something is typed in the search box, only the computers shown are paused, which also works on the All tab. **Resume N paused** ends the pause early for all of them.

## Adding and editing computers

Computers are managed on the dashboard:

- **+ Add computer** opens a form with the name, the IP or hostname, a checkbox for each service preset (showing the ports it checks), and fields for any custom checks.
- **Edit** on a row opens the same form. **Delete** and **Reset uptime** for that computer are in the form too.
- Changes apply straight away; there's no add-on restart.

The list is saved in the add-on's data folder (`hosts.json`) and is included in HA backups of the add-on.

**Bulk import from the Configuration tab.** You can still list computers under `hosts:` in the add-on's Configuration tab, as shown below. On the next start they're merged into the dashboard list (matched by name, so an existing computer is updated rather than duplicated), and the add-on then clears that option so the dashboard stays the single place to manage them. If HA doesn't allow the option to be cleared, entries that were already imported are ignored on later starts, so they can't overwrite your dashboard changes or bring back a computer you deleted.

## Configuration

```yaml
interval: 300              # seconds between checks
retry_interval: 300        # seconds until the re-check after a miss (lower it, e.g. 60, to go red faster)
ping_count: 3              # packets per check; any reply = up
ping_timeout: 2            # seconds to wait per packet
service_timeout: 5         # seconds to wait for a port or web check
history_days: 7            # how long results are kept
notify_services:           # notify.* services, without the "notify." prefix
  - mobile_app_your_phone
persistent_notification: true   # bell-icon notification in HA while something is down
notify_recovery: true           # also notify when something comes back
maintenance_minutes: 30         # default time limit when pausing a host
cert_warn_days: 30              # certificate checks: amber this many days before expiry
cert_crit_days: 7               # ...and red (with a notification) this many days before, or once expired
admin_only_changes: true        # only HA admins (and editors) can add/edit/pause/reset
agent_stale_minutes: 15         # agents: alert if no report for this long
agent_disk_warn: 15             # % free: amber below this
agent_disk_crit: 5              # % free: red below this
agent_failed_logons: 20         # failed logons in one report that count as an attack
agent_patch_days: 60            # amber if no update installed for this long
agent_ignore: []                # see "Tuning" below
editors: []                     # HA usernames of non-admins who can also make changes
notification_url: ""            # where tapping a phone alert goes; blank = this dashboard
log_level: info
hosts:                      # optional bulk import; see above
  - name: DC01
    host: 10.0.1.10
    checks: [dc]
  - name: SQL01
    host: 10.0.1.20
    checks: [sql]
  - name: EXCH01
    host: 10.0.1.30
    checks: [exchange]
  - name: FS01
    host: 10.0.1.12
    checks: [fileserver]
  - name: Plex
    host: 10.0.5.15
    checks: [plex]
  - name: Printer
    host: 10.0.1.90           # no checks = ping only
```

`host` can be an IP or a hostname. Hostnames are resolved on every check, so the IP shown follows DNS changes. A name that can't be resolved counts as a failed ping.

## Service checks

Tick presets in the Add/Edit form, or add custom checks there. In the Configuration tab, the equivalent is a `checks:` list on a host. Each entry is a preset or a custom check, and they can be mixed (`[dc, fileserver, tcp:5985]`). Duplicate targets are only checked once.

### Presets

In the Add/Edit form these are checkboxes, grouped as below, with a search box. Ports are each product's defaults; if yours differs, use a custom check instead.

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

### Custom checks

| Form | Example | Checks |
|---|---|---|
| `tcp:PORT` | `tcp:5985` | The port accepts a connection |
| `http:PORT/path` | `http:8080/status` | A web request to this host |
| `https:PORT/path` | `https:443/owa` | Same over HTTPS |
| Full URL | `https://mail.example.local/owa` | A specific URL, e.g. a vhost or load-balanced name |
| `Label=` prefix | `SQL Reporting=tcp:50123` | Any of the above with your own label |

**Web checks** pass on any response below 500. A 401 from Windows authentication or a 302 redirect to a login page still means the app is answering. A 5xx (such as the 503 from a stopped IIS app pool), a timeout or a refused connection fails. Redirects aren't followed. The check only reads the status line, so devices that send untidy headers are fine.

HTTPS checks are deliberately lenient about security, since they only test whether the service answers: self-signed or expired certificates, 1024-bit keys, TLS 1.0 and old ciphers are all accepted. That covers older kit like Dell iDRAC 6.

For `http:PORT/...` and `https:PORT/...` checks (including presets), if the port answers but not with that protocol, the other one is tried, and whichever works is used from then on. The chip shows "via https" when that happens. For example, Plex with "Secure connections: Required" only answers HTTPS on 32400. Full-URL checks always use exactly the scheme you gave.

**SQL named instances** usually listen on a dynamic port, so use `tcp:<port>` with the instance's actual port instead of the `sql` preset.

### Home Assistant sensors

Any sensor in Home Assistant can be a check on a computer, so devices Home Assistant already knows about, such as UniFi access points and switches through the UniFi Network integration, show their CPU, memory and so on alongside the ping. The current value is shown on the chip (e.g. **CPU 12%**).

In **Edit**, search under **Home Assistant sensors** (it starts with the computer's name) and click **Add**. CPU and memory are added as "problem above 90%", temperature above 80; anything else just needs to be available. Edit the line under **Custom checks** to change it:

| Check | Meaning |
|---|---|
| `CPU=ha:sensor.office_ap_cpu_utilization>90` | Amber, then red (two checks in a row) while CPU is over 90 |
| `Memory=ha:sensor.office_ap_memory_utilization>=85` | The same for memory at 85% or more |
| `ha:sensor.office_ap_state!=Connected` | Red when the state is anything but Connected |
| `ha:binary_sensor.nas_status` | Only needs to exist and not be unavailable |

The condition describes the problem. Operators: `>` `>=` `<` `<=` `=` `!=`. A sensor that's `unavailable` or missing also counts as failing. Sensor checks run with the ping, and like other checks they pause while the computer is down or paused. Some UniFi sensors are disabled by default in Home Assistant; enable them on the device's page first.

### Physical or virtual

Agents (Windows 1.0.13, Linux 1.0.7 and later) report the machine's manufacturer, model and serial number (a Dell service tag, for instance), and whether it's a VM: Hyper-V, VMware, KVM/QEMU (including Proxmox), VirtualBox, Xen or a cloud VM, or a container (LXC, Docker) on Linux. Computers without an agent count as Hyper-V VMs when a Hyper-V host's agent lists a VM with the same name. You can also put "VM" or "Hyper-V" in **Make and model**.

The list shows this under the name (e.g. *Hyper-V VM on HV01*, or *Dell Inc. PowerEdge R720xd · ABC1234*) unless you've typed a make and model. To split the list, make a tab with **Physical or virtual** is *Physical*, *Virtual (any)*, *Hyper-V VM*, *VMware VM*, *KVM / QEMU / Proxmox VM*, *Container* or *Not known*. The **+ New tab** templates include Physical machines, Virtual machines and Hyper-V VMs.

### Certificate expiry

Tick **Certificate expiry on HTTPS (443)** under Network, or add custom checks:

- `cert:8443`: the certificate on another port of this computer.
- `SMTP=cert:25`: mail ports use STARTTLS (25 and 587 SMTP, 110 POP3, 143 IMAP, 21 FTP), so Exchange's SMTP certificate can be checked.
- `cert:mail.example.com:443`: a certificate on another name or address. The name is also sent as SNI, so it picks the right certificate on a server that has several.

Each check reads the certificate the service presents (internal and self-signed ones count too). It's green while it has more than `cert_warn_days` (30) left, amber within that, and red within `cert_crit_days` (7) or once expired; red notifies, and so does renewal if `notify_recovery` is on. The chip's detail shows the expiry date, days left, the name on the certificate and who issued it. If the certificate can't be read (port closed, not TLS), the check goes amber and says why.

### Other addresses

A firewall, router or multi-homed server can have more than one address worth watching, e.g. a WAN IP and an internal IP. Under **Other addresses** in Edit, add each one with a name (e.g. *WAN*), the IP address or hostname, and optionally ports to check there (e.g. `443, 4444`).

- The main **IP address or hostname** still decides whether the device is up or down. The other addresses are checked while it answers, like its other checks. Each one gets its own chip, and turns the device **degraded** if it stops replying (amber at the first miss, red if it's still missing at the next check).
- Syslog from any of the device's addresses is matched to it.
- They're stored as checks, so you can also type them as custom checks: `WAN=ping:203.0.113.5` and `WAN 443=tcp:203.0.113.5:443`. IPv6 addresses go in brackets: `ping:[2001:db8::1]`.

### Icons and make/model

Each computer shows an icon next to its name, in the list and on the Overview. By default it's picked from what the computer is: its name (e.g. "AP1", "NAS", "SQL01", "CCTV"), its agent (Windows Server or desktop, Linux), or its checks (printer, SNMP). To choose one yourself, click **Icon** in Edit. There are 23 device types: rack, storage and tower servers, desktop, laptop, VM, database, NAS, switch, router, firewall, access point, smart home hub, CCTV and dome cameras, printer, UPS, TV, phone, single-board computer, web service, cloud and other.

The built-in icons are generic and drawn for Rollcall; there are no company logos. For a manufacturer's logo or a photo of the actual hardware, choose **Upload image** in the icon picker. It takes PNG, JPEG, WebP or SVG files up to 300 KB, and up to 200 images in total. Uploaded images can be used for any computer, are included in exports, and can be deleted from the picker; computers using a deleted image go back to an automatic icon. Only use images you have the right to use.

**Make and model** (optional) is shown under the name, e.g. "Dell PowerEdge R720xd", and helps pick the automatic icon.

### SNMP (switches and NAS units)

For network kit you can't install an agent on, tick **SNMP** (under Network) when adding or editing the device, and choose the SNMP version:

- **v3** (recommended where the device supports it): create a read-only SNMP v3 user on the device and enter its user name, authentication protocol and password, and privacy (encryption) protocol and password. Authentication can be MD5, SHA, SHA-224, SHA-256, SHA-384 or SHA-512, and privacy DES, AES-128, AES-192 or AES-256. SHA with AES-128 is the most widely supported pair. AES-192 and AES-256 use the same key extension as Net-SNMP (Blumenthal); devices using Cisco's variant aren't supported. Passwords are 8 characters or more. Requests are signed, replies are checked, and with privacy everything is encrypted.
- **v2c**: turn on SNMP v2c on the device with a read-only community, and enter the same name here. The name is case-sensitive, and a TeraStation's default is `TeraStation`. The community travels unencrypted, so anyone capturing traffic on your network could read it. Rollcall reads the device on every check while it answers ping, and **Details** shows what it found:

- **Ports** (any switch): every physical port, with its description, speed and error counts. Tick **Alert** for ports that should always be up (uplinks, servers, access points). They go red if they drop, and amber if someone disables them. Other ports are just shown, so desktops going off at night don't alert.
- **PoE** (switches with the standard PoE MIB, e.g. Netgear GS516TP): power used against the budget (amber at the switch's own alert threshold), a red alert for a port in a PoE fault, amber when a port's overload, short-circuit or power-denied count goes up, and red if the PoE supply is off or faulty.
- **Buffalo TeraStation** (detected automatically): each disk's status and SMART health, RAID arrays and how full they are (amber at 90%, red at 97%), and the errors the NAS reports itself. A degraded or removed disk is red; a removed hot spare or a SMART warning is amber.
- **Restarts**: amber for an hour after the device restarts.

Problems go red, and notify, only if they're still there at the next check, so a port bouncing once doesn't alert. Warnings stay amber and don't notify. If the device stops answering SNMP (wrong community, SNMP turned off), the SNMP check goes red but the device stays up as long as it answers ping. The community and v3 passwords aren't shown on the dashboard. Leaving them blank when editing keeps the ones already saved. They are included in exports, so keep export files safe.

### Syslog

Rollcall receives syslog on **UDP port 514** of the Home Assistant machine. You can change or turn off the port under the add-on's **Configuration → Network**. Tick **Syslog** (under Network) on a device, then set the device to send its logs to Home Assistant's IP address on that port. Messages are matched to the device by the IP address they come from.

- **Logs** next to the device shows its messages, newest first, with search and a severity filter. They're kept for `history_days`, up to 20,000 per device.
- **Alert on** sets which messages alert: critical and worse, errors and worse (the default), warnings and worse, or only your words. Critical, alert and emergency messages, and any message containing one of your **Always alert** words, go red and notify. Others you alert on go amber. Messages containing a **Never alert** word are kept but never alert.
- Alerts last 24 hours. **Acknowledge**, in Logs or next to the alert on the Overview, clears them now; a new message that alerts sets it off again.
- Messages from devices that aren't in Rollcall, or that don't have Syslog ticked, aren't kept. They're listed on the Overview under **Syslog from unknown devices**, with a button to add the device or tick Syslog for it.

Each device can send up to 100 messages a second (with bursts up to 200); more than that are dropped, so a chatty device can't fill the database. Syslog over UDP isn't authenticated, so anything on your network can send messages that appear to come from a device. Treat syslog alerts as a prompt to look, not as proof.

### How services affect status

- Services are only checked while the computer is answering pings. Each service has its own count: one failure turns its chip amber, and two in a row turns it red.
- Any red service makes the computer **Degraded** and sends an alert naming the service, for example "🟠 SQL01: SQL is down". Recovery sends "🟢 SQL01: SQL is back up".
- If the whole computer stops pinging, you get one "down" alert for the computer, not one per service. Its services reset and start counting again once it's back, which gives them time to start after a reboot.
- Pausing a computer also pauses its services.

## Windows agent

One PowerShell script, the same on every server. Each run (every 5 minutes) it works out what the server does and reports what matters for it. Servers appear on the dashboard by themselves once you approve them.

### What it checks

| Check | Goes amber | Goes red (and alerts) |
|---|---|---|
| **Agent** | | No report for `agent_stale_minutes` (15) |
| **Disk** | A volume under `agent_disk_warn` (15%) free | Under `agent_disk_crit` (5%) free |
| **Services** | Another automatic-start service isn't running | A service for one of the server's roles has stopped (two reports in a row) |
| **Updates** | Reboot pending, or no update installed for `agent_patch_days` (60; `0` turns this off) | |
| **IIS** | | An app pool or site stopped (two reports) |
| **Storage** | A disk predicting failure, or a RAID volume rebuilding | A failed disk: a mirror or RAID-5 with failed redundancy, a missing dynamic disk, an unhealthy disk or degraded Storage Space (two reports) |
| **AD** (domain controllers) | | Replication failing, or SYSVOL/NETLOGON not shared (two reports) |
| **DHCP** | A scope 85% or more used | 95% or more used |
| **Hyper-V** | | A VM in a critical state |
| **Printers** (print servers) | A shared printer not ready (paper jam, offline…) | |
| **Defender** | Definitions over 7 days old | Real-time protection off, or malware not removed |
| **Security** | Notable events in the last 24 h | `agent_failed_logons` (20) or more failed logons in one report |
| **Events** | Alert-worthy events in the last 24 h | |

Roles are found from the server's installed Windows roles and services: domain controller, DNS, DHCP, file server, DFS, print server, IIS, Remote Desktop (Session Host, Broker, Gateway, Licensing), Hyper-V, WSUS, Certificate Services, AD FS, NPS, SQL Server, Exchange, SharePoint and Veeam. Each role's services are watched if they're set to start automatically. Roles added or removed later are picked up on the next run.

**Storage health** covers Windows' own RAID: mirrored and RAID-5 volumes on dynamic disks (read with `diskpart` on servers that have dynamic disks), Storage Spaces, and each physical disk's health, including SMART predicted failures. It also reads two vendors' RAID, which Windows itself sees only as one healthy-looking disk:
- **Dell PERC, through OpenManage Server Administrator (OMSA).** If `omreport` is installed, each run reads every controller, virtual disk and physical disk: a degraded or failed virtual disk, a failed disk or a controller fault is red; a rebuild or a disk predicting failure is amber. OMSA's chassis health (power supplies, fans, temperatures, voltages, memory, batteries, intrusion) becomes a **Hardware** check: Critical is red, Non-Critical amber. "Hardware Log" (how full the server's event log is) is shown but doesn't alert.
- **AMD RAIDXpert2.** Its events in the System log ("AMD RAID API") give each array's state: "goes critical" is red until a rebuild starts, a rebuild in progress is amber with its percentage, and "completed" or "goes online" is healthy. The state is remembered, so an array that's been critical for a long time stays red. Disks dropping out, timeouts and remapped bad sectors in the last 24 hours are amber.

Other hardware RAID controllers aren't covered; use the vendor's own alerting.

**Veeam backups.** On a Veeam server the agent adds a **Backups** check and tab:
- **Backup & Replication** (v12/13): every job's result is read from the *Veeam Backup* event log ("… job 'name' finished with Success / Warning / Failed": backup, replication, backup copy, agent jobs and others). A failed job is red, with one notification per failed run giving Veeam's reason; a failure Veeam will retry, or a warning, is amber. Each job's recent run times are remembered, so Rollcall learns how often it runs; a job with no successful run for more than about 1½ times its usual gap (at least 26 hours, or 8 days until it has a few runs of history) is amber, with one "backup overdue" notification. That catches a job that has been disabled or has silently stopped. Jobs with no run for 60 days are dropped.
- **Backup for Microsoft 365**: each job's last status from its PowerShell module, every 30 minutes (loading the module is slow). Failed is red; Warning, Stopped or Disconnected is amber; an enabled job more than 2 hours past its next scheduled run is amber ("missed"). Disabled jobs are listed but not checked.
- **Ignore** on a job in the Backups tab (`backup:<job name>`) leaves it out, e.g. a weekly test job.

**Alerted as they happen** (phone notification for each):
- **Security log:** account locked out (4740), account created or deleted (4720/4726), member added to a security group (4728/4732/4756, e.g. Domain Admins), audit policy changed (4719), Security log cleared (1102). The IDs are in `agent_security_alert_ids`.
- **System log:** unexpected shutdowns and crashes (Kernel-Power 41, EventLog 6008, BugCheck 1001), disk and NTFS errors, plus any Critical-level event. The list is in `agent_event_watch`, as `Source:ID` or just an ID.
- **Microsoft Defender:** every detection, saying whether it was removed.

**Shown in Details** (the **Details** button on a server's row): system info, CPU and memory, roles, disk bars, role services, other stopped services, IIS app pools, AD replication partners, DHCP scopes, Hyper-V VMs, printers, RDS sessions, Defender status, the last 24 h of System/Application errors, and (admins only) failed logons and security events.

### Setting it up

1. In the dashboard, click **Agents** and download **PingMonitorAgent.ps1**. Check the address first: it's what your servers use to reach Home Assistant on port 8100 (use the IP if they can't resolve the name). The script has the address and the enrolment key built in.
2. Copy it to `\\your-domain\NETLOGON` (or any share the servers can read).
3. Group Policy for the servers' OU: *Computer Configuration → Policies → Windows Settings → Scripts → Startup*, script `powershell.exe`, parameters `-NoProfile -ExecutionPolicy Bypass -File \\your-domain\NETLOGON\PingMonitorAgent.ps1 -Install`. Or run that command once as an administrator on a server to start straight away.
   **Or with MECM (Run Scripts):** *Software Library → Scripts → Create Script*, import `PingMonitorAgent.ps1`, then have it approved (by default an author can't approve their own script). Right-click a device collection → **Run Script**, choose it, set **Action** to `Install` and leave the other parameters at their defaults. It runs as SYSTEM straight away, with no restart. MECM shows a warning about the switch parameters (Run Scripts can't pass switches); that's expected, and why `Action` exists. If it fails with a signing error, your client settings' PowerShell execution policy (*Computer Agent*) is set to *All Signed*: either sign the script or use *Bypass* for that collection. To update later, edit the script in MECM with the new version and run it again.
4. Within 5 minutes each server shows under **Waiting for approval**. Check the name and address, then **Approve** (or **Approve all**).
5. Approved servers that aren't on the dashboard yet are added automatically (by IP), unless `agent_auto_add` is off. Existing entries are matched by name or IP.

`-Install` (or `-Action Install`) copies the script to `C:\ProgramData\PingMonitor` and creates a scheduled task, **Ping Monitor Agent** (the name from before the rename, kept so existing installs update in place), that runs every 5 minutes as SYSTEM. Running it again is safe, and it's one way to update: put the new script on the share and it's picked up at the next restart (or run `-Install` again). Agents can also update themselves from the add-on; see [Updating agents automatically](#updating-agents-automatically). `-Uninstall` (`-Action Uninstall`) removes it. `-ShowReport` (`-Action Report`) prints what it would send, for troubleshooting. The agent writes a log to `C:\ProgramData\PingMonitor\agent.log`.

Requirements: Windows Server 2012 R2 or later (Windows PowerShell 4.0+), and port 8100 open from the servers to Home Assistant. Workstations work too; they just have no roles.

**How long a run takes** is in each server's Details, under **Agent run**: total time, CPU, peak memory, and a breakdown by step. The Agent check turns amber if a run takes longer than `agent_slow_seconds` (120). The last-update date is only re-checked every 6 hours or after a restart, because finding it can be slow on some machines.

### Security

- **Nothing runs on the servers at the add-on's request.** The agent only sends reports; it never downloads or runs anything from Home Assistant.
- **Each server has its own token**, generated on the server and stored in `C:\ProgramData\PingMonitor` (readable only by SYSTEM and Administrators). The add-on only keeps a hash of it.
- **The enrolment key only lets a server ask to join.** Nothing is accepted until an admin approves it, so a leaked key can't feed data in. **Rotate key** under Agents if needed; approved servers keep working.
- **Revoke** stops a server's reports. Deleting a computer from the dashboard also revokes its agent. A revoked or rejected copy can't ask again; to re-add the server, run `-Uninstall` then `-Install` on it.
- Security events are only shown to Home Assistant admins.
- Reports go over HTTP by default, so they're readable on your network. To use HTTPS, set `agent_ssl: true` with a certificate in HA's `/ssl` folder (`agent_certfile`, `agent_keyfile`), and download the script with an `https://` address. Tick **Accept a self-signed certificate** if yours is self-signed.

### Tuning

**From the dashboard (admins):** open a server's **Details**.
- **Ignore** appears next to anything that's flagged: stopped services (role or otherwise), stopped IIS app pools and sites, printers, VMs in a critical state, busy DHCP scopes, event IDs and whole disks. It applies to that server straight away, clears the alert, and you don't need to wait for the next report.
- **Ignored on this server** (at the bottom of Details) lists everything being ignored there. **Apply to all servers** makes an item global; **Stop ignoring** undoes it, and anything still wrong goes red again immediately.
- **Disks → Change** sets that disk's own amber and red levels (% free), e.g. amber below 8%, red below 3% for a large data volume. Leave a box blank to use the default, or enter 0 to turn that level off. **Use defaults** removes the override.

- **Acknowledge**: the Events and Security checks stay amber for 24 hours after something alert-worthy. **Acknowledge** (on the check's card in the Overview, or at the top of the Events or Security tab) turns them green without ignoring anything: those items stay listed, greyed out, and anything new that arrives afterwards turns the check amber again. It records who acknowledged it and when; **Undo** puts it back. To stop a recurring event alerting at all, use **Ignore** on it instead.

These settings are stored in the add-on's data folder (`agent_settings.json`) and kept across restarts and agent updates.

### Inside and outside addresses

Under **Agents → Where the agents report to**, there are two addresses: **Inside your network** (e.g. `http://192.168.1.5:8100`) and, optionally, **From outside** (e.g. `https://rollcall.example.com:8100`). Downloads have both built in. Agents try them in order and remember which one worked, so a laptop away from the office goes straight to the outside address next time, and back to the inside one when it returns. An address that can't be reached is skipped after 3 seconds.

For the outside address to work, forward its port on your firewall to Home Assistant's agent port, or publish it through a reverse proxy. Use HTTPS for it: turn on `agent_ssl` (see above), otherwise reports and each server's token cross the internet unencrypted. Servers still have to be approved before their reports count, and every report is checked against that server's own token.

The addresses are saved in the add-on as soon as you change them, and sent to every agent with its next report (Windows agent 1.0.15, Linux agent 1.0.9 and later), so installed agents follow changes without a new download. Each agent also keeps the address it was installed with as a last resort, so a mistake in these boxes can't cut it off. Older agents get the new behaviour through **Update agents automatically**; or download again and run `-Install` / `--install`.

### Updating agents automatically

Each add-on release carries the latest agents. Under **Agents → Download and install**, tick **Update Windows agents automatically** and/or **Update Linux agents automatically**. At its next report, any agent older than the add-on's copy downloads it from Home Assistant and replaces itself; the new version runs from the report after that. To update just one server, use **Update** next to it in the Approved list. Both are off by default, and the Agent column shows which servers are out of date.

An agent only installs an update if all of these pass; otherwise it keeps running the version it has and logs why:
- It is signed (HMAC-SHA256) with that server's own agent token, which only the server and the add-on know, so a copy changed on the way, or sent by anything other than your add-on, is refused.
- It is the version offered, and newer than the one running. Agents never downgrade.
- It parses (PowerShell) or compiles (Python).

The previous copy is kept next to it (`PingMonitorAgent.ps1.old`, `pingmonitor-agent.py.old`). Only installed agents update themselves: a copy run by hand from a share doesn't. A Group Policy startup script pointing at an older copy on a share won't undo an update, because `-Install` doesn't replace a newer installed copy with an older one.

The agent port uses plain HTTP unless `agent_ssl` is on. Signing stops a tampered update being installed, but turning on `agent_ssl` is still recommended so reports and updates can't be read on the network.

**From the Configuration tab** (all servers):
- **`agent_disk_warn` / `agent_disk_crit`** are the default disk thresholds.
- **Last update date** is the newest of: Windows Update history (which includes MECM and WSUS installs), the Setup event log (every package Windows installs, even with the Windows Update service disabled), and the installed-updates list. Details shows which source it came from, and the OS build number. If you'd rather leave patch compliance to MECM, set `agent_patch_days: 0`; a pending reboot is still flagged.
- **`agent_ignore`** quietens known noise. Use a service name (`MapsBroker`), or `event:10016` (the DCOM permission errors), `apppool:OldTestPool`, `site:Default Web Site`, `disk:E:`, `dhcp:10.0.6.0`, `printer:Old MFP`, `vm:TEST01`, `storage:E:` (a volume, disk or array name).
- **`agent_watch_services`** adds services to watch on every server, even manual-start ones (e.g. `AcmeBackupAgent`).
- **`agent_event_alerts` / `agent_security_alerts`** turn those alert types off.
- Pausing a computer (maintenance) silences its agent alerts too.

## Linux agent (e.g. Immich on Ubuntu)

One Python file (`pingmonitor-agent.py`, Python 3.8+ standard library only, so nothing to install on Ubuntu 20.04 or newer). It uses the same enrolment, approval, alerts, Details, Ignore buttons and disk thresholds as the Windows agent, and shows as **Linux ✓** on the dashboard.

### What it checks

| Check | Goes amber | Goes red (and alerts) |
|---|---|---|
| **Agent** | Run slower than `agent_slow_seconds` | No report for `agent_stale_minutes` |
| **Disk** | A mount point under its amber level | Under its red level (per mount, e.g. `/` or `/srv/photos`) |
| **Services** | A failed systemd unit | A Docker container that should be up is stopped, unhealthy or restarting, or docker/containerd/ssh/cron stopped (two reports in a row) |
| **Updates** | Reboot required, security updates waiting with nothing installed for a week, or nothing installed for `agent_patch_days` | |
| **Immich** | Job queue paused or with failed jobs | Immich's API not answering (two reports) |
| **Security** | Notable events in 24 h | `agent_failed_logons` or more failed SSH/sudo logins in one report |
| **Journal** | Alert-worthy errors in 24 h | |

- **Containers:** every container that's running, has a restart policy, or belongs to a Compose stack is watched (Immich's server, machine learning, Postgres and Redis/Valkey included). A one-off container that exited cleanly isn't. Containers can be ignored like services.
- **Immich updates:** when a newer Immich release is out, the Immich check turns amber ("update available: v2.2.3 (running v2.1.0)") and you get one notification per new release, with a link to its release notes. The newest release comes from Immich's own version check if the API key can read it (the `systemMetadata.read` permission, and **Version check** on in Immich's Administration → Settings), otherwise from GitHub, at most every 6 hours (the server needs internet access for that). To stop flagging Immich updates, use **Ignore** next to the version in Details (`update:immich`).
- **Immich:** found from its container (port 2283 unless mapped elsewhere). It always checks the API answers and reports the version. With an API key it also shows each job queue (active, waiting, failed, paused), the photo and video counts and storage use.
- **Alerted as they happen:** out-of-memory kills, disk I/O and filesystem (ext4/XFS/btrfs) errors and any critical journal entry; users created or deleted (4720/4726) and users added to groups such as `sudo` or `docker` (4732). SSH logins are listed in Details but not alerted.
- **Storage:** software RAID (mdadm) arrays from `/proc/mdstat` and ZFS pools. A degraded array or a failed member is red; an array that's already rebuilding is amber.
- **Updates:** last apt run (from apt's history), packages waiting and how many are security updates (re-checked every 6 hours, after a restart, or straight after apt installs anything), and whether a reboot is required.

### Setting it up

1. In the dashboard, click **Agents** and use **Download pingmonitor-agent.py** (it uses the same address as the Windows script; check that first).
2. Copy it to the server, e.g. `scp pingmonitor-agent.py admin@server:`
3. On the server: `sudo python3 pingmonitor-agent.py --install`
   For Immich's job queues and statistics, add an API key created by an Immich admin with the `server.statistics`, `server.storage`, `job.read` (or `queue.read`) and `systemMetadata.read` permissions (Immich → Account Settings → API Keys; Immich before 1.138 needs `all`):
   `sudo python3 pingmonitor-agent.py --install --immich-api-key YOUR_KEY`
   If Immich isn't in a local container, add `--immich-url http://host:2283`.
4. Approve it under **Agents → Waiting for approval**.

It installs to `/usr/local/lib/pingmonitor/`, adds a systemd timer (`pingmonitor-agent.timer`, every 5 minutes, low CPU and disk priority) and keeps its token and log in `/var/lib/pingmonitor/` (root only). Settings, including the API key, are in `/etc/pingmonitor/agent.conf` (root only). To update, download the new version and run `--install` again, or let it update itself (see [Updating agents automatically](#updating-agents-automatically)). `--report` prints what it would send; `--uninstall` removes it. `systemctl status pingmonitor-agent` and `/var/lib/pingmonitor/agent.log` show what it's doing.

## Who can see and change things

The **Rollcall** sidebar panel is visible to every Home Assistant user, not just admins.

- **Admins** (and the owner) can do everything: add, edit and delete computers, pause and resume, and reset uptime.
- **Everyone else** gets a **View only** dashboard, showing status, services, uptime and "Check now". The editing buttons are hidden, and the add-on itself refuses changes from non-admins, so typing the URLs directly doesn't get around it.
- **`editors`**: HA usernames (or display names) of non-admins who should also be allowed to make changes, e.g. `editors: [sam]`.
- **`admin_only_changes: false`** lets anyone who can open the panel make changes.

The add-on reads HA's user list to find out who's an admin. If it can't (the log will say so), only names in `editors` can make changes. If `editors` is empty too, everyone can, so you're never locked out of your own add-on.

To hide the panel from some non-admin users entirely, remove it from their sidebar under their **Profile → Change the order and hide items from the sidebar**. That only hides it; anyone who can sign in to HA could still open the view-only page by URL.

## Monitoring schedules

By default every computer is monitored all the time. For one that's only meant to be on at certain times, open **Edit → Monitoring schedule**, choose **Only at set times** and add one or more windows, each with its days and times, e.g. Mon–Fri 07:00–19:00, or Sat 22:00–06:00 for an overnight job. A window can run past midnight; it belongs to the day it starts.

- **Outside its windows** the computer shows as **Off schedule** (grey), with when monitoring resumes. It's still pinged: if it's switched on anyway, the dot turns half green, half grey and it shows **On · off schedule**. Either way nothing alerts: no down alert, no service or agent alerts, and the agent isn't flagged for not reporting. Off-schedule time doesn't count against uptime %.
- **When a window opens** it shows **Starting up** until it replies, for up to the allowance you set (15 minutes by default, 0–240). If it hasn't replied by then, you get the usual down alert ("It didn't come up after its monitoring window started").
- **When a window closes**, it goes back to Off schedule without an alert.

Times are in Home Assistant's time zone (Settings → System → General), and follow daylight saving. The schedule shows under the computer's name on the dashboard, and the `sensor.ping_monitor_<name>` entity has `off_schedule` and `schedule` attributes. A tab condition **Status is Off schedule** lists them. A manual **Pause** still works on a scheduled computer and takes priority while it lasts.

### Computers that are usually off

For something that's only switched on now and then (cold storage, a monthly backup target), choose **Whenever it's switched on** under Edit → Monitoring schedule. Being off is then normal: it shows as **Off** (grey), never alerts for it, and off time doesn't count against uptime. While it's on, it's monitored like any other computer, with its service checks and agent, so a failed disk or a stopped service still alerts during that monthly run.

### Never alert

**Never alert for this computer** (Edit → Monitoring schedule) turns off every phone and Home Assistant notification for it: down, service checks, agent checks, events and updates. The dashboard still shows its real status and checks, it still counts in tabs such as Needs attention, and its entities and `ping_monitor_status_changed` events still update, so your own automations keep working. A 🔕 next to its name shows it's set. It can be combined with any schedule.

## Pausing for reboots (maintenance mode)

Click **Pause** on a row before rebooting or working on a machine. You'll be asked for a time limit (default `maintenance_minutes`, 30).

While paused, the machine is still pinged but shows blue **Paused** and sends no alerts:

- When it has gone down and then replies again, monitoring resumes on its own and you get a "back online" message (if `notify_recovery` is on).
- If it isn't back by the time limit, it goes red and you're alerted.
- If it never appeared to go down (a reboot quicker than the check interval), it resumes quietly at the time limit.
- **Resume** ends the pause early.

Paused time doesn't count towards uptime %, and pauses survive an add-on restart. An agent isn't flagged for not reporting while its server is paused, and gets a full `agent_stale_minutes` after the pause ends to report again.

## Export and import

**Export / import** (admins) moves everything to another install of the add-on, for example when switching from a local copy to one installed from GitHub, which Home Assistant treats as a separate add-on with its own empty data.

- **Export** downloads one zip: computers and their checks, tabs, pauses, agent approvals and enrolment key, ignores and disk thresholds, each agent's last report, uptime history and the Configuration-tab settings. Keep it safe; it contains the enrolment key.
- **Import** on the new install replaces everything there with the export and restarts the add-on. Tick **Also restore the Configuration-tab settings** to bring notifications, thresholds and agent options across too. The data it replaced is kept in a `before_import_<date>` folder in the add-on's data folder.

Agents keep reporting without being reinstalled, as long as they reach the new install on the same address and port (8100). Stop the old copy once the new one is running, since both can't use port 8100.

## The name change

Rollcall was called Ping Monitor until 1.6.0. The visible name changed; the internal names didn't, so nothing already set up breaks:
- The add-on's ID is still `ping_monitor`, so entities keep their `sensor.ping_monitor_*` names and automations and cards carry on working.
- The agents keep their file names (`PingMonitorAgent.ps1`, `pingmonitor-agent.py`), folders (`C:\ProgramData\PingMonitor`, `/var/lib/pingmonitor`), scheduled task, systemd timer and port (8100), so installed agents carry on reporting and updating as before. There's no need to redeploy them.

## What it creates in Home Assistant

**Agent sensors** — each agent check as `sensor.ping_monitor_<name>_agent_<check>` (e.g. `sensor.ping_monitor_dc01_agent_disk`), plus graphable numbers: `sensor.ping_monitor_<name>_cpu`, `_memory` and `_disk_<letter>_free` (Linux: `_disk_root_free`, `_disk_srv_photos_free`; all %).

**Computer sensors** — `sensor.ping_monitor_<name>` with state `green` / `amber` / `degraded` / `red` / `maintenance`, and attributes `ip`, `host`, `uptime_24h`, `latency_ms`, `consecutive_failures`, `last_check`, `last_change`, `maintenance_until`, `services` (a map of service label to status).

**Service sensors** — `sensor.ping_monitor_<name>_<service>` (e.g. `sensor.ping_monitor_sql01_sql`) with state `green` / `amber` / `red` / `unknown`, and attributes `target`, `detail` (e.g. `HTTP 503`, `connection refused`), `uptime_24h`, `latency_ms`, `last_check`, `last_change`.

All sensors are refreshed every 60 s, so they come back within a minute of an HA restart. They're pushed via the API, so they can't be renamed or given an area in the UI.

**Events** — `ping_monitor_status_changed` on every computer status change (`name`, `host`, `ip`, `old_status`, `new_status`, `entity_id`), and `ping_monitor_service_changed` on every service change (adds `service`, `target`, `detail`, `host_entity_id`). For example:

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

## Dashboard card (optional)

The add-on's own page is the main dashboard, but this Markdown card shows the computers on any HA dashboard:

```yaml
type: markdown
title: Computers
content: >
  | | Name | IP | Uptime 24h | Services down |
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

## Add-on security

Rollcall runs with the least access it needs, which gives it Home Assistant's top security rating of 8:
- **No extra privileges.** Ping uses unprivileged ICMP sockets, which Docker allows by default, so the add-on doesn't need the `NET_RAW` privilege. If a system doesn't allow them, Rollcall says so in its log and on the dashboard, and checks whether each host is up over TCP instead: a host counts as up if any common port (or one of its service-check ports) answers, even by refusing the connection.
- **AppArmor profile** (`apparmor.txt`), based on Home Assistant's example for add-ons that use s6-overlay: no mounting, no tracing other processes, and no capabilities beyond ordinary file ownership.
- **Ingress**: the dashboard is only reachable through Home Assistant, with Home Assistant's login.
- The Supervisor API is used with the default (lowest) role, only to read the add-on's own details, restart it after an import, and update its own options.

## Notes

- **Uptime %** is time-weighted over the last 24 hours. Amber time counts as down. Gaps where the add-on wasn't running are left out rather than guessed. The row's uptime is for ping; each service's own uptime shows when you hover over its chip and in its sensor.
- **`.local` names**: HA's DNS treats `.local` as mDNS, so AD names like `server.example.local` may not resolve from the add-on. If they don't, use IPs.
- Checks come from the HA host, so remote sites must be routable from it, and firewalls must allow ICMP echo and the ports you check.

## Files

```
rollcall/              the add-on (its internal ID is ping_monitor)
├── config.yaml        add-on manifest, options and schema
├── build.yaml         base images per architecture
├── Dockerfile
├── run.sh
├── CHANGELOG.md
├── DOCS.md            this documentation (the add-on's Documentation tab)
├── icon.png, logo.png
└── app/
    ├── main.py        scheduler, ping/port/web checks, SQLite history, HA API, web server
    ├── agents.py      agent enrolment, tokens and report evaluation
    ├── agent/PingMonitorAgent.ps1   the Windows agent
    ├── agent/pingmonitor-agent.py   the Linux agent
    └── web/index.html dashboard (served via ingress)
```
