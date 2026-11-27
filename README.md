# Rollcall

*Who's up, and how are they doing?* Server monitoring for Home Assistant.

[![Add repository to Home Assistant](https://my.home-assistant.io/badges/supervisor_add_addon_repository.svg)](https://my.home-assistant.io/redirect/supervisor_add_addon_repository/?repository_url=https%3A%2F%2Fgithub.com%2Fshoey79%2Frollcall)

Rollcall is a Home Assistant add-on with its own sidebar dashboard. It started as a ping monitor and grew into a small monitoring system for a home lab or a business estate.

## What it does

- **Ping** every device on a schedule: green when it answers, amber after one miss, red (and a notification) after two.
- **Service checks** on each device: TCP ports, web pages, certificates and SIP, with 80+ presets (IIS, SQL Server, Exchange, RDP, domain controllers, Proxmox, Plex, Jellyfin, Immich, UniFi, iDRAC…). A failing service shows the device as *Degraded*.
- **Agents** for Windows (PowerShell, deploy by Group Policy, MECM or an .msi), Linux (one Python file), OpenWrt routers and pfSense, OPNsense and FreeBSD firewalls. They work out each machine's roles and report disks, services, logs, security events, updates, backups (Veeam and more), AD, DHCP, Hyper-V, SQL Server, Exchange, Docker, Proxmox and more. Agents update themselves, can report over HTTPS, and never send a password found in a file.
- **Known vulnerabilities:** Windows builds, Linux packages, common Windows programs (Chrome, 7-Zip, Adobe, .NET and about 45 more) and WordPress sites, from Microsoft's, OSV.dev's, the NVD's, Wordfence's and CISA's public data. End-of-life systems can be listed without alerting, their programs too if they can't be updated.
- **WordPress sites** on IIS servers: versions, plugin and theme updates and closed plugins, read from the files only.
- **Devices without an agent:** SNMP (switches, UPSs, printers, NAS units, firewalls, Cisco and Juniper), syslog (with email and attack tables for Sophos firewalls), HPE iLO, VMware vSphere and Aria, OPNsense, Jellyfin, Plex, Fire TV, Starlink, and any Home Assistant sensor or device.
- **Dashboard** with alerts, search across tabs, custom tabs and filters, notes on each device, a 24-hour history strip, uptime % and graphs.
- **Alerts** as phone notifications, Home Assistant notifications and email; acknowledging, maintenance mode and monitoring schedules; optional hints from AI for errors.
- **Entities** for every device and check, for your own automations and cards.

## Install

1. Click the button above, or in Home Assistant go to **Settings → Add-ons → Add-on Store → ⋮ → Repositories** and add `https://github.com/shoey79/rollcall`.
2. Install **Rollcall**, start it and turn on **Show in sidebar**.

Full documentation is on the add-on's **Documentation** tab, and in [rollcall/DOCS.md](rollcall/DOCS.md).

## Licence

[MIT](LICENSE)
