# Rollcall

*Who's up, and how are they doing?* Server monitoring for Home Assistant.

[![Add repository to Home Assistant](https://my.home-assistant.io/badges/supervisor_add_addon_repository.svg)](https://my.home-assistant.io/redirect/supervisor_add_addon_repository/?repository_url=https%3A%2F%2Fgithub.com%2Fshoey79%2Frollcall)

Rollcall is a Home Assistant add-on with its own sidebar dashboard. It started as a ping monitor and grew into a small monitoring system for a home lab or a business estate.

## What it does

- **Ping** every computer on a schedule: green when it answers, amber after one miss, red (and a notification) after two.
- **Service checks** on each computer: TCP ports and web pages, with 80+ presets (IIS, SQL Server, Exchange, RDP, domain controllers, Proxmox, Plex, Jellyfin, Immich, UniFi, iDRAC…). A failing service shows the computer as *Degraded*.
- **Windows agent** (PowerShell, deploy by Group Policy or MECM): works out each server's roles and reports disk space, role services, System/Application errors, Security log events (lockouts, admin-group changes, cleared logs), Defender, IIS, AD replication, DHCP scopes, Hyper-V and more.
- **Linux agent** (one Python file, no dependencies): disks, failed systemd units, Docker containers and health checks, Immich, journal errors, SSH/sudo failures, user and group changes, pending updates.
- **Home Assistant sensors as checks**, e.g. CPU and memory of UniFi access points.
- **Dashboard** with sorting, search, tabs and custom filters (name, IP range, OS, role, status…), a 24-hour history strip and uptime %.
- **Alerts** as phone notifications (tap to open the dashboard) and Home Assistant notifications; **maintenance mode** for reboots.
- **Entities** for every computer and check, for your own automations and cards.

## Install

1. Click the button above, or in Home Assistant go to **Settings → Add-ons → Add-on Store → ⋮ → Repositories** and add `https://github.com/shoey79/rollcall`.
2. Install **Rollcall**, start it and turn on **Show in sidebar**.

Full documentation is on the add-on's **Documentation** tab, and in [rollcall/DOCS.md](rollcall/DOCS.md).

## Licence

[MIT](LICENSE)
