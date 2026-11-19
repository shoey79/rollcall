# Working on Rollcall

This repository is public. Never publish details of a real network in code, comments,
docs, changelogs, commit messages or test data:

- No real domain names, computer names, account names, IP addresses, phone or SIP providers,
  ports or serial numbers taken from a user's environment, logs or screenshots.
- Use generic stand-ins instead: domain `CONTOSO` / `contoso.local` / `example.local`,
  computers `PC01`, `SRV01`, `DC01`, accounts `svc_backup`, `admin`, addresses `192.168.1.x`
  or `10.0.1.x`, hosts `server.example.local`, providers `sip.provider.example`.
- When a fix comes from a user's real log line, rewrite the example before it goes in
  the changelog or docs.

## Changelog entries for GitHub issues

- When a change comes from a GitHub issue or request, link the issue in its changelog entry and thank
  the person who raised it, e.g. `([#4](https://github.com/shoey79/rollcall/issues/4), thanks to
  [name](https://github.com/name) for the request)`. Their GitHub username is public, so it's fine to use.
- Don't write a bare `@name` in commit messages (it notifies them); link the profile in the changelog instead.

## Queued changes

Small changes the owner has asked for, to include with the next bigger release (not on their own).
Remove each line once it's released.

- Settings: in two-column rows, line the input boxes up level even when one side's help text wraps
  to more lines (e.g. Checking: "Re-check after a miss" box sits lower than "Check interval").
  Check every settings tab.
- Windows services: Automatic (Delayed Start) services are already watched (WMI reports them as
  "Auto"). Have the agent report the delayed flag, show "(delayed start)" in Details, and don't count
  a delayed-start service as stopped until the computer has been up ~5 minutes (avoids a brief amber
  just after a restart).
- Sizes in MB when small ([#12](https://github.com/shoey79/rollcall/issues/12), thanks to
  [tomvining](https://github.com/tomvining)): Details shows memory rounded to whole GB ("45% of 0 GB" on
  a router) and disks only in GB ("0.001 GB free of 0.002 GB" for a small OpenWrt overlay). Show MB
  under 1 GB for memory and disks (index.html System and Disks sections). Also check the Home Assistant
  disk sensor, which skips disks under 0.5 GB, so a router's overlay gets no sensor.
- Say "device" instead of "computer" everywhere users see it: the dashboard, settings and their
  translations (en.yaml), alerts and emails, Home Assistant entity names, agent messages and logs,
  DOCS.md, README.md and the GitHub repo description/issue templates. Keep "computer" where it's a
  Windows term (Group Policy's "Computer Configuration", computer accounts, `$env:COMPUTERNAME`,
  "This computer" on the installer), and don't rename setting keys, API fields or entity IDs, so
  existing setups keep working. Leave past CHANGELOG entries as they are; note the rename in the new one.
- Overview table layout: on a narrower window the rows grow very tall with mostly empty space, and the
  actions column (Check now / Details / Pause / Edit) runs off the right edge with "Edit" cut off.
  Find which column wraps and makes rows tall, keep rows compact, and keep all the buttons visible
  (wrap them or let the table scroll sideways). Check at a few window widths.

## Requested features (not started)

Features the owner has asked for, to build when they say. Remove each once it's released.

- Dependent devices ([#13](https://github.com/shoey79/rollcall/issues/13), thanks to
  [tomvining](https://github.com/tomvining)): let a device have an upstream/parent (e.g. a router).
  When the parent is down, show the devices behind it as unreachable rather than down and send one
  notification for the parent listing what may also be affected, instead of one per device.
- Jellyfin check: a service check run by the add-on (not the agent) using a Jellyfin API key, stored as
  a secret setting that's never shown again and only sent to that Jellyfin server. Up/down (/health),
  version, restart pending and update available (/System/Info), failed scheduled tasks (e.g. library
  scan) shown amber only (no alert), and a count of active streams (no transcoding alert). Confirm
  endpoints against the Jellyfin API docs when building.
