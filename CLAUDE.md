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

Being built now (owner asked 19 Nov), together with the Resources check below:
- Edit/Add device form: explanations next to boxes (Group, Upstream device...) become an "i" with the full text on
  hover; Other addresses above Icon/Make/Line, Upstream device just below Other addresses; clearer lines between
  sections; Home Assistant device and sensors behind a tick box that opens the search; Custom checks help as an "i",
  worded more clearly.
- Details: Group Policy and Time aren't roles, move them out of Roles; lines between sections bolder than lines
  within a section (e.g. between certificates); Agent tab: Agent run above Ignored on this server; Defender: last scan
  time; Signed-in users cleared/hidden while the device is off or not reporting; Agent files: just say the folder's
  permissions were changed by WHO and the agent reset them at TIME.
- Overview: searching shows results in a temporary tab. Manage menu: an icon next to each option.

## Requested features (not started)

Features the owner has asked for, to build when they say. Remove each once it's released.

- Resources check for all agents (Windows, Linux, OpenWrt router): alert on memory and CPU, with limits editable per
  device and a way to switch it off per device. Defaults: memory amber at 90%, red at 95%; CPU amber when over 90% for
  3 reports in a row (CPU is a one-second sample per report, so one spike mustn't alert); on routers, amber when the
  15-minute load is above the number of CPU cores. Alerts like any other check. Today it's only possible via a custom
  line such as `Memory=ha:sensor.ping_monitor_<name>_memory>=90` (Rollcall's own sensors are hidden from the sensor search).
- Starlink: monitor a Starlink dish without an account token, from its local API (gRPC on the dish at
  192.168.100.1:9200, as Home Assistant's official Starlink integration does; works on residential; needs a
  route to it in bypass mode). The dish's address is fixed, so make Rollcall's dish address editable (default
  192.168.100.1:9200) for routers that map it elsewhere, and say in the docs that a LAN/VLAN on 192.168.100.0/24
  clashes with it (renumber it, or a /32 host route out of the Starlink WAN with NAT if .1 isn't the gateway). Up/connected, outage reason, obstruction, ping/latency and drop rate,
  throughput, alerts (thermal throttle, motors stuck, heating, slow ethernet, mast not vertical), update
  available, last restart, in a Starlink tab. Check how to talk to it from the add-on (grpcio vs gRPC-web, or
  reading HA's Starlink entities through a linked HA device). A dish at a REMOTE site isn't reachable from
  Home Assistant: let a Rollcall agent at that site (Windows/Linux, or the OpenWrt router agent) read the dish
  and report it, or reach it over a site-to-site VPN with a route.
  Second way in, for remote sites (owner wants it): the Starlink account (cloud), as the HA integration
  clever-tour/ha-starlink-remote does: the starlink.com session cookie pasted under Edit (copied from the
  browser's developer tools after signing in), then pick the dish from those on the account; gives throughput,
  obstruction, latency, uptime, Wi-Fi clients. Treat the cookie like the Plex token (stored with the device, never
  shown again, only sent to starlink.com); read only (no reboot/stow). It expires if the owner signs in again in the
  same browser: amber "Starlink sign-in expired: paste a new one", no alert; hint to use a private window. Unofficial
  API, may change: say so in the docs; Starlink Business has an official API (service account) if ever needed.
  One Starlink check, two sources (local default, or account), same Starlink tab. Build once the owner's dish
  arrives, to test the local side against it.

## Built, waiting for release

Built and tested on a branch, in CHANGELOG.md under "Unreleased". Show the owner the test results before
releasing; remove each line once it's released.

(none)
