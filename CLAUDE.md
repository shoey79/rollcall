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

(none)

## Requested features (not started)

Features the owner has asked for, to build when they say (he'll say once there's a reasonable number to build
together). Remove each once it's released.

- Several Home Assistant devices on one Rollcall device (owner asked 19 Nov): today a Rollcall device links one HA
  device (h.ha_device). Allow a list, e.g. the myenergi integration's Zappi, house (hub) and Harvi on one entry; each
  device's entities listed under its own heading; edit form lets you link more than one; keep old single links working.
- myenergi profile in hadevice.py, like Pi-hole's (owner asked 19 Nov; needs the multi-device link above). Match
  entities by translation key / unique id ending, never the entity id (renamed devices; ids can include the serial,
  which must never go in the repo: use a made-up serial in tests). From the owner's Zappi (HACS myenergi): status
  (Paused/Charging/Boosting/Completed), plug_status (EV Disconnected/EV Connected/Waiting for EV/Charging/Fault/Restart),
  select charge_mode (Fast/Eco/Eco+/Stopped), charge_added_session (kWh), energy_used_today, green_energy_today,
  power_ct_internal_load (CT1, the charger's own load = charging power), power_ct_grid (CT2, negative = exporting),
  power_ct_generation (CT3), binary_sensor locked, binary_sensor update_available, number_of_phases, firmware.
  Tiles: status, plug, mode, charging power, added this session, used today (green part), grid and solar when
  clamped, locked. Hub device ("myenergi Hub"; the owner named it, keep his name out of the repo): generated_today,
  green_energy_today, grid_export_today, grid_import_today, hub_firmware, hub_serial_number; diagnostic:
  voltage_grid (V), frequency_grid (Hz), home_consumption (W), power_import, power_export, power_grid,
  power_charging, power_generation (W). Hub tiles: grid voltage and frequency, home using now, importing/exporting
  now. Owner confirmed: amber, no notification, when the voltage is outside the UK supply range 216-253 V
  (230 V +10%/-6%) or the frequency outside 49.5-50.5 Hz. Harvi device (wireless CT
  sender; its entity ids include its serial, keep that out of the repo): power_ct_generation, generation_ct1,
  none_ct2/none_ct3 (CTs not set up, ignore "None" CTs), firmware. Generation CTs: DON'T call them "Solar" or
  derive anything from them: the owner's Harvi generation CT also sees his home batteries discharging, so it isn't
  solar. Show "Generation (as myenergi measures it)", summed across the linked myenergi devices' generation CTs,
  information only, never alerted. Day totals tile from the hub: imported, exported, generated today (same caveat). Alerts: plug status Fault/Restart RED with a phone notification;
  update available amber, no alert; HA lost touch (already generic) should say it may be myenergi's cloud.
- Messages to users' screens (owner asked 19 Nov): a simple message box on agent devices, sent in Rollcall's reply to
  each agent's next report (so it arrives within ~5 minutes). Keep it simple, minimal parts: Windows via WTSSendMessage
  from the agent (works as SYSTEM, shows in every signed-in session incl. Remote Desktop; no helper, no toast);
  Linux via wall (and a desktop notification only if trivial); routers left out. Fixed heading the sender can't change:
  "Message from the Rollcall Administrator". Plain text only, no links or buttons, length limit. The whole message
  system is OFF by default (add-on setting); admins choose which machines are included (only those can receive); only
  admins can send; send to one device, a tab or all included devices; an expiry so a device that was off doesn't show a
  stale message later; logged (who, what, which devices, when) and Details shows which devices have shown it. Docs:
  say it's off by default and why (a compromised Home Assistant could otherwise message users), and that a sign-in
  message of the day is better done with Group Policy's "Interactive logon: Message text".
- Agent HTTPS made simple, with pinning (owner asked 19 Nov): today agent_ssl needs the owner's own certificate in
  /ssl, and "Accept a self-signed certificate" makes agents accept ANY certificate (encrypted, but not protected from
  impersonation). Instead: Rollcall generates its own key and self-signed certificate (in /data) the first time HTTPS
  is turned on, with SANs for the inside/outside addresses (IPs and names); no CA, nothing in Windows' trust store.
  Downloaded agent scripts get the public-key (SPKI SHA-256) fingerprint built in, like the enrolment key; agents
  check the key before sending the token or anything else and refuse any other key. Installed agents are moved over
  in the report reply (HTTPS address + fingerprint, as "servers" and secret_scan settings are sent now): that one
  hand-over is over HTTP (trust on first use), pinned from then on. Keep HTTP working for old agents until the owner
  turns it off (a setting). Pin the key, not the certificate, so certificate renewal doesn't matter; if the key ever
  changes, send the next key's pin ahead so agents accept both during the switch. A reverse proxy with a real
  certificate (outside address) keeps normal validation; pinning is for Rollcall's own certificate. Windows PS 5.1:
  in the existing certificate-callback path; Linux: Python ssl, check the peer's key before sending; router:
  uclient-fetch can't pin, so give it Rollcall's certificate as --ca-certificate (SANs must cover the address it
  uses), or pin with curl --pinnedpubkey when curl is installed. Docs: why pinning is stronger than "accept
  self-signed".
  Defaults (owner agreed 19 Nov): existing installs are NOT switched automatically; admins see a dashboard prompt
  ("Agents report over plain HTTP: turn on HTTPS"), one click makes the certificate and moves agents at their next
  report, HTTP stays until the owner turns it off. New installs: on from the start.
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

## Being built now: 1.92.1 security fixes (owner asked 19 Nov, from an outside security review)

- Agent updates signed with an RSA key only Rollcall holds (generated in /data, public key built into downloaded
  scripts), replacing the HMAC keyed by the agent's token (an attacker on a plain-HTTP path could capture the token
  and sign a forged update). Also sign the servers/route list in the report reply. Agents refuse older or equal
  versions (no downgrade replay). Old agents get the new version once the old way. Signature in the reply body, not a
  new header (owner's external agents go through a Sophos reverse proxy). Key included in Export/import. A failed
  check never stops reporting.
- Dashboard editing fails closed when HA's user list can't be read (only 'editors' can change things; dashboard says
  why). Panel is open to all HA users (panel_admin false), so this mattered.
- Base image from Alpine 3.20 (unsupported) to a current HA base; a CI job that builds and starts the container.
- Docs: clear the syslog port if unused; firewall TCP 8100 / UDP 514 to known senders.
Owner wants full testing that no agent loses connectivity: Windows (PS 5.1 + 7) and Linux end to end against the real
add-on, forged/tampered/downgrade updates refused while reporting carries on; router unaffected but run; container
built and an agent reporting into it. Show results before releasing.

## Built, waiting for release

Built and tested on a branch, in CHANGELOG.md under "Unreleased". Show the owner the test results before
releasing; remove each line once it's released.

(none)
