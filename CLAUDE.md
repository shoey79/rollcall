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

- Rename the menu item **Manage > Add computer** to **Add device** (and its dialog title, docs and any other
  wording that says "Add computer" for the same thing).

## Requested features (not started)

Features the owner has asked for, to build when they say. Remove each once it's released.

- **VPN status for Sophos XG/XGS firewalls** (not UTM: it's end of life): a down IPsec tunnel went unnoticed,
  though SNMP and syslog were on. Poll `sfosIPSecVpnTunnelTable` (SFOS-FIREWALL-MIB,
  `.1.3.6.1.4.1.2604.5.1.6.1.1.1`): connection name (`.1.2`), status (`.1.9`: 0 inactive, 1 active,
  2 partially active), activated (`.1.10`). Show each tunnel in the device's details; alert only for tunnels
  that are meant to be up (activated, not on-demand), with per-tunnel Ignore.
- **Agents choose the internal or external address by subnet**: many agents now report through the external
  address. Cause: both agents try the address that worked last first (`last_server` / `PreferredServer`), so one
  failed internal attempt switches them to external for good.
  - New setting under Agents: **internal networks** (a list of subnets, e.g. `10.0.1.0/24`; Home Assistant's
    own networks could be suggested). Sent to agents with the addresses, as `servers` is now.
  - Each run, the agent checks its own IPv4 addresses: on an internal network, try the internal address first,
    then the external one if that fails; otherwise, external first. Don't stick to whichever worked last, so it
    returns to the internal address on the next run.
  - Show which address each agent reported through (internal / external) on the Agents page, so drift is visible.
  - Both agents (Windows and Linux); keep the addresses the agent was installed with as the last fallback.
