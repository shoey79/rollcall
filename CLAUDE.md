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

## Changelog formatting

- Leave a blank line between changelog entries (each top-level `- ` bullet), so changes don't run together.
  Sub-bullets under one entry stay together.

## Queued changes

Small changes the owner has asked for, to include with the next bigger release (not on their own).
Remove each line once it's released.

- SNMP: "Check now" also re-reads the port list (names/descriptions, normally every 6 hours in snmp.py's discovery),
  so a port description just changed on the switch shows straight away (owner asked 20 Nov, GS748). Say so in the docs.
- Details: move the "Domain security" section (privileged groups, KRBTGT, accounts to review; PDC emulator only)
  from the Security tab to the Domain tab (owner asked 21 Nov). Update the jump map (domain: ["security", ...] in
  index.html) and the docs.

## Requested features (not started)

Features the owner has asked for, to build when they say (he'll say once there's a reasonable number to build
together). Remove each once it's released.

- Database details and health (owner asked 20 Nov): Manage → Database. Details: database size, Rollcall's whole
  data folder, free space on Home Assistant's disk; what takes the room (check history, readings, syslog messages,
  agent metrics...) with size, row count, oldest entry, and how long each is kept. Health: SQLite quick_check daily
  and on demand (damage = red with an alert, say to restore from an export/backup); free disk amber below 10%, red
  below 5%; "Compact now" (VACUUM, admins only; check there's free space about the database's size first; it
  briefly pauses writes). Health shown in the window and on a small Rollcall card on the Overview.

## Built, waiting for release

Built and tested on a branch, in CHANGELOG.md under "Unreleased". Show the owner the test results before
releasing; remove each line once it's released.

(none)
