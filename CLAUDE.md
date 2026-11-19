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

Features the owner has asked for, to build when they say. Remove each once it's released.

- Veeam job details: when a Veeam job warns or fails (Backup & Replication jobs and Veeam Agent jobs), the
  agent fetches why: for each VM/object in that session its status and Veeam's reason, plus the session's
  warning/error log lines (Veeam PowerShell, e.g. Get-VBRBackupSession / task sessions, when installed;
  otherwise the Veeam Backup event log's per-task events). Only for the latest warned/failed session, kept
  short. In Details > Backups, a button on that job's row opens the details. No names from a real
  environment in tests or docs.
- Jellyfin in Details: its section (server, version, health, streams count, failed tasks) is only drawn on
  the Overview page of a device WITHOUT an agent (openOverview/renderOverview), so on a server with an agent
  nothing shows. Give Jellyfin its own Details tab (like SNMP/Logs/iLO) for any device with the check.
  Show current streams: user, client/device, what's playing, direct play or transcoding (and why), progress,
  paused; plus other useful server info (e.g. library item counts, active users). Read with the same API key,
  only sent to that Jellyfin server; no real names in tests or docs.

## Built, waiting for release

Built and tested on a branch, in CHANGELOG.md under "Unreleased". Show the owner the test results before
releasing; remove each line once it's released.

(none)
