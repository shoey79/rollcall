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

- LAPS (issue 16, tomvining): when a device hasn't been able to reach a domain controller (Group Policy / time sync
  failing too, or it's been off/away), say "hasn't been on the domain network since <date>" instead of a bare LAPS
  error code, and don't alert for LAPS alone in that case.

## Requested features (not started)

Features the owner has asked for, to build when they say (he'll say once there's a reasonable number to build
together). Remove each once it's released.

- Database details and health (owner asked 20 Nov): Manage → Database. Details: database size, Rollcall's whole
  data folder, free space on Home Assistant's disk; what takes the room (check history, readings, syslog messages,
  agent metrics...) with size, row count, oldest entry, and how long each is kept. Health: SQLite quick_check daily
  and on demand (damage = red with an alert, say to restore from an export/backup); free disk amber below 10%, red
  below 5%; "Compact now" (VACUUM, admins only; check there's free space about the database's size first; it
  briefly pauses writes). Health shown in the window and on a small Rollcall card on the Overview.

- Hints for errors (issue 16, tomvining; owner asked 21 Nov). Two parts, the table first:
  1. Built-in "what this usually means" table for well-known codes (LAPS events, Group Policy failures, Windows
     Update HRESULTs, backup results...), shown under the error. Free, offline.
  2. Claude hints, OFF by default (add-on setting, admins only): the admin's own Anthropic API key, kept like the
     Plex token (never shown again, only sent to Anthropic's API). A 💡 by an amber/red check; clicking asks a small
     fast model for a few sentences, marked as a suggestion from Claude; advice only. On request only, cached per
     error, daily limit. Send only the check, error text/code and basic context; replace computer/account/domain
     names and IPs with stand-ins first; never send security events, account lists or password-scan results.
     Docs: what's sent, cost, privacy. Tests against a stand-in API, including the redaction.

## Built, waiting for release

Built and tested on a branch, in CHANGELOG.md under "Unreleased". Show the owner the test results before
releasing; remove each line once it's released.

(none)
