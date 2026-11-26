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

(none)

## Requested features (not started)

(none)

## Built, waiting for release

Built and tested on a branch, in CHANGELOG.md under "Unreleased". Show the owner the test results before
releasing; remove each line once it's released. Built changes waiting for release are kept on the `pending` branch
(force-pushed as it changes; main stays the released version). At release, rebase it onto main, put the CHANGELOG
rename and version bump in the release commit, push the code, wait for CI, then the bump.

- End-of-life OS ticks (owner asked 26 Nov): Settings ticks per reported release with device counts and end dates; LTSC/LTSB/IoT
  no longer matched by "Windows 10" (that silenced supported LTSC machines in 1.100.0-1.101.0).
- Manage menu (owner asked 26 Nov): grouped under Devices / Activity / Data headers, Settings at the bottom.
