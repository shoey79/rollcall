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

- WordPress on Linux (owner asked 27 Nov): the Linux agent finds WordPress installs (Apache/nginx site configs, /var/www,
  up to two folders down) and sends the same shape as the Windows agent (wordpress.py, WordPress tab and Wordfence already
  OS-agnostic). Files only: version.php and plugin/theme headers, never wp-config.php or the database. Docker-hosted
  WordPress (files in container volumes) as a later step. Leave on the list until asked.

## Built, waiting for release

Built and tested on a branch, in CHANGELOG.md under "Unreleased". Show the owner the test results before
releasing; remove each line once it's released. Built changes waiting for release are kept on the `pending` branch
(force-pushed as it changes; main stays the released version). At release, rebase it onto main, put the CHANGELOG
rename and version bump in the release commit, push the code, wait for CI, then the bump.

- Ping timeout traceback (owner reported 27 Nov): when ping ran out of time just as it finished, proc.kill() raised
  ProcessLookupError and the check logged "Check failed" with a traceback (computers that were off). Now no reply.
- Vulnerability matching speed (owner reported 27 Nov: "held up for 16 s" in thirdparty._parts after updating):
  thirdparty.Data.hits caches per product version; main caches tp/wp findings per device until programs or data change.
