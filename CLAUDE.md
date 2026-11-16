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

- Overview: the agent summary chip should say what it counts. All OK: "Windows ✓ all 14 OK" (was "Windows ✓ 14
  checks"); with problems: "Windows: 14 of 16 OK" (was "Windows: 14 OK", which didn't count the problem chips beside
  it). Same for Linux. In `svcChips()` in `rollcall/app/web/index.html`.

## Requested features (not started)

Features the owner has asked for, to build when they say. Remove each once it's released.

- Time check on domain-joined Windows computers (Windows agent): measure the clock offset with `w32tm /stripchart`
  against the DC in use (members) or the PDC emulator (other DCs). On the PDC emulator, check Windows Time syncs
  from a real source, not "Local CMOS Clock" / "Free-running System Clock". Amber over 1 minute out or not syncing,
  red over 4 minutes (Kerberos fails at 5); both thresholds as settings. Show offset, the DC compared against and
  the sync source; if the DC can't be reached, say so rather than going red. Skip computers not in a domain.
