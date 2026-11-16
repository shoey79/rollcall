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
- Add-on log in the dashboard (Manage menu), so it doesn't need Settings > Apps > Rollcall > Log. The add-on
  already has `hassio_api`, so read its own log from the Supervisor (`GET /addons/self/logs`, which covers before
  the last restart too); fall back to an in-memory buffer of recent lines if that's refused. Admins only; filter
  by level (warnings and errors) and search; refresh/follow; download. Mask anything secret-looking.
- DFS Replication check (1.85.0) misses errors it doesn't know by ID: it only reads 2104, 2212-2214, 4012, 46xx and
  500x, so e.g. 6404 (a replicated folder's local path is invalid or can't be reached) doesn't flag. Also read every
  Error-level event in the DFS Replication log (last 24 h; Warning-level too, shown but not alerting), name the
  common ones (6404 and other 64xx config/path errors, 4302/4304 sharing violations, 4202/4204 staging space,
  2010/2012 volume and database problems) and show the rest with their ID and first line. Amber for an error in
  the last 24 h until the folder is back to normal or the same ID hasn't recurred for a day; keep the existing red
  cases. Ignorable by event ID per server (`dfsr:event:6404`). Needs a Windows agent version.
