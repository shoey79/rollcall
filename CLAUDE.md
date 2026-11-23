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

Features the owner has asked for, to build when they say (he'll say once there's a reasonable number to build
together). Remove each once it's released.

- Offline / airgapped use (owner asked 21 Nov). An "Offline mode" setting: no downloads (vulnerability feeds, winget
  catalogue, Jellyfin/Immich release checks) and no hourly warnings; the Vulnerabilities and Software pages say the
  data is offline and how old it is. Manage → Offline data: export a bundle (vulns/ data and the winget catalogue)
  from a connected Rollcall, import it on the airgapped one, with its date shown. Also fix: the winget catalogue
  already on disk isn't loaded when the download fails (it tries the download first). Docs: what needs the
  internet, and installing the add-on without it (base image and Alpine packages from a local mirror).

- Other backup products: Veritas NetBackup and HPE/OpenText Data Protector (owner asked 22 Nov; used by other Rollcall
  users, not the owner). First a common framework in the Windows agent so each product is a small definition (where
  to read, success/warning/failure, job name, reason), feeding the same Backups check and tab, "Why?" and alerts as
  Veeam. NetBackup: on the master/primary server, its job list (bpdbjobs) with status, client and policy; status codes
  explained in the hints table. Data Protector: on the Cell Manager, session reports (omnirpt) with status, failed /
  completed with errors. Neither can be tested here: build from vendor docs, then ask a user for a sample (output or
  events, names replaced) and confirm before release; say so in the docs. Windows Server Backup is the easy next
  one if wanted (own event log).

- Fast search with many devices (owner asked 22 Nov; 127 devices, typing in the search box is slow). Cause found:
  nothing is fetched; each keystroke runs render() in full (summary, tabs with every tab's rule counts, and every
  row's HTML rebuilt: chips, uptime bars, sparklines), and the 5-second status poll re-renders too. Fix: debounce
  the search box (~120 ms); on a search, show/hide existing rows from a cached per-device search text instead of
  rebuilding; cache each row's HTML and rebuild only rows whose data changed on a poll; don't recount tabs on a
  keystroke. Measure render time with ~150 test devices before and after (Playwright), and keep the result in a test.

- Veeam agent policies on the server's Backups tab (owner asked 23 Nov). A job of type "Agent Policy" (agents
  managed by Veeam B&R) shows the policy's own session, which only runs when the policy's configuration is applied,
  so the row says "no successful run for 198 h" while the agent on the PC backs up nightly (its own Backups tab is
  right: e.g. a Warning for low repository space). Fix: on the B&R server, read each policy's real per-computer
  backup sessions / latest restore point (Get-VBRComputerBackupJobSession, Get-VBRBackup restore points, or the
  agent-backup sessions in the database) and show one sub-row per computer like copy jobs; judge the policy by them,
  not by the config session. Fallback: when a Rollcall device's own agent reports that policy's backup, fill the
  server row from that report (match by computer name; say where it came from). Don't count a config-apply session as
  a backup run.

- Fire TV / Android TV monitoring (owner asked 22 Nov; one stick, network ADB already on). No agent on the stick:
  the add-on connects over network ADB (port 5555, its own RSA key; the TV asks "Allow USB debugging?" once) and runs
  read-only shell commands. A "Fire TV" preset and tab like Starlink: online and ADB still trusted, model, Fire OS
  version, uptime/restarts, free storage, memory, Wi-Fi signal/link speed/band, temperature where reported, app in
  front, installed apps with versions (flag sideloaded). Every value usable as a readings chip with limits. Say
  plainly that network ADB gives full control to anything on the network (suggest a separate network, or ADB off on
  sticks not monitored). Never send input, install, or change settings. Build against a stand-in ADB device in
  tests; give the owner a read-only test script for his stick before release (as for Starlink).
  Owner's test (22 Nov, Fire TV Stick 4K, Fire OS 6): full read ~4 s (each `pm`/`settings` call ~1.5 s, starts Java).
  Fire OS version from `ro.build.mktg.fireos` first (`ro.build.version.fireos` is only the generation, "6.0").
  Load average is useless (5-6 on an idle 4-core stick): use CPU % from two `/proc/stat` reads, never the router
  load rule. `/sys/class/thermal` is permission-denied over ADB: say "not readable on this model". Also add: count
  of disabled packages (`pm list packages -d`; a drop means an update re-enabled debloated apps) and, for each
  sideloaded app, whether it's running (`pidof`) and its service count (e.g. a custom launcher's Home helper).
  CPU swings with video (13% then 47.5%, both YouTube): sample 2-3 s and only go amber when it stays high over
  several checks.
  Don't scrub version numbers as IP addresses. TV approval with Rollcall's own key not yet tested (he used adb).

## Built, waiting for release

Built and tested on a branch, in CHANGELOG.md under "Unreleased". Show the owner the test results before
releasing; remove each line once it's released. Built changes waiting for release are kept on the `pending` branch
(force-pushed as it changes; main stays the released version). At release, rebase it onto main, put the CHANGELOG
rename and version bump in the release commit, push the code, wait for CI, then the bump.

(none)
