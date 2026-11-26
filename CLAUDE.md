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

- Defender definitions show the date updated and age from now (Windows agent 1.0.57 sends the date), not "today".

- Security review fixes F1-F14 (router agent 1.0.5 trusts Rollcall's CA; Linux 1.0.23; Windows 1.0.58; Approve all by
  ids; signed-reply serials; legacy update cut-off; enrolment limits; ingress_only option), and Windows Read-State
  keeping the Veeam policy cache and backup history.
- 26 Nov items: backup warning Acknowledge, security alerts kept until acknowledged (failed logons/events at the top
  of Security, password-scan (i)), LAPS on Domain, Vulnerabilities tab, Hyper-V VM uptime/CPU/memory/checkpoints,
  IP address change prompt (Use / Keep).

- The requested features (owner asked 26 Nov to include them): What's new pop-up; system file check (Windows 1.0.59);
  offline mode and offline data bundles; agents renamed to Rollcall (Windows 1.0.60, Linux 1.0.25; a -DataPath install
  keeps updating); Proxmox VE/PBS through the Linux agent (1.0.24); pfSense/OPNsense/FreeBSD agent (1.0.0); OPNsense
  through its API (no agent); Cisco and Juniper over SNMP; VMware ESXi/vCenter/Aria (tested against vcsim's recorded
  answers; a standalone read-only test script for a user exists in the session, not the repo). Still worth real-kit
  output from users for Cisco/Juniper, VMware, OPNsense API and Aria.
