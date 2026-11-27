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

- End-of-life exclusion too broad (owner reported 27 Nov): ticking Windows 10 in vuln_skip_os (or "Treat this device as
  end of life") silences everything, including third-party programs (e.g. an old Firefox) and WordPress. It should only
  silence the operating system's own vulnerabilities (Windows build / Linux distro packages); other programs and
  WordPress keep alerting. Vulnerabilities tab banner and check detail to say which part is excluded.
  Owner's addition: a second tick for "its programs too", for when programs can't be updated on an old OS. In Settings,
  each ticked release gets "and its programs"; on a device, "Treat as end of life" gets the same two choices; plus
  "Don't alert" on one program on one device (e.g. an app that can't be updated), shown as such and listed under Ignored.
- Vulnerabilities tab split (owner asked 27 Nov): it's one mixed list today (Windows CVEs between WinRAR and Chrome).
  Keep it one tab (owner's words), with its own headings: Operating system (Windows build or distro packages; one line per CVE, with the fixing KB/build),
  Programs (grouped by program: name, installed, fixed in, CVE count, worst score, exploited; expand for the CVEs) and
  WordPress (by site). Each section has its own end-of-life/not-alerted state (goes with the exclusion fix above).
- Ignored services across versions (owner asked 27 Nov): services named with their version (GoogleUpdaterService159.0.8140.0,
  GoogleUpdaterInternalService...) come back as a new name after each update, so Ignore never sticks. Service ignores to
  accept * wildcards (service:GoogleUpdater*), and Ignore on a service whose name ends in a version offers "all versions"
  (stores the name without the version plus *). Show matches as Ignored (all versions). Same for agent_ignore entries.
- Security tab: with no security filters, secFiltersSection() returns a bare hint ("Expected changes, such as a managed
  account being recreated...") that lands under Passwords left in files, as if it belonged there (owner spotted 27 Nov).
  Give it its own "Security filters" heading even when empty, or put it with the security events it's about.

## Requested features (not started)

- WordPress on Linux (owner asked 27 Nov): the Linux agent finds WordPress installs (Apache/nginx site configs, /var/www,
  up to two folders down) and sends the same shape as the Windows agent (wordpress.py, WordPress tab and Wordfence already
  OS-agnostic). Files only: version.php and plugin/theme headers, never wp-config.php or the database. Docker-hosted
  WordPress (files in container volumes) as a later step. Leave on the list until asked.
- Sophos firewall mail and attack tables (owner asked 27 Nov): Sophos XG/XGS syslog (key="value" pairs) already reaches
  Rollcall. On the firewall's Logs tab, add tables built from it:
  - Mail: log_type Anti-Spam / Anti-Virus with log_component SMTP: time, sender, recipient, subject, reason
    (log_subtype / quarantine_reason), action (e.g. QUARANTINE), size, source host, IP and country.
  - Attacks: log_type IDP (and Web Server Protection / WAF): time, message (signature), classification, priority,
    firewall rule, source IP and country, destination IP and port, victim.
  Filter, counts per day, top senders/sources. Mail details are personal data: admins and editors only, kept for
  history_days. Owner's sample lines are real: never copy them; tests use made-up values (contoso.local, 192.168.1.x,
  203.0.113.x / 198.51.100.x for outside addresses, sender@example.com). Leave on the list until asked.

## Built, waiting for release

Built and tested on a branch, in CHANGELOG.md under "Unreleased". Show the owner the test results before
releasing; remove each line once it's released. Built changes waiting for release are kept on the `pending` branch
(force-pushed as it changes; main stays the released version). At release, rebase it onto main, put the CHANGELOG
rename and version bump in the release commit, push the code, wait for CI, then the bump.

- Acknowledge on Vulnerabilities (owner reported 27 Nov): the ack stored only the OS's CVEs, so a program's (Chrome)
  counted as new at once and it never cleared. Now stores every CVE the check counts.
