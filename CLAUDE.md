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

- Settings, AI hints (owner asked 26 Nov): lay out each provider's model and API key side by side on the same row
  (Claude model | Anthropic key, OpenAI model | OpenAI key, Gemini model | Gemini key); today the models are one
  column and the keys the other, so they don't line up.

## Requested features (not started)

- Vulnerabilities: leave out end-of-life OSes (owner asked 26 Nov). Some devices run an OS known to be out of support
  (e.g. Windows 10 without ESU) and are kept on purpose; their vulnerabilities shouldn't alert. A list of OSes (and
  optionally single devices) to exclude, e.g. "Windows 10", "Windows Server 2012 R2", "Ubuntu 20.04": in Settings
  (an option like `vuln_skip_os`) and per device in its Vulnerabilities tab. Excluded ones: no amber/red and no
  notifications from the Vulnerabilities check, known-exploited ones included (owner's decision); no badge or count on
  the Vulnerabilities tab itself. Opening the tab still lists everything found, with a note that the OS is excluded as
  end of life. The Updates check and everything else unchanged. Devices on any OS not excluded (e.g. Windows 11)
  keep the badge, colours and notifications exactly as now. Docs and changelog.

## Built, waiting for release

Built and tested on a branch, in CHANGELOG.md under "Unreleased". Show the owner the test results before
releasing; remove each line once it's released. Built changes waiting for release are kept on the `pending` branch
(force-pushed as it changes; main stays the released version). At release, rebase it onto main, put the CHANGELOG
rename and version bump in the release commit, push the code, wait for CI, then the bump.

(none)
