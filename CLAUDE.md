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

- Hints from other AI providers (owner asked 21 Nov). Error hints currently use Claude only (hints.py, settings
  claude_*). Add a provider choice: Anthropic (Claude), OpenAI, Google Gemini (and similar hosted APIs), each with its
  own API key kept like the Claude key (never shown again, only sent to that provider) and a model setting. Same
  rules for all: off by default, admins only, on request, cached, daily limit, the same redaction and never-sent
  checks; the answer says which provider wrote it. Docs and changelog name the provider in use; migrate the existing
  claude_* settings. Tests against stand-in APIs for each provider.

- Starlink alignment and obstruction map (owner asked 21 Nov). Alignment: read the dish status's alignment stats
  (current and desired boresight azimuth/elevation, tilt) that starlink.py currently skips; draw a compass and tilt
  gauge in Rollcall's own style; "Pointing 292°, wants 300°"; amber when well off (knocked or mount moved).
  Obstruction map: one more read-only request (get obstruction map: grid of SNR cells, clear / obstructed / no data),
  read when the Starlink tab opens, not every check; draw a sky plot with N/E/S/W and say which directions are
  blocked. Note the map builds up over time and resets on reboot. Confirm field numbers against a real dish first
  (owner's local dish, test script like out/starlink-test.py), and whether account mode (starlink.com) offers both.
  Still never changes anything on the dish; update starlink.py's "only request" note and the docs. FakeDish tests.

## Built, waiting for release

Built and tested on a branch, in CHANGELOG.md under "Unreleased". Show the owner the test results before
releasing; remove each line once it's released.

(none)
