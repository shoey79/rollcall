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

- Cisco and Juniper hardware (owner asked 23 Nov). Today any switch or router gets Rollcall's generic SNMP (ports,
  traffic, PoE) and discovery recognises Catalyst/IOS; nothing vendor-specific. Add, by SNMP object ID: Cisco
  (CISCO-PROCESS-MIB CPU, CISCO-MEMORY-POOL / ENHANCED-MEMPOOL, CISCO-ENVMON fans/PSUs/temperatures, ENTITY-SENSOR,
  stack members and ring, config changed since saved (CISCO-CONFIG-MAN), ASA failover state) and Juniper (JUNIPER-MIB
  jnxOperatingTable CPU/memory/temperature per component, jnxRedundancy, alarms jnxYellow/RedAlarmState, chassis
  FRUs), with readings as chips; optional BGP/OSPF neighbour state (BGP4-MIB, OSPF-MIB) for both. Syslog: hints for
  common %LINK/%LINEPROTO/%SYS messages. Can't test on real kit here: build from MIBs with an SNMP stand-in, then ask
  a user for snmpwalk output (names replaced).

- VMware: ESXi, vCenter, Aria (owner asked 23 Nov). Today only HTTPS reachability presets. Add read-only API checks
  with a read-only account (stored like other secrets): ESXi host (hardware health sensors, datastores free space,
  VMs on/off, host alarms, maintenance mode, certificate expiry, uptime, version) and vCenter (REST /api: appliance
  health, services, backup job status, alarms triggered, hosts connected/maintenance, clusters HA/DRS, datastores,
  vSAN health if present, certificate expiry, version/updates). Aria Operations / Automation / Operations for Logs:
  their health/status endpoints. Tabs like iLO; readings as chips. Build against stand-ins (vcsim-style fake), and
  a read-only test script for a user before release.

- Proxmox with an agent (owner asked 23 Nov). Today the preset only checks the web UI (8006/8007). With the Linux
  agent on a Proxmox host, add a "Proxmox VE" role: cluster quorum and nodes (pvecm), VMs and containers with state
  (qm/pct list, or pvesh), storage free (pvesm status), ZFS pool health, backup (vzdump) job results from the task
  log (failed backup red, like Veeam: same Backups check and tab), replication jobs, HA resources, subscription and
  pending updates (apt), Ceph health if present. Proxmox Backup Server: datastores, last verify/prune/GC, sync jobs.
  Read only (pvesh get, not set).

- System file check on Windows agents (owner asked 23 Nov). An option (off by default; per device or for all
  Windows agents) to run `sfc /verifyonly`: read only, never repairs. It takes 10-30 minutes of CPU and disk, so it
  runs in the background, not in the agent's run: weekly at a chosen time, plus a "Run now" on the device. Result
  read from CBS.log ([SR] lines; sfc's own output is unreliable UTF-16): no violations, violations found (with the
  files named), or couldn't run (another servicing operation in progress, pending reboot). Optionally DISM
  /Online /Cleanup-Image /ScanHealth (also read only) for the component store. A "System files" check: amber for
  violations, with a hint (sfc /scannow, DISM /RestoreHealth first); shown on the device's Security or Overview tab
  with when it last ran.

- Rename the agents to Rollcall (owner asked 23 Nov). Windows: PingMonitorAgent.ps1 → RollcallAgent.ps1,
  C:\ProgramData\PingMonitor → C:\ProgramData\Rollcall, task "Ping Monitor Agent" → "Rollcall Agent" (and the
  installer's names). Linux: pingmonitor-agent.py, /var/lib/pingmonitor, unit pingmonitor-agent → rollcall-agent
  (the router agent is already rollcall-agent.sh). Existing agents move themselves at an update, safely: copy the
  script, token and state to the new place, create the new task/unit, let the new one run and report, and only once
  Rollcall has had a report from the new name remove the old task/unit and folder (the old one stays as the fallback
  until then; a failed move leaves the old one running and says why). Rollcall accepts both names during the move;
  install/uninstall commands, docs and the Agents page use the new names. The add-on's own slug (ping_monitor)
  stays: changing it would make Home Assistant see a different add-on.

- pfSense / OPNsense / FreeBSD agent (owner asked 23 Nov; he has pfSense, so test on it). The Linux agent (systemd,
  /proc, apt) and router agent (OpenWrt ubus) don't run on FreeBSD; today pfSense only gets ping, HTTPS, generic SNMP
  (its bsnmpd) and syslog. Add a small sh agent for FreeBSD like the router one (fetch for HTTPS; token in the
  report): CPU, memory, disks, ZFS pool health (zpool status), temperatures (sysctl dev.cpu.N.temperature), uptime;
  pfSense: gateways up/down with loss and latency (dpinger status), CARP master/backup, IPsec (swanctl --list-sas) and
  OpenVPN tunnels, pf state table use (pfctl -si), pfSense version and available updates (pfSense-upgrade -c, pkg
  version), interface errors. OPNsense: the same base, plus its API (read-only key) as an agentless option. Read
  only. Must survive pfSense upgrades (install under /usr/local, cron via the cron package or /etc/crontab note).
  Give the owner a read-only test script for his pfSense first (output with names/addresses blanked), as for
  Starlink and Fire TV.
  Owner's test (23 Nov, pfSense 2.9.0 on FreeBSD 16, a Hyper-V VM, UFS, one gateway, no CARP/OpenVPN, IPsec
  mobile clients configured): every read under 1 s except the update check (~7 s: run daily, not every 5 min).
  CPU from two kern.cp_time reads (user nice sys intr idle); memory from vm.stats page counts x hw.pagesize; no
  temperature sysctls in a VM (say so); uptime from kern.boottime; gateways from `pfSsh.php playback gatewaystatus`
  (name, monitor, delay, stddev, loss, status) or the dpinger sockets ("name delay_us stddev_us loss"); pf states
  from pfctl -si "current entries" against pfctl -sm "states hard limit"; IPsec SAs from swanctl --list-sas (empty
  when nothing's up; --list-conns has the configured ones); interface errors from netstat -ibn <Link#> rows.
  Updates: use pfSense-upgrade -c only ("Your system is up to date"); `pkg version -l '<'` lists php etc. as older
  even when pfSense is current (they come with the next pfSense release), so don't use it. Interface names
  (WAN/LAN) and whether curl/php are there for posting (FreeBSD fetch can't POST): asked the owner to check.
  Gateway and tunnel names are user-defined: never put the owner's in tests or docs.

## Built, waiting for release

Built and tested on a branch, in CHANGELOG.md under "Unreleased". Show the owner the test results before
releasing; remove each line once it's released. Built changes waiting for release are kept on the `pending` branch
(force-pushed as it changes; main stays the released version). At release, rebase it onto main, put the CHANGELOG
rename and version bump in the release commit, push the code, wait for CI, then the bump.

(none)
