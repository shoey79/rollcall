# Contributing to Rollcall

Thanks for helping. Bug reports, ideas, device details and pull requests are all welcome.

## Reporting a bug or asking for something

Open an [issue](https://github.com/shoey79/rollcall/issues/new/choose) and pick the form that fits:

- **Bug report:** something isn't working as it should.
- **Feature request:** something you'd like Rollcall to monitor, show or do.
- **Device or icon support:** a device to recognise, read over SNMP, or give its own icon.

Security problems go through the [security policy](SECURITY.md) instead, not a public issue.

## Keep your network private

This repository is public. Before posting logs, screenshots or examples, replace anything that identifies your network:

| Instead of your real… | Use |
|---|---|
| Domain | `CONTOSO`, `contoso.local`, `example.local` |
| Computer names | `PC01`, `SRV01`, `DC01` |
| Accounts | `jsmith`, `svc_backup`, `admin` |
| Addresses | `192.168.1.x`, `10.0.1.x`, `server.example.local` |
| Phone or SIP provider | `sip.provider.example` |

Remove serial numbers, MAC addresses and public IP addresses too. The same goes for code, comments, tests, docs and changelog entries in pull requests.

## How the project is laid out

| Path | What it is |
|---|---|
| `rollcall/config.yaml` | The add-on's manifest: version, options and their schema |
| `rollcall/app/main.py` | The add-on: checks, scheduling, alerts, Home Assistant integration and the web API |
| `rollcall/app/agents.py` | Agent enrolment, report cleaning and the agent checks (what's green, amber or red) |
| `rollcall/app/snmp.py`, `sipcheck.py`, `syslogrx.py`, `discovery.py`, … | SNMP, SIP, syslog and network discovery |
| `rollcall/app/web/index.html` | The whole dashboard (HTML, CSS and JavaScript in one file) |
| `rollcall/app/agent/PingMonitorAgent.ps1` | The Windows agent |
| `rollcall/app/agent/pingmonitor-agent.py` | The Linux agent |
| `rollcall/DOCS.md` | The documentation shown in the add-on's Documentation tab |
| `rollcall/CHANGELOG.md` | The changelog shown in Home Assistant |

## Making a change

1. Fork the repository and make your change on a branch.
2. Keep the existing style: plain, friendly wording in the dashboard and docs, and no new dependencies unless there's a good reason.
3. **Agents have to stay easy to deploy:**
   - The Windows agent must run on Windows PowerShell 4.0 and 5.1 (Windows Server 2012 R2 and later), so avoid PowerShell 7-only syntax such as `??`, `?.`, ternaries or `-replace` with a script block.
   - The Linux agent must use only Python's standard library (Python 3.8+).
   - Bump `$AgentVersion` or `AGENT_VERSION` when you change an agent, so installed agents update.
4. Add an entry at the top of `rollcall/CHANGELOG.md` and bump `version` in `rollcall/config.yaml`. If the change comes from an issue, link it and thank whoever raised it.
5. Update `rollcall/DOCS.md` if behaviour or options change.
6. Test it: run the add-on, try the change in the dashboard (light and dark mode, and at phone width for layout changes), and for agent changes run the agent against it.
7. Open a pull request and fill in the template.

## Code of conduct

Everyone taking part is expected to follow the [code of conduct](CODE_OF_CONDUCT.md).
