## What this changes

<!-- What it does and why. Link the issue it fixes, e.g. "Fixes #12". -->

## How it was tested

<!-- e.g. ran the add-on locally against a mock agent, checked the dashboard in light and dark mode, tested on Windows Server 2019 with PowerShell 5.1. -->

## Checklist

- [ ] No real network details anywhere (code, comments, docs, changelog, tests, screenshots): stand-ins like `CONTOSO`, `SRV01`, `192.168.1.x` instead.
- [ ] `rollcall/CHANGELOG.md` has an entry, and `version` in `rollcall/config.yaml` is bumped.
- [ ] `rollcall/DOCS.md` is updated if behaviour or options changed.
- [ ] If an agent changed: its version is bumped, the Windows agent still runs on Windows PowerShell 4.0 and 5.1 (no PowerShell 7-only syntax), and the Linux agent still uses only Python's standard library.
