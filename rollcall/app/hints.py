"""Hints for errors: what an error usually means and what to try.

Two parts:
1. A built-in table of well-known codes and messages (LAPS, Group Policy, Windows Update, domain sign-in, time,
   certificates, backups...). Free, instant, and nothing leaves the network.
2. Hints from an AI (Claude, ChatGPT or Gemini), OFF unless an admin turns them on and enters their own API key for
   the chosen provider. Only on request (a
   click on the 💡), cached per error, with a daily limit. Only the check, its error text and basic context are sent,
   and computer, account and domain names and addresses are replaced with stand-ins first. Security events,
   account lists and password-scan results are never sent.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import time
from pathlib import Path

import aiohttp

# ---------------------------------------------------------------------------------------------------------------------
# 1. The built-in table
# ---------------------------------------------------------------------------------------------------------------------
# codes: HRESULTs / error numbers, matched as whole words (case doesn't matter). words: phrases (regular expressions)
# as Rollcall or Windows words them. checks: only for these checks (None: any).
KNOWN: list[dict] = [
    # Finding or signing in to the domain
    {"codes": ["0x8007054B"], "words": [r"specified domain either does not exist", r"couldn't find a domain controller",
                                         r"no network connection to a domain controller", r"failed to find a domain controller",
                                         r"hasn't been on the domain network"],
     "means": "The device couldn't find or reach a domain controller. Usually it's off the office network (at home, "
              "without a VPN), or its DNS doesn't point at the domain's DNS servers.",
     "try": "Check it's on the network or VPN, and that ipconfig /all lists your DNS servers. nltest /dsgetdc:<your domain> "
            "shows whether it can find a domain controller."},
    {"codes": ["0x8007051F"], "words": [r"no logon servers"],
     "means": "No domain controller was available to sign in against.",
     "try": "Check the device can reach a domain controller (VPN, DNS, firewall), and that the domain controllers are up."},
    {"codes": ["0x800706BA"], "words": [r"rpc server is unavailable"],
     "means": "The other computer didn't answer an RPC call: it's off, unreachable, or a firewall is blocking RPC (TCP 135 "
              "and the dynamic ports).",
     "try": "Check the target is up and reachable, and that Windows Firewall allows the remote administration rules."},
    {"codes": ["0x8007052E"], "words": [r"password is wrong", r"unknown user name or bad password"],
     "means": "The account's user name or password was refused.",
     "try": "Update the saved password wherever this account is used (scheduled task, service or backup job)."},
    {"codes": ["0x80070532"], "words": [r"password has expired"],
     "means": "The account's password has expired.",
     "try": "Change it, and set service accounts' passwords not to expire (or use a managed service account)."},
    {"codes": ["0x80070533"], "words": [r"account is (currently )?disabled"], "means": "The account is disabled.",
     "try": "Enable it in Active Directory Users and Computers if it should still be used."},
    {"codes": ["0x80070775"], "words": [r"account is (currently )?locked out"],
     "means": "The account is locked out after too many wrong passwords, often an old password saved somewhere.",
     "try": "Unlock it, then find where the old password is still saved (the lockout event 4740 names the computer)."},
    {"codes": ["0x80070005"], "words": [r"access (is )?denied"],
     "means": "Access denied: the account doing the work doesn't have permission.",
     "try": "Check which account runs it (task, service or job) and its rights on the folder, share or object involved."},
    {"codes": ["0x80070569"], "words": [r"log on as a batch job"],
     "means": "The account isn't allowed to log on as a batch job, which scheduled tasks need.",
     "try": "Grant 'Log on as a batch job' to it (Local Security Policy, or a GPO), or run the task as another account."},
    {"codes": ["0x80070002", "0x80070003"], "words": [r"\bfile not found\b", r"path not found"],
     "means": "A file or folder it needs doesn't exist (moved, deleted, or a drive letter that isn't mapped for that account).",
     "try": "Check the path, and use a full UNC path (\\\\server\\share) rather than a mapped drive in tasks and services."},
    {"codes": ["0x80070070"], "words": [r"not enough space on the disk"],
     "means": "The disk is full.", "try": "Free up space on the drive involved (Disk Cleanup, old logs, old backups)."},
    {"codes": ["0x80090322"], "words": [r"target principal name is incorrect"],
     "means": "Kerberos found the name used to connect belongs to a different account (a DNS alias or a duplicate SPN).",
     "try": "Connect by the server's real name, or fix the SPN: setspn -X lists duplicates."},
    # Time
    {"words": [r"Kerberos sign-ins fail at 5 minutes", r"\b(ahead of|behind) .* by", r"isn't syncing \(", r"Windows Time isn't syncing"],
     "checks": ["time"],
     "means": "The clock is out, or Windows Time isn't syncing. Kerberos refuses sign-ins once a clock is 5 minutes out.",
     "try": "On a domain member: w32tm /config /syncfromflags:domhier /update, then w32tm /resync. Run w32tm /query /status "
            "to see where it syncs from."},
    {"words": [r"PDC emulator isn't syncing"], "checks": ["time"],
     "means": "The PDC emulator sets the time for the whole domain, and it's running on its own clock.",
     "try": "On the PDC emulator: w32tm /config /manualpeerlist:\"pool.ntp.org\" /syncfromflags:manual /reliable:yes /update, "
            "then restart Windows Time. On a virtual machine, turn off the host's time sync for it."},
    # Group Policy (Rollcall's wording of event IDs 1006 to 1129)
    {"words": [r"couldn't bind to a domain controller"], "checks": ["gpo"],
     "means": "Group Policy (event 1006) couldn't connect to a domain controller over LDAP: usually network, DNS or a "
              "clock that's out.", "try": "Check DNS and time, then run gpupdate /force and look at the event's error code."},
    {"words": [r"couldn't read a policy from SYSVOL"], "checks": ["gpo"],
     "means": "Group Policy (event 1058) couldn't read a policy's gpt.ini from SYSVOL: SYSVOL isn't reachable, or "
              "replication between domain controllers is broken.",
     "try": "Open \\\\<your domain>\\SYSVOL from the device. Check SYSVOL replication (dcdiag /test:sysvolcheck) on the "
            "domain controllers."},
    {"words": [r"couldn't process a policy file"], "checks": ["gpo"],
     "means": "Group Policy (event 1096) couldn't read a registry.pol file, which is usually damaged.",
     "try": "The event names the file. Delete the local copy (under C:\\Windows\\System32\\GroupPolicy\\Machine) and run "
            "gpupdate /force; if it's the copy in SYSVOL, re-save the GPO."},
    {"words": [r"a settings extension failed"], "checks": ["gpo"],
     "means": "Group Policy (event 1085) applied, but one of its parts (drive maps, printers, software installation...) failed.",
     "try": "gpresult /h report.html shows which part failed and why."},
    {"words": [r"couldn't get the list of Group Policy objects", r"couldn't find the user or computer name",
               r"couldn't resolve the computer name"], "checks": ["gpo"],
     "means": "Group Policy couldn't look up the computer or its policies in Active Directory: usually DNS or reaching a "
              "domain controller.", "try": "Check DNS points at the domain's DNS servers, then run gpupdate /force."},
    # LAPS
    {"words": [r"no LAPS password in Active Directory yet"], "checks": ["laps"],
     "means": "The device hasn't been able to write its LAPS password to Active Directory. Usually the computer isn't "
              "allowed to write to its own object yet, or the schema hasn't been extended.",
     "try": "Windows LAPS: Update-LapsADSchema once, then Set-LapsADComputerSelfPermission -Identity <the OU>. Legacy LAPS: "
            "Set-AdmPwdComputerSelfPermission. Then Invoke-LapsPolicyProcessing on the device."},
    {"words": [r"Password not rotated", r"Password rotation overdue"], "checks": ["laps"],
     "means": "LAPS should have changed the password by now. It needs to reach a domain controller to do it.",
     "try": "Run Invoke-LapsPolicyProcessing on the device and look in Event Viewer under Applications and Services > "
            "Microsoft > Windows > LAPS > Operational."},
    {"words": [r"managed account .* not found"], "checks": ["laps"],
     "means": "The account LAPS is set to manage doesn't exist on the device.",
     "try": "Create the account, or correct the account name in the LAPS policy."},
    # Windows Update and servicing
    {"codes": ["0x80244022"], "means": "The update server answered 503 (busy). With WSUS this is usually its IIS "
                                       "application pool (WsusPool) stopping when it runs out of memory.",
     "try": "On the WSUS server, start WsusPool in IIS and raise its Private Memory Limit (e.g. to 0, or 4 GB+)."},
    {"codes": ["0x8024401C", "0x80072EE2"], "means": "Timed out talking to the update server.",
     "try": "Check the device can reach WSUS or Windows Update (proxy, firewall), and that the WSUS server isn't overloaded."},
    {"codes": ["0x8024402C", "0x80072EE7"], "means": "The update server's name couldn't be found, or a proxy is in the way.",
     "try": "Check DNS and the WSUS address in Group Policy; netsh winhttp show proxy shows the proxy Windows Update uses."},
    {"codes": ["0x80072EFD", "0x80072EFE"], "means": "Couldn't connect to the update server (refused or cut off).",
     "try": "Check the firewall or proxy allows the device to the update server."},
    {"codes": ["0x80072F8F"], "means": "A secure connection failed: usually the device's clock is wrong, or TLS settings "
                                       "don't match the server.", "try": "Check the date and time, then try again."},
    {"codes": ["0x8024002E"], "means": "Windows Update is blocked by policy from using Microsoft's servers (Do not "
                                       "connect to any Windows Update Internet locations).",
     "try": "Expected with WSUS. If it should use Microsoft's servers, change the policy."},
    {"codes": ["0x80240438"], "means": "Windows Update couldn't reach its server, often because policy blocks it.",
     "try": "Check the Windows Update policies and the proxy settings."},
    {"codes": ["0x80244010"], "means": "Too many round trips to the update server; usually WSUS offering too many updates.",
     "try": "Decline superseded updates on the WSUS server and run the Server Cleanup Wizard."},
    {"codes": ["0x8024200D"], "means": "The update needs downloading again.", "try": "It normally sorts itself out on the next scan."},
    {"codes": ["0x80073712"], "means": "Windows' component store is damaged, so updates can't install.",
     "try": "DISM /Online /Cleanup-Image /RestoreHealth, then sfc /scannow, then try the update again."},
    {"codes": ["0x800F081F", "0x800F0831"], "means": "Files Windows needs to install the update are missing from its "
                                                     "component store.",
     "try": "DISM /Online /Cleanup-Image /RestoreHealth (with /Source pointing at matching install media if it can't download)."},
    {"codes": ["0x800F0922"], "means": "The update couldn't finish installing: often the system reserved partition is too "
                                       "small or full, or a VPN blocked a download during install.",
     "try": "Check free space on the system reserved partition, and try again without the VPN connected."},
    {"codes": ["0x80070643"], "means": "A fatal error during installation. For the WinRE update (KB5034441) it means the "
                                       "recovery partition is too small.",
     "try": "For KB5034441, enlarge the recovery partition (Microsoft's KB5028997) or hide the update; otherwise check "
            "C:\\Windows\\Logs\\CBS\\CBS.log."},
    # Certificates
    {"codes": ["0x80092013"], "means": "The certificate's revocation list couldn't be downloaded (the CA's CRL is offline).",
     "try": "Check the CRL address in the certificate is reachable, and that the CA has published a current CRL."},
    {"codes": ["0x800B0109"], "means": "The certificate chains to a root that isn't trusted on this device.",
     "try": "Install the issuing CA's root certificate in Trusted Root Certification Authorities (by GPO for many devices)."},
    {"codes": ["0x800B0101"], "means": "A certificate has expired.", "try": "Renew it and bind the new one where it's used."},
    # DFS Replication / SYSVOL
    {"words": [r"\b4012\b", r"offline too long"], "checks": ["sysvol", "dfsr"],
     "means": "DFS Replication stopped because the server was cut off for longer than MaxOfflineTimeInDays (60 by default), "
              "so its copy might bring back deleted data.",
     "try": "Microsoft's guidance is a non-authoritative sync of SYSVOL from a good domain controller (msDFSR-Enabled / "
            "msDFSR-Options). Don't just raise MaxOfflineTimeInDays."},
    {"words": [r"\b2213\b", r"unclean shutdown"], "checks": ["sysvol", "dfsr"],
     "means": "DFS Replication paused after an unexpected shutdown, waiting to be told it's safe to carry on.",
     "try": "Event 2213 gives the exact command (wmic ... dfsrVolumeConfig ... call ResumeReplication). Back up the folder first."},
    # Backups
    {"words": [r"Cannot use CBT", r"no change tracking data available", r"Changed block tracking (is disabled|cannot be used)"],
     "means": "Veeam couldn't use changed block tracking for this disk, so it read the whole disk to find what changed. "
              "The backup is fine, just slower. On Hyper-V it usually happens once after the VM was moved, restored, "
              "merged from a checkpoint, or after the host restarted unexpectedly.",
     "try": "Nothing, if the next run is clean. If it repeats every run, check the VM has no leftover checkpoints and "
            "see Veeam's guidance for the exact message."},
    {"words": [r"\bVSS\b", r"shadow copy", r"0x8004230F", r"0x80042306"], "checks": ["backups"],
     "means": "The backup couldn't take a shadow copy (VSS) of the volume.",
     "try": "vssadmin list writers shows any writer in a failed state; restarting the service it belongs to usually clears it. "
            "Check there's free space for shadow copies."},
    # NetBackup status codes (as the agent words them: "status 58: can't connect to client")
    {"words": [r"status 1: partially successful"], "checks": ["backups"],
     "means": "NetBackup backed up most of the client but skipped some files, usually ones that were open, locked or "
              "removed while it ran.",
     "try": "The job's details in the NetBackup console list the files. Exclude temporary or always-locked files, or use "
            "snapshots (Windows Open File Backup / VSS) for files that are open."},
    {"words": [r"status (54|58|59|25|41): "], "checks": ["backups"],
     "means": "The NetBackup server couldn't reach the client, or the client turned it away.",
     "try": "Check the client is on and its NetBackup client service is running, that ports 1556 and 13724 are open "
            "between them, that each can resolve the other's name, and that the server is in the client's server list."},
    {"words": [r"status (84|96|2074|2106|800): "], "checks": ["backups"],
     "means": "NetBackup couldn't write the backup: no media or disk was available, or the storage was down.",
     "try": "Check the storage unit and disk pool are up and have free space, and that tapes are available in the pool."},
    {"words": [r"status 196: "], "checks": ["backups"],
     "means": "The backup window closed before the job could start, often because earlier jobs ran long.",
     "try": "Widen the schedule's window, or spread the clients across more streams or times."},
    # Data Protector
    {"words": [r"disk agents? failed", r"completed with (errors|failures)"], "checks": ["backups"],
     "means": "Data Protector finished the session, but some objects (a disk agent per drive or database) failed or had errors.",
     "try": "Open the session's messages in the Data Protector GUI (or omnidb -session <ID> -report) to see which "
            "object failed and why; locked files and unreachable clients are the usual reasons."},
    {"words": [r"not run since", r"missed", r"didn't run"], "checks": ["backups"],
     "means": "The backup job hasn't run when it should have: the server was off, the job is disabled, or its schedule changed.",
     "try": "Check the job's schedule and that the backup service is running."},
]

for _k in KNOWN:
    _k["_re"] = re.compile("|".join([r"(?<![0-9a-fx])" + re.escape(c) + r"(?![0-9a-f])" for c in _k.get("codes", [])]
                                    + _k.get("words", [])), re.I)


def known(check: str, text: str, limit: int = 2) -> list[dict]:
    """The built-in hints that match a check's error text: [{"code", "means", "try"}]."""
    if not text:
        return []
    out = []
    for k in KNOWN:
        if k.get("checks") and check not in k["checks"]:
            continue
        m = k["_re"].search(text)
        if m:
            out.append({"code": m.group(0) if m.group(0).lower().startswith("0x") else "", "means": k["means"], "try": k["try"]})
            if len(out) >= limit:
                break
    return out


# ---------------------------------------------------------------------------------------------------------------------
# 2. Hints from an AI provider (off unless an admin turns them on)
# ---------------------------------------------------------------------------------------------------------------------
TEST_BASE = os.environ.get("PM_AI_TEST_BASE", "")  # tests point this at a stand-in API; never set in the add-on
NEVER = {"security", "secrets", "domain", "integrity", "vulns", "aduser"}  # never sent, whatever they say
SYSTEM = ("You help IT administrators understand monitoring alerts from Rollcall, a Home Assistant add-on that checks "
          "servers and PCs. Given one failing check, say in 2 to 4 short sentences what the error usually means and what "
          "to try first, naming the exact command or setting where there is one. Plain text, no headings, no lists, no "
          "preamble. Names and addresses have been replaced with stand-ins such as PC01 and CONTOSO; use them as given. "
          "If the error is too vague to say, say what extra detail would help.")

_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_IPV6 = re.compile(r"(?<![\w:])(?=[0-9A-Fa-f:]*:[0-9A-Fa-f]*:)[0-9A-Fa-f:]{3,39}(?![\w:])")
_EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b")
_UNC = re.compile(r"\\\\[^\\\s]+")
_ACCOUNT = re.compile(r"(?<![\\:/\w.-])((?:NT |IIS )?[A-Za-z0-9][\w.-]{0,30})\\([\w.$-]{1,64})(?![\\\w])")
_SID = re.compile(r"\bS-1-5-21(?:-\d+){1,5}\b")
_PROFILE = re.compile(r"(?i)\b([A-Z]:\\Users\\)([^\\\s]+)")
_HOME = re.compile(r"(/home/|/Users/)([^/\s]+)")
_MAC = re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b")
_FQDN = re.compile(r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+(?:local|lan|corp|internal|home|intranet|localdomain|arpa|com|net|org|edu|gov|mil|int|info|biz|io|co|uk|"
                   r"de|fr|nl|be|ie|es|it|eu|us|ca|au|nz|in|jp|ch|at|se|no|dk|fi|pl|cz|pt|za|br|mx|app|dev|cloud|online|site|"
                   r"tech|me|tv|xyz|ai)(?![\w-]|\.\w)", re.I)
# Names Windows and Microsoft use that aren't anybody's: kept as they are
KEEP_DOMAINS = {"NT AUTHORITY", "BUILTIN", "NT SERVICE", "WORKGROUP", "IIS APPPOOL", "WINDOW MANAGER", "FONT DRIVER HOST"}
KEEP_HOSTS = re.compile(r"(?i)(^|\.)(microsoft\.com|windowsupdate\.com|windows\.com|office\.com|pool\.ntp\.org|"
                        r"time\.windows\.com|digicert\.com|letsencrypt\.org|anthropic\.com|contoso\.local|example\.(com|local))$|\.(exe|dll|sys|log|pol|ini|"
                        r"msi|ps1|txt|xml|json|cab|msu|bak|vhdx?|evtx|html)$")


class Redactor:
    """Replaces names and addresses with stand-ins, the same one each time within a request."""

    def __init__(self, names: list[str] = (), domains: list[str] = (), users: list[str] = ()):
        self.map: dict[str, str] = {}
        self.users = sorted({u for u in users if u and len(u) > 2}, key=len, reverse=True)
        self.count: dict[str, int] = {}
        self.names = sorted({n for n in names if n and len(n) > 1}, key=len, reverse=True)
        self.domains = sorted({d for d in domains if d and len(d) > 1}, key=len, reverse=True)

    def _stand_in(self, kind: str, real: str) -> str:
        key = kind + ":" + real.lower()
        if key not in self.map:
            n = self.count[kind] = self.count.get(kind, 0) + 1
            self.map[key] = {"pc": f"PC{n:02d}", "dom": "CONTOSO" if n == 1 else f"CONTOSO{n}",
                             "fqdn": f"host{n}.contoso.local", "user": f"user{n}", "ip4": f"192.0.2.{n}",
                             "ip6": f"2001:db8::{n}", "mail": f"user{n}@contoso.local", "unc": f"\\\\SRV{n:02d}",
                             "sid": f"S-1-5-21-0-0-0-{1000 + n}", "mac": f"00-00-5E-00-53-{n:02X}"}[kind]
        return self.map[key]

    def __call__(self, text: str) -> str:
        if not text:
            return ""
        t = _SID.sub(lambda m: self._stand_in("sid", m.group(0)), text)
        t = _EMAIL.sub(lambda m: self._stand_in("mail", m.group(0)), t)
        t = _UNC.sub(lambda m: self._stand_in("unc", m.group(0)), t)

        def acct(m):
            dom, user = m.group(1), m.group(2)
            if dom.upper() in KEEP_DOMAINS or dom.upper() in ("C", "D", "E"):
                return m.group(0)
            return self._stand_in("dom", dom) + "\\" + self._stand_in("user", user)
        t = _ACCOUNT.sub(acct, t)
        t = _PROFILE.sub(lambda m: m.group(1) + self._stand_in("user", m.group(2)), t)
        t = _HOME.sub(lambda m: m.group(1) + self._stand_in("user", m.group(2)), t)
        t = _MAC.sub(lambda m: self._stand_in("mac", m.group(0)), t)

        def ip4(m):
            try:
                ipaddress.IPv4Address(m.group(0))
            except ValueError:
                return m.group(0)  # a version number like 10.0.19045.1
            return self._stand_in("ip4", m.group(0))
        t = _IPV4.sub(ip4, t)

        def ip6(m):
            try:
                ipaddress.IPv6Address(m.group(0))
            except ValueError:
                return m.group(0)
            return self._stand_in("ip6", m.group(0))
        t = _IPV6.sub(ip6, t)
        t = _FQDN.sub(lambda m: m.group(0) if KEEP_HOSTS.search(m.group(0)) else self._stand_in("fqdn", m.group(0)), t)
        for d in self.domains:  # the domain's own names (NetBIOS and DNS), wherever they appear on their own
            t = re.sub(r"(?i)(?<![\w-])" + re.escape(d) + r"(?![\w-])", lambda m: self._stand_in("dom", m.group(0)), t)
        for u in self.users:    # people signed in to agent devices
            t = re.sub(r"(?i)(?<![\w-])" + re.escape(u) + r"(?![\w-])", lambda m: self._stand_in("user", m.group(0)), t)
        for n in self.names:    # every device Rollcall knows, by name
            t = re.sub(r"(?i)(?<![\w-])" + re.escape(n) + r"(?![\w-])", lambda m: self._stand_in("pc", m.group(0)), t)
        return t


def prompt(check_label: str, level: str, detail: str, context: dict) -> str:
    lines = [f"Check: {check_label}", f"State: {'red (failing)' if level == 'red' else 'amber (warning)'}", f"Error: {detail}"]
    for k, v in context.items():
        if v:
            lines.append(f"{k}: {v}")
    return "\n".join(lines)


class ClaudeHints:
    """Asks Claude about one error at a time, on request. Answers are cached per error (30 days) and there's a daily
    limit. State lives in a small file: the cache and today's count, never the API key."""

    CACHE_DAYS = 30
    MAX_CACHE = 500

    def __init__(self, path: Path):
        self.path = path
        self.state: dict = {"cache": {}, "day": "", "used": 0}
        try:
            self.state.update(json.loads(path.read_text()))
        except (OSError, ValueError):
            pass

    def _save(self) -> None:
        try:
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(self.state))
            tmp.replace(self.path)
        except OSError:
            pass

    @staticmethod
    def key(check: str, sent: str, provider: str = "anthropic") -> str:
        # The same error is the same question: how long ago the agent last reported doesn't change the answer
        same = "\n".join(x for x in sent.split("\n") if not x.startswith("Last agent report:"))
        return hashlib.sha256(((provider + "\n" if provider != "anthropic" else "") + check + "\n" + same).encode()).hexdigest()[:32]

    def cached(self, key: str, now: float) -> dict | None:
        c = self.state["cache"].get(key)
        if c and now - c.get("at", 0) < self.CACHE_DAYS * 86400:
            return c
        return None

    def left_today(self, day: str, limit: int) -> int:
        return max(0, limit - (self.state["used"] if self.state.get("day") == day else 0))

    async def ask(self, session: aiohttp.ClientSession, api_key: str, model: str, check: str, sent: str,
                  day: str, limit: int, now: float, provider: str = "anthropic") -> dict:
        """{"text", "model", "provider", "at", "cached"}; raises ValueError with something to show if it can't."""
        p = PROVIDERS.get(provider) or PROVIDERS["anthropic"]
        k = self.key(check, sent, provider)
        c = self.cached(k, now)
        if c:
            return {**c, "cached": True}
        if not api_key:
            raise ValueError(f"No {p['key_name']} is set (Settings → Error hints).")
        if self.left_today(day, limit) <= 0:
            raise ValueError(f"Today's limit of {limit} AI hint(s) has been reached. It resets at midnight.")
        if self.state.get("day") != day:
            self.state["day"], self.state["used"] = day, 0
        self.state["used"] += 1  # counted when asked, so failures can't run up a bill unnoticed either
        self._save()
        text, used_model = await call(session, provider, api_key, model or p["model"], SYSTEM, sent)
        entry = {"text": text[:2000], "model": used_model[:80], "provider": p["name"], "at": now}
        cache = self.state["cache"]
        cache[k] = entry
        if len(cache) > self.MAX_CACHE:
            for old in sorted(cache, key=lambda x: cache[x].get("at", 0))[: len(cache) - self.MAX_CACHE]:
                del cache[old]
        self._save()
        return {**entry, "cached": False}


# Each provider: who it is, its key, its default model (a small, fast one; admins can change it), and where its
# API is. Keys are only ever sent to their own provider.
PROVIDERS = {
    "anthropic": {"name": "Claude", "company": "Anthropic", "key_name": "Anthropic API key", "model": "claude-haiku-5-5",
                  "url": "https://api.anthropic.com/v1/messages", "test_path": "/v1/messages"},
    "openai": {"name": "ChatGPT", "company": "OpenAI", "key_name": "OpenAI API key", "model": "gpt-5.4-mini",
               "url": "https://api.openai.com/v1/chat/completions", "test_path": "/v1/chat/completions"},
    "gemini": {"name": "Gemini", "company": "Google", "key_name": "Gemini API key", "model": "gemini-3.5-flash-lite",
               "url": "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent",
               "test_path": "/v1beta/models/{model}:generateContent"},
}


async def call(session: aiohttp.ClientSession, provider: str, api_key: str, model: str, system: str, user: str,
               max_tokens: int = 1000) -> tuple[str, str]:
    """Ask one provider one question: (answer, model that answered). Raises ValueError with something to show.
    max_tokens leaves room for models that think before answering."""
    p = PROVIDERS[provider]
    url = (TEST_BASE.rstrip("/") + p["test_path"]) if TEST_BASE else p["url"]
    url = url.replace("{model}", re.sub(r"[^A-Za-z0-9._-]", "", model))
    if provider == "anthropic":
        headers = {"x-api-key": api_key, "anthropic-version": "2023-06-01", "content-type": "application/json"}
        body = {"model": model, "max_tokens": max_tokens, "system": system, "messages": [{"role": "user", "content": user}]}
    elif provider == "openai":
        headers = {"Authorization": f"Bearer {api_key}", "content-type": "application/json"}
        body = {"model": model, "max_completion_tokens": max_tokens,
                "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]}
    else:  # gemini: the key goes in a header, never the address (addresses end up in logs)
        headers = {"x-goog-api-key": api_key, "content-type": "application/json"}
        body = {"systemInstruction": {"parts": [{"text": system}]}, "contents": [{"role": "user", "parts": [{"text": user}]}],
                "generationConfig": {"maxOutputTokens": max_tokens}}
    who = p["name"]
    try:
        async with session.post(url, json=body, headers=headers, timeout=aiohttp.ClientTimeout(total=40)) as r:
            try:
                j = await r.json(content_type=None)
            except ValueError:
                j = {}
            if r.status != 200:
                e = j.get("error") if isinstance(j, dict) else None
                msg = (e.get("message") if isinstance(e, dict) else str(e or "")) or f"HTTP {r.status}"
                if r.status == 401 or (r.status in (400, 403) and re.search(r"(?i)api.?key.*(invalid|not valid)|invalid.*api.?key", msg)):
                    msg = "the API key was refused"
                raise ValueError(f"{who} didn't answer: {msg}"[:300])
    except (aiohttp.ClientError, TimeoutError) as e:
        raise ValueError(f"Couldn't reach {p['company']}'s API: {e or type(e).__name__}"[:300]) from None
    if not isinstance(j, dict):
        j = {}
    if provider == "anthropic":
        text = "".join(b.get("text", "") for b in (j.get("content") or []) if isinstance(b, dict) and b.get("type") == "text")
    elif provider == "openai":
        ch = (j.get("choices") or [{}])[0] if isinstance(j.get("choices"), list) and j.get("choices") else {}
        text = str(((ch or {}).get("message") or {}).get("content") or "")
    else:
        cand = (j.get("candidates") or [{}])[0] if isinstance(j.get("candidates"), list) and j.get("candidates") else {}
        text = "".join(str(x.get("text") or "") for x in ((cand or {}).get("content") or {}).get("parts") or [] if isinstance(x, dict) and not x.get("thought"))
    text = text.strip()
    if not text:
        raise ValueError(f"{who} didn't answer with any text.")
    return text, str(j.get("model") or j.get("modelVersion") or model)
