"""Build a Windows installer (.msi) for the agent, with the add-on's addresses and enrolment key
built in, using msitools (wixl + msibuild) so it works inside the Linux add-on."""
from __future__ import annotations

import asyncio
import re
import shutil
import tempfile
from pathlib import Path

UPGRADE_CODE = "6E0B7D8A-3C41-4F6B-9B2E-6A2F4C1D9E10"   # never change: lets newer MSIs replace older ones
COMPONENT_GUID = "9C3E2B71-5A0D-4E8F-A1B6-2D7C4E9F0A13"

WXS = """<?xml version="1.0" encoding="utf-8"?>
<Wix xmlns="http://schemas.microsoft.com/wix/2006/wi">
  <Product Id="*" Name="Rollcall agent" Language="1033" Version="{version}" Manufacturer="Rollcall" UpgradeCode="{upgrade}">
    <Package InstallerVersion="500" Compressed="yes" InstallScope="perMachine"
             Description="Rollcall monitoring agent" Comments="Reports this computer's health to Rollcall"/>
    <Media Id="1" Cabinet="agent.cab" EmbedCab="yes"/>
    <MajorUpgrade DowngradeErrorMessage="A newer Rollcall agent is already installed." AllowSameVersionUpgrades="yes"/>
    <Property Id="ARPNOMODIFY" Value="1"/>
    <Property Id="ARPNOREPAIR" Value="1"/>
    <Property Id="ARPCOMMENTS" Value="Reports this computer's health to Rollcall"/>
    <Directory Id="TARGETDIR" Name="SourceDir">
      <Directory Id="ProgramFiles64Folder">
        <Directory Id="INSTALLDIR" Name="Rollcall">
          <Component Id="AgentScript" Guid="{component}" Win64="yes">
            <File Id="AgentPs1" Name="PingMonitorAgent.ps1" Source="PingMonitorAgent.ps1" KeyPath="yes"/>
          </Component>
        </Directory>
      </Directory>
      <Directory Id="System64Folder"/>
    </Directory>
    <Feature Id="Main" Level="1"><ComponentRef Id="AgentScript"/></Feature>
    <Property Id="POWERSHELL" Value="powershell.exe"/>
    <CustomAction Id="RegisterAgent" Property="POWERSHELL" Execute="deferred" Impersonate="no" Return="check" ExeCommand="-Install"/>
    <CustomAction Id="UnregisterAgent" Property="POWERSHELL" Execute="deferred" Impersonate="no" Return="ignore" ExeCommand="-Uninstall"/>
    <InstallExecuteSequence>
      <Custom Action="RegisterAgent" After="InstallFiles">NOT REMOVE</Custom>
      <Custom Action="UnregisterAgent" Before="RemoveFiles">REMOVE="ALL" AND NOT UPGRADINGPRODUCTCODE</Custom>
    </InstallExecuteSequence>
  </Product>
</Wix>
"""

# wixl can't write "run this command line" custom actions, so the rows are replaced afterwards:
# type 34 (exe, working directory) + 1024 deferred + 2048 no impersonation (runs as SYSTEM); +64 = ignore the exit code.
_PS = ('"[System64Folder]WindowsPowerShell\\v1.0\\powershell.exe" -NoProfile -NonInteractive -ExecutionPolicy Bypass '
       '-File "[INSTALLDIR]PingMonitorAgent.ps1"')
_ROWS = [("RegisterAgent", 34 + 1024 + 2048, "INSTALLDIR", _PS + " -Install"),
         ("UnregisterAgent", 34 + 1024 + 2048 + 64, "INSTALLDIR", _PS + " -Uninstall")]


# The screens shown when someone installs it by double-clicking (never with /qn, e.g. from MECM):
# a "finished" screen on success (sequence -1) and a "wasn't installed" one on failure (-3).
# wixl can't write dialogs either, so these tables are added afterwards like the custom actions.
_DONE = ("The Rollcall agent is installed and running on [ComputerName].\r\n\r\n"
         "It sends its first report to Rollcall now, so this computer should appear there within a minute or two. "
         "If it's new to Rollcall, an administrator approves it under Manage > Agents; after that it reports every 5 minutes.\r\n\r\n"
         "There's nothing more to do here. You can close this window.")
_FAILED = ("The Rollcall agent wasn't installed, and nothing has been changed on this computer.\r\n\r\n"
           "To see why, run the installer again from a command prompt opened with Run as administrator, writing a log:\r\n"
           "msiexec /i \"[OriginalDatabase]\" /l*v \"%TEMP%\\rollcall-install.log\"\r\n\r\n"
           "then look near the end of rollcall-install.log for the error.")
_UI = {
    "TextStyle": ("TextStyle\tFaceName\tSize\tColor\tStyleBits\r\ns72\ts32\ti2\tI4\tI2\r\nTextStyle\tTextStyle\r\n",
                  [("RcFont", "Segoe UI", "9", "", ""), ("RcTitle", "Segoe UI", "14", "", "1")]),
    "Dialog": ("Dialog\tHCentering\tVCentering\tWidth\tHeight\tAttributes\tTitle\tControl_First\tControl_Default\tControl_Cancel\r\n"
               "s72\ti2\ti2\ti2\ti2\tI4\tL128\ts50\tS50\tS50\r\nDialog\tDialog\r\n",
               [("RcDone", "50", "50", "370", "220", "3", "[ProductName]", "Finish", "Finish", "Finish"),
                ("RcFailed", "50", "50", "370", "220", "3", "[ProductName]", "Finish", "Finish", "Finish")]),
    "Control": ("Dialog_\tControl\tType\tX\tY\tWidth\tHeight\tAttributes\tProperty\tText\tControl_Next\tHelp\r\n"
                "s72\ts50\ts20\ti2\ti2\ti2\ti2\tI4\tS72\tL0\tS50\tL50\r\nControl\tDialog_\tControl\r\n",
                [("RcDone", "Title", "Text", "20", "18", "330", "26", "196611", "", "{\\RcTitle}Rollcall agent installed", "", ""),
                 ("RcDone", "Body", "Text", "20", "52", "330", "120", "196611", "", _DONE, "", ""),
                 ("RcDone", "Line", "Line", "0", "182", "370", "0", "1", "", "", "", ""),
                 ("RcDone", "Finish", "PushButton", "290", "192", "66", "18", "3", "", "&Finish", "", ""),
                 ("RcFailed", "Title", "Text", "20", "18", "330", "26", "196611", "", "{\\RcTitle}Rollcall agent wasn't installed", "", ""),
                 ("RcFailed", "Body", "Text", "20", "52", "330", "120", "196611", "", _FAILED, "", ""),
                 ("RcFailed", "Line", "Line", "0", "182", "370", "0", "1", "", "", "", ""),
                 ("RcFailed", "Finish", "PushButton", "290", "192", "66", "18", "3", "", "&Finish", "", "")]),
    "ControlEvent": ("Dialog_\tControl_\tEvent\tArgument\tCondition\tOrdering\r\ns72\ts50\ts50\ts255\tS255\tI2\r\n"
                     "ControlEvent\tDialog_\tControl_\tEvent\tArgument\tCondition\r\n",
                     [("RcDone", "Finish", "EndDialog", "Return", "1", "1"),
                      ("RcFailed", "Finish", "EndDialog", "Exit", "1", "1")]),
}
_UI_SEQUENCE = [("RcDone", "", "-1"), ("RcFailed", "", "-3")]


def _idt(header: str, rows: list) -> str:
    # In these table files a tab, carriage return or line feed inside a value is written as 0x10, 0x11, 0x19
    enc = lambda v: v.replace("\t", "\x10").replace("\r", "\x11").replace("\n", "\x19")
    return header + "".join("\t".join(enc(v) for v in r) + "\r\n" for r in rows)


def available() -> bool:
    return bool(shutil.which("wixl") and shutil.which("msibuild"))


async def _run(*args: str, cwd: str) -> bytes:
    p = await asyncio.create_subprocess_exec(*args, cwd=cwd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    out, err = await asyncio.wait_for(p.communicate(), 120)
    if p.returncode != 0:
        raise RuntimeError(f"{args[0]} failed ({p.returncode}): {(err or out).decode(errors='replace')[-400:]}")
    return out


async def build(script: bytes, version: str) -> bytes:
    """script: the agent .ps1 (with BOM and CRLFs) to put in the installer."""
    ver = ".".join((re.findall(r"\d+", version) + ["0", "0", "0"])[:3])
    with tempfile.TemporaryDirectory(prefix="rollcall-msi-") as d:
        Path(d, "PingMonitorAgent.ps1").write_bytes(script)
        Path(d, "agent.wxs").write_text(WXS.format(version=ver, upgrade=UPGRADE_CODE, component=COMPONENT_GUID), encoding="utf-8")
        await _run("wixl", "-a", "x64", "-o", "agent.msi", "agent.wxs", cwd=d)
        idt = "Action\tType\tSource\tTarget\tExtendedType\r\ns72\ti2\tS72\tS255\tI4\r\nCustomAction\tAction\r\n" + \
              "".join(f"{a}\t{t}\t{s}\t{g}\t\r\n" for a, t, s, g in _ROWS)
        Path(d, "CustomAction.idt").write_text(idt, encoding="utf-8", newline="")
        await _run("msibuild", "agent.msi", "-i", "CustomAction.idt", cwd=d)
        # The screens: new tables, plus rows added to the UI sequence and the default font
        for name, (header, rows) in _UI.items():
            Path(d, f"{name}.idt").write_text(_idt(header, rows), encoding="cp1252", newline="")
            await _run("msibuild", "agent.msi", "-i", f"{name}.idt", cwd=d)
        for table, extra in (("InstallUISequence", ["\t".join(r) for r in _UI_SEQUENCE]), ("Property", ["DefaultUIFont\tRcFont"])):
            text = (await _run("msiinfo", "export", "agent.msi", table, cwd=d)).decode("cp1252", errors="replace").rstrip("\r\n")
            Path(d, f"{table}.idt").write_text(text + "\r\n" + "\r\n".join(extra) + "\r\n", encoding="cp1252", newline="")
            await _run("msibuild", "agent.msi", "-i", f"{table}.idt", cwd=d)
        return Path(d, "agent.msi").read_bytes()
