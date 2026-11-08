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


def available() -> bool:
    return bool(shutil.which("wixl") and shutil.which("msibuild"))


async def _run(*args: str, cwd: str) -> None:
    p = await asyncio.create_subprocess_exec(*args, cwd=cwd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
    out, _ = await asyncio.wait_for(p.communicate(), 120)
    if p.returncode != 0:
        raise RuntimeError(f"{args[0]} failed: {out.decode(errors='replace')[-400:]}")


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
        return Path(d, "agent.msi").read_bytes()
