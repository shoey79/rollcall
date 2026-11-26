<#
.SYNOPSIS
    Rollcall agent for Windows (formerly Ping Monitor). Reports server health to the Rollcall
    Home Assistant add-on.

.DESCRIPTION
    The same script runs on every server. Each run it works out what the
    server does (domain controller, DNS, DHCP, SQL, IIS, Exchange, RDS, file
    and print, Hyper-V and so on) and reports what's relevant:

      - disk space, CPU, memory, uptime, pending reboot, last patch date
      - the services that matter for each detected role, plus any stopped
        automatic-start service
      - new Critical/Error events from the System and Application logs
      - notable Security events: failed logons, lockouts, account and
        admin-group changes, audit log cleared
      - role checks: IIS app pools and sites, AD replication and SYSVOL,
        DHCP scope usage, Hyper-V VM state, shared printer status,
        RDS sessions, Microsoft Defender status and detections
      - if turned on in the dashboard: files with passwords left in them. Only
        where they are is sent (file, line, setting name, length), never the
        passwords themselves.

    It runs every 5 minutes as a SYSTEM scheduled task and sends a small
    JSON report to the add-on. It never accepts commands from the add-on.

    First run: the server asks to join, and an admin approves it in the
    Rollcall dashboard (Agents). Until then reports are refused.

.PARAMETER Install
    Copy the script to C:\ProgramData\Rollcall, create the scheduled task
    and run it once. Safe to run repeatedly (e.g. as a GPO startup script);
    it also updates the installed copy.

.PARAMETER Uninstall
    Remove the scheduled task and C:\ProgramData\Rollcall (and anything left under the old name, C:\ProgramData\PingMonitor).

.PARAMETER Action
    Install, Uninstall or Report: the same as the switches, as text. Use this
    from tools that can't pass switches, such as MECM Run Scripts.

.PARAMETER ShowReport
    Collect and print the report without sending it (troubleshooting).

.PARAMETER SecretTest
    Scan a folder for passwords left in files and print what would be reported: where each
    one is, never the password. Nothing is sent.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File \\example.local\NETLOGON\RollcallAgent.ps1 -Install

.EXAMPLE
    MECM, Software Library > Scripts: paste this script, approve it, then
    run it on a collection with Action = Install.
#>
[CmdletBinding()]
param(
    [switch]$Install,
    [switch]$Uninstall,
    [switch]$ShowReport,
    [string]$Action = '',
    [string]$Server = '__PM_SERVER__',
    [string]$EnrolKey = '__PM_ENROL_KEY__',
    [int]$IntervalMinutes = 5,
    [string[]]$ExtraServices = @(),
    [switch]$IgnoreCertificate,
    [string]$DataPath = '',
    [string]$SecretTest = ''
)

$AgentVersion = '1.0.60'
# The public half of Rollcall's own signing key, built in when the script is downloaded. Agent updates and the
# addresses Rollcall tells this agent to use must be signed with it. Not a parameter: it can't be swapped at run time.
$UpdateKey = '__PM_UPDATE_KEY__'
# Rollcall's own HTTPS (1.93.0): the port and its key's fingerprint, built in when it was on at download (else learnt
# from Rollcall's signed reply). Reports then go to https://<same address>:<port>, checked against exactly that key.
$TlsPin = '__PM_TLS_PIN__'
$TlsPort = 0
# Where this script is running from, captured at the top level so Install can
# copy it even when it's run from MECM's script store or as a script block.
$SelfPath = $PSCommandPath
$SelfText = $null
try { if ($MyInvocation.MyCommand.ScriptContents) { $SelfText = $MyInvocation.MyCommand.ScriptContents } } catch { }
if (-not $SelfText) { try { $SelfText = $MyInvocation.MyCommand.ScriptBlock.ToString() } catch { } }
$ErrorActionPreference = 'Stop'
# Windows PowerShell started from PowerShell 7 inherits 7's module path, and then can't load its own security module
# (Get-Acl, Set-Acl): load it from Windows PowerShell's own folder first
if ($PSVersionTable.PSVersion.Major -lt 6) {
    foreach ($m in 'Microsoft.PowerShell.Security', 'Microsoft.PowerShell.Management', 'Microsoft.PowerShell.Utility') {
        try { Import-Module (Join-Path $PSHOME "Modules\$m\$m.psd1") -ErrorAction Stop } catch { }
    }
}
# Rollcall's names (1.0.60 on); before, Ping Monitor's. An agent running from the old place keeps the old names
# until it has moved itself (Move-ToNewName).
$OldDataPath = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'PingMonitor'
$NewDataPath = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'Rollcall'
$OldTaskName, $NewTaskName = 'Ping Monitor Agent', 'Rollcall Agent'
$OldScriptName, $NewScriptName = 'PingMonitorAgent.ps1', 'RollcallAgent.ps1'
$script:LegacyLayout = $false
if (-not $DataPath) {
    if ($PSCommandPath -and ((Split-Path $PSCommandPath -Parent) -eq $OldDataPath)) { $DataPath = $OldDataPath; $script:LegacyLayout = $true }
    else { $DataPath = $NewDataPath }
}
$TaskName = if ($script:LegacyLayout) { $OldTaskName } else { $NewTaskName }
$ScriptName = if ($script:LegacyLayout) { $OldScriptName } else { $NewScriptName }
$StatePath = Join-Path $DataPath 'state.json'
$LogPath = Join-Path $DataPath 'agent.log'
$script:Errors = New-Object System.Collections.ArrayList

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
function Write-AgentLog([string]$Message) {
    try {
        if ((Test-Path $LogPath) -and (Get-Item $LogPath).Length -gt 1MB) {
            Move-Item $LogPath "$LogPath.old" -Force
        }
        Add-Content -Path $LogPath -Value ("{0} {1}" -f (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'), $Message)
    } catch { }
    Write-Verbose $Message
}

function Add-CollectorError([string]$Collector, $Err) {
    $msg = "{0}: {1}" -f $Collector, ($Err.Exception.Message -replace '\s+', ' ')
    [void]$script:Errors.Add($msg.Substring(0, [Math]::Min(300, $msg.Length)))
    Write-AgentLog "WARN $msg"
}

$script:Timings = [ordered]@{}
$script:StepFile = $null  # set once a run has the lock: which step it's on, so a stuck run can be explained
function Measure-Step([string]$Name, [scriptblock]$Block) {
    # Runs one part of the collection and records how long it took (ms).
    if ($script:StepFile) { try { [IO.File]::WriteAllText($script:StepFile, "$Name`t$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))") } catch { } }
    $sw = [Diagnostics.Stopwatch]::StartNew()
    try { return (& $Block) }
    finally { $script:Timings[$Name] = [int]$sw.ElapsedMilliseconds }
}

function ConvertTo-UtcString($Date) {
    if ($null -eq $Date) { return $null }
    return ([DateTime]$Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
}

function Limit-Text([string]$Text, [int]$Max = 300) {
    if (-not $Text) { return '' }
    $t = ($Text -replace '\s+', ' ').Trim()
    if ($t.Length -gt $Max) { $t = $t.Substring(0, $Max - 1) + [char]0x2026 }
    return $t
}

function New-Token {
    $bytes = New-Object byte[] 32
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($bytes)
    return (($bytes | ForEach-Object { $_.ToString('x2') }) -join '')
}

function Read-State {
    $state = @{ token = $null; last_run = $null; cursors = @{}; watch = @(); patch = $null; amd_raid = $null; veeam = $null; veeam_cursor = $null; vbo = $null; vbo_checked = $null; apps_sent = $null; secrets_sent = $null; secret_scan = $null; reboot_pkgs = $null; integrity = $null; perm_checked = $false }
    if (Test-Path $StatePath) {
        try {
            $raw = Get-Content $StatePath -Raw | ConvertFrom-Json
            $state.token = $raw.token
            $state.last_run = $raw.last_run
            if ($raw.cursors) {
                foreach ($p in $raw.cursors.PSObject.Properties) { $state.cursors[$p.Name] = [long]$p.Value }
            }
            if ($raw.watch) { $state.watch = @($raw.watch) }
            if ($raw.last_server) { $state.last_server = [string]$raw.last_server }
            if ($raw.servers) { $state.servers = @($raw.servers | ForEach-Object { [string]$_ }) }
            if ($raw.route -and $raw.route.inside -and $raw.route.outside) {
                $state.route = @{ inside = [string]$raw.route.inside; outside = [string]$raw.route.outside
                    networks = @($raw.route.networks | Where-Object { $_ } | ForEach-Object { [string]$_ }) }
            }
            if ($raw.route_side) { $state.route_side = [string]$raw.route_side }
            if ($raw.amd_raid) { $state.amd_raid = [string]$raw.amd_raid }
            if ($raw.veeam) { $state.veeam = [string]$raw.veeam }
            if ($raw.veeam_cursor) { $state.veeam_cursor = [int64]$raw.veeam_cursor }
            if ($raw.veeam_agent) { $state.veeam_agent = [string]$raw.veeam_agent }
            if ($raw.veeam_agent_cursor) { $state.veeam_agent_cursor = [int64]$raw.veeam_agent_cursor }
            # Agent policies' computers (read hourly), other backup products' history, and the last signed serial
            if ($raw.veeam_policy) { $state.veeam_policy = [string]$raw.veeam_policy; $state.veeam_policy_key = [string]$raw.veeam_policy_key
                try { $state.veeam_policy_checked = [int64]$raw.veeam_policy_checked } catch { } }
            foreach ($p in @($raw.PSObject.Properties | Where-Object { $_.Name -like 'bp_*' })) { $state[$p.Name] = [string]$p.Value }
            if ($raw.sig_serial) { try { $state.sig_serial = [int64]$raw.sig_serial } catch { } }
            if ($raw.sfc_job) { $state.sfc_job = [string]$raw.sfc_job }
            if ($raw.sfc_conf) { try { $state.sfc_conf = @{ on = [bool]$raw.sfc_conf.on; day = [int]$raw.sfc_conf.day; hour = [int]$raw.sfc_conf.hour; dism = [bool]$raw.sfc_conf.dism; run_now = [int64]$raw.sfc_conf.run_now } } catch { } }
            if ($raw.vbo) { $state.vbo = [string]$raw.vbo }
            if ($raw.apps_sent) { $state.apps_sent = [string]$raw.apps_sent }
            if ($raw.secrets_sent) { $state.secrets_sent = [string]$raw.secrets_sent }
            if ($raw.secret_scan) { $state.secret_scan = @{ on = [bool]$raw.secret_scan.on; paths = @($raw.secret_scan.paths | Where-Object { $_ } | ForEach-Object { [string]$_ }); hours = [int]$raw.secret_scan.hours } }
            if ($raw.vbo_checked) { try { $state.vbo_checked = [int64]$raw.vbo_checked } catch { } }
            if ($raw.exch_dbs) { $state.exch_dbs = [string]$raw.exch_dbs }
            if ($raw.exch_checked) { try { $state.exch_checked = [int64]$raw.exch_checked } catch { } }
            if ($raw.ad_report) { $state.ad_report = [string]$raw.ad_report }
            if ($raw.ad_checked) { try { $state.ad_checked = [int64]$raw.ad_checked } catch { } }
            if ($raw.laps_ad_at) { try { $state.laps_ad_at = [int64]$raw.laps_ad_at; $state.laps_ad_exp = [string]$raw.laps_ad_exp; $state.laps_ad_attr = [string]$raw.laps_ad_attr } catch { } }
            if ($raw.patch) {
                $state.patch = @{ checked = $raw.patch.checked; date = $raw.patch.date; kb = $raw.patch.kb; source = $raw.patch.source
                    title = $(if ($raw.patch.PSObject.Properties['title']) { [string]$raw.patch.title } else { $null }) }
            }
            if ($raw.integrity -and $raw.integrity.at) { $state.integrity = @{ at = [string]$raw.integrity.at; first = [bool]$raw.integrity.first; what = @($raw.integrity.what | Where-Object { $_ } | ForEach-Object { [string]$_ }) } }
            if ($raw.perm_checked) { $state.perm_checked = $true }
            if ($raw.tls) { $state.tls = @{ port = [int]$raw.tls.port; pin = [string]$raw.tls.pin; off = [bool]$raw.tls.off } }
            if ($raw.messages_log) { $state.messages_log = @($raw.messages_log | Where-Object { $_ -and $_.id } | Select-Object -Last 20 | ForEach-Object {
                    $e = [ordered]@{ id = [string]$_.id; sessions = [int]$_.sessions }; if ($_.error) { $e.error = [string]$_.error }; $e }) }
            if ($raw.reboot_pkgs) { $state.reboot_pkgs = @{ boot = [string]$raw.reboot_pkgs.boot; checked = $raw.reboot_pkgs.checked; list = @($raw.reboot_pkgs.list | Where-Object { $_ } | ForEach-Object { [string]$_ }) } }
        } catch {
            Write-AgentLog "WARN state file unreadable, starting fresh: $($_.Exception.Message)"
        }
    }
    return $state
}

function Save-State($State) {
    if (-not (Test-Path $DataPath)) { New-Item -ItemType Directory -Path $DataPath -Force | Out-Null }
    $State | ConvertTo-Json -Depth 4 | Set-Content -Path $StatePath -Encoding UTF8
}

function Protect-DataFolder([string]$Path = $DataPath) {
    # The token lives here: SYSTEM and Administrators only. The folder's permissions are replaced
    # whole, in one step (anything else on it, e.g. an account Explorer added when someone opened the
    # folder, is dropped), then everything inside goes back to inheriting just that.
    $ErrorActionPreference = 'Continue'
    try {
        $sec = New-Object System.Security.AccessControl.DirectorySecurity
        $sec.SetAccessRuleProtection($true, $false)
        $admins = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
        $sec.SetOwner($admins)
        foreach ($sid in 'S-1-5-18', 'S-1-5-32-544') {
            $sec.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
                        (New-Object System.Security.Principal.SecurityIdentifier($sid)), 'FullControl', 'ContainerInherit, ObjectInherit', 'None', 'Allow')))
        }
        $dir = New-Object System.IO.DirectoryInfo($Path)
        try { $dir.SetAccessControl($sec) } catch {
            [System.IO.FileSystemAclExtensions]::SetAccessControl($dir, $sec)  # PowerShell 7 has it here instead
        }
        $null = & icacls.exe (Join-Path $DataPath '*') /setowner '*S-1-5-32-544' /T /C /Q 2>&1
        $null = & icacls.exe (Join-Path $DataPath '*') /reset /T /C /Q 2>&1
    } catch { Write-AgentLog "WARN couldn't set folder permissions: $($_.Exception.Message)" }
}

# Who other than SYSTEM and Administrators could change the agent's folder: read back after Protect-DataFolder,
# so a folder that couldn't be locked down (an unusual file system, or a policy) is never run from (review F9).
# Returns their names; empty when it's locked down.
function Get-DataFolderWriters([string]$Path = $DataPath) {
    $ok = @('S-1-5-18', 'S-1-5-32-544')
    # write, append, extended attributes, delete children, attributes, delete, permissions, ownership, generic write/all
    $mask = 0x2 -bor 0x4 -bor 0x10 -bor 0x40 -bor 0x100 -bor 0x10000 -bor 0x40000 -bor 0x80000 -bor 0x40000000 -bor 0x10000000
    $out = @()
    if ($PSVersionTable.PSVersion.Major -ge 6 -and -not $IsWindows) { return @() }  # Windows file permissions only (tests run elsewhere)
    $acl = $null
    try { $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop }
    catch {
        # Get-Acl's module can fail to load in Windows PowerShell started from PowerShell 7 (its module path comes
        # along); .NET reads the same permissions without it
        try { $acl = [System.IO.Directory]::GetAccessControl($Path) } catch { }
    }
    if (-not $acl) {
        # Not being able to read the permissions isn't a sign anyone else can write: say so, and don't stop the agent
        $script:FolderCheckNote = "couldn't read the permissions on $Path, so they weren't checked"
        return @()
    }
    try {
        foreach ($r in @($acl.Access)) {
            if ([string]$r.AccessControlType -ne 'Allow') { continue }
            $rights = 0; try { $rights = [int64]$r.FileSystemRights } catch { $rights = $mask }  # unreadable: assume it can write
            if (($rights -band $mask) -eq 0) { continue }
            $sid = $null
            try { $sid = $r.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { $sid = [string]$r.IdentityReference }
            if ($ok -notcontains $sid) { $out += [string]$r.IdentityReference }
        }
    } catch { $script:FolderCheckNote = "couldn't read the permissions on $Path ($($_.Exception.Message)), so they weren't checked" }
    return @($out | Select-Object -Unique)
}

# Each run: the agent's folder and everything in it must still belong to SYSTEM or Administrators,
# give nobody else access and not inherit permissions from above (someone may have opened it up to
# read the log). Anything else is put back, and Rollcall is told what was found. Called after the
# report is sent, and can never fail a run.
function Test-AgentFolderSecurity($State) {
    $ErrorActionPreference = 'Continue'
    if ($env:OS -ne 'Windows_NT') { return }
    try {
        $allowed = @('S-1-5-18', 'S-1-5-32-544')
        $sidOf = {
            param($Ref)
            try { return $Ref.Translate([Security.Principal.SecurityIdentifier]).Value } catch { return [string]$Ref }
        }
        $found = New-Object System.Collections.ArrayList
        $items = @(Get-Item -LiteralPath $DataPath -Force) + @(Get-ChildItem -LiteralPath $DataPath -Force -Recurse -ErrorAction SilentlyContinue)
        foreach ($it in $items) {
            # Straight from .NET (no module to load); Get-Acl if that's not there (PowerShell 7)
            $acl = $null
            try { $acl = $it.GetAccessControl() } catch { $acl = Get-Acl -LiteralPath $it.FullName }
            $name = if ($it.FullName -eq (Get-Item -LiteralPath $DataPath -Force).FullName) { 'the agent folder' } else { $it.Name }
            $owner = & $sidOf ($acl.GetOwner([Security.Principal.NTAccount]))
            if ($allowed -notcontains $owner) { [void]$found.Add("$name was owned by $($acl.Owner)") }
            if ($name -eq 'the agent folder' -and -not $acl.AreAccessRulesProtected) { [void]$found.Add('the agent folder took permissions from the folder above it') }
            $who = @($acl.Access | Where-Object { $allowed -notcontains (& $sidOf $_.IdentityReference) } | ForEach-Object { [string]$_.IdentityReference } | Select-Object -Unique)
            if ($who.Count) { [void]$found.Add("$($who -join ', ') had access to $name") }
            if ($found.Count -ge 10) { break }
        }
        $first = -not $State.perm_checked  # the first check after updating to 1.0.40: just tidying up
        $State.perm_checked = $true
        if (-not $found.Count) { return }
        # Put it back: owner Administrators, SYSTEM and Administrators only, children inheriting just that
        Protect-DataFolder
        $what = @($found | Select-Object -Unique | ForEach-Object { Limit-Text $_ 200 })
        $State.integrity = @{ at = ConvertTo-UtcString (Get-Date); what = $what; first = $first }
        Write-AgentLog ("WARN Put back the permissions on the agent's folder: " + ($what -join '; '))
    } catch { Write-AgentLog "WARN Couldn't check the agent folder's permissions: $($_.Exception.Message)" }
}

# Thin wrappers around external tools, so they're easy to stub when testing.
function Invoke-AppCmd([string[]]$Arguments) {
    $exe = Join-Path $env:windir 'system32\inetsrv\appcmd.exe'
    if (-not $env:windir -or -not (Test-Path $exe)) { return $null }
    return (& $exe @Arguments) -join "`n"
}
function Invoke-RepAdmin([string[]]$Arguments) {
    $exe = Join-Path $env:windir 'system32\repadmin.exe'
    if (-not $env:windir -or -not (Test-Path $exe)) { return $null }
    return (& $exe @Arguments 2>$null)
}
function Invoke-W32tm([string[]]$Arguments) {
    $exe = Join-Path $env:windir 'system32\w32tm.exe'
    if (-not $env:windir -or -not (Test-Path $exe)) { return $null }
    return @(& $exe @Arguments 2>$null)
}
function Invoke-Nltest([string[]]$Arguments) {
    $exe = Join-Path $env:windir 'system32\nltest.exe'
    if (-not $env:windir -or -not (Test-Path $exe)) { return $null }
    return @(& $exe @Arguments 2>$null)
}
function Get-FtpSiteState([string]$Name, [string]$Fallback) {
    try {
        $dll = Join-Path $env:windir 'system32\inetsrv\Microsoft.Web.Administration.dll'
        if (Test-Path $dll) {
            Add-Type -Path $dll -ErrorAction Stop
            $site = (New-Object Microsoft.Web.Administration.ServerManager).Sites[$Name]
            if ($site) {
                $v = $site.GetChildElement('ftpServer').GetAttributeValue('state')
                $map = @{ 0 = 'Starting'; 1 = 'Started'; 2 = 'Stopping'; 3 = 'Stopped' }
                if ($null -ne $v -and $map.ContainsKey([int]$v)) { return $map[[int]$v] }
            }
        }
    } catch { }
    try {
        $svc = @(Get-CimInstance -ClassName Win32_Service -Filter "Name = 'FTPSVC'") | Where-Object { $_.Name -eq 'FTPSVC' } | Select-Object -First 1
        if ($svc) { if ($svc.State -eq 'Running') { return 'Started' } else { return 'Stopped' } }
    } catch { }
    return $Fallback
}
function Get-QUserOutput {
    try { return (& quser.exe 2>$null) } catch { return $null }
}

$ScanLimit = 200000   # most records read from one log in one run

function Get-RecentRecords([string]$Log, [DateTime]$Since, [long]$After) {
    # Reads the log backwards from the newest record and stops at the last record seen
    # (or $Since), so a run only touches what's new. A filtered query (Get-WinEvent with
    # IDs and StartTime) can't do that: the event log has no index, so Windows reads the
    # whole log every time, which takes minutes on a large Security log.
    if (-not ('System.Diagnostics.Eventing.Reader.EventLogQuery' -as [type])) {
        # Built in to Windows PowerShell 5.1; PowerShell 7 loads it with its Diagnostics module.
        try { Import-Module Microsoft.PowerShell.Diagnostics -ErrorAction Stop } catch { }
        try { Add-Type -AssemblyName System.Diagnostics.EventLog -ErrorAction Stop } catch { }
    }
    $q = New-Object System.Diagnostics.Eventing.Reader.EventLogQuery($Log, [System.Diagnostics.Eventing.Reader.PathType]::LogName, '*')
    $q.ReverseDirection = $true
    $reader = New-Object System.Diagnostics.Eventing.Reader.EventLogReader($q)
    $out = New-Object System.Collections.ArrayList
    $res = @{ records = $out; newest = $null; capped = $false }
    try {
        $n = 0
        while ($true) {
            $e = $reader.ReadEvent()
            if ($null -eq $e) { break }
            if ($null -eq $res.newest) { $res.newest = [long]$e.RecordId; if ($After -and $res.newest -lt $After) { $After = 0 } }  # log was cleared
            if ($After -and $e.RecordId -le $After) { $e.Dispose(); break }
            if ($e.TimeCreated -and $e.TimeCreated -lt $Since) { $e.Dispose(); break }
            [void]$out.Add($e)
            if (++$n -ge $ScanLimit) { $res.capped = $true; break }
        }
    } finally { $reader.Dispose() }
    return $res
}

function Get-NewEvents([string]$Log, [DateTime]$Since, [int[]]$Ids, [int[]]$Levels, [string]$CursorName, $State) {
    # Matching events newer than the last run, newest first. The cursor is the newest
    # record read, so the next run stops there.
    $after = 0
    if ($State.cursors.ContainsKey($CursorName)) { $after = [long]$State.cursors[$CursorName] }
    $res = Get-RecentRecords $Log $Since $after
    if ($res.capped) { Add-CollectorError "events-$Log" ([pscustomobject]@{ Exception = [pscustomobject]@{ Message = "more than $ScanLimit new records since the last run; only the newest were checked" } }) }
    if ($null -ne $res.newest) { $State.cursors[$CursorName] = [long]$res.newest }
    $idSet = $null; if ($Ids) { $idSet = New-Object 'System.Collections.Generic.HashSet[int]'; foreach ($i in $Ids) { [void]$idSet.Add($i) } }
    $out = New-Object System.Collections.ArrayList
    foreach ($e in $res.records) {
        $keep = (-not $idSet -or $idSet.Contains([int]$e.Id)) -and (-not $Levels -or ($Levels -contains [int]$e.Level))
        if ($keep) { [void]$out.Add($e) } else { $e.Dispose() }
    }
    return $out
}

function Get-EventMessage($Event) {
    if ($Event.PSObject.Properties['Message'] -and $Event.Message) { return [string]$Event.Message }
    try { $m = $Event.FormatDescription(); if ($m) { return [string]$m } } catch { }
    return '(no description)'
}

function Get-EventFields($Event) {
    $h = @{}
    try {
        $x = [xml]$Event.ToXml()
        foreach ($d in @($x.Event.EventData.Data)) {
            if ($d -and $d.Name) { $h[$d.Name] = [string]$d.'#text' }
        }
        if ($x.Event.UserData) {
            foreach ($n in $x.Event.UserData.ChildNodes) {
                foreach ($c in $n.ChildNodes) { $h[$c.LocalName] = [string]$c.InnerText }
            }
        }
    } catch { }
    return $h
}

# ---------------------------------------------------------------------------
# Role discovery
# ---------------------------------------------------------------------------
# Feature: regex against Win32_ServerFeature names (Windows Server roles).
# Marker: service that identifies the role when feature info isn't available.
# Services: services to watch when the role is present (only those that exist
#           and are set to start automatically).
# Pattern: regex of service names for apps that aren't Windows roles.
$RoleDefinitions = @(
    @{ Role = 'Domain controller'; Feature = '^Active Directory Domain Services$'; Marker = 'NTDS'; Services = @('NTDS', 'Netlogon', 'Kdc', 'DFSR', 'NtFrs', 'W32Time', 'ADWS', 'IsmServ') },
    @{ Role = 'DNS server'; Feature = '^DNS Server$'; Marker = 'DNS'; Services = @('DNS') },
    @{ Role = 'DHCP server'; Feature = '^DHCP Server$'; Marker = 'DHCPServer'; Services = @('DHCPServer') },
    @{ Role = 'File server'; Feature = '^File Server$'; Services = @('LanmanServer') },
    @{ Role = 'DFS Namespaces'; Feature = '^DFS Namespaces$'; Services = @('Dfs') },
    @{ Role = 'DFS Replication'; Feature = '^DFS Replication$'; Services = @('DFSR') },
    @{ Role = 'Print server'; Feature = '^Print Server$'; Services = @('Spooler') },
    @{ Role = 'IIS'; Feature = '^Web Server \(IIS\)$'; Marker = 'W3SVC'; Services = @('W3SVC', 'WAS') },
    @{ Role = 'Remote Desktop Session Host'; Feature = '^Remote Desktop Session Host$'; Services = @('TermService', 'SessionEnv', 'UmRdpService') },
    @{ Role = 'RD Connection Broker'; Feature = '^Remote Desktop Connection Broker$'; Marker = 'Tssdis'; Services = @('Tssdis') },
    @{ Role = 'RD Gateway'; Feature = '^Remote Desktop Gateway$'; Marker = 'TSGateway'; Services = @('TSGateway') },
    @{ Role = 'RD Licensing'; Feature = '^Remote Desktop Licensing$'; Marker = 'TermServLicensing'; Services = @('TermServLicensing') },
    @{ Role = 'Hyper-V'; Feature = '^Hyper-V$'; Marker = 'vmms'; Services = @('vmms', 'vmcompute') },
    @{ Role = 'WSUS'; Feature = '^Windows Server Update Services$'; Marker = 'WsusService'; Services = @('WsusService') },
    @{ Role = 'Certificate Services'; Feature = '^Certification Authority$'; Marker = 'CertSvc'; Services = @('CertSvc') },
    @{ Role = 'AD FS'; Feature = '^Federation Service'; Marker = 'adfssrv'; Services = @('adfssrv') },
    @{ Role = 'NPS'; Feature = '^Network Policy Server$'; Marker = 'IAS'; Services = @('IAS') },
    @{ Role = 'SQL Server'; Pattern = '^(MSSQLSERVER|MSSQL\$.+|SQLSERVERAGENT|SQLAgent\$.+|SQLBrowser|ReportServer.*|SQLServerReportingServices|MSSQLServerOLAPService|MSOLAP\$.+)$' },
    @{ Role = 'Exchange'; Pattern = '^MSExchange(IS|Transport|FrontEndTransport|ServiceHost|ADTopology|RPC|MailboxAssistants|Submission|Delivery|Repl|DagMgmt|EdgeSync|UM|MailboxReplication|HM|Throttling)$' },
    @{ Role = 'SharePoint'; Pattern = '^(SPTimerV4|SPAdminV4|SPSearchHostController|OSearch\d+|SPTraceV4)$' },
    @{ Role = 'Veeam Backup'; Pattern = '^Veeam(BackupSvc|BrokerSvc|CatalogSvc|DeploySvc|MountSvc|TransportSvc|BackupRESTSvc)$' },
    @{ Role = 'Veeam Backup for Microsoft 365'; Pattern = '^Veeam\.Archiver\.(Service|Proxy|REST)$' }
)

function Get-Discovery($AllServices, [string[]]$ExtraWatch, [bool]$Workstation = $false) {
    $features = $null
    try {
        # Windows Server roles only exist on Server; don't ask a workstation.
        if (-not $Workstation) {
            $features = @(Get-CimInstance -ClassName Win32_ServerFeature -ErrorAction Stop | ForEach-Object { $_.Name })
        }
    } catch {
        # Not a Server SKU, or WMI class unavailable: fall back to marker services.
        $features = $null
    }
    $byName = @{}
    foreach ($s in $AllServices) { $byName[$s.Name.ToLower()] = $s }

    $roles = New-Object System.Collections.ArrayList
    $watch = @{}
    foreach ($def in $RoleDefinitions) {
        $present = $false
        $candidates = @()
        if ($def.Pattern) {
            $candidates = @($AllServices | Where-Object { $_.Name -match $def.Pattern })
            $present = $candidates.Count -gt 0
        } else {
            if ($null -ne $features -and $def.Feature) {
                $present = @($features | Where-Object { $_ -match $def.Feature }).Count -gt 0
            }
            if (-not $present -and $def.Marker) {
                $present = $byName.ContainsKey($def.Marker.ToLower())
            }
            if ($present) {
                $candidates = @($def.Services | ForEach-Object { $byName[$_.ToLower()] } | Where-Object { $_ })
            }
        }
        if (-not $present) { continue }
        [void]$roles.Add($def.Role)
        foreach ($svc in $candidates) {
            if ($svc.StartMode -eq 'Auto' -and -not $watch.ContainsKey($svc.Name)) { $watch[$svc.Name] = $def.Role }
        }
    }
    foreach ($name in $ExtraWatch) {
        if (-not $name) { continue }
        $svc = $byName[$name.ToLower()]
        if ($svc -and -not $watch.ContainsKey($svc.Name)) { $watch[$svc.Name] = 'Requested' }
    }
    return @{ roles = @($roles); watch = $watch }
}

# ---------------------------------------------------------------------------
# Collectors (each one is independent; a failure is reported, not fatal)
# ---------------------------------------------------------------------------
$NoisyAutoServices = @(
    'gupdate', 'gupdatem', 'edgeupdate', 'edgeupdatem', 'MapsBroker', 'sppsvc', 'RemoteRegistry',
    'CDPSvc', 'tiledatamodelsvc', 'WbioSrvc', 'ShellHWDetection', 'DoSvc', 'UsoSvc', 'WaaSMedicSvc',
    'TrustedInstaller', 'BITS', 'wuauserv', 'NetTcpPortSharing', 'sysmain', 'stisvc', 'Wcmsvc',
    'GoogleUpdaterService', 'GoogleUpdaterInternalService', 'MozillaMaintenance', 'AdobeARMservice',
    'clr_optimization_v4.0.30319_32', 'clr_optimization_v4.0.30319_64', 'OneSyncSvc', 'CDPUserSvc',
    'WpnUserService', 'PimIndexMaintenanceSvc', 'UnistoreSvc', 'UserDataSvc', 'MessagingService',
    'BluetoothUserService', 'CaptureService', 'cbdhsvc', 'DevicesFlowUserSvc', 'PrintWorkflowUserSvc',
    'IntelAudioService', 'RtkAudioUniversalService', 'AGMService', 'AGSService'
)

function Get-VirtualKind([string]$Vendor, [string]$Model) {
    # What the machine is running on, from its system manufacturer and model; '' for physical.
    $t = "$Vendor $Model"
    if ($Vendor -match 'Microsoft' -and $Model -match 'Virtual') { return 'Hyper-V' }
    if ($t -match 'VMware') { return 'VMware' }
    if ($t -match 'VirtualBox|innotek') { return 'VirtualBox' }
    if ($t -match 'QEMU|KVM|Proxmox|Standard PC \(|oVirt|Red Hat|Nutanix|Bochs') { return 'KVM / QEMU' }
    if ($t -match 'Xen') { return 'Xen' }
    if ($t -match 'Parallels') { return 'Parallels' }
    if ($t -match 'Amazon EC2') { return 'AWS' }
    if ($t -match 'Google Compute') { return 'Google Cloud' }
    return ''
}

function Get-HardwareText($Value) {
    # A make, model or serial number, or '' when the BIOS only holds a placeholder
    $t = ([string]$Value).Trim()
    if ($t -match '^(system manufacturer|system product name|system version|system serial number|system sku|to be filled by o\.?e\.?m\.?|default string|not applicable|not specified|not available|none|n/?a|o\.?e\.?m\.?|oem manufacturer|invalid|undefined|unknown|type1productconfigid|sku|x+|0+|1234567890|0123456789|123456789|base board serial number|chassis serial number|default|empty|\.+|-+)$') { return '' }
    return $t
}

function Get-SystemInfo {
    $info = [ordered]@{}
    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem
    $build = [string]$os.Version
    try {
        $ubr = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop).UBR
        if ($null -ne $ubr) { $build = "$build.$ubr" }
    } catch { }
    $info.os = Limit-Text ("{0} ({1})" -f $os.Caption, $build) 120
    $info.os_build = $build
    $info.boot_time = ConvertTo-UtcString $os.LastBootUpTime
    $info.uptime_s = [int]((Get-Date) - [DateTime]$os.LastBootUpTime).TotalSeconds
    $info.mem_total_mb = [int]($os.TotalVisibleMemorySize / 1024)
    $info.mem_free_mb = [int]($os.FreePhysicalMemory / 1024)
    $info.domain = [string]$cs.Domain
    $info.part_of_domain = [bool]$cs.PartOfDomain
    $vendor = Get-HardwareText $cs.Manufacturer
    $model = Get-HardwareText $cs.Model
    $info.virtual = Get-VirtualKind ([string]$cs.Manufacturer) ([string]$cs.Model)
    if (-not $info.virtual -and (-not $vendor -or -not $model)) {
        # A custom-built PC leaves the system fields as placeholders, so name it by its motherboard instead
        try {
            $board = Get-CimInstance -ClassName Win32_BaseBoard -ErrorAction Stop | Select-Object -First 1
            $bv = Get-HardwareText $board.Manufacturer
            $bm = Get-HardwareText $board.Product
            if ($bv -or $bm) { $vendor = $bv; $model = $bm; $info.hw_board = $true }
        } catch { }
    }
    $info.hw_vendor = Limit-Text $vendor 80
    $info.hw_model = Limit-Text $model 80
    try {
        $serial = Get-HardwareText (Get-CimInstance -ClassName Win32_BIOS -ErrorAction Stop).SerialNumber
        if ($serial) { $info.serial = Limit-Text $serial 60 }
    } catch { }
    $info.workstation = ([int]$os.ProductType -eq 1)
    try {
        $cpu = Measure-Step 'cpu' { (Get-CimInstance -ClassName Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average }
        $info.cpu_pct = if ($null -ne $cpu) { [int]$cpu } else { $null }
    } catch { Add-CollectorError 'cpu' $_ }
    try {
        $ips = @(Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter 'IPEnabled = TRUE' |
            ForEach-Object { $_.IPAddress } |
            Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' -and $_ -notlike '169.254.*' -and $_ -ne '127.0.0.1' })
        $info.ips = $ips
    } catch { Add-CollectorError 'ip' $_ }
    # Restart pending, and which parts of Windows are asking for it
    $reasons = New-Object System.Collections.ArrayList
    try { if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') { [void]$reasons.Add('Windows component servicing') } } catch { }
    try { if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { [void]$reasons.Add('Windows Update') } } catch { }
    try {
        $ccm = Invoke-CimMethod -Namespace 'root\ccm\ClientSDK' -ClassName CCM_ClientUtilities -MethodName DetermineIfRebootPending -ErrorAction Stop
        if ($ccm -and ($ccm.RebootPending -or $ccm.IsHardRebootPending)) { [void]$reasons.Add('Configuration Manager client') }
    } catch { }  # no Configuration Manager client
    $info.pending_reboot = ($reasons.Count -gt 0)
    if ($info.pending_reboot) {
        # Files Windows will replace at the next restart (often an Exchange or SQL Server update);
        # only mentioned when a restart is already pending, as some programs leave these about.
        try {
            # Pairs of entries: the file, then what replaces it (blank = delete it)
            $pfro = @((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction Stop).PendingFileRenameOperations |
                    ForEach-Object { ([string]$_) -replace '^!', '' -replace '^\\\?\?\\', '' })
            $dirs = @{}
            for ($i = 0; $i -lt $pfro.Count; $i += 2) {
                if (-not $pfro[$i]) { continue }
                $d = Split-Path -Path $pfro[$i] -Parent -ErrorAction SilentlyContinue
                if ($d) { $dirs[$d] = 1 + [int]$dirs[$d] }
            }
            foreach ($kv in @($dirs.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 3)) {
                [void]$reasons.Add((Limit-Text ("Files waiting to be replaced in {0} ({1})" -f $kv.Key, $kv.Value) 160))
            }
        } catch { }
    }
    $info.reboot_reasons = @($reasons)
    return $info
}

# What was installed since the last restart, when one is pending: Windows Update history, and
# packages the Setup log says need a restart to finish. Re-checked every 30 minutes.
function Get-RebootPackages($State, $BootTime) {
    $c = $State.reboot_pkgs
    if ($c -and $c.boot -eq $BootTime -and $c.checked) {
        try { if (((Get-Date) - [DateTime]$c.checked).TotalMinutes -lt 30) { return @($c.list) } } catch { }
    }
    $boot = ([DateTime]$BootTime).ToLocalTime()
    $list = New-Object System.Collections.ArrayList
    try {
        $searcher = (New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher()
        $count = $searcher.GetTotalHistoryCount()
        if ($count -gt 0) {
            foreach ($h in @($searcher.QueryHistory(0, [Math]::Min($count, 50)))) {
                if ($h.Operation -ne 1 -or ($h.ResultCode -ne 2 -and $h.ResultCode -ne 3)) { continue }
                if (([DateTime]$h.Date).ToLocalTime() -le $boot) { continue }
                if ($h.Title -match 'Security Intelligence Update|Definition Update|Antimalware platform|Antivirus platform|KB2267602|KB4052623|KB915597') { continue }
                $title = Limit-Text ([string]$h.Title) 160
                if ($title -and -not $list.Contains($title)) { [void]$list.Add($title) }
            }
        }
    } catch { }
    try {
        foreach ($e in @(Get-WinEvent -FilterHashtable @{ LogName = 'Setup'; Id = 4; StartTime = $boot } -MaxEvents 30 -ErrorAction Stop)) {
            $kb = ([regex]'KB\d{6,8}').Match([string]$e.Message).Value
            if ($kb -and -not ($list | Where-Object { $_ -like "*$kb*" })) { [void]$list.Add($kb) }
        }
    } catch { }  # none since the restart
    $out = @($list | Select-Object -First 10)
    $State.reboot_pkgs = @{ boot = $BootTime; checked = ConvertTo-UtcString (Get-Date); list = $out }
    return $out
}

function Get-PatchInfo($State, $BootTime) {
    # The last-update date only changes when updates are installed (which means a
    # reboot), and finding it can be slow on some machines (Windows Update history
    # in particular), so it's re-checked every 6 hours or after a restart.
    $c = $State.patch
    $fresh = $false
    if ($c -and $c.checked) {
        try {
            $checked = [DateTime]$c.checked
            $fresh = ((Get-Date) - $checked).TotalHours -lt 6
            if ($fresh -and $BootTime -and ([DateTime]$BootTime) -gt $checked) { $fresh = $false }
        } catch { $fresh = $false }
    }
    if ($fresh -and $null -ne $c.title) { return @{ date = $c.date; kb = $c.kb; title = $c.title; source = $c.source; cached = $true } }
    $p = Get-LastPatch
    $State.patch = @{ checked = ConvertTo-UtcString (Get-Date); date = (ConvertTo-UtcString $p.date); kb = $p.kb; title = $p.title; source = $p.source }
    return @{ date = $State.patch.date; kb = $p.kb; title = $p.title; source = $p.source; cached = $false }
}

function Get-LastPatch {
    # The newest of three sources, because each can miss things:
    #  - Windows Update Agent history: includes MECM/WSUS installs (MECM uses the agent)
    #  - Setup event log: Windows Servicing records every package it installs,
    #    however it arrived, even with the Windows Update service disabled
    #  - Win32_QuickFixEngineering: its InstalledOn text is US-format; Get-HotFix
    #    can misread it on non-US servers, so it's parsed here explicitly
    $best = @{ date = $null; kb = $null; title = $null; source = $null }
    $consider = {
        param($Date, $Kb, $Source, $Title)
        if ($Date -and $Date -le (Get-Date).AddDays(1) -and (-not $best.date -or $Date -gt $best.date)) {
            $best.date = $Date; $best.kb = $Kb; $best.source = $Source; $best.title = $Title
        }
    }
    try {
        $searcher = (New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher()
        $count = $searcher.GetTotalHistoryCount()
        if ($count -gt 0) {
            # Newest first; the latest real update is nearly always in the last 100 entries.
            foreach ($h in @($searcher.QueryHistory(0, [Math]::Min($count, 100)))) {
                if ($h.Operation -ne 1 -or ($h.ResultCode -ne 2 -and $h.ResultCode -ne 3)) { continue }
                if ($h.Title -match 'Security Intelligence Update|Definition Update|Antimalware platform|Antivirus platform|KB2267602|KB4052623|KB915597') { continue }
                $kb = ([regex]'KB\d{6,8}').Match([string]$h.Title).Value
                & $consider ([DateTime]$h.Date).ToLocalTime() $kb 'Windows Update history' (Limit-Text ([string]$h.Title) 200)
            }
        }
    } catch { }
    try {
        $events = @(Get-WinEvent -FilterHashtable @{ LogName = 'Setup'; Id = 2 } -MaxEvents 50 -ErrorAction Stop |
            Where-Object { $_.ProviderName -like '*Servicing*' })
        foreach ($e in $events) {
            $kb = ([regex]'KB\d{6,8}').Match([string]$e.Message).Value
            if ($kb) { & $consider $e.TimeCreated $kb 'Setup event log'; break }
        }
    } catch { }
    try {
        $formats = [string[]]@('M/d/yyyy', 'MM/dd/yyyy', 'M/d/yyyy h:mm:ss tt', 'yyyyMMdd', 'yyyy-MM-dd')
        foreach ($q in @(Get-CimInstance -ClassName Win32_QuickFixEngineering -ErrorAction Stop)) {
            $d = $null
            if ($q.InstalledOn -is [DateTime]) { $d = $q.InstalledOn }
            else {
                $parsed = [DateTime]::MinValue
                if ([DateTime]::TryParseExact(([string]$q.InstalledOn).Trim(), $formats,
                        [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::None, [ref]$parsed)) { $d = $parsed }
            }
            & $consider $d ([string]$q.HotFixID) 'Installed updates list' ([string]$q.Description)
        }
    } catch { Add-CollectorError 'updates' $_ }
    return $best
}

function Get-Disks {
    return @(Get-CimInstance -ClassName Win32_LogicalDisk -Filter 'DriveType = 3' | Where-Object { $_.Size -gt 0 } | ForEach-Object {
            [ordered]@{
                name    = [string]$_.DeviceID
                label   = [string]$_.VolumeName
                size_gb = [Math]::Round($_.Size / 1GB, 1)
                free_gb = [Math]::Round($_.FreeSpace / 1GB, 1)
            }
        })
}

function Test-DelayedStart($Service) {
    # Automatic (Delayed Start): WMI reports these as 'Auto' too. Windows Server 2016 / 10 and later say so
    # in DelayedAutoStart; older ones only in the registry.
    if ($Service.StartMode -ne 'Auto') { return $false }
    if ($null -ne $Service.PSObject.Properties['DelayedAutoStart'] -and $null -ne $Service.DelayedAutoStart) { return [bool]$Service.DelayedAutoStart }
    try { return [int](Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$($Service.Name)" -Name DelayedAutostart -ErrorAction Stop).DelayedAutostart -eq 1 } catch { return $false }
}

function Get-ServiceReport($AllServices, $Discovery) {
    $watched = @()
    foreach ($name in $Discovery.watch.Keys) {
        $s = $AllServices | Where-Object { $_.Name -eq $name } | Select-Object -First 1
        if ($s) {
            $watched += [ordered]@{
                name = [string]$s.Name; display = [string]$s.DisplayName; state = [string]$s.State
                start_mode = [string]$s.StartMode; role = [string]$Discovery.watch[$name]
                delayed = (Test-DelayedStart $s)
            }
        }
    }
    $stopped = @()
    foreach ($s in $AllServices) {
        if ($s.StartMode -ne 'Auto' -or $s.State -eq 'Running') { continue }
        if ($Discovery.watch.ContainsKey($s.Name)) { continue }
        $base = ($s.Name -split '_')[0]
        if ($NoisyAutoServices -contains $s.Name -or $NoisyAutoServices -contains $base) { continue }
        # Trigger-start services stop on their own when idle; not a fault.
        try {
            if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\$($s.Name)\TriggerInfo") { continue }
        } catch { }
        $stopped += [ordered]@{ name = [string]$s.Name; display = [string]$s.DisplayName; state = [string]$s.State; delayed = (Test-DelayedStart $s) }
        if ($stopped.Count -ge 50) { break }
    }
    return [ordered]@{ watched = @($watched | Sort-Object { $_.name }); stopped_auto = $stopped }
}

function Get-EventReport($State, [DateTime]$Since) {
    $counts = [ordered]@{}
    $recent = New-Object System.Collections.ArrayList
    foreach ($log in @('System', 'Application')) {
        $counts[$log] = [ordered]@{ critical = 0; error = 0 }
        try {
            $events = @(Get-NewEvents $log $Since $null @(1, 2) "$log-scan" $State | Select-Object -First 300)
            foreach ($e in $events) {
                if ($e.Level -eq 1) { $counts[$log].critical++ } else { $counts[$log].error++ }
            }
            foreach ($e in ($events | Sort-Object TimeCreated -Descending | Select-Object -First 25)) {
                [void]$recent.Add([ordered]@{
                        time    = ConvertTo-UtcString $e.TimeCreated
                        log     = $log
                        level   = if ($e.Level -eq 1) { 'Critical' } else { 'Error' }
                        id      = [int]$e.Id
                        source  = [string]$e.ProviderName
                        message = Limit-Text (Get-EventMessage $e) 300
                    })
            }
        } catch { Add-CollectorError "events-$log" $_ }
    }
    $top = @($recent | Sort-Object { $_.time } -Descending | Select-Object -First 30)
    return [ordered]@{ since = ConvertTo-UtcString $Since; counts = $counts; recent = $top }
}

$SecurityIds = @{
    4740 = 'Account locked out'; 4720 = 'User account created'; 4726 = 'User account deleted'
    4728 = 'Added to global security group'; 4732 = 'Added to local security group'; 4756 = 'Added to universal security group'
    4729 = 'Removed from global security group'; 4733 = 'Removed from local security group'; 4757 = 'Removed from universal security group'
    1102 = 'Security log cleared'; 4719 = 'Audit policy changed'; 4724 = 'Password reset by another account'
    4767 = 'Account unlocked'; 4722 = 'User account enabled'; 4725 = 'User account disabled'
}

function Get-SecurityReport($State, [DateTime]$Since) {
    $report = [ordered]@{ since = ConvertTo-UtcString $Since; failed_logons = [ordered]@{ count = 0; top = @() }; items = @() }
    $all = @()
    try {
        $ids = @($SecurityIds.Keys | ForEach-Object { [int]$_ }) + 4625
        $all = @(Get-NewEvents 'Security' $Since $ids $null 'Security-scan' $State)
    } catch { Add-CollectorError 'security' $_; return $report }
    try {
        $events = @($all | Where-Object { $_.Id -ne 4625 } | Select-Object -First 300)
        $items = @()
        $names = @{}
        # Group-membership events name the member only by its SID for local accounts (MemberName is "-"),
        # and by its directory DN for domain ones: show it as DOMAIN-backslash-name for both.
        $member = {
            param($f)
            $sid = [string]$f['MemberSid']
            if ($sid -and $sid -ne '-' -and $sid -match '^S-1-') {
                if (-not $names.ContainsKey($sid)) {
                    $nm = ''
                    try { $nm = (New-Object Security.Principal.SecurityIdentifier $sid).Translate([Security.Principal.NTAccount]).Value } catch { }
                    $names[$sid] = $nm
                }
                if ($names[$sid]) { return $names[$sid] }
            }
            $n = [string]$f['MemberName']
            if ($n -match '^CN=((?:[^,\\]|\\.)+)') { return ($matches[1] -replace '\\(.)', '$1') }
            if ($n -and $n -ne '-') { return $n }
            if ($sid -and $sid -ne '-') { return $sid }
            return ''
        }
        $self = "$($env:COMPUTERNAME)`$"
        foreach ($e in ($events | Sort-Object TimeCreated -Descending | Select-Object -First 50)) {
            $f = Get-EventFields $e
            $who = @($f['TargetDomainName'], $f['TargetUserName']) | Where-Object { $_ -and $_ -ne '-' }
            $items += [ordered]@{
                time    = ConvertTo-UtcString $e.TimeCreated
                id      = [int]$e.Id
                what    = $SecurityIds[[int]$e.Id]
                account = if ($e.Id -in 4728, 4732, 4756, 4729, 4733, 4757) { & $member $f } else { ($who -join '\') }
                group   = if ($e.Id -in 4728, 4732, 4756, 4729, 4733, 4757) { (@($f['TargetDomainName'], $f['TargetUserName']) | Where-Object { $_ }) -join '\' } else { $null }
                by      = (@($f['SubjectDomainName'], $f['SubjectUserName']) | Where-Object { $_ -and $_ -ne '-' }) -join '\'
                source  = if ($e.Id -eq 4740) { [string]$f['TargetDomainName'] } else { $null }
            }
            # Done by the computer's own account: Windows itself (SYSTEM), e.g. LAPS or Group Policy
            if ([string]$f['SubjectUserName'] -eq $self) { $items[-1].by = "SYSTEM ($($items[-1].by))" }
        }
        # 4740's TargetDomainName is the caller computer, not a domain
        foreach ($i in $items) { if ($i.id -eq 4740) { $i.account = ($i.account -split '\\')[-1] } }
        $report.items = $items
    } catch { Add-CollectorError 'security' $_ }
    try {
        $failed = @($all | Where-Object { $_.Id -eq 4625 })
        $report.failed_logons.count = $failed.Count
        $failed = @($failed | Select-Object -First 2000)
        if (@($failed).Count -gt 0) {
            # Why Windows refused the logon (SubStatus, or Status when that's 0)
            $reasons = @{ '0xc0000064' = "user name doesn't exist"; '0xc000006a' = 'wrong password'; '0xc0000234' = 'account locked out'
                '0xc0000072' = 'account disabled'; '0xc000006f' = 'outside allowed logon hours'; '0xc0000070' = 'not allowed from this workstation'
                '0xc0000071' = 'password expired'; '0xc0000193' = 'account expired'; '0xc0000224' = 'must change password at next logon'
                '0xc000015b' = 'logon type not granted on this computer'; '0xc0000133' = "clocks out of sync with the domain controller"
                '0xc000018c' = 'trust with the domain failed'; '0xc0000413' = 'blocked by authentication firewall'; '0xc000005e' = 'no logon server available'
                '0xc000006d' = 'bad user name or authentication information'; '0xc000006e' = 'account restriction'; '0xc0000192' = 'NetLogon service not started' }
            $types = @{ '2' = 'interactive'; '3' = 'network'; '4' = 'batch'; '5' = 'service'; '7' = 'unlock'; '8' = 'network (clear text)'
                '9' = 'new credentials'; '10' = 'remote desktop'; '11' = 'cached' }
            $rows = foreach ($e in $failed) {
                $f = Get-EventFields $e
                $user = [string]$f['TargetUserName']; $dom = [string]$f['TargetDomainName']
                # A user name that already includes a domain was sent like that by the client: show it as received
                $account = if ($user -match '\\|@' -and $dom -and $dom -ne '-') { "$user (with domain $dom)" }
                           else { ((@($dom, $user) | Where-Object { $_ -and $_ -ne '-' }) -join '\') }
                $code = ([string]$(if ($f['SubStatus'] -and $f['SubStatus'] -notmatch '^0x0+$') { $f['SubStatus'] } else { $f['Status'] })).ToLower()
                [pscustomobject]@{
                    account = $account
                    source  = if ($f['IpAddress'] -and $f['IpAddress'] -ne '-') { $f['IpAddress'] } else { [string]$f['WorkstationName'] }
                    reason  = if ($reasons[$code]) { $reasons[$code] } elseif ($code) { $code } else { '' }
                    type    = if ($types[[string]$f['LogonType']]) { $types[[string]$f['LogonType']] } else { [string]$f['LogonType'] }
                    via     = (@([string]$f['AuthenticationPackageName'], ([string]$f['ProcessName'] -split '\\')[-1]) | Where-Object { $_ -and $_ -ne '-' }) -join ', '
                    machine = [string]$f['WorkstationName']
                }
            }
            $report.failed_logons.top = @($rows | Group-Object account, source, reason | Sort-Object Count -Descending |
                Select-Object -First 5 | ForEach-Object {
                    $g = $_.Group[0]
                    [ordered]@{ account = $g.account; source = $g.source; count = $_.Count; reason = $g.reason; type = $g.type; via = $g.via
                                machine = if ($g.machine -and $g.machine -ne '-' -and $g.machine -ne $g.source) { $g.machine } else { '' } }
                })
        }
    } catch { Add-CollectorError 'failed-logons' $_ }
    return $report
}

function Get-AdsProperty($Object, [string]$Name) {
    try { return $Object.GetType().InvokeMember($Name, 'GetProperty', $null, $Object, $null) } catch { return $null }
}

function Get-AdminGroupMembers([string]$Machine) {
    # The built-in Administrators group is found by its well-known SID, so non-English Windows
    # works too; on a domain controller it's the domain's built-in Administrators group.
    $gname = (New-Object Security.Principal.SecurityIdentifier 'S-1-5-32-544').Translate([Security.Principal.NTAccount]).Value.Split('\')[-1]
    $group = [ADSI]"WinNT://$Machine/$gname,group"
    foreach ($m in @($group.psbase.Invoke('Members'))) {
        $sid = ''
        $bytes = Get-AdsProperty $m 'objectSid'
        if ($bytes) { try { $sid = (New-Object Security.Principal.SecurityIdentifier($bytes, 0)).Value } catch { } }
        [pscustomobject]@{ path = [string](Get-AdsProperty $m 'ADsPath'); class = [string](Get-AdsProperty $m 'Class'); sid = $sid
            flags = Get-AdsProperty $m 'UserFlags' }
    }
}

function Get-LocalAdmins {
    # Direct members of the Administrators group. Groups inside it are listed, not expanded.
    $machine = if ($env:COMPUTERNAME) { $env:COMPUTERNAME } else { [Environment]::MachineName }
    $list = @()
    foreach ($m in @(Get-AdminGroupMembers $machine)) {
        $parts = @(($m.path -replace '^WinNT://', '').Split('/') | Where-Object { $_ })
        $sid = [string]$m.sid
        $domain = ''; $name = ''
        if ($parts.Count -ge 3) { $domain = $parts[-2]; $name = $parts[-1] }
        elseif ($parts.Count -eq 2) { $domain = $parts[0]; $name = $parts[1] }
        elseif ($parts.Count -eq 1) { $name = $parts[0] }
        if (-not $sid -and $name -match '^S-1-\d') { $sid = $name }
        $source = 'Domain'
        if ($name -match '^S-1-\d') {
            # Windows couldn't name it: an Azure AD (Entra ID) account or group, or one that's been deleted
            $source = if ($name -like 'S-1-12-1-*') { 'Azure AD' } else { 'Unknown (deleted?)' }
            try { $n = (New-Object Security.Principal.SecurityIdentifier $name).Translate([Security.Principal.NTAccount]).Value; $domain, $name = $n.Split('\', 2) } catch { }
        }
        elseif ($domain -eq $machine) { $source = 'Local' }
        elseif ($domain -in 'NT AUTHORITY', 'BUILTIN', 'NT SERVICE') { $source = 'Built-in' }
        elseif ($domain -eq 'AzureAD') { $source = 'Azure AD' }
        $type = switch ($m.class) { 'User' { 'user' } 'Group' { 'group' } '' { 'unknown' } default { ([string]$m.class).ToLower() } }
        $disabled = $null
        if ($source -eq 'Local' -and $type -eq 'user' -and $null -ne $m.flags) { $disabled = [bool]([int]$m.flags -band 2) }
        $list += [ordered]@{
            account  = if ($domain) { "$domain\$name" } else { $name }
            name     = $name
            domain   = $domain
            type     = $type
            source   = $source
            sid      = $sid
            disabled = $disabled
            builtin  = ($sid -match '^S-1-5-21-.+-500$')
        }
        if ($list.Count -ge 200) { break }
    }
    return $list
}

function ConvertTo-IdleMinutes([string]$Idle) {
    # quser's idle time: "none" or ".", minutes, h:mm, or d+h:mm
    if ($Idle -match '^(\d+)\+(\d+):(\d+)$') { return [int]$Matches[1] * 1440 + [int]$Matches[2] * 60 + [int]$Matches[3] }
    if ($Idle -match '^(\d+):(\d+)$') { return [int]$Matches[1] * 60 + [int]$Matches[2] }
    if ($Idle -match '^\d+$') { return [int]$Idle }
    return 0
}

function Get-SignedInUsers {
    # Who is signed in: the console and every Remote Desktop session (quser), disconnected ones included.
    # Windows Home has no quser, so fall back to the console user.
    $out = New-Object System.Collections.Generic.List[object]
    $console = ''
    try { $console = [string](Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop).UserName } catch { }
    $quser = Join-Path $env:SystemRoot 'System32\quser.exe'
    $lines = @()
    if (Test-Path $quser) { try { $lines = @(& $quser 2>$null) } catch { } }
    foreach ($l in ($lines | Select-Object -Skip 1)) {
        # USERNAME  SESSIONNAME  ID  STATE  IDLE TIME  LOGON TIME; disconnected sessions have no session name
        if ($l -notmatch '^.(\S+)\s+(?:(\S+)\s+)?(\d+)\s+(\S+)\s+(\S+)\s+(.+?)\s*$') { continue }
        $user, $sess, $state, $idle, $logon = $Matches[1], [string]$Matches[2], $Matches[4], $Matches[5], $Matches[6]
        if ($console -and $console.Split('\')[-1] -ieq $user) { $user = $console }
        $since = ''
        try { $since = ConvertTo-UtcString ([datetime]::Parse($logon, [Globalization.CultureInfo]::CurrentCulture)) } catch { }
        $out.Add([ordered]@{
            user = Limit-Text $user 80
            session = $(if ($sess -match '^console$') { 'console' } elseif ($sess -match '^rdp') { 'rdp' } elseif ($sess) { Limit-Text $sess.ToLower() 30 } else { '' })
            state = $(if ($state -match '^(Active|Aktiv|Actif|Activo|Attivo|Actief|Ativo|Aktywny)') { 'active' } else { 'disconnected' })
            idle_min = ConvertTo-IdleMinutes $idle; since = $since; from = ''
        })
        if ($out.Count -ge 50) { break }
    }
    if (-not $out.Count -and $console) {
        $out.Add([ordered]@{ user = Limit-Text $console 80; session = 'console'; state = 'active'; idle_min = 0; since = ''; from = '' })
    }
    return $out.ToArray()
}

function Get-InstalledApps {
    # Installed programs as "Apps & features" lists them: the Uninstall keys for the machine (64- and 32-bit)
    # and for each signed-in user. Not Win32_Product, which is slow and can make MSI packages repair themselves.
    $sources = New-Object System.Collections.Generic.List[object]
    $sources.Add(@{ path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'; arch = $(if ([Environment]::Is64BitOperatingSystem) { 'x64' } else { 'x86' }); scope = 'machine' })
    if ([Environment]::Is64BitOperatingSystem) { $sources.Add(@{ path = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'; arch = 'x86'; scope = 'machine' }) }
    try {
        foreach ($u in @(Get-ChildItem -Path 'Registry::HKEY_USERS' -ErrorAction Stop | Where-Object { $_.PSChildName -match '^S-1-5-21-[\d-]+$' })) {
            $sources.Add(@{ path = "Registry::HKEY_USERS\$($u.PSChildName)\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"; arch = ''; scope = 'user' })
        }
    } catch { }
    $seen = @{}
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($src in $sources) {
        foreach ($k in @(Get-ItemProperty -Path $src.path -ErrorAction SilentlyContinue)) {
            $name = ([string]$k.DisplayName).Trim()
            if (-not $name -or $k.SystemComponent -eq 1 -or $k.ParentKeyName -or [string]$k.ReleaseType -match 'Update|Hotfix') { continue }
            $ver = ([string]$k.DisplayVersion).Trim()
            $id = ('{0}|{1}|{2}' -f $name, $ver, $src.arch).ToLowerInvariant()
            if ($seen.ContainsKey($id)) { continue }
            $seen[$id] = $true
            $date = ''
            if ([string]$k.InstallDate -match '^(\d{4})(\d\d)(\d\d)$') { $date = '{0}-{1}-{2}' -f $Matches[1], $Matches[2], $Matches[3] }
            $size = 0
            try { if ($k.EstimatedSize) { $size = [math]::Round([double]$k.EstimatedSize / 1024, 1) } } catch { }
            $out.Add([ordered]@{
                name = Limit-Text $name 150; version = Limit-Text $ver 60; publisher = Limit-Text ([string]$k.Publisher).Trim() 100
                installed = $date; size_mb = $size; arch = $src.arch; scope = $src.scope
                code = Limit-Text ([string]$k.PSChildName) 100  # the Uninstall key name: an MSI product code, or what winget matches on
            })
            if ($out.Count -ge 2000) { break }
        }
    }
    return @($out.ToArray() | Sort-Object { $_.name }, { $_.version })
}

function Get-AppsHash($Apps) {
    # A fingerprint of the list, so it's only sent when something changes
    $text = (@($Apps | ForEach-Object { '{0}|{1}|{2}|{3}|{4}|{5}' -f $_.name, $_.version, $_.publisher, $_.arch, $_.scope, $_.code }) -join "`n")
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($text))) -replace '-', '').Substring(0, 32).ToLower() } finally { $sha.Dispose() }
}

function Get-NetworkReport {
    # Every visible network adapter: status, link speed, addresses and traffic counters.
    # Get-NetAdapter is Windows 8 / Server 2012 and later; older systems fall back to WMI.
    $out = New-Object System.Collections.Generic.List[object]
    $ips = @{}
    try {
        foreach ($a in @(Get-NetIPAddress -ErrorAction Stop | Where-Object { $_.IPAddress -notlike 'fe80*' -and $_.IPAddress -ne '127.0.0.1' -and $_.IPAddress -ne '::1' })) {
            $k = [int]$a.InterfaceIndex
            if (-not $ips.ContainsKey($k)) { $ips[$k] = New-Object System.Collections.Generic.List[string] }
            if ($ips[$k].Count -lt 8) { $ips[$k].Add(('{0}/{1}' -f $a.IPAddress, $a.PrefixLength)) }
        }
    } catch { }
    $adapters = $null
    try { $adapters = @(Get-NetAdapter -ErrorAction Stop) } catch { }
    if ($null -ne $adapters) {
        $stats = @{}
        try { foreach ($x in @(Get-NetAdapterStatistics -ErrorAction Stop)) { $stats[[string]$x.Name] = $x } } catch { }
        foreach ($a in ($adapters | Sort-Object ifIndex | Select-Object -First 40)) {
            $status = switch ([string]$a.Status) { 'Up' { 'up' } 'Disabled' { 'disabled' } 'Not Present' { 'notpresent' } default { 'down' } }
            $x = $stats[[string]$a.Name]
            $speed = 0
            if ($status -eq 'up' -and $a.Speed -and [double]$a.Speed -lt 1e13) { $speed = [int64][math]::Round([double]$a.Speed / 1e6) }
            $row = [ordered]@{
                name = Limit-Text ([string]$a.Name) 80; desc = Limit-Text ([string]$a.InterfaceDescription) 120
                status = $status; speed_mbps = $speed; mac = ([string]$a.MacAddress).Replace('-', ':')
                virtual = -not [bool]$a.HardwareInterface; media = [string]$a.MediaType
                ips = @(if ($ips.ContainsKey([int]$a.ifIndex)) { $ips[[int]$a.ifIndex].ToArray() })
            }
            if ($x) {
                $row.rx_bytes = [int64]$x.ReceivedBytes; $row.tx_bytes = [int64]$x.SentBytes
                $row.rx_errors = [int64]$x.ReceivedPacketErrors; $row.tx_errors = [int64]$x.OutboundPacketErrors
                $row.rx_drops = [int64]$x.ReceivedDiscardedPackets; $row.tx_drops = [int64]$x.OutboundDiscardedPackets
            }
            $out.Add($row)
        }
    } else {
        foreach ($a in @(Get-CimInstance -ClassName Win32_NetworkAdapter -Filter 'NetConnectionID IS NOT NULL' -ErrorAction Stop | Select-Object -First 40)) {
            $n = [int]$a.NetConnectionStatus
            $status = if ($a.NetEnabled -eq $false -and $n -ne 4) { 'disabled' } elseif ($n -eq 2) { 'up' } elseif ($n -eq 4) { 'notpresent' } else { 'down' }
            $out.Add([ordered]@{
                name = Limit-Text ([string]$a.NetConnectionID) 80; desc = Limit-Text ([string]$a.Name) 120; status = $status
                speed_mbps = $(if ($status -eq 'up' -and $a.Speed -and [double]$a.Speed -lt 1e13) { [int64][math]::Round([double]$a.Speed / 1e6) } else { 0 })
                mac = [string]$a.MACAddress; virtual = -not [bool]$a.PhysicalAdapter; media = ''
                ips = @(if ($ips.ContainsKey([int]$a.InterfaceIndex)) { $ips[[int]$a.InterfaceIndex].ToArray() })
            })
        }
    }
    return [ordered]@{ adapters = $out.ToArray() }
}

function Get-BitLockerStatus {
    # BitLocker state of each fixed drive, from WMI (works without the BitLocker PowerShell module).
    # Reads states and which kinds of key protector exist; never the keys or recovery passwords themselves.
    $vols = $null
    try { $vols = @(Get-CimInstance -Namespace 'root\cimv2\Security\MicrosoftVolumeEncryption' -ClassName Win32_EncryptableVolume -ErrorAction Stop) }
    catch { return $null }  # BitLocker isn't installed here (a server without the feature)
    $methods = @{ 1 = 'AES 128 with Diffuser'; 2 = 'AES 256 with Diffuser'; 3 = 'AES 128'; 4 = 'AES 256'; 5 = 'Hardware encryption'; 6 = 'XTS-AES 128'; 7 = 'XTS-AES 256' }
    $kinds = @{ 1 = 'TPM'; 2 = 'External key'; 3 = 'Recovery password'; 4 = 'TPM and PIN'; 5 = 'TPM and startup key'; 6 = 'TPM, PIN and startup key'
        7 = 'Certificate'; 8 = 'Password'; 9 = 'TPM certificate'; 10 = 'Active Directory account' }
    $states = @('decrypted', 'encrypted', 'encrypting', 'decrypting', 'encrypting_paused', 'decrypting_paused')
    $list = New-Object System.Collections.Generic.List[object]
    foreach ($v in $vols) {
        $type = [int]$v.VolumeType
        if (-not $v.DriveLetter -or $type -eq 2) { continue }  # no letter, or removable (BitLocker To Go)
        $conv = [int]$v.ConversionStatus
        $pct = $null
        try {
            $cs = Invoke-CimMethod -InputObject $v -MethodName GetConversionStatus -ErrorAction Stop
            if ([int]$cs.ReturnValue -eq 0) { $conv = [int]$cs.ConversionStatus; $pct = [int]$cs.EncryptionPercentage }
        } catch { }
        $prot = New-Object System.Collections.Generic.List[string]
        try {
            $kp = Invoke-CimMethod -InputObject $v -MethodName GetKeyProtectors -Arguments @{ KeyProtectorType = [uint32]0 } -ErrorAction Stop
            foreach ($id in @($kp.VolumeKeyProtectorID)) {
                if (-not $id) { continue }
                $t = Invoke-CimMethod -InputObject $v -MethodName GetKeyProtectorType -Arguments @{ VolumeKeyProtectorID = [string]$id } -ErrorAction Stop
                $n = $kinds[[int]$t.KeyProtectorType]
                if ($n -and -not $prot.Contains($n)) { $prot.Add($n) }
            }
        } catch { }
        $locked = $null
        try {
            $ls = Invoke-CimMethod -InputObject $v -MethodName GetLockStatus -ErrorAction Stop
            if ([int]$ls.ReturnValue -eq 0) { $locked = ([int]$ls.LockStatus -eq 1) }
        } catch { }
        $ps = [int]$v.ProtectionStatus
        $list.Add([ordered]@{
            drive      = ([string]$v.DriveLetter).ToUpper()
            kind       = if ($type -eq 0) { 'os' } else { 'data' }
            protection = if ($ps -eq 1) { 'on' } elseif ($ps -eq 0) { 'off' } else { 'unknown' }
            status     = if ($conv -ge 0 -and $conv -lt $states.Count) { $states[$conv] } else { 'unknown' }
            percent    = $pct
            method     = [string]$methods[[int]$v.EncryptionMethod]
            protectors = @($prot)
            locked     = $locked
        })
        if ($list.Count -ge 26) { break }
    }
    return [ordered]@{ volumes = @($list | Sort-Object { $_.kind -ne 'os' }, { $_.drive }); tpm = Get-TpmInfo }
}

function Get-TpmInfo {
    # Whether this computer has a TPM that Windows can use. No instance means no TPM (or it's turned off
    # in the firmware); an error means it couldn't be checked, which is left as unknown.
    $t = $null
    try { $t = @(Get-CimInstance -Namespace 'root\cimv2\Security\MicrosoftTpm' -ClassName Win32_Tpm -ErrorAction Stop) | Select-Object -First 1 }
    catch { return [ordered]@{ present = $null } }
    if (-not $t) { return [ordered]@{ present = $false } }
    $ver = ([string]$t.SpecVersion -split ',')[0].Trim()
    return [ordered]@{
        present   = $true
        version   = Limit-Text $ver 10
        enabled   = if ($null -ne $t.IsEnabled_InitialValue) { [bool]$t.IsEnabled_InitialValue } else { $null }
        activated = if ($null -ne $t.IsActivated_InitialValue) { [bool]$t.IsActivated_InitialValue } else { $null }
        maker     = Limit-Text ([string]$t.ManufacturerIdTxt).Trim() 20
    }
}

function Get-StoreCerts([string]$Store) {
    @(Get-ChildItem -Path "Cert:\LocalMachine\$Store" -ErrorAction Stop)
}

function Get-CertBindings {
    # Thumbprints of certificates in use: HTTP.sys bindings (IIS, RD Gateway, WinRM HTTPS, ADFS...)
    # and the Remote Desktop listener. Lower-case hex, no spaces.
    $map = @{}
    try {
        $out = & netsh.exe http show sslcert 2>$null
        $where = ''
        foreach ($line in $out) {
            # The labels are in the system's language, so go by the values: an address:port, then a 40-hex hash
            if ($line -match '^\s*\S.*?\s+:\s*((?:\d{1,3}\.){3}\d{1,3}:\d+|\[[0-9a-fA-F:]+\]:\d+|[A-Za-z0-9.*_-]+:\d+)\s*$') { $where = $Matches[1] }
            elseif ($line -match '^\s*\S.*?\s+:\s*([0-9a-fA-F]{40})\s*$') {
                $t = $Matches[1].ToLower()
                if (-not $map[$t]) { $map[$t] = New-Object System.Collections.Generic.List[string] }
                if ($where -and $map[$t].Count -lt 4) { $map[$t].Add("HTTPS $where") }
            }
        }
    } catch { }
    try {
        $ts = Get-CimInstance -Namespace 'root\cimv2\TerminalServices' -ClassName Win32_TSGeneralSetting -Filter "TerminalName='RDP-Tcp'" -ErrorAction Stop
        $t = ([string]$ts.SSLCertificateSHA1Hash).ToLower()
        if ($t -match '^[0-9a-f]{40}$') {
            if (-not $map[$t]) { $map[$t] = New-Object System.Collections.Generic.List[string] }
            $map[$t].Add('Remote Desktop')
        }
    } catch { }
    return $map
}

function Get-CertificateReport {
    # Certificates with a private key in the computer's Personal, Remote Desktop and Web Hosting stores:
    # what they're for and when they expire. Never exports a key.
    $bind = Get-CertBindings
    $list = New-Object System.Collections.Generic.List[object]
    foreach ($store in 'My', 'Remote Desktop', 'WebHosting') {
        $certs = @()
        try { $certs = Get-StoreCerts $store } catch { continue }
        foreach ($c in $certs) {
            if (-not $c.HasPrivateKey) { continue }
            $self = $c.Subject -eq $c.Issuer
            if ($store -eq 'Remote Desktop' -and $self) { continue }  # Windows makes and renews these itself
            $t = ([string]$c.Thumbprint).ToLower()
            $tpl = ''
            foreach ($e in @($c.Extensions)) {
                if ($e.Oid.Value -in '1.3.6.1.4.1.311.21.7', '1.3.6.1.4.1.311.20.2') {
                    $f = $e.Format($false)
                    $tpl = if ($f -match 'Template=([^(,]+)') { $Matches[1].Trim() } else { $f.Trim() }
                    break
                }
            }
            $dns = @()
            try { $dns = @($c.DnsNameList | ForEach-Object { [string]$_.Unicode } | Select-Object -First 6) } catch { }
            $list.Add([ordered]@{
                thumbprint = $t
                store      = $store
                subject    = Limit-Text ($c.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)) 120
                issuer     = Limit-Text ($c.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $true)) 120
                names      = @($dns)
                not_before = ConvertTo-UtcString $c.NotBefore
                not_after  = ConvertTo-UtcString $c.NotAfter
                self_signed = $self
                template   = Limit-Text $tpl 80
                used_by    = @(if ($bind[$t]) { $bind[$t] })
            })
            if ($list.Count -ge 60) { break }
        }
    }
    return [ordered]@{ certs = $list.ToArray() }  # @() of an empty List fails inside a hashtable literal
}

function Get-TaskReport {
    # Scheduled tasks outside \Microsoft\ (yours, and other vendors'): when each last ran, its result and
    # when it's next due. The server decides which ones alert.
    $kinds = @{ MSFT_TaskDailyTrigger = 'daily'; MSFT_TaskWeeklyTrigger = 'weekly'; MSFT_TaskMonthlyTrigger = 'monthly'
        MSFT_TaskMonthlyDOWTrigger = 'monthly'; MSFT_TaskTimeTrigger = 'time'; MSFT_TaskBootTrigger = 'startup'; MSFT_TaskLogonTrigger = 'logon'
        MSFT_TaskEventTrigger = 'event'; MSFT_TaskIdleTrigger = 'idle'; MSFT_TaskSessionStateChangeTrigger = 'session'; MSFT_TaskRegistrationTrigger = 'registration' }
    $all = @(Get-ScheduledTask -ErrorAction Stop | Where-Object { $_.TaskPath -notlike '\Microsoft\*' })
    $list = New-Object System.Collections.Generic.List[object]
    foreach ($t in $all) {
        if ($list.Count -ge 80) { break }
        $info = $null
        try { $info = Get-ScheduledTaskInfo -InputObject $t -ErrorAction Stop } catch { }
        $last = if ($info -and $info.LastRunTime -and ([DateTime]$info.LastRunTime).Year -gt 2000) { ConvertTo-UtcString $info.LastRunTime } else { $null }
        $next = if ($info -and $info.NextRunTime -and ([DateTime]$info.NextRunTime).Year -gt 2000) { ConvertTo-UtcString $info.NextRunTime } else { $null }
        $trig = @(@($t.Triggers) | Where-Object { $_ -and $_.Enabled -ne $false } | ForEach-Object {
            $k = $kinds[[string]$_.CimClass.CimClassName]; if ($k) { $k } else { 'other' } } | Select-Object -Unique)
        $user = ''
        try { $user = [string]$t.Principal.UserId; if (-not $user) { $user = [string]$t.Principal.GroupId } } catch { }
        $action = ''
        try { $a = @($t.Actions)[0]; if ($a.Execute) { $action = (Split-Path -Leaf ([string]$a.Execute).Trim('"')) } } catch { }
        $list.Add([ordered]@{
            name     = Limit-Text ([string]$t.TaskName) 120
            path     = Limit-Text ([string]$t.TaskPath) 120
            state    = [string]$t.State
            last_run = $last
            result   = if ($info -and $null -ne $info.LastTaskResult) { [int64][uint32]$info.LastTaskResult } else { $null }
            next_run = $next
            missed   = if ($info -and $null -ne $info.NumberOfMissedRuns) { [int]$info.NumberOfMissedRuns } else { $null }
            triggers = @($trig)
            run_as   = Limit-Text $user 80
            action   = Limit-Text $action 80
            author   = Limit-Text ([string]$t.Author) 80
        })
    }
    return [ordered]@{ tasks = $list.ToArray(); total = $all.Count }
}

function Invoke-SqlQuery([string]$Instance, [string]$Query, [int]$Timeout = 15) {
    # One query against a local SQL Server instance as this computer's account (SYSTEM). Rows as ordered hashtables.
    $cn = [System.Data.SqlClient.SqlConnection]::new("Server=$Instance;Database=master;Integrated Security=SSPI;Connect Timeout=5;Application Name=Rollcall agent")
    try {
        $cn.Open()
        $cmd = $cn.CreateCommand(); $cmd.CommandText = $Query; $cmd.CommandTimeout = $Timeout
        $rd = $cmd.ExecuteReader()
        $rows = New-Object System.Collections.Generic.List[object]
        while ($rd.Read()) {
            $h = [ordered]@{}
            for ($i = 0; $i -lt $rd.FieldCount; $i++) { $v = $rd.GetValue($i); $h[$rd.GetName($i)] = if ($v -is [DBNull]) { $null } else { $v } }
            $rows.Add($h)
        }
        $rd.Close()
        return $rows.ToArray()  # callers wrap this in @(), so one row or none still makes a list
    } finally { $cn.Dispose() }
}

function Get-SqlReport($AllServices) {
    # Each running SQL Server instance: databases and their state, backups, log use and SQL Agent jobs.
    # Each part is tried on its own, so a missing permission only loses that part (and says so).
    $names = @($AllServices | Where-Object { $_.State -eq 'Running' -and ($_.Name -eq 'MSSQLSERVER' -or $_.Name -like 'MSSQL$*') } | ForEach-Object { $_.Name } | Sort-Object | Select-Object -First 8)
    if (-not $names.Count) { return $null }
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($svc in $names) {
        $inst = if ($svc -eq 'MSSQLSERVER') { '.' } else { '.\' + $svc.Substring(6) }
        $label = if ($svc -eq 'MSSQLSERVER') { 'MSSQLSERVER' } else { $svc.Substring(6) }
        # Windows Internal Database (WSUS, AD FS, RD Connection Broker, IPAM) only listens on a local pipe
        $internal = $label -like 'MICROSOFT##*'
        if ($label -eq 'MICROSOFT##WID') { $inst = 'np:\\.\pipe\MICROSOFT##WID\tsql\query' }
        elseif ($label -eq 'MICROSOFT##SSEE') { $inst = 'np:\\.\pipe\MSSQL$MICROSOFT##SSEE\sql\query' }
        $i = [ordered]@{ instance = $label; internal = $internal; denied = @(); errors = @() }
        $fail = { param($part, $err) $m = Limit-Text ([string]$err.Exception.InnerException.Message + [string]$(if (-not $err.Exception.InnerException) { $err.Exception.Message })) 200
            if ($m -match 'permission|denied|not able to access|Login failed') { $i.denied += $part } else { $i.errors += "${part}: $m" } }
        try {
            $v = @(Invoke-SqlQuery $inst "SELECT CAST(SERVERPROPERTY('ProductVersion') AS nvarchar(40)) AS version, CAST(SERVERPROPERTY('Edition') AS nvarchar(80)) AS edition, CAST(SERVERPROPERTY('ProductLevel') AS nvarchar(20)) AS level, SUSER_SNAME() AS login")[0]
            $i.version = [string]$v.version; $i.edition = [string]$v.edition; $i.level = [string]$v.level; $i.login = [string]$v.login
        } catch {
            $m = Limit-Text ([string]$_.Exception.Message) 200
            $i.connect_error = $m
            $out.Add($i); continue
        }
        try {
            $i.databases = @(Invoke-SqlQuery $inst @"
SELECT name, state_desc AS state, recovery_model_desc AS recovery, is_read_only AS read_only, log_reuse_wait_desc AS log_wait,
       create_date AS created, CASE WHEN source_database_id IS NULL THEN 0 ELSE 1 END AS snapshot, database_id AS id
FROM sys.databases WHERE name <> 'tempdb' ORDER BY name
"@ | Select-Object -First 100 | ForEach-Object { [ordered]@{ name = [string]$_.name; state = [string]$_.state; recovery = [string]$_.recovery
                read_only = [bool]$_.read_only; log_wait = [string]$_.log_wait; created = ConvertTo-UtcString $_.created; snapshot = [bool]$_.snapshot; system = ([int]$_.id -le 4) } })
        } catch { & $fail 'databases' $_ }
        try {
            $ag = @(Invoke-SqlQuery $inst "SELECT d.name, sys.fn_hadr_backup_is_preferred_replica(d.name) AS preferred FROM sys.databases d WHERE d.replica_id IS NOT NULL")
            foreach ($r in $ag) { foreach ($d in @($i.databases)) { if ($d.name -eq $r.name) { $d.ag = $true; $d.ag_preferred = [bool]$r.preferred } } }
        } catch { }  # before SQL Server 2012, or no availability groups
        try {
            $bk = @(Invoke-SqlQuery $inst @"
SELECT database_name AS db, type, MAX(backup_finish_date) AS finished FROM msdb.dbo.backupset
WHERE type IN ('D', 'I', 'L') AND backup_finish_date > DATEADD(day, -35, GETDATE()) GROUP BY database_name, type
"@)
            foreach ($d in @($i.databases)) {
                foreach ($r in $bk | Where-Object { $_.db -eq $d.name }) {
                    $k = @{ D = 'last_full'; I = 'last_diff'; L = 'last_log' }[[string]$r.type]
                    if ($k) { $d[$k] = ConvertTo-UtcString $r.finished }  # SQL Server's times are this computer's local time
                }
            }
            $i.backups_read = $true
        } catch { & $fail 'backups' $_ }
        try {
            $ls = @(Invoke-SqlQuery $inst 'DBCC SQLPERF(LOGSPACE) WITH NO_INFOMSGS')
            foreach ($d in @($i.databases)) {
                $r = $ls | Where-Object { $_['Database Name'] -eq $d.name } | Select-Object -First 1
                if ($r) { $d.log_mb = [math]::Round([double]$r['Log Size (MB)'], 1); $d.log_used_pct = [math]::Round([double]$r['Log Space Used (%)'], 1) }
            }
        } catch { & $fail 'log space' $_ }
        if ($i.edition -notlike 'Express*' -and -not $internal) {  # no SQL Agent in Express or WID
            try {
                $i.jobs = @(Invoke-SqlQuery $inst @"
SELECT j.name, j.enabled, h.run_status, h.run_date, h.run_time, LEFT(h.message, 300) AS message
FROM msdb.dbo.sysjobs j
OUTER APPLY (SELECT TOP 1 run_status, run_date, run_time, message FROM msdb.dbo.sysjobhistory WHERE job_id = j.job_id AND step_id = 0 ORDER BY instance_id DESC) h
ORDER BY j.name
"@ | Select-Object -First 60 | ForEach-Object {
                    $when = $null
                    if ($_.run_date) { try { $when = ConvertTo-UtcString ([datetime]::ParseExact(('{0:D8}{1:D6}' -f [int]$_.run_date, [int]$_.run_time), 'yyyyMMddHHmmss', $null)) } catch { } }
                    [ordered]@{ name = Limit-Text ([string]$_.name) 120; enabled = [bool]$_.enabled; outcome = @{ 0 = 'failed'; 1 = 'succeeded'; 2 = 'retry'; 3 = 'cancelled'; 4 = 'running' }[[int]$(if ($null -ne $_.run_status) { $_.run_status } else { -1 })]
                        last_run = $when; message = Limit-Text ([string]$_.message) 300 } })
            } catch { & $fail 'jobs' $_ }
        }
        $out.Add($i)
    }
    return [ordered]@{ instances = $out.ToArray() }
}

function Get-LogEvents([string]$Log, [string]$Provider, [int[]]$Ids, [DateTime]$Since, [int]$Max = 200) {
    $f = @{ LogName = $Log; StartTime = $Since }
    if ($Provider) { $f.ProviderName = $Provider }
    if ($Ids) { $f.Id = $Ids }
    try { @(Get-WinEvent -FilterHashtable $f -MaxEvents $Max -ErrorAction Stop) }
    catch {
        # "No events found" is an error in Get-WinEvent; its message is in the system's language, so go by its ID
        if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*' -or $_.Exception.Message -match 'No events were found|specified query') { @() } else { throw }
    }
}

function Get-GroupPolicyStatus {
    # Group Policy's own results in the System log over the last 24 hours: when it last applied, and failures since.
    $ok = 1500, 1501, 1502, 1503
    $ev = @(Get-LogEvents 'System' 'Microsoft-Windows-GroupPolicy' $null (Get-Date).AddHours(-24) 300)
    $succ = @($ev | Where-Object { $ok -contains $_.Id } | Sort-Object TimeCreated -Descending)
    $errs = @($ev | Where-Object { $ok -notcontains $_.Id -and [int]$_.Level -in 1, 2, 3 } | Sort-Object TimeCreated -Descending)
    $first = { param($e) $m = ([string]$e.Message -split "`r?`n" | Where-Object { $_.Trim() } | Select-Object -First 2) -join ' '; Limit-Text $m 300 }
    return [ordered]@{
        last_success          = if ($succ.Count) { ConvertTo-UtcString $succ[0].TimeCreated } else { $null }
        last_computer_success = ConvertTo-UtcString (@($succ | Where-Object { $_.Id -in 1500, 1502 } | Select-Object -First 1).TimeCreated)
        failures              = @($errs | Select-Object -First 10 | ForEach-Object {
            [ordered]@{ id = [int]$_.Id; time = ConvertTo-UtcString $_.TimeCreated; level = [int]$_.Level; message = & $first $_ } })
        failures_24h          = $errs.Count
    }
}

function Get-SysvolStatus {
    # SYSVOL replication on a domain controller: DFS-R's state for the SYSVOL folder, the DFS-R events
    # that mean replication has stopped or a partner can't be reached, and whether it still uses FRS.
    $out = [ordered]@{}
    try {
        $mig = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\DFSR\Parameters\SysVols\Migrating SysVols' -ErrorAction Stop
        $out.frs_migration = [int]$mig.'Local State'  # 3 = FRS eliminated
    } catch { }
    try {
        $rf = @(Get-CimInstance -Namespace 'root\MicrosoftDFS' -ClassName DfsrReplicatedFolderInfo -ErrorAction Stop | Where-Object { $_.ReplicatedFolderName -eq 'SYSVOL Share' }) | Select-Object -First 1
        if ($rf) { $out.state = [int]$rf.State }
    } catch { $out.wmi_error = Limit-Text ([string]$_.Exception.Message) 160 }
    try {
        $out.frs_running = ((Get-Service -Name NtFrs -ErrorAction Stop).Status -eq 'Running')
    } catch { $out.frs_running = $false }
    $ids = 2212, 2213, 2214, 4012, 4602, 4604, 4614, 5002, 5004, 5008, 5014
    $ev = @(Get-LogEvents 'DFS Replication' $null $ids (Get-Date).AddDays(-7) 200)
    $out.events = @($ev | Sort-Object TimeCreated -Descending | Select-Object -First 40 | ForEach-Object {
        $partner = ''
        if ([string]$_.Message -match '(?im)^\s*(Partner|Connected Partner|Partner DNS Address|Partner Name)\s*:\s*(\S+)') { $partner = $Matches[2] }
        [ordered]@{ id = [int]$_.Id; time = ConvertTo-UtcString $_.TimeCreated; partner = Limit-Text $partner 120
            message = Limit-Text (([string]$_.Message -split "`r?`n" | Where-Object { $_.Trim() } | Select-Object -First 1) -join ' ') 240 } })
    return $out
}

function Get-DfsrStatus {
    # DFS Replication on a file server: DFS-R's state for each replicated folder (SYSVOL is checked
    # separately on domain controllers), and the events that mean replication has stopped, is
    # recovering its database (e.g. scanning the volume after an unclean shutdown) or can't reach a partner.
    $out = [ordered]@{ folders = @() }
    try {
        $out.folders = @(Get-CimInstance -Namespace 'root\MicrosoftDFS' -ClassName DfsrReplicatedFolderInfo -ErrorAction Stop |
            Where-Object { $_.ReplicatedFolderName -ne 'SYSVOL Share' } | Select-Object -First 100 | ForEach-Object {
                [ordered]@{ name = Limit-Text ([string]$_.ReplicatedFolderName) 120; group = Limit-Text ([string]$_.ReplicationGroupName) 120; state = [int]$_.State } })
    } catch { $out.wmi_error = Limit-Text ([string]$_.Exception.Message) 160 }
    try { $out.service = [string](Get-Service -Name DFSR -ErrorAction Stop).Status } catch { }
    if ($out.folders.Count -eq 0 -and -not $out.wmi_error) { return $null }   # only SYSVOL, or nothing set up yet
    $ids = 2104, 2212, 2213, 2214, 4012, 4602, 4604, 4614, 5002, 5004, 5008, 5014
    $ev = @(Get-LogEvents 'DFS Replication' $null $ids (Get-Date).AddDays(-7) 300)
    $out.events = @($ev | Sort-Object TimeCreated -Descending | Select-Object -First 40 | ForEach-Object {
        $partner = ''; $folder = ''; $volume = ''
        if ([string]$_.Message -match '(?im)^\s*(Partner|Connected Partner|Partner DNS Address|Partner Name)\s*:\s*(\S+)') { $partner = $Matches[2] }
        if ([string]$_.Message -match '(?im)^\s*Replicated Folder Name\s*:\s*(.+?)\s*$') { $folder = $Matches[1] }
        if ([string]$_.Message -match '(?im)^\s*Volume\s*:\s*(.+?)\s*$') { $volume = $Matches[1] }
        [ordered]@{ id = [int]$_.Id; time = ConvertTo-UtcString $_.TimeCreated; partner = Limit-Text $partner 120
            folder = Limit-Text $folder 120; volume = Limit-Text $volume 120
            message = Limit-Text (([string]$_.Message -split "`r?`n" | Where-Object { $_.Trim() } | Select-Object -First 1) -join ' ') 240 } })
    # Every other error and warning in the last 24 hours (e.g. 6404, a replicated folder's path can't be
    # reached), grouped by event ID, so problems it has no specific rule for still show.
    $other = @(Get-WinEventSafe @{ LogName = 'DFS Replication'; Level = 2, 3; StartTime = (Get-Date).AddHours(-24) } 500 |
        Where-Object { $ids -notcontains [int]$_.Id -and [string]$_.Message -notmatch 'SYSVOL Share|Domain System Volume' })
    $out.errors = @($other | Group-Object Id | ForEach-Object {
        $last = $_.Group | Sort-Object TimeCreated -Descending | Select-Object -First 1
        $folder = ''
        if ([string]$last.Message -match '(?im)^\s*Replicated Folder Name\s*:\s*(.+?)\s*$') { $folder = $Matches[1] }
        [ordered]@{ id = [int]$_.Name; level = [int]$last.Level; count = $_.Count; time = ConvertTo-UtcString $last.TimeCreated
            folder = Limit-Text $folder 120
            message = Limit-Text (([string]$last.Message -split "`r?`n" | Where-Object { $_.Trim() } | Select-Object -First 1) -join ' ') 240 }
    } | Sort-Object @{ Expression = { $_.level } }, @{ Expression = { $_.time }; Descending = $true } | Select-Object -First 20)  # errors first, newest first
    return $out
}

function Get-WinEventSafe([hashtable]$Filter, [int]$Max = 200) {
    # Get-WinEvent with "no events found" as an empty list rather than an error.
    try { @(Get-WinEvent -FilterHashtable $Filter -MaxEvents $Max -ErrorAction Stop) }
    catch { if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*' -or $_.Exception.Message -match 'No events were found|specified query') { @() } else { throw } }
}

function Get-TimeStatus([string]$Domain, [bool]$IsDc) {
    # This computer's clock against the domain: members against the DC they use, other DCs against the
    # PDC emulator (which the domain takes its time from). The PDC emulator itself reports where it syncs from.
    $out = [ordered]@{ role = 'member'; target = ''; offset_s = $null; error = ''; source = ''; type = '' }
    try { $out.type = [string](Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters' -ErrorAction Stop).Type } catch { }
    $src = @(Invoke-W32tm @('/query', '/source') | Where-Object { [string]$_ -match '\S' })
    if ($src.Count) { $out.source = Limit-Text ([string]$src[0]).Trim() 120 }
    if ($IsDc) {
        $out.role = 'dc'
        try { if (Test-IsPdc) { $out.role = 'pdc'; return $out } } catch { }
    }
    $dc = @(Invoke-Nltest (@("/dsgetdc:$Domain") + $(if ($IsDc) { @('/pdc') } else { @() })))
    $line = @($dc | Where-Object { [string]$_ -match '^\s*DC:\s*\\\\(\S+)' } | Select-Object -First 1)
    if ($line.Count -and [string]$line[0] -match '^\s*DC:\s*\\\\(\S+)') { $out.target = $Matches[1] }
    if (-not $out.target) { $out.error = "couldn't find a domain controller"; return $out }
    if ($out.target -replace '\..*$', '' -eq $env:COMPUTERNAME) { $out.error = 'this device is the domain controller it would compare with'; return $out }
    $chart = @(Invoke-W32tm @("/stripchart", "/computer:$($out.target)", '/samples:1', '/dataonly'))
    $hit = @($chart | Where-Object { [string]$_ -match ',\s*([+-]?\d+(?:[.,]\d+)?)s\s*$' } | Select-Object -First 1)
    if ($hit.Count -and [string]$hit[0] -match ',\s*([+-]?\d+(?:[.,]\d+)?)s\s*$') {
        $out.offset_s = [Math]::Round([double]($Matches[1] -replace ',', '.'), 3)
    } else {
        $e = @($chart | Where-Object { [string]$_ -match 'error|0x[0-9a-f]{8}' } | Select-Object -First 1)
        $out.error = if ($e.Count) { Limit-Text ([string]$e[0]).Trim() 160 } else { "no answer from $($out.target)" }
    }
    return $out
}

function Get-ExchangeCounters {
    # Transport queue lengths from Exchange's performance counters (no Exchange permissions needed).
    $names = @{ 'aggregate delivery queue length (all queues)' = 'delivery'; 'submission queue length' = 'submission'; 'poison queue length' = 'poison'
        'unreachable queue length' = 'unreachable'; 'retry remote delivery queue length' = 'retry' }
    $paths = @($names.Keys | ForEach-Object { "\MSExchangeTransport Queues(_total)\$_" })
    $out = [ordered]@{}
    $samples = @((Get-Counter -Counter $paths -ErrorAction SilentlyContinue).CounterSamples)
    foreach ($c in $samples) {
        $k = $names[($c.Path -split '\\')[-1].ToLower()]
        if ($k) { $out[$k] = [int][math]::Round($c.CookedValue) }
    }
    return $out
}

function Get-ExComponentStates {
    # Exchange records each server component's state in the registry: a value per requester
    # (Functional, Maintenance, Sidelined...), "state:timestamp", 0 = inactive. Inactive if any requester says so.
    $root = 'HKLM:\SOFTWARE\Microsoft\ExchangeServer\v15\ServerComponentStates'
    $list = New-Object System.Collections.Generic.List[object]
    foreach ($k in @(Get-ChildItem -Path $root -ErrorAction Stop)) {
        $vals = Get-ItemProperty -Path $k.PSPath -ErrorAction SilentlyContinue
        $inactive = @()
        foreach ($p in @($vals.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' })) {
            if ([string]$p.Value -match '^0:') { $inactive += $p.Name }
        }
        $list.Add([ordered]@{ name = [string]$k.PSChildName; active = (-not $inactive.Count); by = @($inactive) })
    }
    return $list.ToArray()
}

function Get-ExDatabaseCopies {
    # Database copies on this server, from the Exchange snap-in (needs the computer account to be allowed).
    Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn -ErrorAction Stop
    @(Get-MailboxDatabaseCopyStatus -Server $env:COMPUTERNAME -ErrorAction Stop | ForEach-Object {
        [ordered]@{ name = [string]$_.DatabaseName; status = [string]$_.Status; index = [string]$_.ContentIndexState
            copy_queue = [int]$_.CopyQueueLength; replay_queue = [int]$_.ReplayQueueLength; active = [bool]($_.ActiveCopy)
            message = Limit-Text ([string]$_.ErrorMessage) 200 } })
}

function Get-ExchangeReport($State) {
    $out = [ordered]@{}
    try { $out.queues = Get-ExchangeCounters } catch { $out.queues_error = Limit-Text ([string]$_.Exception.Message) 160 }
    try { $out.components = @(Get-ExComponentStates) } catch { }
    try {
        $ev = @(Get-LogEvents 'Application' 'MSExchangeTransport' @(15004, 15005, 15006, 15007) (Get-Date).AddDays(-2) 50)
        $out.back_pressure = @($ev | Sort-Object TimeCreated -Descending | Select-Object -First 10 | ForEach-Object {
            [ordered]@{ id = [int]$_.Id; time = ConvertTo-UtcString $_.TimeCreated
                message = Limit-Text (([string]$_.Message -split "`r?`n" | Where-Object { $_.Trim() } | Select-Object -First 1) -join ' ') 300 } })
    } catch { }
    # Database copies: the snap-in takes several seconds to load, so this runs every 15 minutes
    $nowTs = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    if (-not $State.exch_checked -or $nowTs - [int64]$State.exch_checked -ge 900) {
        try { $State.exch_dbs = (@{ ok = $true; dbs = @(Get-ExDatabaseCopies) } | ConvertTo-Json -Depth 4 -Compress) }
        catch { $State.exch_dbs = (@{ ok = $false; error = (Limit-Text ([string]$_.Exception.Message) 200) } | ConvertTo-Json -Compress) }
        $State.exch_checked = $nowTs
    }
    if ($State.exch_dbs) {
        try {
            $c = $State.exch_dbs | ConvertFrom-Json
            if ($c.ok) { $out.databases = @($c.dbs) } else { $out.databases_error = [string]$c.error }
            $out.databases_checked = ConvertTo-UtcString ([DateTimeOffset]::FromUnixTimeSeconds([int64]$State.exch_checked).LocalDateTime)
        } catch { }
    }
    return $out
}

function Test-IsPdc {
    # The domain-wide checks run on one DC only: the one holding the PDC emulator role.
    $d = [System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain()
    return ([string]$d.PdcRoleOwner.Name -split '\.')[0] -eq $env:COMPUTERNAME
}

function Find-AdObjects([string]$Filter, [string[]]$Props, [int]$Max = 200, [string]$Base = '') {
    # LDAP search of this domain as the computer's account. Rows as ordered hashtables (first value of each property).
    if (-not $Base) { $Base = ([ADSI]'LDAP://RootDSE').defaultNamingContext }
    $s = [System.DirectoryServices.DirectorySearcher]::new([ADSI]"LDAP://$Base", $Filter)
    $s.PageSize = 500; $s.SizeLimit = $Max
    foreach ($p in $Props) { [void]$s.PropertiesToLoad.Add($p) }
    $out = New-Object System.Collections.Generic.List[object]
    $res = $s.FindAll()
    try {
        foreach ($r in $res) {
            $h = [ordered]@{}
            foreach ($p in $Props) { $v = $r.Properties[$p.ToLower()]; $h[$p] = if ($v -and $v.Count) { $v[0] } else { $null } }
            $out.Add($h)
            if ($out.Count -ge $Max) { break }
        }
    } finally { $res.Dispose() }
    return $out.ToArray()
}

function Get-DomainSecurity($State) {
    # Once an hour, on the PDC emulator: privileged group members, KRBTGT's password age, and accounts worth reviewing.
    $nowTs = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    if ($State.ad_report -and $State.ad_checked -and $nowTs - [int64]$State.ad_checked -lt 3600) {
        if ($State.ad_report -eq 'not-pdc') { return $null }
        return ($State.ad_report | ConvertFrom-Json)
    }
    if (-not (Test-IsPdc)) { $State.ad_report = 'not-pdc'; $State.ad_checked = $nowTs; return $null }
    $ft = { param($v) if ($null -eq $v -or [int64]$v -le 0 -or [int64]$v -ge 9223372036854775807) { $null } else { ConvertTo-UtcString ([DateTime]::FromFileTimeUtc([int64]$v)) } }
    $acct = { param($o) [ordered]@{ name = [string]$o.sAMAccountName; kind = $(if ([string]$o.objectClass -eq 'group' -or "$($o.objectCategory)" -like 'CN=Group,*') { 'group' } elseif ("$($o.objectCategory)" -like 'CN=Computer,*') { 'computer' } else { 'user' })
        enabled = -not ([int]$o.userAccountControl -band 2); last_logon = & $ft $o.lastLogonTimestamp; pwd_set = & $ft $o.pwdLastSet } }
    $props = 'sAMAccountName', 'objectCategory', 'userAccountControl', 'lastLogonTimestamp', 'pwdLastSet', 'whenCreated', 'distinguishedName'
    $out = [ordered]@{ domain = ''; groups = @(); checked = ConvertTo-UtcString (Get-Date) }
    try { $out.domain = [string]([System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain()).Name } catch { }
    $names = 'Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators', 'Account Operators', 'Server Operators', 'Backup Operators', 'Print Operators', 'DnsAdmins', 'Group Policy Creator Owners'
    foreach ($g in $names) {
        $grp = @(Find-AdObjects "(&(objectClass=group)(sAMAccountName=$g))" @('distinguishedName') 1) | Select-Object -First 1
        if (-not $grp) { continue }
        $dn = ([string]$grp.distinguishedName).Replace('\', '\5c').Replace('(', '\28').Replace(')', '\29').Replace('*', '\2a')  # LDAP filter escaping
        $members = @(Find-AdObjects "(memberOf=$dn)" $props 100 | ForEach-Object { & $acct $_ })
        $out.groups += [ordered]@{ name = $g; members = $members }
    }
    $k = @(Find-AdObjects '(&(objectCategory=person)(objectClass=user)(sAMAccountName=krbtgt))' @('pwdLastSet') 1) | Select-Object -First 1
    if ($k) { $out.krbtgt_pwd_set = & $ft $k.pwdLastSet }
    $enabled = '(!(userAccountControl:1.2.840.113556.1.4.803:=2))'
    $out.never_expires = @(Find-AdObjects "(&(objectCategory=person)(objectClass=user)$enabled(userAccountControl:1.2.840.113556.1.4.803:=65536))" $props 200 | ForEach-Object { & $acct $_ })
    $out.no_password = @(Find-AdObjects "(&(objectCategory=person)(objectClass=user)$enabled(userAccountControl:1.2.840.113556.1.4.803:=32))" $props 100 | ForEach-Object { & $acct $_ })
    $cut = (Get-Date).AddDays(-90).ToFileTimeUtc()
    $created = (Get-Date).AddDays(-90).ToUniversalTime().ToString('yyyyMMddHHmmss.0Z')
    $stale = "(|(lastLogonTimestamp<=$cut)(&(!(lastLogonTimestamp=*))(whenCreated<=$created)))"
    $out.stale_users = @(Find-AdObjects "(&(objectCategory=person)(objectClass=user)$enabled$stale)" $props 200 | ForEach-Object { & $acct $_ })
    $out.stale_computers = @(Find-AdObjects "(&(objectCategory=computer)$enabled$stale)" $props 200 | ForEach-Object { & $acct $_ })
    $State.ad_report = ($out | ConvertTo-Json -Depth 5 -Compress)
    $State.ad_checked = $nowTs
    return $out
}

# ---------------------------------------------------------------------------
# System file check (1.0.59): sfc /verifyonly, read only, never repairs. It takes 10-30 minutes of CPU and disk,
# so it runs as its own scheduled task in the background; each report says how it's going and, once it's done,
# what it found (from CBS.log: sfc's own output is UTF-16 and in the device's language).
# ---------------------------------------------------------------------------
$SfcTaskName = "$TaskName (system file check)"
$SfcRunner = @'
param([switch]$Dism)
$ErrorActionPreference = 'Continue'
$out = Join-Path $PSScriptRoot 'sfc-result.json'
$r = [ordered]@{ started = (Get-Date).ToUniversalTime().ToString('o') }
$sys = if (Test-Path "$env:SystemRoot\Sysnative") { "$env:SystemRoot\Sysnative" } else { "$env:SystemRoot\System32" }
function Run([string]$Exe, [string[]]$Arguments, [string]$Log) {
    $p = Start-Process -FilePath $Exe -ArgumentList $Arguments -NoNewWindow -PassThru -RedirectStandardOutput $Log
    try { $p.PriorityClass = 'BelowNormal' } catch { }
    $p.WaitForExit()
    return $p.ExitCode
}
try { $r.sfc_exit = Run "$sys\sfc.exe" @('/verifyonly') (Join-Path $PSScriptRoot 'sfc-output.txt') } catch { $r.error = $_.Exception.Message }
if ($Dism) {
    try { $r.dism_exit = Run "$sys\dism.exe" @('/Online', '/Cleanup-Image', '/ScanHealth', '/English') (Join-Path $PSScriptRoot 'dism-output.txt') } catch { $r.dism_error = $_.Exception.Message }
}
$r.finished = (Get-Date).ToUniversalTime().ToString('o')
$r | ConvertTo-Json | Set-Content -Path $out -Encoding ASCII
'@

function Read-TextLoose([string]$Path) {
    # sfc writes UTF-16 with stray NULs; this reads either kind as plain text
    if (-not (Test-Path $Path)) { return '' }
    $b = [IO.File]::ReadAllBytes($Path)
    $nul = @($b | Where-Object { $_ -eq 0 }).Count
    $enc = if ($b.Length -and $nul * 4 -gt $b.Length) { [Text.Encoding]::Unicode } else { [Text.Encoding]::ASCII }  # sfc: UTF-16; DISM: one byte each
    return ($enc.GetString($b) -replace "`0", '') -replace "[^\x09\x0A\x0D\x20-\x7E]", ''
}

function Read-CbsSince([DateTime]$Since) {
    # The lines CBS.log has from the run on (the last 40 MB at most); its times are local
    $path = Join-Path $env:SystemRoot 'Logs\CBS\CBS.log'
    if (-not (Test-Path $path)) { return @() }
    $fs = [IO.File]::Open($path, 'Open', 'Read', 'ReadWrite')
    try {
        $len = $fs.Length; $max = 40MB
        if ($len -gt $max) { $null = $fs.Seek(-$max, 'End') }
        $text = (New-Object IO.StreamReader($fs)).ReadToEnd()
    } finally { $fs.Dispose() }
    $from = $Since.ToLocalTime().AddMinutes(-1).ToString('yyyy-MM-dd HH:mm:ss')
    return @($text -split "`r?`n" | Where-Object { $_.Length -gt 19 -and $_.Substring(0, 19) -ge $from })
}

function Get-SfcVerdict($Job, $Done) {
    $lines = @(Read-CbsSince ([DateTime]::Parse([string]$Job.started, [Globalization.CultureInfo]::InvariantCulture, 'AdjustToUniversal')))
    $files = New-Object System.Collections.ArrayList
    foreach ($l in $lines) {
        foreach ($pat in @("do not match actual file \[l:\d+\]'([^']+)'", "Hashes for file member \[l:\d+\]'([^']+)' do not match", "Cannot (?:repair|verify) member file \[l:\d+\]'([^']+)'")) {
            if ($l -match $pat -and -not $files.Contains($Matches[1])) { $null = $files.Add($Matches[1]) }
        }
    }
    $complete = [bool]($lines | Where-Object { $_ -match '\[SR\] Verify complete' } | Select-Object -First 1)
    $out = Read-TextLoose (Join-Path $DataPath 'sfc-output.txt')
    $v = [ordered]@{ state = 'failed'; started = $Job.started; finished = $(if ($Done) { [string]$Done.finished } else { $null }); trigger = $Job.trigger; files = @($files | Select-Object -First 30); count = $files.Count; detail = $null }
    if ($files.Count) { $v.state = 'violations' }
    elseif ($out -match 'did not find any integrity violations') { $v.state = 'ok' }
    elseif ($out -match 'found (?:integrity violations|corrupt files)') { $v.state = 'violations' }
    elseif ($complete) { $v.state = 'ok' }
    else {
        $last = @($out -split "`r?`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ -and $_ -notmatch '^(Beginning|Verification)\b' }) | Select-Object -Last 1
        $v.detail = $(if ($out -match 'repair pending|requires? (?:a )?reboot') { 'a repair is waiting for a restart' }
            elseif ($out -match 'could not perform|servicing operation') { 'another servicing operation (Windows Update, an install) was running' }
            elseif ($Done -and $Done.error) { [string]$Done.error } elseif ($last) { $last } else { "no result (exit code $($Done.sfc_exit))" })
    }
    if ($Done -and $null -ne $Done.dism_exit) {
        $d = Read-TextLoose (Join-Path $DataPath 'dism-output.txt')
        $v.dism = [ordered]@{ state = $(if ($d -match 'No component store corruption detected') { 'healthy' } elseif ($d -match 'component store is repairable') { 'repairable' }
                elseif ($d -match 'cannot be repaired') { 'not_repairable' } else { 'failed' }); detail = $null }
        if ($v.dism.state -eq 'failed') { $v.dism.detail = (@($d -split "`r?`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ }) | Select-Object -Last 1) }
    }
    return $v
}

function Start-SystemFileCheck([bool]$Dism) {
    $runner = Join-Path $DataPath 'sfc-run.ps1'
    Set-Content -Path $runner -Value $SfcRunner -Encoding ASCII
    foreach ($f in 'sfc-result.json', 'sfc-output.txt', 'dism-output.txt') { Remove-Item (Join-Path $DataPath $f) -Force -ErrorAction SilentlyContinue }
    $cmd = "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$runner`"" + $(if ($Dism) { ' -Dism' } else { '' })
    $ErrorActionPreference = 'Continue'
    $null = & schtasks.exe /Create /TN $SfcTaskName /TR $cmd /SC ONCE /SD 01/01/2000 /ST 00:00 /RU SYSTEM /RL HIGHEST /F 2>&1
    if ($LASTEXITCODE -ne 0) { throw "Couldn't create the system file check task (schtasks exit code $LASTEXITCODE)" }
    try { Set-TaskTimeLimit @($SfcTaskName) 'PT3H' } catch { }
    $null = & schtasks.exe /Run /TN $SfcTaskName 2>&1
    if ($LASTEXITCODE -ne 0) { throw "Couldn't start the system file check (schtasks exit code $LASTEXITCODE)" }
}

function Get-SfcSlot($Conf, [DateTime]$Now) {
    # The latest weekly start time at or before now (local time)
    $d = $Now.Date.AddHours([int]$Conf.hour)
    $d = $d.AddDays(-((7 + [int]$d.DayOfWeek - [int]$Conf.day) % 7))
    if ($d -gt $Now) { $d = $d.AddDays(-7) }
    return $d
}

function Get-SystemFileCheck($State, $Conf) {
    $job = $null
    if ($State.sfc_job) { try { $job = $State.sfc_job | ConvertFrom-Json } catch { } }
    $nowUtc = (Get-Date).ToUniversalTime()
    if ($job -and $job.state -eq 'running') {
        $done = $null; $res = Join-Path $DataPath 'sfc-result.json'
        if (Test-Path $res) { try { $done = Get-Content $res -Raw | ConvertFrom-Json } catch { } }
        $started = [DateTime]::Parse([string]$job.started, [Globalization.CultureInfo]::InvariantCulture, 'AdjustToUniversal')
        if ($done -and $done.finished) {
            $v = Get-SfcVerdict $job $done
            $v.requested_now = $job.requested_now; $v.since = $job.since
            $job = $v
            Write-AgentLog "System file check finished: $($v.state)$(if ($v.count) { " ($($v.count) file(s))" })"
        } elseif (($nowUtc - $started).TotalHours -gt 3) {
            $job = [ordered]@{ state = 'failed'; started = $job.started; finished = $null; trigger = $job.trigger; detail = "it didn't finish within 3 hours"; requested_now = $job.requested_now; since = $job.since }
        }
    }
    $on = $Conf -and $Conf.on
    $now = [int64]$Conf.run_now -gt [int64]$(if ($job) { $job.requested_now } else { 0 })
    if (-not $on -and -not $now -and -not $job) { return $null }
    if (-not $job) { $job = [ordered]@{ state = 'never'; since = ConvertTo-UtcString (Get-Date) } }
    if (-not ($job.state -eq 'running')) {
        $due = $false
        if ($on) {
            $slot = Get-SfcSlot $Conf (Get-Date)
            $last = if ($job.started) { [DateTime]::Parse([string]$job.started, [Globalization.CultureInfo]::InvariantCulture, 'AdjustToUniversal').ToLocalTime() } else { $null }
            $since = if ($job.since) { [DateTime]::Parse([string]$job.since, [Globalization.CultureInfo]::InvariantCulture, 'AdjustToUniversal').ToLocalTime() } else { [DateTime]::MinValue }
            # Not straight away when it's first turned on (a weekday afternoon): from the next weekly time
            $due = $slot -gt $since -and (-not $last -or $last -lt $slot)
        }
        if ($due -or $now) {
            try {
                Start-SystemFileCheck ([bool]$Conf.dism)
                $job = [ordered]@{ state = 'running'; started = ConvertTo-UtcString (Get-Date); trigger = $(if ($now) { 'now' } else { 'schedule' })
                    requested_now = $(if ($now) { [int64]$Conf.run_now } else { $job.requested_now }); since = $job.since }
                Write-AgentLog "System file check started ($($job.trigger))"
            } catch {
                $job = [ordered]@{ state = 'failed'; started = ConvertTo-UtcString (Get-Date); trigger = $(if ($now) { 'now' } else { 'schedule' }); detail = $_.Exception.Message
                    requested_now = $(if ($now) { [int64]$Conf.run_now } else { $job.requested_now }); since = $job.since }
            }
        }
    }
    $State.sfc_job = ($job | ConvertTo-Json -Compress -Depth 4)
    if (-not $on -and $job.state -eq 'never') { return $null }
    $out = [ordered]@{}
    foreach ($k in 'state', 'started', 'finished', 'trigger', 'files', 'count', 'detail', 'dism') { if ($null -ne $job.$k) { $out[$k] = $job.$k } }
    return $out
}

function Get-LapsStatus($State, [bool]$IsDc, [bool]$Domain) {
    # Which LAPS applies and whether it's rotating the managed password on schedule. Never reads the password.
    # Windows LAPS uses the first of these policy roots that has any setting (Microsoft's documented order).
    $roots = @(
        @('HKLM:\Software\Microsoft\Policies\LAPS', 'Intune / MDM'),
        @('HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS', 'Group Policy'),
        @('HKLM:\Software\Microsoft\Windows\CurrentVersion\LAPS\Config', 'Local configuration'))
    $policy = $null; $source = ''
    foreach ($r in $roots) {
        try {
            $p = Get-ItemProperty -Path $r[0] -ErrorAction Stop
            if (@($p.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' }).Count) { $policy = $p; $source = $r[1]; break }
        } catch { }
    }
    $legacy = $null
    try { $legacy = Get-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft Services\AdmPwd' -ErrorAction Stop } catch { }
    $winLaps = Test-Path "$env:SystemRoot\System32\laps.dll"
    $legacyCse = Test-Path "$env:ProgramFiles\LAPS\CSE\AdmPwd.dll"
    $out = [ordered]@{ product = ''; source = ''; enabled = $false; backup = ''; age_days = 30; account = ''; legacy = $false; dc = $IsDc }
    if ($policy -and $winLaps) {
        $bd = if ($null -ne $policy.BackupDirectory) { [int]$policy.BackupDirectory } else { 0 }
        $out.product = 'Windows LAPS'; $out.source = $source
        $out.enabled = $bd -in 1, 2
        $out.backup = switch ($bd) { 1 { 'Microsoft Entra ID' } 2 { 'Active Directory' } default { 'none (backup disabled)' } }
        if ($null -ne $policy.PasswordAgeDays) { $out.age_days = [int]$policy.PasswordAgeDays }
        $out.account = [string]$policy.AdministratorAccountName
        if ([int]$policy.AutomaticAccountManagementEnabled -eq 1) {
            $out.account = if ($policy.AutomaticAccountManagementNameOrPrefix) { [string]$policy.AutomaticAccountManagementNameOrPrefix } else { 'WLapsAdmin' }
            $out.auto_account = $true
        }
        if ($IsDc) { $out.dsrm = ([int]$policy.ADBackupDSRMPassword -eq 1) }
    } elseif ($legacy -and [int]$legacy.AdmPwdEnabled -eq 1) {
        $out.legacy = $true; $out.source = 'Group Policy (legacy LAPS)'; $out.backup = 'Active Directory'
        $out.product = if ($legacyCse) { 'Microsoft LAPS (legacy)' } elseif ($winLaps) { 'Windows LAPS (legacy emulation)' } else { 'Microsoft LAPS (legacy)' }
        $out.enabled = $legacyCse -or $winLaps
        if (-not $out.enabled) { $out.problem = "The legacy LAPS policy is set, but neither the LAPS client (AdmPwd) nor Windows LAPS is installed" }
        if ($null -ne $legacy.PasswordAgeDays) { $out.age_days = [int]$legacy.PasswordAgeDays }
        $out.account = [string]$legacy.AdminAccountName
    } elseif ($policy) {
        $out.product = 'Windows LAPS'; $out.source = $source; $out.backup = 'none'
        $out.problem = "A LAPS policy is set, but this version of Windows doesn't include Windows LAPS (it needs the April 2023 update or later)"
    } else {
        return $null  # LAPS isn't configured here
    }

    # The managed account's password age (domain controllers manage the DSRM password instead)
    if (-not $IsDc -and -not $out.auto_account) {
        try {
            $u = $null
            if (Get-Command Get-LocalUser -ErrorAction SilentlyContinue) {
                $u = if ($out.account) { Get-LocalUser -Name $out.account -ErrorAction Stop }
                     else { Get-LocalUser -ErrorAction Stop | Where-Object { $_.SID.Value -match '^S-1-5-21-.+-500$' } | Select-Object -First 1 }
                if ($u) {
                    $out.account = [string]$u.Name; $out.account_enabled = [bool]$u.Enabled
                    if ($u.PasswordLastSet) { $out.password_set = ConvertTo-UtcString $u.PasswordLastSet }
                }
            } else {
                $name = $out.account
                if (-not $name) { $name = [string](Get-CimInstance -ClassName Win32_UserAccount -Filter "LocalAccount = TRUE AND SID LIKE '%-500'" | Select-Object -First 1).Name }
                $a = [ADSI]"WinNT://$env:COMPUTERNAME/$name,user"
                $age = $a.PasswordAge.Value
                if ($null -ne $age) {
                    $u = $true; $out.account = $name
                    $out.password_set = ConvertTo-UtcString ((Get-Date).AddSeconds(-[int]$age))
                    $out.account_enabled = -not ([int]$a.UserFlags.Value -band 2)
                }
            }
            $out.account_found = [bool]$u
        } catch { $out.account_found = $false }
    }

    # Windows LAPS logs each policy run and each password it backs up
    if ($out.product -like 'Windows LAPS*') {
        $log = 'Microsoft-Windows-LAPS/Operational'
        $newest = { param([int[]]$Ids) try { Get-WinEvent -FilterHashtable @{ LogName = $log; Id = $Ids } -MaxEvents 1 -ErrorAction Stop } catch { $null } }
        $b = & $newest @(10018, 10029)
        if ($b) { $out.last_backup = ConvertTo-UtcString $b.TimeCreated; $out.last_backup_to = if ($b.Id -eq 10029) { 'Microsoft Entra ID' } else { 'Active Directory' } }
        $c = & $newest @(10020)
        if ($c) { $out.last_rotation = ConvertTo-UtcString $c.TimeCreated }
        $ok = & $newest @(10004)
        $fail = & $newest @(10005)
        if ($ok) { $out.last_run = ConvertTo-UtcString $ok.TimeCreated }
        if ($fail -and (-not $ok -or $fail.TimeCreated -gt $ok.TimeCreated)) {
            $out.last_error = Limit-Text (Get-EventMessage $fail) 300
            $out.last_error_time = ConvertTo-UtcString $fail.TimeCreated
            $out.last_run = $out.last_error_time
        }
    }

    # When the password expires, from the computer's own AD object (the expiry is readable; the password isn't).
    # Asked at most hourly; kept for a day so a laptop away from the office still shows it.
    if ($out.enabled -and $out.backup -eq 'Active Directory' -and $Domain) {
        $attr = if ($out.legacy) { 'ms-Mcs-AdmPwdExpirationTime' } else { 'msLAPS-PasswordExpirationTime' }
        $nowTs = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
        if (-not $State.laps_ad_at -or $nowTs - [int64]$State.laps_ad_at -gt 3600 -or $State.laps_ad_attr -ne $attr) {
            try {
                $ds = New-Object DirectoryServices.DirectorySearcher
                $ds.Filter = "(&(objectCategory=computer)(sAMAccountName=$($env:COMPUTERNAME)`$))"
                [void]$ds.PropertiesToLoad.Add($attr)
                $ds.ClientTimeout = [TimeSpan]::FromSeconds(10)
                $res = $ds.FindOne()
                $exp = ''
                if ($res -and $res.Properties[$attr.ToLower()].Count) { $exp = ConvertTo-UtcString ([DateTime]::FromFileTimeUtc([int64]$res.Properties[$attr.ToLower()][0]).ToLocalTime()) }
                $State.laps_ad_at = $nowTs; $State.laps_ad_exp = $exp; $State.laps_ad_attr = $attr
            } catch {
                $out.ad_error = Limit-Text $_.Exception.Message 200
            }
        }
        if ($State.laps_ad_at -and $nowTs - [int64]$State.laps_ad_at -lt 86400 -and $State.laps_ad_attr -eq $attr) {
            $out.expires = $State.laps_ad_exp  # '' = no expiry in AD: the password has never been backed up
            $out.expires_checked = ConvertTo-UtcString ([DateTimeOffset]::FromUnixTimeSeconds([int64]$State.laps_ad_at).LocalDateTime)
        }
    }
    return $out
}

function Get-RoleChecks($Roles, [DateTime]$Since, $State) {
    $checks = [ordered]@{}
    $null = Measure-Step 'iis' {
    if ($Roles -contains 'IIS') {
        try {
            $pools = Invoke-AppCmd @('list', 'apppool', '/xml')
            $sites = Invoke-AppCmd @('list', 'site', '/xml')
            if ($pools -or $sites) {
                $checks.iis = [ordered]@{
                    app_pools = @(if ($pools) { ([xml]$pools).appcmd.APPPOOL | Where-Object { $_ } | ForEach-Object { [ordered]@{ name = $_.'APPPOOL.NAME'; state = $_.state } } })
                    sites     = @(if ($sites) { ([xml]$sites).appcmd.SITE | Where-Object { $_ } | ForEach-Object {
                                $protos = @(([string]$_.bindings -split ',') | ForEach-Object { ($_ -split '/')[0].Trim().ToLower() } |
                                    Where-Object { $_ } | Select-Object -Unique)
                                $state = [string]$_.state
                                # FTP sites are run by the FTP service, so appcmd (which asks the web
                                # service) always says "Unknown". Ask the FTP side instead.
                                if ($protos.Count -gt 0 -and @($protos | Where-Object { $_ -ne 'ftp' }).Count -eq 0) {
                                    $state = Get-FtpSiteState ([string]$_.'SITE.NAME') $state
                                }
                                [ordered]@{ name = $_.'SITE.NAME'; state = $state; protocols = $protos }
                            } })
                }
            }
        } catch { Add-CollectorError 'iis' $_ }
    }
    }
    $null = Measure-Step 'ad replication' {
    if ($Roles -contains 'Domain controller') {
        try {
            $ad = [ordered]@{ replication = @(); partners = 0; sysvol_shared = $null; netlogon_shared = $null }
            $csv = Invoke-RepAdmin @('/showrepl', $env:COMPUTERNAME, '/csv')
            if ($csv) {
                $rows = @($csv | ConvertFrom-Csv | Where-Object { $_.'showrepl_COLUMNS' -eq 'showrepl_INFO' })
                $ad.partners = $rows.Count
                $ad.replication = @($rows | Where-Object { [int]$_.'Number of Failures' -gt 0 } | ForEach-Object {
                        [ordered]@{
                            partner = [string]$_.'Source DSA'; naming_context = [string]$_.'Naming Context'
                            failures = [int]$_.'Number of Failures'; last_error = [string]$_.'Last Failure Status'
                            last_success = [string]$_.'Last Success Time'
                        }
                    })
            }
            $shares = @(Get-CimInstance -ClassName Win32_Share | ForEach-Object { $_.Name })
            $ad.sysvol_shared = $shares -contains 'SYSVOL'
            $ad.netlogon_shared = $shares -contains 'NETLOGON'
            $checks.ad = $ad
        } catch { Add-CollectorError 'ad' $_ }
    }
    }
    $null = Measure-Step 'dhcp scopes' {
    if ($Roles -contains 'DHCP server' -and (Get-Command Get-DhcpServerv4ScopeStatistics -ErrorAction SilentlyContinue)) {
        try {
            $scopes = @{}
            foreach ($s in @(Get-DhcpServerv4Scope)) { $scopes[[string]$s.ScopeId] = $s }
            $checks.dhcp = @(Get-DhcpServerv4ScopeStatistics | ForEach-Object {
                    $sc = $scopes[[string]$_.ScopeId]
                    [ordered]@{
                        scope = [string]$_.ScopeId; name = if ($sc) { [string]$sc.Name } else { '' }
                        active = if ($sc) { [string]$sc.State -eq 'Active' } else { $true }
                        in_use_pct = [Math]::Round([double]$_.PercentageInUse, 1); free = [int]$_.Free
                    }
                })
        } catch { Add-CollectorError 'dhcp' $_ }
    }
    }
    $null = Measure-Step 'hyper-v' {
    if ($Roles -contains 'Hyper-V' -and (Get-Command Get-VM -ErrorAction SilentlyContinue)) {
        try {
            # Each VM's state, uptime, CPU and memory, and its checkpoints (snapshots): one call for all of them
            $snaps = @{}
            try { foreach ($c in @(Get-VM | Get-VMSnapshot -ErrorAction SilentlyContinue)) { $k = [string]$c.VMName; if (-not $snaps[$k]) { $snaps[$k] = @() }; $snaps[$k] += $c } } catch { }
            $checks.hyperv = @(Get-VM | ForEach-Object {
                    $v = $_; $mine = @($snaps[[string]$v.Name] | Where-Object { $_ } | Sort-Object CreationTime)
                    $up = $null; try { if ($v.Uptime) { $up = [int64]$v.Uptime.TotalSeconds } } catch { }
                    $mb = { param($b) if ($null -eq $b) { $null } else { [int64]([int64]$b / 1MB) } }
                    [ordered]@{ name = [string]$v.Name; state = [string]$v.State; status = [string]$v.Status
                        uptime_s = $up; cpu_pct = $(try { [int]$v.CPUUsage } catch { $null }); cpus = $(try { [int]$v.ProcessorCount } catch { $null })
                        mem_mb = (& $mb $v.MemoryAssigned); mem_demand_mb = (& $mb $v.MemoryDemand); mem_startup_mb = (& $mb $v.MemoryStartup)
                        mem_max_mb = $(if ($v.DynamicMemoryEnabled) { & $mb $v.MemoryMaximum } else { $null }); dynamic = [bool]$v.DynamicMemoryEnabled
                        generation = $(try { [int]$v.Generation } catch { $null }); replication = [string]$v.ReplicationHealth
                        checkpoints = $mine.Count
                        oldest_checkpoint = $(if ($mine.Count) { ConvertTo-UtcString $mine[0].CreationTime } else { $null })
                        checkpoint_names = @($mine | Select-Object -Last 5 | ForEach-Object { Limit-Text ([string]$_.Name) 80 })
                        checkpoint_type = $(if ($mine.Count) { [string]$mine[-1].SnapshotType } else { $null }) }
                })
        } catch { Add-CollectorError 'hyperv' $_ }
    }
    }
    $null = Measure-Step 'printers' {
    if ($Roles -contains 'Print server' -and (Get-Command Get-Printer -ErrorAction SilentlyContinue)) {
        try {
            $checks.printers = @(Get-Printer | Where-Object { $_.Shared } | ForEach-Object {
                    [ordered]@{ name = [string]$_.Name; status = [string]$_.PrinterStatus; jobs = [int]$_.JobCount }
                })
        } catch { Add-CollectorError 'printers' $_ }
    }
    }
    $null = Measure-Step 'rds sessions' {
    if ($Roles -contains 'Remote Desktop Session Host') {
        try {
            $lines = @(Get-QUserOutput | Select-Object -Skip 1)
            $checks.rds = [ordered]@{
                active       = @($lines | Where-Object { $_ -match '\sActive\s' }).Count
                disconnected = @($lines | Where-Object { $_ -match '\sDisc\s' }).Count
            }
        } catch { Add-CollectorError 'rds' $_ }
    }
    }
    $null = Measure-Step 'defender' {
    if (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue) {
        try {
            $mp = Get-MpComputerStatus
            $mode = [string]$mp.AMRunningMode
            $def = [ordered]@{
                mode = $mode; antivirus_enabled = [bool]$mp.AntivirusEnabled
                realtime = [bool]$mp.RealTimeProtectionEnabled
                signature_age_days = $(if ($null -ne $mp.AntivirusSignatureAge) { [int]$mp.AntivirusSignatureAge } else { $null })
                signature_updated = $null; signature_version = [string]$mp.AntivirusSignatureVersion
                quick_scan_end = $null; full_scan_end = $null
                detections = @()
            }
            # When the last quick and full scans finished (never: empty, or year 1601 on some builds)
            # When the definitions were last updated on this PC (the age above is as of this report, not now)
            foreach ($p in @(@('quick_scan_end', 'QuickScanEndTime'), @('full_scan_end', 'FullScanEndTime'), @('signature_updated', 'AntivirusSignatureLastUpdated'))) {
                try { $t = $mp.($p[1]); if ($t -and ([DateTime]$t).Year -gt 2000) { $def[$p[0]] = ConvertTo-UtcString $t } } catch { }
            }
            try {
                $names = @{}
                foreach ($t in @(Get-MpThreat -ErrorAction SilentlyContinue)) { $names[[string]$t.ThreatID] = [string]$t.ThreatName }
                # Only detections not reported before (tracked by detection time).
                $after = $Since
                if ($State.cursors.ContainsKey('Defender')) { $after = [DateTime]::FromFileTimeUtc([long]$State.cursors['Defender']).ToLocalTime() }
                $new = @(Get-MpThreatDetection -ErrorAction SilentlyContinue |
                    Where-Object { $_.InitialDetectionTime -gt $after } | Sort-Object InitialDetectionTime)
                if ($new.Count -gt 0) {
                    $State.cursors['Defender'] = ([DateTime]$new[-1].InitialDetectionTime).ToFileTimeUtc()
                }
                $def.detections = @($new | Select-Object -Last 20 | ForEach-Object {
                        [ordered]@{
                            time = ConvertTo-UtcString $_.InitialDetectionTime
                            threat = if ($names[[string]$_.ThreatID]) { $names[[string]$_.ThreatID] } else { "Threat $($_.ThreatID)" }
                            resource = Limit-Text ([string](@($_.Resources)[0])) 200
                            action_success = [bool]$_.ActionSuccess
                        }
                    })
            } catch { }
            $checks.defender = $def
        } catch { Add-CollectorError 'defender' $_ }
    }
    }
    return $checks
}

function ConvertFrom-DiskPartTable([string[]]$Lines) {
    # diskpart prints fixed-width tables; the row of dashes under the header gives the columns.
    $dash = -1
    for ($i = 1; $i -lt $Lines.Count; $i++) { if ($Lines[$i] -match '^\s*-{3,}(\s+-{2,})+\s*$') { $dash = $i; break } }
    if ($dash -lt 1) { return @() }
    $starts = @(); $lens = @()
    foreach ($m in [regex]::Matches($Lines[$dash], '-+')) { $starts += $m.Index; $lens += $m.Length }
    $header = $Lines[$dash - 1].PadRight($Lines[$dash].Length)
    $names = @(for ($c = 0; $c -lt $starts.Count; $c++) { $header.Substring($starts[$c], $lens[$c]).Trim() })
    $rows = @()
    for ($i = $dash + 1; $i -lt $Lines.Count; $i++) {
        $line = $Lines[$i]
        if (-not $line.Trim()) { break }
        $row = [ordered]@{}
        for ($c = 0; $c -lt $starts.Count; $c++) {
            $a = $starts[$c]
            $b = if ($c + 1 -lt $starts.Count) { $starts[$c + 1] } else { [Math]::Max($line.Length, $a) }
            $row[$names[$c]] = if ($line.Length -gt $a) { $line.Substring($a, [Math]::Min($b, $line.Length) - $a).Trim() } else { '' }
        }
        $rows += , $row
    }
    return , $rows
}

function Invoke-DiskPart([string]$Command) {
    $tmp = [IO.Path]::GetTempFileName()
    $outFile = "$tmp.out"
    try {
        Set-Content -Path $tmp -Value $Command -Encoding ASCII
        $p = Start-Process -FilePath 'diskpart.exe' -ArgumentList "/s `"$tmp`"" -RedirectStandardOutput $outFile -NoNewWindow -PassThru
        if (-not $p.WaitForExit(60000)) { try { $p.Kill() } catch { }; throw 'diskpart timed out' }
        return @(Get-Content -Path $outFile -ErrorAction SilentlyContinue)
    } finally {
        Remove-Item -Path $tmp, $outFile -Force -ErrorAction SilentlyContinue
    }
}

function Get-AmdRaidHealth($State) {
    # AMD RAIDXpert2 writes array and disk events to the System log as "AMD RAID API".
    # The array state is worked out from them (latest event per logical drive) and kept
    # in the state file, so an array that went critical long ago is still known.
    $src = 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\System\AMD RAID API'
    if (-not (Test-Path $src) -and -not $State.amd_raid) { return $null }
    $drives = @{}
    if ($State.amd_raid) {
        try { foreach ($p in ($State.amd_raid | ConvertFrom-Json).PSObject.Properties) { $drives[$p.Name] = @{ state = [string]$p.Value.state; detail = [string]$p.Value.detail; time = (ConvertTo-IsoText $p.Value.time) } } } catch { }
    }
    $since = (Get-Date).AddDays(-90)
    $events = @()
    try {
        $events = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'AMD RAID API'; StartTime = $since } -MaxEvents 2000 -ErrorAction Stop | Sort-Object TimeCreated, RecordId)
    } catch {
        if (-not ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*' -or $_.Exception.Message -like 'No events were found*')) { throw }
    }
    $warnings = @()
    $recent = (Get-Date).AddHours(-24)
    $ports = @{}
    foreach ($e in $events) {
        $msg = [string]$e.Message
        if (-not $msg) { try { $msg = [string](([xml]$e.ToXml()).Event.EventData.Data | Select-Object -First 1) } catch { } }
        $when = ConvertTo-UtcString $e.TimeCreated
        if ($msg -match 'Logical drive "\s*(.+?)\s*" goes (\w+)') {
            $name = $Matches[1]; $word = $Matches[2].ToLower()
            # (not $state: PowerShell variable names ignore case, so it would overwrite $State)
            $driveState = switch -regex ($word) { '^(online|normal|functional|ready)$' { 'Healthy' } '^(critical|degraded)$' { 'Critical' } default { 'Offline' } }
            $drives[$name] = @{ state = $driveState; detail = ''; time = $when }
        } elseif ($msg -match 'Rebuild on logical drive "\s*(.+?)\s*" (.+)$') {
            $name = $Matches[1]; $what = $Matches[2].Trim().ToLower()
            if (-not $drives.ContainsKey($name)) { $drives[$name] = @{ state = 'Critical'; detail = ''; time = $when } }
            if ($what -eq 'completed') { $drives[$name] = @{ state = 'Healthy'; detail = 'rebuild completed'; time = $when } }
            elseif ($drives[$name].state -ne 'Healthy' -or $what -eq 'started') {
                $pct = if ($what -match '(\d+)%') { "$($Matches[1])%" } elseif ($what -match 'resumed|started') { $what } else { $what }
                $drives[$name] = @{ state = 'Rebuilding'; detail = $pct; time = $when }
                if ($what -match 'paused|aborted|stopped|failed') { $drives[$name].state = 'Critical'; $drives[$name].detail = "rebuild $what" }
            }
        } elseif ($e.TimeCreated -ge $recent -and $msg -match '[Pp]ort (\d+) target (\d+)') {
            $key = "port $($Matches[1]) target $($Matches[2])"
            if (-not $ports.ContainsKey($key)) { $ports[$key] = @{ down = 0; timeout = 0; bad = 0; unplugged = 0 } }
            if ($msg -match 'set down') { $ports[$key].down++ }
            elseif ($msg -match 'timeout') { $ports[$key].timeout++ }
            elseif ($msg -match 'BSL update') { $ports[$key].bad++ }
            elseif ($msg -match 'unplugged') { $ports[$key].unplugged++ }
        }
    }
    foreach ($k in $ports.Keys) {
        $p = $ports[$k]; $bits = @()
        if ($p.down) { $bits += "dropped out $($p.down) time(s)" }
        if ($p.unplugged) { $bits += "unplugged" }
        if ($p.timeout) { $bits += "$($p.timeout) timeout(s)" }
        if ($p.bad) { $bits += "$($p.bad) bad sector(s) remapped" }
        if ($bits) { $warnings += "AMD RAID disk on $($k): $($bits -join ', ') in the last 24 h" }
    }
    $State.amd_raid = ($drives | ConvertTo-Json -Depth 3 -Compress)
    $volumes = @(foreach ($n in ($drives.Keys | Sort-Object)) {
        $d = $drives[$n]
        $status = switch ($d.state) {
            'Healthy' { 'Healthy' }
            'Rebuilding' { "Rebuilding $($d.detail)".Trim() }
            'Critical' { 'Critical (a disk has failed)' + $(if ($d.detail) { ", $($d.detail)" } else { '' }) }
            default { 'Offline (failed)' }
        }
        [ordered]@{ volume = $n; letter = ''; label = $n; type = 'AMD RAID'; status = $status; info = "since $($d.time)" }
    })
    return [ordered]@{ volumes = $volumes; warnings = $warnings }
}

function Find-OmReport {
    $c = Get-Command omreport.exe -ErrorAction SilentlyContinue
    if ($c) { return $c.Source }
    foreach ($p in @("$env:ProgramFiles\Dell\SysMgt\oma\bin\omreport.exe", "${env:ProgramFiles(x86)}\Dell\SysMgt\oma\bin\omreport.exe")) {
        if ($p -and (Test-Path $p)) { return $p }
    }
    return $null
}

function Invoke-OmReport([string]$Exe, [string[]]$Arguments) {
    # omreport's semicolon-separated output: tables of "Header;Header" then rows.
    $outFile = [IO.Path]::GetTempFileName()
    try {
        $p = Start-Process -FilePath $Exe -ArgumentList ($Arguments + @('-fmt', 'ssv')) -RedirectStandardOutput $outFile -NoNewWindow -PassThru
        if (-not $p.WaitForExit(90000)) { try { $p.Kill() } catch { }; throw "omreport $($Arguments -join ' ') timed out" }
        return ConvertFrom-OmSsv @(Get-Content -Path $outFile -ErrorAction SilentlyContinue)
    } finally { Remove-Item -Path $outFile -Force -ErrorAction SilentlyContinue }
}

function ConvertFrom-OmSsv([string[]]$Lines) {
    $rows = @(); $head = $null; $section = ''
    foreach ($line in $Lines) {
        $t = $line.Trim()
        if (-not $t) { $head = $null; continue }
        if ($t -notmatch ';') { $section = $t; $head = $null; continue }
        $cells = @($t.Split(';') | ForEach-Object { $_.Trim() })
        if (-not $head) { $head = $cells; continue }
        $row = [ordered]@{ '_section' = $section }
        for ($i = 0; $i -lt $head.Count; $i++) { $row[$head[$i]] = if ($i -lt $cells.Count) { $cells[$i] } else { '' } }
        $rows += , $row
    }
    return , $rows
}

function Get-DellOmsaHealth {
    # Dell OpenManage Server Administrator: PERC controllers, virtual and physical
    # disks, and the chassis health summary (power, fans, temperatures, memory...).
    $exe = Find-OmReport
    if (-not $exe) { return $null }
    $res = [ordered]@{ physical = @(); volumes = @(); drives = @(); hardware = @() }
    $ctrls = Invoke-OmReport $exe @('storage', 'controller')
    foreach ($c in $ctrls) {
        if (-not $c['ID']) { continue }
        $cname = $c['Name']
        if ($c['Status'] -and $c['Status'] -ne 'Ok') {
            $res.drives += [ordered]@{ name = "Controller $cname"; index = [int]$c['ID']; status = "$($c['Status']) ($($c['State']))" }
        }
        foreach ($v in (Invoke-OmReport $exe @('storage', 'vdisk', "controller=$($c['ID'])"))) {
            if ($null -eq $v['ID'] -or $v['ID'] -eq '') { continue }
            $st = [string]$v['State']; $sev = [string]$v['Status']
            $status = if ($st -match 'Degraded') { 'Degraded (a disk has failed)' }
                      elseif ($st -match 'Failed|Offline') { "Failed ($st)" }
                      elseif ($st -match 'Rebuild|Resynch|Reconstruct') { $(if ($st -eq 'Rebuilding') { 'Rebuilding' } else { "Rebuilding ($st)" }) }
                      elseif ($sev -eq 'Critical' -or $sev -eq 'Non-Recoverable') { "Failed ($st, $sev)" }
                      elseif ($sev -and $sev -ne 'Ok') { "Warning ($st)" }
                      else { 'Healthy' }
            $res.volumes += [ordered]@{ volume = "$cname VD $($v['ID'])"; letter = ''; label = $(if ($v['Name']) { $v['Name'] } else { "VD $($v['ID'])" })
                type = "PERC $($v['Layout'])".Trim(); status = $status; info = [string]$v['Device Name'] }
        }
        foreach ($d in (Invoke-OmReport $exe @('storage', 'pdisk', "controller=$($c['ID'])"))) {
            if (-not $d['ID']) { continue }
            $sev = [string]$d['Status']; $st = [string]$d['State']
            $pred = [string]$d['Failure Predicted'] -eq 'Yes'
            $health = if ($sev -eq 'Critical' -or $sev -eq 'Non-Recoverable' -or $st -match 'Failed|Offline|Removed') { 'Unhealthy' }
                      elseif ($pred -or ($sev -and $sev -ne 'Ok')) { 'Warning' } else { 'Healthy' }
            $res.physical += [ordered]@{ name = "Disk $($d['ID'])"; serial = [string]$d['Serial No.']; media = [string]$d['Media']; bus = [string]$d['Bus Protocol']
                health = $health; status = $(if ($pred) { "Predictive failure, $st" } else { $st }); size_gb = $(if ($d['Capacity'] -match '([\d.,]+)\s*GB') { [Math]::Round([double]($Matches[1] -replace ',', ''), 0) } else { 0 }) }
        }
    }
    foreach ($h in (Invoke-OmReport $exe @('chassis'))) {
        if ($h['COMPONENT']) { $res.hardware += [ordered]@{ component = [string]$h['COMPONENT']; severity = [string]$h['SEVERITY'] } }
    }
    return $res
}

function ConvertTo-IsoText($Value) {
    # PowerShell 7's ConvertFrom-Json turns ISO date strings into DateTimes; keep them as text.
    if ($Value -is [DateTime]) { return ConvertTo-UtcString $Value }
    return [string]$Value
}

function Get-PreviousRun($Runs, [string]$Finished) {
    # When the run before this one finished (so this run's events come after it), else a day earlier
    $before = @(@($Runs) | Where-Object { $_ -and [string]$_ -lt $Finished } | Sort-Object)
    if ($before.Count) { return [string]$before[-1] }
    try { return ConvertTo-UtcString ([DateTime]::Parse($Finished).ToUniversalTime().AddDays(-1)) } catch { return '' }
}

# Why one run warned or failed, from Veeam's PowerShell: each VM or item's status, Veeam's reason and its own
# warning lines, and the run's warning and error lines. Run in this PowerShell, or in PowerShell 7 when Veeam's
# module needs it (Backup & Replication 13 needs 7.6), so it's kept as text.
function Get-VeeamLookupScript { return @'
param([string]$Session)
function Cut([string]$t, [int]$n) { $t = ($t -replace '\s+', ' ').Trim(); if ($t.Length -gt $n) { $t.Substring(0, $n - 1) + [char]0x2026 } else { $t } }
Import-Module Veeam.Backup.PowerShell -ErrorAction Stop -WarningAction SilentlyContinue -DisableNameChecking
$s = $null
try { $s = Get-VBRBackupSession -Id ([guid]$Session) -ErrorAction Stop } catch { $s = [Veeam.Backup.Core.CBackupSession]::Get([guid]$Session) }
if (-not $s) { return $null }
$tasks = @()
try { $tasks = @(Get-VBRTaskSession -Session $s -ErrorAction Stop) } catch { try { $tasks = @($s.GetTaskSessions()) } catch { } }
$objects = @($tasks | Sort-Object { if ([string]$_.Status -eq 'Success') { 1 } else { 0 } }, Name | Select-Object -First 30 | ForEach-Object {
    $details = @()
    if ([string]$_.Status -ne 'Success') {  # the VM's own warning and error lines (e.g. why changed block tracking couldn't be used)
        try { $details = @($_.Logger.GetLog().UpdatedRecords | Where-Object { [string]$_.Status -in 'EWarning', 'EFailed' } | Select-Object -First 8 |
            ForEach-Object { Cut ([string]$_.Title) 400 } | Where-Object { $_ } | Select-Object -Unique) } catch { }
    }
    [ordered]@{ name = (Cut ([string]$_.Name) 120); status = [string]$_.Status; reason = (Cut ([string]$_.Info.Reason) 400); details = @($details) } })
$log = @()
try {
    $log = @($s.Logger.GetLog().UpdatedRecords | Where-Object { [string]$_.Status -in 'EWarning', 'EFailed' } | Select-Object -First 20 | ForEach-Object {
        [ordered]@{ status = $(if ([string]$_.Status -eq 'EFailed') { 'Failed' } else { 'Warning' }); text = (Cut ([string]$_.Title) 400) } })
} catch { }
[ordered]@{ objects = @($objects); log = @($log) }
'@ }

function Get-VeeamPolicyScript { return @'
param([string]$Names)
# Each agent policy's computers and their latest backup: the policy's own sessions (named "<policy>") only send
# its settings to the computers; each computer's backup is a session named "<policy> - <computer>". Read only.
Import-Module Veeam.Backup.PowerShell -ErrorAction Stop -WarningAction SilentlyContinue -DisableNameChecking
$since = (Get-Date).AddDays(-14)
$all = $null
$out = @()
foreach ($n in @($Names -split "`n" | Where-Object { $_ })) {
    $rows = @{}
    $sess = @()
    try { $sess = @(Get-VBRComputerBackupJobSession -Name "$n*" -ErrorAction Stop) } catch {
        try { if ($null -eq $all) { $all = @(Get-VBRComputerBackupJobSession -ErrorAction Stop) }
              $sess = @($all | Where-Object { ([string]$_.Name + [string]$_.JobName) -like "*$n*" }) } catch { } }
    foreach ($x in $sess) {
        $nm = [string]$(if ($x.Name) { $x.Name } else { $x.JobName })
        if ($nm -notlike "$n - *") { continue }
        $comp = $nm.Substring($n.Length + 3).Trim()
        $end = $x.EndTime
        if (-not ($end -is [DateTime]) -or $end.Year -lt 2000 -or $end -lt $since) { continue }  # still running, or old
        $res = switch -regex ([string]$x.Result) { '^Succe' { 'Success' } '^Warn' { 'Warning' } '^Fail' { 'Failed' } default { '' } }
        if (-not $res) { continue }
        $t = $end.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        $r = $rows[$comp]; if (-not $r) { $r = @{ computer = $comp; result = ''; finished = ''; last_success = ''; runs = @() }; $rows[$comp] = $r }
        if ($t -gt $r.finished) { $r.finished = $t; $r.result = $res }
        if ($res -ne 'Failed' -and $t -gt $r.last_success) { $r.last_success = $t }
        $r.runs = @(@($r.runs) + $t | Sort-Object -Unique | Select-Object -Last 12)
    }
    if (-not $rows.Count) {  # no sessions to read: the restore points say when each computer last backed up
        try {
            foreach ($b in @(Get-VBRBackup -ErrorAction Stop | Where-Object { [string]$_.JobName -eq $n -or [string]$_.Name -like "$n*" })) {
                foreach ($rp in @(Get-VBRRestorePoint -Backup $b -ErrorAction Stop)) {
                    $comp = [string]$rp.Name; $ct = $rp.CreationTime
                    if (-not $comp -or -not ($ct -is [DateTime])) { continue }
                    $t = $ct.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
                    $r = $rows[$comp]; if (-not $r) { $r = @{ computer = $comp; result = 'Success'; finished = ''; last_success = ''; runs = @(); from = 'restore points' }; $rows[$comp] = $r }
                    if ($t -gt $r.finished) { $r.finished = $t; $r.last_success = $t }
                    $r.runs = @(@($r.runs) + $t | Sort-Object -Unique | Select-Object -Last 12)
                }
            }
        } catch { }
    }
    foreach ($r in $rows.Values) { $out += [ordered]@{ policy = $n; computer = $r.computer; result = $r.result; finished = $r.finished
        last_success = $r.last_success; runs = @($r.runs); from = $(if ($r.from) { $r.from } else { 'sessions' }) } }
}
[ordered]@{ computers = @($out) }
'@ }

function Invoke-VeeamScript([string]$Script, [string]$Arg) {
    # One of the read-only scripts above, with Veeam's PowerShell: in this PowerShell, or PowerShell 7 when the
    # module needs it (Backup & Replication 13). $null if the module isn't there.
    $mod = Get-Module -ListAvailable -Name 'Veeam.Backup.PowerShell' -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $mod) { return $null }
    $needs = $null; try { $needs = [version]$mod.PowerShellVersion } catch { }
    if ($needs -and $needs -gt $PSVersionTable.PSVersion) {
        $pwsh = Find-Pwsh
        if (-not $pwsh) { throw "Veeam's PowerShell needs PowerShell $needs or later, which isn't installed" }
        $b64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($Arg))
        $cmd = "& { $Script } ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('$b64'))) | ConvertTo-Json -Depth 6 -Compress"
        $txt = Invoke-InPwsh $pwsh $cmd
        $line = @($txt -split "`r?`n" | Where-Object { $_.Trim().StartsWith('{') }) | Select-Object -Last 1
        if ($line) { return ($line | ConvertFrom-Json) }
        return $null
    }
    return (& ([scriptblock]::Create($Script)) $Arg)
}

function Get-VeeamPolicyComputers($State, [string[]]$Policies) {
    # Agent policies' computers (Get-VeeamPolicyScript), read at most hourly; the last answer in between
    $Policies = @($Policies | Where-Object { $_ } | Sort-Object -Unique)
    if (-not $Policies.Count) { return @() }
    $nowSecs = [int64]([DateTime]::UtcNow - [DateTime]'1970-01-01').TotalSeconds
    $key = $Policies -join "`n"
    if ($State.veeam_policy -and $State.veeam_policy_key -eq $key -and ($nowSecs - [int64]$State.veeam_policy_checked) -lt 3600) {
        try { return @(@(ConvertFrom-Json $State.veeam_policy) | Where-Object { $_ }) } catch { }
    }
    $rows = @()
    try {
        $r = Invoke-VeeamScript (Get-VeeamPolicyScript) $key
        if ($r) { $rows = @(@($r.computers) | Where-Object { $_ } | ForEach-Object { [ordered]@{ policy = [string]$_.policy; computer = [string]$_.computer
            result = [string]$_.result; finished = (ConvertTo-IsoText $_.finished); last_success = (ConvertTo-IsoText $_.last_success)
            runs = @(@($_.runs) | Where-Object { $_ } | ForEach-Object { ConvertTo-IsoText $_ }); from = [string]$_.from } }) }
    } catch { Write-AgentLog "WARN Veeam PowerShell couldn't read the agent policies' computers: $($_.Exception.Message)" }
    $State.veeam_policy = (ConvertTo-Json @($rows) -Depth 5 -Compress); $State.veeam_policy_key = $key; $State.veeam_policy_checked = $nowSecs
    return $rows
}

function Find-Pwsh {
    # PowerShell 7, for modules that need it
    foreach ($c in @((Get-Command pwsh.exe -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty Source),
                     "$env:ProgramFiles\PowerShell\7\pwsh.exe", "$env:ProgramFiles\PowerShell\7-preview\pwsh.exe")) {
        if ($c -and (Test-Path -LiteralPath $c)) { return $c }
    }
    return $null
}

function Invoke-InPwsh([string]$Pwsh, [string]$Command, [int]$TimeoutSec = 180) {
    # Runs a command in PowerShell 7 and returns what it printed; stopped after TimeoutSec
    $enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($Command))
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $Pwsh
    $psi.Arguments = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand $enc"
    $psi.UseShellExecute = $false; $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true; $psi.CreateNoWindow = $true
    $p = [System.Diagnostics.Process]::Start($psi)
    $out = $p.StandardOutput.ReadToEndAsync(); $err = $p.StandardError.ReadToEndAsync()
    if (-not $p.WaitForExit($TimeoutSec * 1000)) { try { $p.Kill() } catch { }; throw "PowerShell 7 didn't finish within $TimeoutSec s" }
    if ($p.ExitCode -ne 0) { throw ("PowerShell 7: " + (($err.Result -split "`r?`n" | Where-Object { $_ } | Select-Object -First 1) -as [string])) }
    return $out.Result
}

function Get-VeeamRunIssue([string]$Log, [string]$Session, [string]$JobId = '', [string]$Since, [string]$Until, [switch]$NoPowerShell) {
    # Why one run of a Veeam job warned or failed: from Veeam's PowerShell on a backup server (Backup &
    # Replication 11 or later; 13 and later through PowerShell 7), else from the Veeam event log between the
    # run before and this one finishing.
    $issue = [ordered]@{ session = $Session; source = ''; objects = @(); log = @() }
    $mod = if (-not $NoPowerShell -and $Session -match '^[0-9a-fA-F-]{36}$') { Get-Module -ListAvailable -Name 'Veeam.Backup.PowerShell' -ErrorAction SilentlyContinue | Select-Object -First 1 }
    if ($mod) {
        try {
            $r = $null
            $needs = $null; try { $needs = [version]$mod.PowerShellVersion } catch { }
            if ($needs -and $needs -gt $PSVersionTable.PSVersion) {
                $pwsh = Find-Pwsh
                if (-not $pwsh) { throw "Veeam's PowerShell needs PowerShell $needs or later, which isn't installed" }
                $cmd = "& { $(Get-VeeamLookupScript) } '$Session' | ConvertTo-Json -Depth 6 -Compress"
                $txt = Invoke-InPwsh $pwsh $cmd
                $line = @($txt -split "`r?`n" | Where-Object { $_.Trim().StartsWith('{') }) | Select-Object -Last 1
                if ($line) { $r = $line | ConvertFrom-Json }
            } else {
                $r = & ([scriptblock]::Create((Get-VeeamLookupScript))) $Session
            }
            if ($r) {
                $issue.source = 'Veeam PowerShell'
                $issue.objects = @(@($r.objects) | Where-Object { $_ } | ForEach-Object { [ordered]@{ name = [string]$_.name; status = [string]$_.status
                    reason = [string]$_.reason; details = @(@($_.details) | Where-Object { $_ } | ForEach-Object { [string]$_ }) } })
                $issue.log = @(@($r.log) | Where-Object { $_ } | ForEach-Object { [ordered]@{ status = [string]$_.status; text = [string]$_.text } })
                return $issue
            }
        } catch { Write-AgentLog "WARN Veeam PowerShell couldn't read the run: $($_.Exception.Message)" }
    }
    # The event log: warnings and errors written during the run (not the job's own "finished" event)
    $issue.source = 'event log'
    try {
        $from = [DateTime]::Parse($Since).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.000Z')
        $to = [DateTime]::Parse($Until).ToUniversalTime().AddSeconds(5).ToString('yyyy-MM-ddTHH:mm:ss.000Z')
        $xp = "*[System[(Level=2 or Level=3) and TimeCreated[@SystemTime>'$from' and @SystemTime<='$to']]]"
        $evs = @(Get-WinEvent -LogName $Log -FilterXPath $xp -MaxEvents 200 -ErrorAction Stop | Sort-Object RecordId)
        $mine = @($evs | Where-Object { $x = $_.ToXml(); ($Session -match '^[0-9a-fA-F-]{36}$' -and $x -match [regex]::Escape($Session)) -or ($JobId -match '^[0-9a-fA-F-]{36}$' -and $x -match [regex]::Escape($JobId)) })
        if ($mine.Count) { $evs = $mine }  # events that name this run or job, when there are any
        $issue.log = @($evs | Where-Object { $_.Id -notin 190, 191, 490, 790 } | Select-Object -Last 20 | ForEach-Object {
            $t = ''; try { $t = [string]$_.Message } catch { }
            [ordered]@{ status = $(if ($_.Level -eq 2) { 'Failed' } else { 'Warning' }); text = (Limit-Text (($t -split "`r?`n")[0] -replace '\s+', ' ') 400) } } | Where-Object { $_.text })
    } catch { }
    return $issue
}

function Get-VeeamJobs($State) {
    # Veeam Backup & Replication: every job writes a "... job '<name>' finished with
    # <result>" event to the Veeam Backup log (190 backup and replication, 490 backup
    # copy, 790 agent backup...). Each job's latest result and recent run times are kept
    # in the state file, so a job that stops running at all can be spotted too.
    $jobs = @{}
    if ($State.veeam) {
        try {
            foreach ($p in ($State.veeam | ConvertFrom-Json).PSObject.Properties) {
                $v = $p.Value
                $jobs[$p.Name] = @{ name = [string]$v.name; type = [string]$v.type; result = [string]$v.result; finished = (ConvertTo-IsoText $v.finished)
                    retry = [bool]$v.retry; detail = [string]$v.detail; last_success = (ConvertTo-IsoText $v.last_success); session = [string]$v.session
                    runs = @($v.runs | Where-Object { $_ } | ForEach-Object { ConvertTo-IsoText $_ }); issue = $v.issue }
            }
        } catch { }
    }
    $hasLog = $false
    try { $hasLog = [bool](Get-WinEvent -ListLog 'Veeam Backup' -ErrorAction Stop) } catch { }
    if (-not $hasLog -and -not $jobs.Count) { return $null }
    if ($hasLog) {
        $xp = if ($State.veeam_cursor) { "*[System[EventRecordID>$([int64]$State.veeam_cursor)]]" }
              else { "*[System[TimeCreated[timediff(@SystemTime) <= $(30 * 86400000)]]]" }
        $events = @()
        try { $events = @(Get-WinEvent -LogName 'Veeam Backup' -FilterXPath $xp -MaxEvents 5000 -ErrorAction Stop | Sort-Object RecordId) }
        catch { if (-not ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*' -or $_.Exception.Message -like 'No events were found*')) { throw } }
        foreach ($e in $events) {
            if ($e.RecordId -gt [int64]$State.veeam_cursor) { $State.veeam_cursor = [int64]$e.RecordId }
            $vals = @()
            try { $vals = @(([xml]$e.ToXml()).Event.EventData.Data | ForEach-Object { if ($_ -is [string]) { $_ } elseif ($_) { [string]$_.'#text' } else { '' } }) } catch { continue }
            if ($vals.Count -lt 3) { continue }
            $desc = [string]$vals[$vals.Count - 1]
            # Most say "Backup job 'Name' finished with Success."; agent backup jobs (event 790) leave
            # out the quotes: "Agent Backup job Name finished with Success."
            if ($desc -notmatch "^(?<type>.+?) job (?:'(?<name>.+)'|(?<bare>.+?)) finished with (?<res>\w+)\.?\s*(?<detail>.*)$") { continue }
            $jname = if ($Matches['name']) { $Matches['name'] } else { $Matches['bare'] }
            $jtype = $Matches['type']; $jdetail = $Matches['detail']; $jres = $Matches['res']
            if ($vals.Count -gt 6 -and [string]$vals[6]) { $jname = [string]$vals[6] }  # the job's own spelling
            $res = switch ([string]$vals[2]) { '0' { 'Success' } '1' { 'Warning' } '2' { 'Failed' } default { $jres } }
            $id = if ([string]$vals[1] -match '^[0-9a-fA-F-]{36}$') { [string]$vals[1] } else { $jname }
            $when = ConvertTo-UtcString $e.TimeCreated
            $j = if ($jobs.ContainsKey($id)) { $jobs[$id] } else { @{ runs = @(); last_success = '' } }
            $j.name = $jname; $j.type = $jtype; $j.result = $res; $j.finished = $when
            $j.detail = Limit-Text $jdetail 200; $j.session = [string]$vals[0]
            $j.retry = ($res -eq 'Failed' -and $vals.Count -gt 5 -and [string]$vals[5] -eq 'True')
            if ($res -ne 'Failed') { $j.last_success = $when }
            if (@($j.runs) -notcontains $when) { $j.runs = @(@($j.runs) + $when | Select-Object -Last 12) }
            $jobs[$id] = $j
        }
    }
    # Forget jobs with no run for 60 days (deleted, or retired).
    $cutoff = (Get-Date).ToUniversalTime().AddDays(-60).ToString('yyyy-MM-ddTHH:mm:ssZ')
    foreach ($k in @($jobs.Keys)) { if ($jobs[$k].finished -and [string]$jobs[$k].finished -lt $cutoff) { $jobs.Remove($k) } }
    # Why the latest run of a job warned or failed: looked up once per run
    $looked = 0
    foreach ($k in @($jobs.Keys)) {
        $j = $jobs[$k]
        if ($j.result -notin 'Warning', 'Failed') { $j.issue = $null; continue }
        if ($j.issue -and [string]$j.issue.session -eq [string]$j.session) { continue }
        if ($looked -ge 5) { continue }  # a few per run, so one bad night doesn't make a slow run
        $looked++
        $since = Get-PreviousRun $j.runs $j.finished
        $j.issue = Get-VeeamRunIssue -Log 'Veeam Backup' -Session $j.session -JobId $k -Since $since -Until $j.finished
    }
    $State.veeam = ($jobs | ConvertTo-Json -Depth 7 -Compress)
    $list = @(foreach ($k in $jobs.Keys) { $j = $jobs[$k]
        [ordered]@{ source = 'Backup & Replication'; id = $k; name = $j.name; type = $j.type; result = $j.result; finished = $j.finished
            retry = [bool]$j.retry; detail = $j.detail; last_success = $j.last_success; session = $j.session; runs = @($j.runs); issue = $j.issue } })
    # Agent policies: each computer's own backups, listed under the policy as "<policy>\<computer>"
    $pol = @($list | Where-Object { [string]$_.type -match '(?i)\b(agent|backup) policy\b' })
    if ($pol.Count) {
        foreach ($c in @(Get-VeeamPolicyComputers $State @($pol | ForEach-Object { [string]$_.name }))) {
            $p = $pol | Where-Object { [string]$_.name -eq [string]$c.policy } | Select-Object -First 1
            $list += [ordered]@{ source = 'Backup & Replication'; id = "$(if ($p) { $p.id } else { $c.policy })\$($c.computer)"
                name = "$($c.policy)\$($c.computer)"; type = 'Agent backup'; result = $c.result; finished = $c.finished; retry = $false
                detail = $(if ($c.from -eq 'restore points') { 'from its restore points' } else { '' }); last_success = $c.last_success
                session = $c.finished; runs = @($c.runs); issue = $null }
        }
    }
    return $list
}

function Get-VeeamAgentJobs($State) {
    # Veeam Agent for Microsoft Windows on this computer (standalone, or managed by a backup server
    # through a backup policy or agent backup job): each session writes event 190 "Veeam Agent
    # 'Name' finished with Success." (191 when it failed and will be retried) to its own log.
    $jobs = @{}
    if ($State.veeam_agent) {
        try {
            foreach ($p in ($State.veeam_agent | ConvertFrom-Json).PSObject.Properties) {
                $v = $p.Value
                $jobs[$p.Name] = @{ name = [string]$v.name; result = [string]$v.result; finished = (ConvertTo-IsoText $v.finished)
                    retry = [bool]$v.retry; detail = [string]$v.detail; last_success = (ConvertTo-IsoText $v.last_success)
                    runs = @($v.runs | Where-Object { $_ } | ForEach-Object { ConvertTo-IsoText $_ }); issue = $v.issue }
            }
        } catch { }
    }
    $hasLog = $false
    try { $hasLog = [bool](Get-WinEvent -ListLog 'Veeam Agent' -ErrorAction Stop) } catch { }
    if (-not $hasLog -and -not $jobs.Count) { return $null }
    if ($hasLog) {
        $xp = if ($State.veeam_agent_cursor) { "*[System[(EventID=190 or EventID=191) and EventRecordID>$([int64]$State.veeam_agent_cursor)]]" }
              else { "*[System[(EventID=190 or EventID=191) and TimeCreated[timediff(@SystemTime) <= $(30 * 86400000)]]]" }
        $events = @()
        try { $events = @(Get-WinEvent -LogName 'Veeam Agent' -FilterXPath $xp -MaxEvents 2000 -ErrorAction Stop | Sort-Object RecordId) }
        catch { if (-not ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*' -or $_.Exception.Message -like 'No events were found*')) { throw } }
        foreach ($e in $events) {
            if ($e.RecordId -gt [int64]$State.veeam_agent_cursor) { $State.veeam_agent_cursor = [int64]$e.RecordId }
            $texts = @()
            try { $texts = @(([xml]$e.ToXml()).Event.EventData.Data | ForEach-Object { if ($_ -is [string]) { $_ } elseif ($_) { [string]$_.'#text' } else { '' } }) } catch { }
            try { $texts += [string]$e.Message } catch { }
            $m = $null
            foreach ($x in $texts) {
                if ($x -match "Veeam Agent (?:'(?<name>[^']+)'|(?<bare>.+?)) finished with (?<res>\w+)") { $m = $Matches; break }
            }
            if (-not $m) { continue }
            $jname = if ($m['name']) { $m['name'] } else { $m['bare'] }
            $res = switch -regex ([string]$m['res']) { '^Succe' { 'Success' } '^Warn' { 'Warning' } '^(Fail|Err)' { 'Failed' } default { [string]$m['res'] } }
            if ($e.Id -eq 191) { $res = 'Failed' }
            elseif ($e.Level -eq 2) { $res = 'Failed' } elseif ($e.Level -eq 3 -and $res -eq 'Success') { $res = 'Warning' }
            $detail = ''
            foreach ($x in $texts) { if ($x -match 'Job details:\s*(?<d>.+)') { $detail = $Matches['d'].Trim(); break } }
            $id = "agent:$jname"
            $when = ConvertTo-UtcString $e.TimeCreated
            $j = if ($jobs.ContainsKey($id)) { $jobs[$id] } else { @{ runs = @(); last_success = '' } }
            $j.name = $jname; $j.result = $res; $j.finished = $when; $j.detail = Limit-Text $detail 200
            $j.retry = ($e.Id -eq 191)
            if ($res -ne 'Failed') { $j.last_success = $when }
            if (@($j.runs) -notcontains $when) { $j.runs = @(@($j.runs) + $when | Select-Object -Last 12) }
            $jobs[$id] = $j
        }
    }
    $cutoff = (Get-Date).ToUniversalTime().AddDays(-60).ToString('yyyy-MM-ddTHH:mm:ssZ')
    foreach ($k in @($jobs.Keys)) { if ($jobs[$k].finished -and [string]$jobs[$k].finished -lt $cutoff) { $jobs.Remove($k) } }
    foreach ($k in @($jobs.Keys)) {
        $j = $jobs[$k]
        if ($j.result -notin 'Warning', 'Failed') { $j.issue = $null; continue }
        if ($j.issue -and [string]$j.issue.session -eq [string]$j.finished) { continue }
        $since = Get-PreviousRun $j.runs $j.finished
        $j.issue = Get-VeeamRunIssue -Log 'Veeam Agent' -Session $j.finished -Since $since -Until $j.finished -NoPowerShell
    }
    $State.veeam_agent = ($jobs | ConvertTo-Json -Depth 7 -Compress)
    return @(foreach ($k in $jobs.Keys) { $j = $jobs[$k]
        [ordered]@{ source = 'Veeam Agent'; id = $k; name = $j.name; type = 'Agent backup (this device)'; result = $j.result; finished = $j.finished
            retry = [bool]$j.retry; detail = $j.detail; last_success = $j.last_success; session = $j.finished; runs = @($j.runs); issue = $j.issue } })
}

# ---- Other backup products ----------------------------------------------------------------------------------------
# Each is a small definition: how to find its command on this computer, and how to turn the command's output into
# job results ({ id; name; type; result = Success | Warning | Failed; finished (UTC); detail }). Get-BackupProductJobs
# keeps each job's history in the state file (as for Veeam), so a job that stops running is spotted too, and feeds
# the same Backups check and tab. Only read: each command lists jobs and changes nothing.
function Get-NbuStatusText([int]$Code) {
    $t = @{ 1 = 'partially successful: some files were not backed up'; 2 = 'none of the requested files were backed up'
    13 = 'file read failed'; 24 = 'socket write failed'; 25 = 'cannot connect on socket'; 41 = 'network connection timed out'
    42 = 'network read failed'; 48 = 'client hostname could not be found'; 50 = 'client process aborted'
    54 = 'timed out connecting to client'; 58 = "can't connect to client"; 59 = 'access to the client was not allowed'
    71 = 'none of the files in the file list exist'; 84 = 'media write error'; 96 = 'unable to allocate new media for backup'
    150 = 'termination requested by administrator'; 156 = 'snapshot error encountered'
    196 = 'client backup was not attempted because the backup window closed'; 800 = 'resource request failed'
    2074 = 'disk volume is down'; 2106 = 'disk storage server is down' }
    if ($t.ContainsKey($Code)) { return $t[$Code] }
    return 'see the NetBackup status code reference'
}

function ConvertFrom-NbuJobs([string[]]$Lines) {
    # bpdbjobs -report -all_columns: one job per line, commas between fields ("\," inside one). Fields: jobid, jobtype,
    # state, status, policy, schedule, client, server, started, elapsed, ended (Unix times), ... Backups (type 0) and
    # catalog backups (6) that are done (state 3); status 0 is success, 1 partly successful, anything else failed.
    $out = @()
    foreach ($ln in $Lines) {
        $f = @([regex]::Split([string]$ln, '(?<!\\),') | ForEach-Object { $_ -replace '\\,', ',' })
        if ($f.Count -lt 11 -or $f[0] -notmatch '^\d+$') { continue }
        if ($f[1] -notin '0', '6' -or $f[2] -ne '3' -or $f[3] -notmatch '^\d+$' -or $f[10] -notmatch '^\d+$' -or [int64]$f[10] -le 0) { continue }
        $code = [int]$f[3]
        $res = if ($code -eq 0) { 'Success' } elseif ($code -eq 1) { 'Warning' } else { 'Failed' }
        $policy = $(if ($f[1] -eq '6') { 'Catalog backup' } else { $f[4] }); $client = $f[6]
        $why = if ($code -eq 0) { '' } else { "status ${code}: $(Get-NbuStatusText $code)" }
        $out += [ordered]@{ id = "nbu:$policy|$client"; name = "$policy / $client"; type = "NetBackup $(if ($f[5]) { $f[5] } else { 'backup' })"
            result = $res; finished = ([DateTime]'1970-01-01Z').AddSeconds([int64]$f[10]).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
            detail = $why; job = $f[0] }
    }
    return $out
}

function ConvertFrom-DpSessions([string[]]$Lines) {
    # omnirpt -report list_sessions -tab: lines starting # are headings (the last one names the columns), the rest
    # one session each, tabs between. Backup sessions that have finished: Completed is a success, Completed/Errors and
    # Completed/Failures finished with warnings, Failed and Aborted failed.
    $head = $null; $out = @()
    foreach ($ln in $Lines) {
        if ([string]$ln -match '^#') { if ($ln -match "`t") { $head = @(($ln -replace '^#\s*', '') -split "`t" | ForEach-Object { $_.Trim() }) }; continue }
        if (-not $head -or [string]$ln -notmatch "`t") { continue }
        $v = @($ln -split "`t"); $r = @{}
        for ($i = 0; $i -lt [Math]::Min($head.Count, $v.Count); $i++) { $r[$head[$i]] = ([string]$v[$i]).Trim() }
        if ($r['Session Type'] -and $r['Session Type'] -ne 'Backup') { continue }
        $res = switch -regex ([string]$r['Status']) { '^Completed$' { 'Success' } '^Completed/' { 'Warning' } '^(Failed|Aborted)' { 'Failed' } default { '' } }
        if (-not $res) { continue }  # in progress, queuing, waiting for a mount
        $end = $null
        foreach ($k in 'End Time_t', 'Start Time_t') { if ($r[$k] -match '^\d{9,}$') { $end = ([DateTime]'1970-01-01Z').AddSeconds([int64]$r[$k]).ToUniversalTime(); break } }
        if (-not $end) { foreach ($k in 'End Time', 'Start Time') { $t = [DateTime]::MinValue; if ($r[$k] -and [DateTime]::TryParse($r[$k], [ref]$t)) { $end = $t.ToUniversalTime(); break } } }
        if (-not $end) { continue }
        $spec = $(if ($r['Specification']) { $r['Specification'] } else { 'Interactive' })
        $bits = @()
        if ($res -ne 'Success') { $bits += ([string]$r['Status']).ToLower() -replace '/', ' with ' }
        foreach ($k in 'Errors', 'Warnings') { if ($r[$k] -match '^\d+$' -and [int]$r[$k] -gt 0) { $bits += "$($r[$k]) $($k.ToLower().TrimEnd('s'))(s)" } }
        if ($r['Failed DA'] -match '^\d+$' -and [int]$r['Failed DA'] -gt 0) {
            $all = [int]$r['Failed DA'] + $(if ($r['Completed DA'] -match '^\d+$') { [int]$r['Completed DA'] } else { 0 })
            $bits += "$($r['Failed DA']) of $all disk agents failed"
        }
        $out += [ordered]@{ id = "dp:$spec"; name = $spec; type = "Data Protector $(if ($r['Mode']) { $r['Mode'] } else { 'backup' })"
            result = $res; finished = $end.ToString('yyyy-MM-ddTHH:mm:ssZ'); detail = ($bits -join '; '); job = [string]$r['Session ID'] }
    }
    return $out
}

function Get-BackupProducts {
    return @(
        @{ name = 'NetBackup'; key = 'nbu'
           find = { foreach ($c in @("$env:ProgramFiles\Veritas\NetBackup\bin\admincmd\bpdbjobs.exe", (Get-Command bpdbjobs.exe -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty Source))) { if ($c -and (Test-Path -LiteralPath $c)) { return $c } } }
           read = { param($exe) ConvertFrom-NbuJobs @(& $exe -report -all_columns 2>$null) } },
        @{ name = 'Data Protector'; key = 'dp'
           find = { foreach ($c in @("$env:ProgramFiles\OmniBack\bin\omnirpt.exe", (Get-Command omnirpt.exe -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty Source))) { if ($c -and (Test-Path -LiteralPath $c)) { return $c } } }
           read = { param($exe) ConvertFrom-DpSessions @(& $exe -report list_sessions -timeframe 168 168 -tab 2>$null) } }
    )
}

function Get-BackupProductJobs($State, $Products = (Get-BackupProducts)) {
    # Every product found on this computer: its jobs' latest results, with their history kept here. $null if none.
    $all = @(); $found = $false
    foreach ($p in $Products) {
        $exe = & $p.find
        $key = "bp_$($p.key)"
        if (-not $exe -and -not $State.$key) { continue }
        $found = $true
        $jobs = @{}
        if ($State.$key) {
            try { foreach ($q in ($State.$key | ConvertFrom-Json).PSObject.Properties) { $v = $q.Value
                $jobs[$q.Name] = @{ name = [string]$v.name; type = [string]$v.type; result = [string]$v.result; finished = (ConvertTo-IsoText $v.finished)
                    detail = [string]$v.detail; last_success = (ConvertTo-IsoText $v.last_success); job = [string]$v.job
                    runs = @($v.runs | Where-Object { $_ } | ForEach-Object { ConvertTo-IsoText $_ }) } } } catch { }
        }
        if ($exe) {
            $rows = @()
            try { $rows = @(& $p.read $exe) } catch { Write-AgentLog "WARN $($p.name): couldn't read its jobs: $($_.Exception.Message)" }
            foreach ($r in @($rows | Sort-Object { $_.finished })) {
                $j = if ($jobs.ContainsKey($r.id)) { $jobs[$r.id] } else { @{ runs = @(); last_success = '' } }
                if ($j.finished -and [string]$r.finished -lt [string]$j.finished) { continue }
                $j.name = $r.name; $j.type = $r.type; $j.result = $r.result; $j.finished = $r.finished; $j.detail = Limit-Text $r.detail 300; $j.job = $r.job
                if ($r.result -ne 'Failed') { $j.last_success = $r.finished }
                if (@($j.runs) -notcontains $r.finished) { $j.runs = @(@($j.runs) + $r.finished | Select-Object -Last 12) }
                $jobs[$r.id] = $j
            }
        }
        $cutoff = (Get-Date).ToUniversalTime().AddDays(-60).ToString('yyyy-MM-ddTHH:mm:ssZ')
        foreach ($k in @($jobs.Keys)) { if ($jobs[$k].finished -and [string]$jobs[$k].finished -lt $cutoff) { $jobs.Remove($k) } }
        $State.$key = ($jobs | ConvertTo-Json -Depth 5 -Compress)
        foreach ($k in $jobs.Keys) { $j = $jobs[$k]
            $issue = if ($j.result -in 'Warning', 'Failed' -and $j.detail) { [ordered]@{ session = $j.finished; source = $p.name; objects = @()
                log = @([ordered]@{ status = $j.result; text = $j.detail }) } } else { $null }
            $all += [ordered]@{ source = $p.name; id = $k; name = $j.name; type = $j.type; result = $j.result; finished = $j.finished
                retry = $false; detail = $j.detail; last_success = $j.last_success; session = "$($j.job)"; runs = @($j.runs); issue = $issue } }
    }
    if (-not $found) { return $null }
    return $all
}

function Get-VboJobs($State) {
    # Veeam Backup for Microsoft 365, through its PowerShell module. Loading the module
    # is slow, so this runs every 30 minutes and the last answer is reused in between.
    if (-not (Get-Service -Name 'Veeam.Archiver.Service' -ErrorAction SilentlyContinue)) { return $null }
    $nowSecs = [int64]([DateTime]::UtcNow - [DateTime]'1970-01-01').TotalSeconds
    if ($State.vbo -and $State.vbo_checked -and ($nowSecs - [int64]$State.vbo_checked) -lt 1800) {
        # Windows PowerShell 5.1's ConvertFrom-Json returns a JSON array as one object rather
        # than one item per job, so unwrap it with foreach instead of the pipeline.
        try {
            $cached = ConvertFrom-Json $State.vbo
            return @(foreach ($j in @($cached)) { if ($null -eq $j) { continue }
                    $o = [ordered]@{}; foreach ($p in $j.PSObject.Properties) { $o[$p.Name] = $(if ($p.Value -is [DateTime]) { ConvertTo-UtcString $p.Value } else { $p.Value }) }; $o })
        } catch { }
    }
    try { Import-Module Veeam.Archiver.PowerShell -ErrorAction Stop -WarningAction SilentlyContinue | Out-Null }
    catch {
        $mod = Get-ChildItem -Path "$env:ProgramFiles\Veeam" -Filter 'Veeam.Archiver.PowerShell.psd1' -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
        if (-not $mod) { throw "Veeam Backup for Microsoft 365's PowerShell module isn't installed or can't be loaded: $($_.Exception.Message)" }
        Import-Module $mod.FullName -ErrorAction Stop -WarningAction SilentlyContinue | Out-Null
    }
    $list = @()
    $sets = @(@{ type = 'Backup'; cmd = 'Get-VBOJob' }, @{ type = 'Backup copy'; cmd = 'Get-VBOCopyJob' })
    foreach ($set in $sets) {
        if (-not (Get-Command $set.cmd -ErrorAction SilentlyContinue)) { continue }
        $jobs = @()
        try { $jobs = @(& $set.cmd -ErrorAction Stop) } catch { Add-CollectorError "veeam m365 ($($set.cmd))" $_; continue }
        foreach ($j in $jobs) {
            $last = $null; $next = $null
            try { if ($j.LastRun -and ([DateTime]$j.LastRun).Year -gt 2000) { $last = ConvertTo-UtcString $j.LastRun } } catch { }
            try { if ($j.NextRun -and ([DateTime]$j.NextRun).Year -gt 2000) { $next = ConvertTo-UtcString $j.NextRun } } catch { }
            $list += [ordered]@{ source = 'Microsoft 365'; id = "vbo:$($j.Name)"; name = [string]$j.Name; type = $set.type; result = [string]$j.LastStatus
                finished = $last; next_run = $next; enabled = [bool]$j.IsEnabled; retry = $false; detail = ''; runs = @() }
        }
    }
    $State.vbo = (ConvertTo-Json -InputObject @($list) -Depth 3 -Compress)
    $State.vbo_checked = $nowSecs
    return $list
}

function Get-StorageHealth($State) {
    # Physical disks and Storage Spaces (Windows 8 / Server 2012 and later), software RAID on
    # dynamic disks (mirrors, RAID-5) from diskpart, and SMART status from the disk drives.
    $st = [ordered]@{ physical = @(); virtual = @(); volumes = @(); dyn_disks = @(); drives = @(); warnings = @(); hardware = @() }
    if (Get-Command Get-PhysicalDisk -ErrorAction SilentlyContinue) {
        try {
            $st.physical = @(Get-PhysicalDisk -ErrorAction Stop | ForEach-Object {
                    [ordered]@{ name = [string]$_.FriendlyName; serial = ([string]$_.SerialNumber).Trim(); media = [string]$_.MediaType; bus = [string]$_.BusType
                        health = [string]$_.HealthStatus; status = (@($_.OperationalStatus) -join ', '); size_gb = [Math]::Round($_.Size / 1GB, 0) }
                })
        } catch { Add-CollectorError 'physical disks' $_ }
        try {
            $st.virtual = @(Get-VirtualDisk -ErrorAction Stop | ForEach-Object {
                    [ordered]@{ name = [string]$_.FriendlyName; layout = [string]$_.ResiliencySettingName
                        health = [string]$_.HealthStatus; status = (@($_.OperationalStatus) -join ', ') }
                })
        } catch { }
    }
    try {
        $st.drives = @(Get-CimInstance -ClassName Win32_DiskDrive -ErrorAction Stop | Where-Object { $_.Status -and $_.Status -ne 'OK' } | ForEach-Object {
                [ordered]@{ name = [string]$_.Model; index = [int]$_.Index; status = [string]$_.Status }
            })
    } catch { }
    try {
        $amd = Get-AmdRaidHealth $State
        if ($amd) {
            $st.volumes = @($st.volumes) + @($amd.volumes)
            $st.warnings = @($amd.warnings)
        }
    } catch { Add-CollectorError 'amd raid' $_ }
    try {
        $dell = Get-DellOmsaHealth
        if ($dell) {
            $st.physical = @($st.physical) + @($dell.physical)
            $st.volumes = @($st.volumes) + @($dell.volumes)
            $st.drives = @($st.drives) + @($dell.drives)
            $st.hardware = @($dell.hardware)
        }
    } catch { Add-CollectorError 'dell omsa' $_ }
    $dynamic = $false
    try { $dynamic = [bool](@(Get-CimInstance -ClassName Win32_DiskPartition -ErrorAction Stop | Where-Object { $_.Type -match 'Logical Disk Manager' }).Count) } catch { }
    if ($dynamic) {
        try {
            $vols = ConvertFrom-DiskPartTable (Invoke-DiskPart 'list volume')
            $st.volumes = @($st.volumes) + @($vols | Where-Object { $_['Type'] -and $_['Type'] -ne 'Partition' -and $_['Type'] -ne 'Removable' -and $_['Type'] -ne 'DVD-ROM' } | ForEach-Object {
                    [ordered]@{ volume = [string]$_['Volume ###']; letter = [string]$_['Ltr']; label = [string]$_['Label']; type = [string]$_['Type']
                        status = [string]$_['Status']; info = [string]$_['Info'] }
                })
            $disks = ConvertFrom-DiskPartTable (Invoke-DiskPart 'list disk')
            $st.dyn_disks = @($disks | Where-Object { $_['Status'] -and $_['Status'] -ne 'Online' } | ForEach-Object {
                    [ordered]@{ disk = ([string]$_['Disk ###']).TrimStart('*', ' '); status = [string]$_['Status']; size = [string]$_['Size'] }
                })
        } catch { Add-CollectorError 'software raid' $_ }
    }
    return $st
}

# ---------------------------------------------------------------------------
# Password exposure scan (opt-in: turned on per computer in the Rollcall dashboard)
# ---------------------------------------------------------------------------
# PRIVACY: no password ever leaves this computer. Not the password, not part of it, not a hash
# of it and not the text around it. A finding holds only:
#   path - the file it is in        line - the line (or paragraph) number
#   rule - which kind of thing matched, e.g. "keyvalue"
#   key  - the setting's name, e.g. "DbPassword" (letters, digits, space and ._- only, up to 40)
#   len  - how many characters the value has
# The matched value is measured and then dropped; it is never stored, logged or sent. The
# findings kept between runs in secrets.json on this computer hold the same fields, nothing more.
# File and folder names are sent as they are, so the admin can find the file.
# The rules are generated from the Linux agent's, so both agents find the same things.
$SecretsPath = Join-Path $DataPath 'secrets.json'
$SecretFilesPath = Join-Path $DataPath 'secrets-files.txt'
$SecretBudget = 45          # seconds of scanning per agent run; carries on next run
$SecretMaxText = 2MB
$SecretMaxOffice = 10MB
$SecretPerFile = 20
$SecretMax = 500
$SecretRules = @(
    ,@('cpassword', '\bcpassword[ \t]*=[ \t]*"([^"\r\n]+)"', 'cpassword', @(1), $null, 'any')
    ,@('unattend', '(?is)<(AdministratorPassword|Password)>\s*<Value>([^<]{1,200})</Value>', '{1}', @(2), $null, 'any')
    ,@('securestring', '(?i)ConvertTo-SecureString[ \t]+(?:-String[ \t]+)?(["\''])([^\r\n]{1,200}?)\1', 'ConvertTo-SecureString', @(2), '(?i)-AsPlainText', 'any')
    ,@('securestring', '(?i)ConvertTo-SecureString\b[^|;\r\n]*?-String[ \t]+(["\''])([^\r\n]{1,200}?)\1', 'ConvertTo-SecureString', @(2), '(?i)-AsPlainText', 'any')
    ,@('param', '(?i)(?:^|[ \t(])-(Password|Passwd|Pwd|Pass|PlainPassword|Secret|ApiKey|Token|ClientSecret)[ \t]+(["\''])([^\r\n]{1,200}?)\2', '-{1}', @(3), $null, 'any')
    ,@('netuse', '(?i)\bnet(?:\.exe)?[ \t]+use\b[^\r\n]*?[ \t]/user:[^ \t\r\n]+[ \t]+("[^"\r\n]+"|[^ \t\r\n/"]+)', 'net use', @(1), $null, 'any')
    ,@('netuse', '(?i)\bnet(?:\.exe)?[ \t]+use[ \t]+(?:[a-z]:[ \t]+|\*[ \t]+)?\\\\[^ \t\r\n]+[ \t]+("[^"\r\n]+"|[^ \t\r\n/"]+)', 'net use', @(1), $null, 'any')
    ,@('netuser', '(?i)\bnet(?:\.exe)?[ \t]+user[ \t]+(?:"[^"\r\n]+"|[^ \t\r\n/"]+)[ \t]+("[^"\r\n]+"|[^ \t\r\n/"*]+)', 'net user', @(1), $null, 'any')
    ,@('url', '(?i)\b([a-z][a-z0-9+.\-]{1,15})://[^ \t\r\n/:@"\''<>]{1,64}:([^ \t\r\n/@"\''<>]{1,128})@[\w.\-]', '{1}', @(2), $null, 'any')
    ,@('cmdline', '\b[Mm]ysql(?:dump|admin)?\b[^|;\r\n]*?[ \t]-p([^ \t\r\n\''"\-][^ \t\r\n\''"]{2,199})', 'mysql -p', @(1), $null, 'any')
    ,@('cmdline', '(?:^|[ \t;|&])sshpass[ \t]+-p[ \t]*(["\'']?)([^ \t\r\n"\'']{1,200})\1', 'sshpass -p', @(2), $null, 'any')
    ,@('cmdline', '(?i)\bcurl\b[^|;\r\n]*?[ \t](?:-u|--user)[ \t]+["\'']?[^: \t\r\n"\'']+:([^ \t\r\n"\'']{1,200})', 'curl -u', @(1), $null, 'any')
    ,@('aws', '\b((?:AKIA|ASIA)[0-9A-Z]{16})\b', 'AWS access key', @(1), $null, 'any')
    ,@('github', '\b(gh[pousr]_[A-Za-z0-9]{36,251}|github_pat_[A-Za-z0-9_]{22,250})\b', 'GitHub token', @(1), $null, 'any')
    ,@('slack', '\b(xox[abposr]-[A-Za-z0-9\-]{10,200})', 'Slack token', @(1), $null, 'any')
    ,@('azurekey', '(?i)\b(AccountKey|SharedAccessKey)[ \t]*=[ \t]*([A-Za-z0-9+/]{20,}={0,2})', '{1}', @(2), $null, 'any')
    ,@('connstring', '(?i)(?:^|[;"\'' \t])(password|pwd)[ \t]*=[ \t]*([^;"\''<> \t\r\n][^;"\''<>\r\n]{0,199})', '{1}', @(2), '(?i)(server|data source|user id|uid|host|database|initial catalog)[ \t]*=[^;\r\n]*;', 'any')
    ,@('appsetting', '(?i)\bkey[ \t]*=[ \t]*"([^"\r\n]*(?:password|passwd|pwd|secret|api[_\-]?key|token)[^"\r\n]*)"[ \t]+value[ \t]*=[ \t]*"([^"\r\n]{1,200})"', '{1}', @(2), $null, 'any')
    ,@('xml', '(?i)<([a-z0-9_:.\-]*(?:password|passwd|pwd|secret)[a-z0-9_:.\-]*)(?:[ \t][^>\r\n]*)?>([^<\r\n]{1,200})</', '{1}', @(2), $null, 'any')
    ,@('keyvalue', '(?i)(?:^|[ \t;,{(\[&?"\''<$@])([a-z0-9_.\-]*(?:password|passwd|passwort|kennwort|wachtwoord|pwd|secret|api[_\-]?key|access[_\-]?key|auth[_\-]?token|access[_\-]?token|client[_\-]?secret|private[_\-]?key)[a-z0-9_.\-]*)["\'']?[ \t]*[:=][ \t]*(?:"([^"\r\n]{1,200})"|\''([^\''\r\n]{1,200})\''|([^ \t\r\n"\'',;}<>]{1,200}))', '{1}', @(2, 3, 4), $null, 'any')
    ,@('notes', '(?i)(?:^|[ \t(\[,;:\-])(password|passwd|passcode|pass|pwd|pw|kennwort|passwort|wachtwoord)[ \t]*(?:is[ \t]+|:|=|-)[ \t]*["\'']?([^ \t\r\n"\'']{4,200})', '{1}', @(2), $null, 'doc')
    ,@('savedlogin', '(?i)\bpassword[ \t]+([^ \t\r\n]{1,200})', 'password', @(1), $null, 'netrc')
    ,@('savedlogin', '(?m)^[^#:\r\n]+:[^:\r\n]*:[^:\r\n]*:[^:\r\n]*:([^\r\n]{1,200})', '.pgpass', @(1), $null, 'pgpass')
    ,@('privkey', '(?m)^Encryption:[ \t]*none', 'PuTTY key', @(), $null, 'any')
)
$SecretKeySkip = New-Object Text.RegularExpressions.Regex('(?i)(expir|polic|length|_len|maxage|minage|age$|hint|reset|requir|change|complex|histor|never|last|count|min[_\-]|max[_\-]|_min|_max|minimum|maximum|enabled|type|format|prompt|label|file|path|url|uri|hash|salt|field|column|placeholder|validat|strength|rule|mode|timeout|attempt|lockout|forgot|manager)')
$SecretPlaceholder = New-Object Text.RegularExpressions.Regex('(?i)^(\$[\w{(]|%[\w()]+%|\{\{|\{%|<%|<[\w/!]|#\{|@\{|@\(|\[\[|env[:.]|process\.env|os\.environ|getenv|\(|vault[:(]|enc\(|encrypted[:(]|\{cipher\}|!vault|secretref|keyvault|/|\\\\|[a-z]:\\)')
$SecretSheetHeader = New-Object Text.RegularExpressions.Regex('(?i)^[ \t"]*(passwords?|passwd|pwd|pw|pass|kennwort|passwort|wachtwoord)[ \t"]*$')
$SecretFileName = New-Object Text.RegularExpressions.Regex('(?i)^((my[ _\-]?)?(password|passwd|pwd|login|credential|secret)s?|creds|(.*[^a-z])?(passwords|passwds|pwds|logins|credentials|creds|kennw(\u00f6|oe)rter|passw(\u00f6|oe)rter|wachtwoorden)([^a-z].*)?)$')
$SecretWords = @('always', 'auto', 'default', 'disabled', 'dummy', 'empty', 'enabled', 'example', 'false', 'fixme', 'hidden', 'masked', 'n/a', 'never', 'nil', 'no', 'none', 'not_set', 'notset', 'null', 'optional', 'pass', 'passwd', 'password', 'placeholder', 'prompt', 'redacted', 'required', 'sample', 'secret', 'string', 'tbd', 'todo', 'token', 'true', 'undefined', 'unset', 'yes', 'your-password', 'your_password', 'yourpassword')
$SecretSkipDirs = @('$recycle.bin', '.cache', '.cargo', '.config', '.gem', '.git', '.gradle', '.hg', '.local', '.m2',
    '.mozilla', '.npm', '.nuget', '.nvm', '.pyenv', '.rbenv', '.rustup', '.svn', '.thunderbird', '.trash', '.venv',
    '.vscode-server', '__pycache__', 'anaconda3', 'appdata', 'bower_components', 'dist-packages', 'miniconda3',
    'node_modules', 'packages', 'program files', 'program files (x86)', 'programdata', 'site-packages', 'snap',
    'system volume information', 'trash', 'vendor', 'venv', 'windows', 'winsxs')
$SecretTextExt = @('bash', 'bat', 'cfg', 'cmd', 'cnf', 'conf', 'config', 'cs', 'csv', 'env', 'go', 'inc', 'ini',
    'java', 'js', 'json', 'key', 'md', 'pem', 'php', 'ppk', 'properties', 'ps1', 'psd1', 'psm1', 'py', 'rb', 'reg',
    'rtf', 'sh', 'sql', 'tfvars', 'toml', 'ts', 'txt', 'udl', 'vbs', 'xml', 'yaml', 'yml', 'zsh')
$SecretTextNames = @('.bash_history', '.boto', '.env', '.git-credentials', '.my.cnf', '.mysql_history', '.netrc',
    '.npmrc', '.pgpass', '.psql_history', '.pypirc', '.python_history', '.s3cfg', '.sh_history', '.zsh_history',
    '_netrc', 'credentials', 'id_dsa', 'id_ecdsa', 'id_ed25519', 'id_rsa')
$SecretDocExt = @('csv', 'docx', 'md', 'rtf', 'txt', 'xlsx')
$SecretCodeExt = @('cs', 'go', 'java', 'js', 'php', 'ps1', 'psm1', 'py', 'rb', 'ts', 'vbs')
$SecretNameOnlyExt = @('doc', 'ods', 'odt', 'pdf', 'xls')

function Get-SecretRules {
    if (-not $script:SecretRx) {
        $script:SecretRx = @(foreach ($r in $SecretRules) {
                $need = $null
                if ($r[4]) { $need = New-Object Text.RegularExpressions.Regex($r[4]) }
                @{ id = $r[0]; rx = New-Object Text.RegularExpressions.Regex($r[1], [Text.RegularExpressions.RegexOptions]::Multiline)
                    key = $r[2]; vals = @($r[3]); need = $need; scope = $r[5] }
            })
    }
    return $script:SecretRx
}

# How long the value is if it looks like a real secret, else $null. The value itself is not kept.
function Get-SecretValueLength([string]$Value, [string]$Key, [bool]$Quoted, [string]$Kind) {
    $v = $Value.Trim()
    if (-not $Quoted) { $v = $v.TrimEnd([char[]]'.,;)') }
    if ($v.Length -ge 2 -and ($v[0] -eq [char]'"' -or $v[0] -eq [char]"'") -and $v[$v.Length - 1] -eq $v[0]) {
        $v = $v.Substring(1, $v.Length - 2); $Quoted = $true
    }
    $low = $v.ToLowerInvariant()
    if ($v.Length -lt 4 -or $SecretPlaceholder.IsMatch($v) -or [regex]::IsMatch($v, '^(.)\1+$') -or $SecretWords -ccontains $low) { return $null }
    if ($low.Contains('example') -or $low.Contains('xxxx') -or $v.Contains('****') -or $v.Contains([string][char]0x2026) -or $v.Contains('<') -or $low -ceq $Key.ToLowerInvariant()) { return $null }
    if (-not $Quoted) {
        if ($Kind -eq 'code' -or $v.Contains('(') -or [regex]::IsMatch($v, '^[A-Za-z_]\w*(\.\w+)+$')) { return $null }
    }
    return $v.Length
}

# For free text: the word after "password" only counts if it looks like one (a digit or symbol,
# or a capital letter after the first character).
function Test-SecretComplex([string]$Value) {
    $v = $Value.Trim().TrimEnd([char[]]'.,;)')
    return ([regex]::IsMatch($v, '[^A-Za-z]') -or ($v.Length -gt 1 -and [regex]::IsMatch($v.Substring(1), '[A-Z]')))
}

function New-SecretFinding($Line, [string]$Rule, [string]$Key, $Len) {
    return [ordered]@{ line = $Line; rule = $Rule; key = $Key; len = $Len }
}

# Run the rules over a file's text. Returns findings without any of the matched text.
function Get-SecretTextFindings([string]$Text, [string]$Kind, [string]$Special = '') {
    $out = New-Object System.Collections.ArrayList
    $seen = @{}; $hitLines = @{}
    $starts = New-Object 'System.Collections.Generic.List[int]'
    $starts.Add(0)
    foreach ($m in [regex]::Matches($Text, "`n")) { $starts.Add($m.Index + 1) }
    $sa = $starts.ToArray()
    foreach ($r in (Get-SecretRules)) {
        if ($r.scope -eq 'doc' -and $Kind -ne 'doc') { continue }
        if (($r.scope -eq 'netrc' -or $r.scope -eq 'pgpass') -and $Special -ne $r.scope) { continue }
        foreach ($m in $r.rx.Matches($Text)) {
            $ln = [Array]::BinarySearch($sa, $m.Index)
            if ($ln -lt 0) { $ln = (-bnot $ln) - 1 }
            if ($r.need) {
                $end = if ($ln + 1 -lt $sa.Length) { $sa[$ln + 1] } else { $Text.Length }
                if (-not $r.need.IsMatch($Text.Substring($sa[$ln], $end - $sa[$ln]))) { continue }
            }
            $k = $r.key
            for ($g = 1; $g -lt $m.Groups.Count; $g++) { $k = $k.Replace("{$g}", $m.Groups[$g].Value) }
            $k = [regex]::Replace($k, '[^A-Za-z0-9_.\- ]', '')
            if ($k.Length -gt 40) { $k = $k.Substring(0, 40) }
            $generic = ($r.id -eq 'xml' -or $r.id -eq 'keyvalue' -or $r.id -eq 'notes')
            if (($generic -or $r.id -eq 'appsetting') -and $SecretKeySkip.IsMatch($k)) { continue }
            if ($generic -and $hitLines.ContainsKey($ln)) { continue }  # a more specific rule already reported this line
            $n = $null
            if ($r.vals.Count) {
                $gi = $null
                foreach ($g in $r.vals) { if ($m.Groups[$g].Success) { $gi = $g; break } }
                if ($null -eq $gi) { continue }
                $quoted = -not ($r.id -eq 'notes' -or ($r.id -eq 'keyvalue' -and $gi -eq 4))
                $n = Get-SecretValueLength $m.Groups[$gi].Value $k $quoted $Kind
                if ($null -eq $n) { continue }
                if (($r.id -eq 'notes' -or ($r.id -eq 'keyvalue' -and $gi -eq 4 -and $Kind -eq 'doc')) -and -not (Test-SecretComplex $m.Groups[$gi].Value)) { continue }
            }
            $sig = "$ln|$($k.ToLowerInvariant())"
            if ($seen.ContainsKey($sig)) { continue }
            $seen[$sig] = $true
            if (-not $generic) { $hitLines[$ln] = $true }
            [void]$out.Add((New-SecretFinding ($ln + 1) $r.id $k $n))
        }
    }
    # Private keys with no passphrase
    foreach ($m in [regex]::Matches($Text, '-----BEGIN ((?:RSA |EC |DSA |OPENSSH )?)PRIVATE KEY-----')) {
        $kind = $m.Groups[1].Value.Trim()
        $body = $Text.Substring($m.Index + $m.Length, [Math]::Min(20000, $Text.Length - $m.Index - $m.Length))
        if ($kind -eq 'OPENSSH') {
            $b64 = [regex]::Replace(($body -split '-----END', 2)[0], '\s', '')
            if ($b64.Length -gt 200) { $b64 = $b64.Substring(0, 200) }
            while ($b64.Length % 4) { $b64 += '=' }
            try { $raw = [Convert]::FromBase64String($b64) } catch { continue }
            if ($raw.Length -lt 19 -or [Text.Encoding]::ASCII.GetString($raw, 0, 15) -ne "openssh-key-v1`0") { continue }
            $n = ([int]$raw[15] -shl 24) + ([int]$raw[16] -shl 16) + ([int]$raw[17] -shl 8) + [int]$raw[18]
            if ($raw.Length -lt 19 + $n -or [Text.Encoding]::ASCII.GetString($raw, 19, $n) -ne 'none') { continue }
        } elseif ($body.Substring(0, [Math]::Min(200, $body.Length)).Contains('ENCRYPTED')) { continue }
        $ln = [Array]::BinarySearch($sa, $m.Index)
        if ($ln -lt 0) { $ln = (-bnot $ln) - 1 }
        $label = if ($kind) { "$kind private key" } else { 'private key' }
        [void]$out.Add((New-SecretFinding ($ln + 1) 'privkey' $label $null))
    }
    # Sort by line, keeping the rules' order within a line
    $i = 0
    $sorted = @($out | ForEach-Object { $i++; [pscustomobject]@{ f = $_; l = [int]$_.line; i = $i } } | Sort-Object l, i | ForEach-Object { $_.f })
    return , $sorted
}

function ConvertFrom-XmlText([string]$Xml) {
    $Xml = [regex]::Replace($Xml, '<w:tab/>|<w:br/>', ' ')
    $Xml = [regex]::Replace($Xml, '<[^>]+>', '')
    return $Xml.Replace('&lt;', '<').Replace('&gt;', '>').Replace('&quot;', '"').Replace('&apos;', "'").Replace('&amp;', '&')
}

function Read-ZipEntry($Zip, [string]$Name) {
    $e = $Zip.GetEntry($Name)
    if (-not $e) { return $null }
    $sr = New-Object IO.StreamReader($e.Open(), [Text.Encoding]::UTF8)
    try { return $sr.ReadToEnd() } finally { $sr.Dispose() }
}

function Get-SecretExtension([string]$Name) {
    $low = $Name.ToLowerInvariant()
    $t = $low.TrimStart('.')
    if ($t.Contains('.')) { return $low.Substring($low.LastIndexOf('.') + 1) }
    return ''
}

function Get-SecretDedupe($Found) {
    $out = New-Object System.Collections.ArrayList
    $seen = @{}
    foreach ($f in $Found) {
        $r = if ($f.rule -eq 'filename' -or $f.rule -eq 'sheet') { $f.rule } else { '' }
        $s = "$($f.line)|$r|$($f.key.ToLowerInvariant())"
        if (-not $seen.ContainsKey($s)) { $seen[$s] = $true; [void]$out.Add($f) }
        if ($out.Count -ge $SecretPerFile) { break }
    }
    return , $out
}

function Get-SheetKey([string]$Cell) {
    $k = [regex]::Replace($Cell.Trim([char[]]" `t`"`r"), '[^A-Za-z0-9_.\- ]', '')
    if ($k.Length -gt 40) { $k = $k.Substring(0, 40) }
    return $k
}

# Findings for one file (no values). Throws if it can't be read.
function Get-SecretFileFindings([string]$Path, [string]$Name) {
    $low = $Name.ToLowerInvariant()
    $ext = Get-SecretExtension $Name
    $stem = if ($ext) { $Name.Substring(0, $Name.Length - $ext.Length - 1) } else { $Name }
    $kind = if ($SecretDocExt -contains $ext) { 'doc' } elseif ($SecretCodeExt -contains $ext) { 'code' } else { 'config' }
    $found = New-Object System.Collections.ArrayList
    if (($SecretDocExt -contains $ext -or $SecretNameOnlyExt -contains $ext) -and $SecretFileName.IsMatch($stem)) {
        [void]$found.Add((New-SecretFinding $null 'filename' '' $null))
    }
    if ($SecretNameOnlyExt -contains $ext) { return , $found }
    if ($ext -eq 'docx' -or $ext -eq 'xlsx') {
        try { Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop } catch { }
        $zip = $null
        try { $zip = [IO.Compression.ZipFile]::OpenRead($Path) } catch [IO.InvalidDataException] { return , $found }
        try {
            if ($ext -eq 'docx') {
                $xml = Read-ZipEntry $zip 'word/document.xml'
                if ($null -ne $xml) {
                    $text = (@($xml -split '</w:p>') | ForEach-Object { ConvertFrom-XmlText $_ }) -join "`n"
                    foreach ($f in (Get-SecretTextFindings $text 'doc')) { [void]$found.Add($f) }
                }
            } else {
                $xml = Read-ZipEntry $zip 'xl/sharedStrings.xml'
                if ($null -eq $xml) { $xml = '' }
                $cells = @(foreach ($m in [regex]::Matches($xml, '<si>(.*?)</si>', [Text.RegularExpressions.RegexOptions]::Singleline)) { ConvertFrom-XmlText $m.Groups[1].Value })
                foreach ($c in $cells) {
                    if ($SecretSheetHeader.IsMatch($c)) { [void]$found.Add((New-SecretFinding $null 'sheet' (Get-SheetKey $c) $null)); break }
                }
                foreach ($f in (Get-SecretTextFindings (($cells | ForEach-Object { $_.Replace("`n", ' ') }) -join "`n") 'doc')) {
                    $f.line = $null; [void]$found.Add($f)
                }
            }
        } finally { $zip.Dispose() }
        return Get-SecretDedupe $found
    }
    $fs = [IO.File]::Open($Path, 'Open', 'Read', 'ReadWrite')
    try {
        $buf = New-Object byte[] ([Math]::Min($fs.Length, $SecretMaxText + 1))
        $got = 0
        while ($got -lt $buf.Length) { $n = $fs.Read($buf, $got, $buf.Length - $got); if ($n -le 0) { break }; $got += $n }
    } finally { $fs.Dispose() }
    if ($got -ge 2 -and $buf[0] -eq 0xFF -and $buf[1] -eq 0xFE) { $text = [Text.Encoding]::Unicode.GetString($buf, 2, $got - 2) }
    elseif ($got -ge 2 -and $buf[0] -eq 0xFE -and $buf[1] -eq 0xFF) { $text = [Text.Encoding]::BigEndianUnicode.GetString($buf, 2, $got - 2) }
    elseif ([Array]::IndexOf($buf, [byte]0, 0, [Math]::Min($got, 8000)) -ge 0) { return , $found }
    else {
        $start = 0
        if ($got -ge 3 -and $buf[0] -eq 0xEF -and $buf[1] -eq 0xBB -and $buf[2] -eq 0xBF) { $start = 3 }
        try { $text = (New-Object Text.UTF8Encoding($false, $true)).GetString($buf, $start, $got - $start) }
        catch {
            $enc = $null
            try { $enc = [Text.Encoding]::GetEncoding(1252) } catch { $enc = [Text.Encoding]::GetEncoding(28591) }
            $text = $enc.GetString($buf, 0, $got)
        }
    }
    $special = ''
    if ($low -eq '.netrc' -or $low -eq '_netrc') { $special = 'netrc' } elseif ($low -eq '.pgpass') { $special = 'pgpass' }
    if ($ext -eq 'csv') {
        foreach ($c in (($text -split "`n", 2)[0] -split ',')) {
            if ($SecretSheetHeader.IsMatch($c.Trim())) { [void]$found.Add((New-SecretFinding 1 'sheet' (Get-SheetKey $c) $null)); break }
        }
    }
    foreach ($f in (Get-SecretTextFindings $text $kind $special)) { [void]$found.Add($f) }
    return Get-SecretDedupe $found
}

function Test-SecretCandidate([string]$Name, [long]$Size) {
    $low = $Name.ToLowerInvariant()
    $ext = Get-SecretExtension $Name
    if ($ext -eq 'docx' -or $ext -eq 'xlsx') { return $Size -le $SecretMaxOffice }
    if ($SecretNameOnlyExt -contains $ext) { return $true }
    if ($SecretTextExt -contains $ext -or $SecretTextNames -contains $low -or $low.StartsWith('.env.')) { return $Size -le $SecretMaxText }
    return $false
}

# Where to look by default: users' folders (not AppData), PowerShell command histories, setup answer
# files, IIS, SYSVOL on domain controllers and common script folders, plus the dashboard's extra folders.
function Get-SecretRoots($Conf) {
    $roots = New-Object System.Collections.ArrayList
    $sd = if ($env:SystemDrive) { $env:SystemDrive } else { 'C:' }
    $win = if ($env:SystemRoot) { $env:SystemRoot } else { "$sd\Windows" }
    $users = "$sd\Users"
    $cands = @($users, "$sd\inetpub", "$sd\Scripts", "$sd\Temp", "$sd\Install", "$sd\Deploy",
        "$win\Panther\unattend.xml", "$win\Panther\Unattend\unattend.xml", "$win\System32\sysprep\unattend.xml",
        "$win\System32\sysprep\Panther\unattend.xml", "$sd\unattend.xml", "$sd\autounattend.xml")
    if (Test-Path $users) {
        foreach ($u in @(Get-ChildItem -LiteralPath $users -Force -ErrorAction SilentlyContinue | Where-Object { $_.PSIsContainer })) {
            $cands += $u.FullName + '\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'
        }
    }
    try {
        $sv = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -Name SysVol -ErrorAction Stop).SysVol
        if ($sv) { $cands += $sv }
    } catch { }
    foreach ($p in @($Conf.paths)) { if ([string]$p -match '^([A-Za-z]:\\|\\\\)') { $cands += [string]$p } }
    foreach ($c in $cands) { if ($c -and (Test-Path -LiteralPath $c) -and -not $roots.Contains($c)) { [void]$roots.Add($c) } }
    return [string[]]$roots.ToArray()
}

function Read-SecretState {
    $st = @{ sig = $null; stack = @(); done_at = $null; pass_start = $null; errors = 0; truncated = $false; ms = 0
        found = (New-Object System.Collections.ArrayList); files = @{}; cur = @{} }
    if (Test-Path $SecretsPath) {
        try {
            $raw = Get-Content -Path $SecretsPath -Raw | ConvertFrom-Json
            foreach ($k in 'sig', 'done_at', 'pass_start', 'errors', 'truncated', 'ms') { if ($null -ne $raw.$k) { $st[$k] = $raw.$k } }
            $st.stack = @($raw.stack | Where-Object { $_ } | ForEach-Object { [string]$_ })
            foreach ($f in @($raw.found)) { if ($f) { [void]$st.found.Add([ordered]@{ path = [string]$f.path; line = $f.line; rule = [string]$f.rule; key = [string]$f.key; len = $f.len }) } }
        } catch { }
    }
    if (Test-Path $SecretFilesPath) {
        foreach ($l in [IO.File]::ReadAllLines($SecretFilesPath)) {
            $p = $l.Split("`t", 3)
            if ($p.Count -eq 3) { if ($l[0] -eq [char]'P') { $st.files[$p[2]] = $p[1] } else { $st.cur[$p[2]] = $p[1] } }
        }
    }
    return $st
}

function Save-SecretState($St) {
    $o = [ordered]@{ sig = $St.sig; stack = @($St.stack); done_at = $St.done_at; pass_start = $St.pass_start; errors = $St.errors
        truncated = $St.truncated; ms = $St.ms; found = @($St.found) }
    $o | ConvertTo-Json -Depth 4 -Compress | Set-Content -Path $SecretsPath -Encoding UTF8
    $lines = New-Object 'System.Collections.Generic.List[string]'
    foreach ($kv in $St.files.GetEnumerator()) { $lines.Add("P`t$($kv.Value)`t$($kv.Key)") }
    foreach ($kv in $St.cur.GetEnumerator()) { $lines.Add("C`t$($kv.Value)`t$($kv.Key)") }
    [IO.File]::WriteAllLines($SecretFilesPath, $lines)
}

# Scan for up to $Budget seconds, carrying on where the last run stopped. Returns the scan state.
function Invoke-SecretScan($State, [int]$Budget = $SecretBudget, [string[]]$Roots = $null) {
    $conf = $State.secret_scan
    if (-not $Roots -and -not ($conf -and $conf.on)) {
        foreach ($p in $SecretsPath, $SecretFilesPath) { if (Test-Path $p) { Remove-Item -Path $p -Force } }
        return $null
    }
    $hours = 24
    if ($conf -and $conf.hours) { $hours = [Math]::Max(1, [int]$conf.hours) }
    if (-not $Roots) { $Roots = @(Get-SecretRoots $conf) }
    $st = if ($Budget) { Read-SecretState } else { $null }
    if (-not $st) { $st = @{ sig = $null; stack = @(); done_at = $null; found = (New-Object System.Collections.ArrayList); files = @{}; cur = @{}; errors = 0; truncated = $false } }
    $sha = [Security.Cryptography.SHA256]::Create()
    $sig = (-join ($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes((($Roots -join "`n") + "|$hours"))) | ForEach-Object { $_.ToString('x2') })).Substring(0, 16)
    $now = [long]([DateTime]::UtcNow - [DateTime]'1970-01-01').TotalSeconds
    if ($st.sig -ne $sig) { $st.sig = $sig; $st.stack = @(); $st.done_at = $null }
    if (-not @($st.stack).Count) {
        if ($st.done_at -and ($now - [long]$st.done_at) -lt $hours * 3600) { return $st }
        $list = @($Roots); [Array]::Reverse($list)
        $st.stack = $list; $st.cur = @{}; $st.pass_start = $now; $st.errors = 0; $st.truncated = $false
        if ($Budget) {
            # Automatic sign-in (autologon) password kept in the registry in plain text
            $wl = 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
            $keep = @($st.found | Where-Object { $_.path -ne $wl })
            $st.found = New-Object System.Collections.ArrayList
            foreach ($f in $keep) { [void]$st.found.Add($f) }
            try {
                $dp = (Get-ItemProperty -Path ('Registry::' + $wl) -Name DefaultPassword -ErrorAction Stop).DefaultPassword
                if ($dp) { [void]$st.found.Add([ordered]@{ path = $wl; line = $null; rule = 'autologon'; key = 'DefaultPassword'; len = ([string]$dp).Length }) }
                $dp = $null
            } catch { }
            $st.cur[$wl] = '0'
        }
    }
    $stack = New-Object System.Collections.ArrayList
    foreach ($s in @($st.stack)) { [void]$stack.Add([string]$s) }
    $cur = $st.cur; $prev = $st.files; $found = $st.found
    $sw = [Diagnostics.Stopwatch]::StartNew()
    if ($Budget) { try { (Get-Process -Id $PID).PriorityClass = 'BelowNormal' } catch { } }
    $visit = {
        param($Item)
        $path = $Item.FullName
        if ($cur.ContainsKey($path)) { return }
        $sig_ = "$([long]($Item.LastWriteTimeUtc.Ticks / 10000000)):$($Item.Length)"
        $cur[$path] = $sig_
        if ($prev[$path] -eq $sig_) { return }  # unchanged since the last pass: its findings stand
        for ($j = $found.Count - 1; $j -ge 0; $j--) { if ($found[$j].path -eq $path) { $found.RemoveAt($j) } }
        try { $new = Get-SecretFileFindings $path $Item.Name } catch { $st.errors = [int]$st.errors + 1; return }
        foreach ($f in $new) {
            if ($found.Count -ge $SecretMax) { $st.truncated = $true; break }
            $f.Insert(0, 'path', $path)
            [void]$found.Add($f)
        }
    }
    while ($stack.Count) {
        if ($Budget -and $sw.Elapsed.TotalSeconds -gt $Budget) { break }
        $d = $stack[$stack.Count - 1]; $stack.RemoveAt($stack.Count - 1)
        $items = $null
        try {
            if ([IO.File]::Exists($d)) { & $visit (New-Object IO.FileInfo($d)); continue }
            $items = @((New-Object IO.DirectoryInfo($d)).GetFileSystemInfos() | Sort-Object Name)
        } catch { continue }
        $subdirs = New-Object System.Collections.ArrayList
        $stopped = $false
        foreach ($e in $items) {
            try {
                $attr = [int]$e.Attributes
                if ($e -is [IO.DirectoryInfo]) {
                    # Skip junctions and links (they loop back), except OneDrive's own folders
                    if (($attr -band 0x400) -and $e.FullName -notmatch '\\OneDrive') { continue }
                    if ($SecretSkipDirs -notcontains $e.Name.ToLowerInvariant() -and @($e.FullName.Split([char[]]'\/')).Count -lt 40) { [void]$subdirs.Add($e.FullName) }
                } elseif (-not ($attr -band 0x441000)) {
                    # (cloud-only files are skipped so the scan never downloads them)
                    if (Test-SecretCandidate $e.Name $e.Length) { & $visit $e }
                }
            } catch { continue }
            if ($Budget -and $sw.Elapsed.TotalSeconds -gt $Budget) { [void]$stack.Add($d); $stopped = $true; break }  # finish this folder next time
        }
        if (-not $stopped) { for ($j = $subdirs.Count - 1; $j -ge 0; $j--) { [void]$stack.Add($subdirs[$j]) } }
    }
    $st.stack = @($stack)
    $st.ms = [int]$sw.Elapsed.TotalMilliseconds
    if (-not $stack.Count) {
        $st.files = $cur
        $keep = @($found | Where-Object { $cur.ContainsKey($_.path) })
        $st.found = New-Object System.Collections.ArrayList
        foreach ($f in $keep) { [void]$st.found.Add($f) }
        $st.cur = @{}
        $st.done_at = $now
        $st.finished = $true  # this run completed a pass
    }
    if ($Budget) { Save-SecretState $st }
    return $st
}

# What the report says about the scan: its status, and the findings when they changed.
function Get-SecretReport($State) {
    $conf = $State.secret_scan
    if (-not ($conf -and $conf.on)) { return [ordered]@{ on = $false } }
    $st = Read-SecretState
    $found = @($st.found | Sort-Object @{ e = { $_.path } }, @{ e = { [int]$_.line } }, @{ e = { $_.rule } } |
            ForEach-Object { [ordered]@{ path = $_.path; line = $_.line; rule = $_.rule; key = $_.key; len = $_.len } })
    $text = ($found | ForEach-Object { "$($_.path)|$($_.line)|$($_.rule)|$($_.key)|$($_.len)" }) -join "`n"
    $sha = [Security.Cryptography.SHA256]::Create()
    $h = (-join ($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($text)) | ForEach-Object { $_.ToString('x2') })).Substring(0, 16)
    $iso = { param($t) if ($t) { ([DateTime]'1970-01-01').AddSeconds([double]$t).ToString('yyyy-MM-ddTHH:mm:ssZ') } else { $null } }
    $r = [ordered]@{ on = $true; scanning = [bool]@($st.stack).Count; pass_start = (& $iso $st.pass_start); done_at = (& $iso $st.done_at)
        files = $st.files.Count; errors = [int]$st.errors; truncated = [bool]$st.truncated; count = $found.Count; hash = $h }
    if ($State.secrets_sent -ne $h) { $r.findings = $found }
    return $r
}

function Get-Report($State, [string[]]$ExtraWatch) {
    $now = Get-Date
    $since = if ($State.last_run) { ([DateTime]$State.last_run).ToLocalTime().AddMinutes(-2) } else { $now.AddMinutes(-60) }
    if ($since -lt $now.AddHours(-24)) { $since = $now.AddHours(-24) }

    $name = if ($env:COMPUTERNAME) { $env:COMPUTERNAME } else { [Environment]::MachineName }
    $report = [ordered]@{ agent_version = $AgentVersion; ps_version = $PSVersionTable.PSVersion.ToString(); hostname = $name; collected = ConvertTo-UtcString $now }

    $script:Timings = [ordered]@{}
    $sys = $null
    try {
        $sys = Measure-Step 'system info' { Get-SystemInfo }
        foreach ($k in $sys.Keys) { $report[$k] = $sys[$k] }
        $report.fqdn = if ($sys.part_of_domain -and $sys.domain) { "$name.$($sys.domain)".ToLower() } else { $name.ToLower() }
    } catch { Add-CollectorError 'system' $_ }

    try {
        $patch = Measure-Step 'update history' { Get-PatchInfo $State $(if ($sys) { $sys.boot_time } else { $null }) }
        if ($patch.date) {
            $report.last_patch = $patch.date
            $report.last_patch_kb = $patch.kb
            $report.last_patch_title = $patch.title
            $report.last_patch_source = $patch.source
        }
        $report.last_patch_cached = [bool]$patch.cached
    } catch { Add-CollectorError 'updates' $_ }
    if ($sys -and $sys.pending_reboot -and $sys.boot_time) {
        try { $report.reboot_packages = @(Measure-Step 'pending restart' { Get-RebootPackages $State $sys.boot_time }) } catch { Add-CollectorError 'pending restart' $_ }
    }

    $allServices = @()
    try { $allServices = @(Measure-Step 'service list' { Get-CimInstance -ClassName Win32_Service }) } catch { Add-CollectorError 'services' $_ }
    $discovery = Measure-Step 'roles' { Get-Discovery $allServices $ExtraWatch $(if ($sys) { [bool]$sys.workstation } else { $false }) }
    $report.roles = $discovery.roles

    # @() keeps a single disk as a list: PowerShell unwraps one-item arrays returned from functions
    try { $report.disks = @(Measure-Step 'disks' { Get-Disks }) } catch { Add-CollectorError 'disks' $_ }
    try { $report.sessions = @(Measure-Step 'signed-in users' { Get-SignedInUsers }) } catch { Add-CollectorError 'signed-in users' $_ }
    try {
        $apps = @(Measure-Step 'installed software' { Get-InstalledApps })
        $report.apps_hash = Get-AppsHash $apps
        if ($State.apps_sent -ne $report.apps_hash) { $report.apps = $apps }  # only when it changed, or Rollcall asked
    } catch { Add-CollectorError 'installed software' $_ }
    try { $report.secrets = Measure-Step 'password scan' { Get-SecretReport $State } } catch { Add-CollectorError 'password scan' $_ }
    if ($State.integrity) { $report.agent_integrity = $State.integrity }  # its folder's permissions had been changed (put back)
    if ($State.messages_log) { $report.messages_shown = @($State.messages_log) }  # which messages it showed, and to how many sessions
    try { $report.services = Measure-Step 'services' { Get-ServiceReport $allServices $discovery } } catch { Add-CollectorError 'services' $_ }
    $report.events = Measure-Step 'event logs' { Get-EventReport $State $since }
    $report.security = Measure-Step 'security log' { Get-SecurityReport $State $since }
    try { $report.security.admins = @(Measure-Step 'administrators' { Get-LocalAdmins }) } catch { Add-CollectorError 'administrators' $_ }
    $report.checks = Get-RoleChecks $discovery.roles $since $State
    try {
        $bjobs = @()
        $vbr = Measure-Step 'veeam b&r' { Get-VeeamJobs $State }
        if ($null -ne $vbr) { $bjobs += @($vbr) }
        $vaw = $null
        try { $vaw = Measure-Step 'veeam agent' { Get-VeeamAgentJobs $State } } catch { Add-CollectorError 'veeam agent' $_ }
        if ($null -ne $vaw) { $bjobs += @($vaw) }
        $vbo = $null
        try { $vbo = Measure-Step 'veeam m365' { Get-VboJobs $State } } catch { Add-CollectorError 'veeam m365' $_ }
        if ($null -ne $vbo) { $bjobs += @($vbo) }
        $other = $null
        try { $other = Measure-Step 'other backups' { Get-BackupProductJobs $State } } catch { Add-CollectorError 'other backups' $_ }
        if ($null -ne $other) { $bjobs += @($other) }
        if ($null -ne $vbr -or $null -ne $vbo -or $null -ne $vaw -or $null -ne $other) { $report.checks.backups = [ordered]@{ jobs = @($bjobs) } }
    } catch { Add-CollectorError 'veeam' $_ }
    try {
        $laps = Measure-Step 'laps' { Get-LapsStatus $State ($discovery.roles -contains 'Domain controller') $(if ($sys) { [bool]$sys.part_of_domain } else { $false }) }
        if ($laps) { $report.checks.laps = $laps }
    } catch { Add-CollectorError 'laps' $_ }
    try {
        $sfc = Measure-Step 'system file check' { Get-SystemFileCheck $State $State.sfc_conf }
        if ($sfc) { $report.checks.sfc = $sfc }
    } catch { Add-CollectorError 'system file check' $_ }
    try {
        $bl = Measure-Step 'bitlocker' { Get-BitLockerStatus }
        if ($bl) { $report.checks.bitlocker = $bl }
    } catch { Add-CollectorError 'bitlocker' $_ }
    try {
        $nics = Measure-Step 'network' { Get-NetworkReport }
        if ($nics -and $nics.adapters.Count) { $report.checks.nics = $nics }
    } catch { Add-CollectorError 'network' $_ }
    if ($sys -and $sys.part_of_domain) {
        try { $report.checks.gpo = Measure-Step 'group policy' { Get-GroupPolicyStatus } } catch { Add-CollectorError 'group policy' $_ }
        try { $report.checks.time = Measure-Step 'time' { Get-TimeStatus $sys.domain ($discovery.roles -contains 'Domain controller') } } catch { Add-CollectorError 'time' $_ }
    }
    if ($discovery.roles -contains 'DFS Replication') {
        try {
            $dfsr = Measure-Step 'dfs replication' { Get-DfsrStatus }
            if ($dfsr) { $report.checks.dfsr = $dfsr }
        } catch { Add-CollectorError 'dfs replication' $_ }
    }
    if ($discovery.roles -contains 'Domain controller') {
        try { $report.checks.sysvol = Measure-Step 'sysvol replication' { Get-SysvolStatus } } catch { Add-CollectorError 'sysvol replication' $_ }
        try {
            $dsec = Measure-Step 'domain security' { Get-DomainSecurity $State }
            if ($dsec) { $report.checks.domain = $dsec }
        } catch { Add-CollectorError 'domain security' $_ }
    }
    if ($discovery.roles -contains 'Exchange') {
        try { $report.checks.exchange = Measure-Step 'exchange' { Get-ExchangeReport $State } } catch { Add-CollectorError 'exchange' $_ }
    }
    try {
        $sql = Measure-Step 'sql server' { Get-SqlReport $allServices }
        if ($sql) { $report.checks.sql = $sql }
    } catch { Add-CollectorError 'sql server' $_ }
    try {
        $tasks = Measure-Step 'scheduled tasks' { Get-TaskReport }
        if ($tasks -and $tasks.total) { $report.checks.tasks = $tasks }
    } catch { Add-CollectorError 'scheduled tasks' $_ }
    try {
        $certs = Measure-Step 'certificates' { Get-CertificateReport }
        if ($certs -and $certs.certs.Count) { $report.checks.certs = $certs }
    } catch { Add-CollectorError 'certificates' $_ }
    try {
        $storage = Measure-Step 'storage health' { Get-StorageHealth $State }
        if ($storage) { $report.checks.storage = $storage }
    } catch { Add-CollectorError 'storage' $_ }
    $report.errors = @($script:Errors)
    try {
        $proc = [Diagnostics.Process]::GetCurrentProcess()
        $report.run_ms = [int]((Get-Date) - $proc.StartTime).TotalMilliseconds   # includes PowerShell starting up
        $report.cpu_ms = [int]$proc.TotalProcessorTime.TotalMilliseconds
        $report.peak_mem_mb = [int]($proc.PeakWorkingSet64 / 1MB)
    } catch { }
    $report.timings = $script:Timings
    return $report
}

# ---------------------------------------------------------------------------
# Talking to the add-on
# ---------------------------------------------------------------------------
function Test-InNetwork([string]$Ip, [string]$Cidr) {
    # Is this IPv4 address in this subnet (e.g. 10.0.1.0/24)?
    try {
        $parts = $Cidr.Trim() -split '/'
        $bits = if ($parts.Count -gt 1) { [int]$parts[1] } else { 32 }
        if ($bits -lt 0 -or $bits -gt 32) { return $false }
        $a = [System.Net.IPAddress]::Parse($Ip).GetAddressBytes(); $n = [System.Net.IPAddress]::Parse($parts[0]).GetAddressBytes()
        if ($a.Count -ne 4 -or $n.Count -ne 4) { return $false }
        $ai = ([uint64]$a[0] -shl 24) + ([uint64]$a[1] -shl 16) + ([uint64]$a[2] -shl 8) + [uint64]$a[3]
        $ni = ([uint64]$n[0] -shl 24) + ([uint64]$n[1] -shl 16) + ([uint64]$n[2] -shl 8) + [uint64]$n[3]
        $size = [uint64][math]::Pow(2, 32 - $bits)
        return ([math]::Floor($ai / $size) -eq [math]::Floor($ni / $size))
    } catch { return $false }
}

function Get-OwnIPv4 {
    # This computer's IPv4 addresses on connected adapters (not loopback or self-assigned 169.254.x.x)
    try {
        return @([System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces() |
            Where-Object { $_.OperationalStatus -eq 'Up' -and $_.NetworkInterfaceType -ne 'Loopback' } |
            ForEach-Object { $_.GetIPProperties().UnicastAddresses } |
            Where-Object { $_.Address.AddressFamily -eq 'InterNetwork' } |
            ForEach-Object { $_.Address.ToString() } | Where-Object { $_ -notlike '169.254.*' -and $_ -notlike '127.*' })
    } catch { return @() }
}

function Get-RouteSide($Route) {
    # 'inside' when this computer has an address on one of the internal networks set under Agents
    foreach ($ip in @(Get-OwnIPv4)) {
        foreach ($net in @($Route.networks)) { if (Test-InNetwork $ip $net) { return 'inside' } }
    }
    return 'outside'
}

function Get-ServerList {
    # With Rollcall's own HTTPS on, each plain HTTP address gets its HTTPS twin (same address, the HTTPS port)
    # tried first; the HTTP one stays as the fallback until Rollcall turns plain HTTP off.
    $plain = @(Get-ServerListPlain)
    if (-not $script:TlsPinNow) { return $plain }
    $out = New-Object Collections.ArrayList
    foreach ($u in $plain) {
        if ($u -like 'http://*') { try { $h = ([uri]$u).Host; [void]$out.Add("https://${h}:$($script:TlsPortNow)") } catch { } }
        [void]$out.Add($u)
    }
    return @($out | Select-Object -Unique)
}

function Test-PinnedUrl([string]$Url) {
    if (-not $script:TlsPinNow -or $Url -notlike 'https://*') { return $false }
    try { return ([uri]$Url).Port -eq $script:TlsPortNow } catch { return $false }
}

function Initialize-PinCheck {
    if ('Rollcall.Pin' -as [type]) { return }
    Add-Type -TypeDefinition @'
using System;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
namespace Rollcall {
    public static class Pin {
        // A P-256 key's SubjectPublicKeyInfo: this header, then the 65-byte point (as Rollcall hashes it)
        static readonly byte[] Header = { 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00 };
        static readonly byte[] P256 = { 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 };
        public static string Expected;
        public static string Seen;
        public static string Of(X509Certificate cert) {
            var c = new X509Certificate2(cert);
            byte[] key = c.PublicKey.EncodedKeyValue.RawData, prm = c.PublicKey.EncodedParameters.RawData;
            if (c.PublicKey.Oid.Value != "1.2.840.10045.2.1" || key.Length != 65 || prm.Length != P256.Length) return "";
            for (int i = 0; i < P256.Length; i++) if (prm[i] != P256[i]) return "";
            var all = new byte[Header.Length + key.Length];
            Buffer.BlockCopy(Header, 0, all, 0, Header.Length);
            Buffer.BlockCopy(key, 0, all, Header.Length, key.Length);
            using (var sha = SHA256.Create()) return Convert.ToBase64String(sha.ComputeHash(all));
        }
        public static bool Check(object sender, X509Certificate cert, X509Chain chain, SslPolicyErrors errors) {
            // Exactly Rollcall's key; names and certificate authorities don't come into it
            Seen = cert == null ? "" : Of(cert);
            return !string.IsNullOrEmpty(Expected) && Seen == Expected;
        }
        public static readonly RemoteCertificateValidationCallback Callback = Check;
    }
}
'@
}

function Invoke-PinnedRequest([string]$Uri, [string]$Method, [byte[]]$Body, [string]$Token, [int]$TimeoutSec = 30) {
    # A request to Rollcall's own HTTPS, refused unless the server has exactly the key Rollcall told this agent about
    Initialize-PinCheck
    [Rollcall.Pin]::Expected = $script:TlsPinNow
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    $req = [Net.HttpWebRequest][Net.WebRequest]::Create($Uri)
    $req.Method = $Method; $req.Timeout = $TimeoutSec * 1000; $req.ReadWriteTimeout = $TimeoutSec * 1000
    $req.ServerCertificateValidationCallback = [Rollcall.Pin]::Callback
    try { $req.ServicePoint.Expect100Continue = $false } catch { }
    if ($Token) { $req.Headers['Authorization'] = "Bearer $Token" }
    $resp = $null
    try {
        if ($Body) {
            $req.ContentType = 'application/json; charset=utf-8'; $req.ContentLength = $Body.Length
            $s = $req.GetRequestStream(); try { $s.Write($Body, 0, $Body.Length) } finally { $s.Close() }
        }
        $resp = $req.GetResponse()
    } catch {
        $e = $_.Exception
        while ($e -and -not ($e -is [Net.WebException])) { $e = $e.InnerException }
        if ($e -and $e.Response) { $resp = $e.Response }
        elseif ([Rollcall.Pin]::Seen -and [Rollcall.Pin]::Seen -ne [Rollcall.Pin]::Expected) { throw "the server at $Uri doesn't have Rollcall's key (it has $([Rollcall.Pin]::Seen.Substring(0, [Math]::Min(12, [Rollcall.Pin]::Seen.Length)))...), so nothing was sent" }
        else { throw }
    }
    try {
        $ms = New-Object IO.MemoryStream
        $resp.GetResponseStream().CopyTo($ms)
        return @{ status = [int]$resp.StatusCode; bytes = $ms.ToArray() }
    } finally { $resp.Close() }
}

function Get-ServerListPlain {
    # -Server can list several addresses, e.g. internal then external:
    # 'http://10.0.0.5:8100,https://rollcall.example.com:8100'. The one that worked last is tried first.
    # Addresses the add-on sent (set under Agents) come first; the ones this copy was installed with
    # stay on the end, so a mistake in the dashboard can't cut the agent off.
    # With internal networks set under Agents, the address is chosen afresh each run instead: on an internal
    # network, the inside address first; elsewhere, the outside one first. The other is the fallback.
    $all = @(@($script:PushedServers) + @($Server -split '[,;\s]+') | Where-Object { $_ } | ForEach-Object { $_.Trim().TrimEnd('/') } | Select-Object -Unique)
    if ($script:Route) {
        $pair = if ($script:RouteSide -eq 'inside') { @($script:Route.inside, $script:Route.outside) } else { @($script:Route.outside, $script:Route.inside) }
        return @(@($pair) + @($all) | Where-Object { $_ } | ForEach-Object { ([string]$_).Trim().TrimEnd('/') } | Select-Object -Unique)
    }
    if ($script:PreferredServer -and $all -contains $script:PreferredServer) {
        $all = @($script:PreferredServer) + @($all | Where-Object { $_ -ne $script:PreferredServer })
    }
    return $all
}

# Just after Windows starts (the start-up run, a minute after boot), the network can take a while longer:
# DHCP, the domain network profile, a VPN. Rather than failing that run (and Rollcall only hearing about
# the restart at the next one, up to 5 minutes later), wait up to 3 minutes for Rollcall to be reachable.
# Any other time, and once it answers, this returns at once.
function Wait-Network([int]$MaxSeconds = 180, [int]$BootWindow = 600) {
    try { $upFor = ((Get-Date) - [DateTime](Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).LastBootUpTime).TotalSeconds } catch { return }
    if ($upFor -gt $BootWindow) { return }
    $servers = @(Get-ServerList)
    $started = Get-Date
    while ($true) {
        foreach ($srv in $servers) {
            if (Test-Reachable $srv 2000) {
                $waited = [int]((Get-Date) - $started).TotalSeconds
                if ($waited -ge 5) { Write-AgentLog "Network ready $waited s into the start-up run" }
                return
            }
        }
        if (((Get-Date) - $started).TotalSeconds -ge $MaxSeconds) {
            Write-AgentLog "WARN Still can't reach Rollcall $MaxSeconds s after starting ($([int]$upFor) s after Windows started); trying anyway"
            return
        }
        Start-Sleep -Seconds 10
    }
}

function Test-Reachable([string]$Url, [int]$Ms = 3000) {
    # Quick TCP check, so an address that can't be reached from here doesn't hold up the run.
    try {
        $u = [uri]$Url
        $port = if ($u.Port -gt 0) { $u.Port } elseif ($u.Scheme -eq 'https') { 443 } else { 80 }
        $c = New-Object System.Net.Sockets.TcpClient
        try { $t = $c.ConnectAsync($u.Host, $port); return ($t.Wait($Ms) -and $c.Connected) } finally { $c.Close() }
    } catch { return $false }
}

function Send-Json([string]$Path, $Body, [string]$Token) {
    $servers = @(Get-ServerList)
    $lastErr = $null
    foreach ($srv in $servers) {
        if ($servers.Count -gt 1 -and -not (Test-Reachable $srv)) { $lastErr = "can't reach $srv"; continue }
        try {
            $r = Send-JsonTo $srv $Path $Body $Token
            $script:ActiveServer = $srv
            return $r
        } catch {
            $lastErr = $_.Exception.Message
            if ($servers.Count -gt 1) { Write-AgentLog "WARN $srv didn't answer ($lastErr); trying the next address" }
        }
    }
    throw "Couldn't reach Rollcall at any of its addresses ($($servers -join ', ')): $lastErr"
}

function Send-JsonTo([string]$Srv, [string]$Path, $Body, [string]$Token) {
    $uri = $Srv + $Path
    if ($Body -is [System.Collections.IDictionary]) { $Body['sent_to'] = $Srv }  # so Rollcall knows which address was used
    $json = $Body | ConvertTo-Json -Depth 10 -Compress
    $params = @{
        Uri = $uri; Method = 'Post'; Body = [Text.Encoding]::UTF8.GetBytes($json)
        ContentType = 'application/json; charset=utf-8'; TimeoutSec = 30; UseBasicParsing = $true
    }
    if ($Token) { $params.Headers = @{ Authorization = "Bearer $Token" } }
    if (Test-PinnedUrl $uri) {
        $r = Invoke-PinnedRequest $uri 'POST' $params.Body $Token
        $content = $null
        if ($r.bytes.Length) { try { $content = [Text.Encoding]::UTF8.GetString($r.bytes) | ConvertFrom-Json } catch { } }
        return @{ status = $r.status; body = $content }
    }
    # Windows PowerShell 5.1 otherwise asks permission before sending (Expect: 100-continue): an extra
    # round trip, and if Rollcall is slow to answer that, the request can be abandoned half-way.
    [Net.ServicePointManager]::Expect100Continue = $false
    if ($uri -like 'https:*') {
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        if ($IgnoreCertificate) {
            if ($PSVersionTable.PSVersion.Major -ge 6) { $params.SkipCertificateCheck = $true }
            else { $prevCb = [Net.ServicePointManager]::ServerCertificateValidationCallback; [Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }; $cbSet = $true }
        }
    }
    try {
        $r = Invoke-WebRequest @params
        $content = $null
        if ($r.Content) { try { $content = $r.Content | ConvertFrom-Json } catch { } }
        return @{ status = [int]$r.StatusCode; body = $content }
    } catch {
        $resp = $_.Exception.Response
        if ($resp) { return @{ status = [int]$resp.StatusCode; body = $null } }
        throw
    } finally {
        # -IgnoreCertificate: only for this request to Rollcall, not every later HTTPS call (review F14)
        if ($cbSet) { [Net.ServicePointManager]::ServerCertificateValidationCallback = $prevCb }
    }
}

function Test-NewerVersion([string]$A, [string]$B) {
    # True when version A is newer than version B (e.g. 1.0.10 > 1.0.9).
    try { return ([version]($A -replace '[^\d.]', '')) -gt ([version]($B -replace '[^\d.]', '')) } catch { return $false }
}

function Test-RollcallSignature([byte[]]$Data, [string]$Signature) {
    # True if $Signature (base64) is Rollcall's signature of $Data: RSASSA-PKCS1-v1_5 with SHA-256, checked with
    # the public key built into this script. The whole expected padded block is built and compared byte for byte
    # (RFC 8017), so nothing in the signature is parsed. BigInteger keeps it working on .NET 4.5 and PowerShell 7.
    if (-not $UpdateKey -or $UpdateKey -like '__PM_*' -or -not $Signature) { return $false }
    try {
        Add-Type -AssemblyName System.Numerics -ErrorAction SilentlyContinue
        $nb = [Convert]::FromBase64String($UpdateKey); $sb = [Convert]::FromBase64String($Signature)
        $k = $nb.Length
        if ($k -lt 256 -or $sb.Length -ne $k) { return $false }
        $big = {  # big-endian unsigned bytes -> BigInteger (which wants little-endian, with a sign byte)
            param([byte[]]$B)
            $le = New-Object byte[] ($B.Length + 1)
            for ($i = 0; $i -lt $B.Length; $i++) { $le[$i] = $B[$B.Length - 1 - $i] }
            New-Object Numerics.BigInteger (, $le)
        }
        $n = & $big $nb; $s = & $big $sb
        if ($s -ge $n) { return $false }
        $le = [Numerics.BigInteger]::ModPow($s, 65537, $n).ToByteArray()
        $m = New-Object byte[] $k
        for ($i = 0; $i -lt $le.Length; $i++) {
            if ($i -lt $k) { $m[$k - 1 - $i] = $le[$i] } elseif ($le[$i] -ne 0) { return $false }
        }
        $hash = (New-Object Security.Cryptography.SHA256Managed).ComputeHash($Data)
        $t = [byte[]](0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20) + $hash
        $want = New-Object byte[] $k
        $want[1] = 1
        for ($i = 2; $i -lt $k - $t.Length - 1; $i++) { $want[$i] = 0xff }
        [Array]::Copy([byte[]]$t, 0, $want, $k - $t.Length, $t.Length)
        $diff = 0
        for ($i = 0; $i -lt $k; $i++) { $diff = $diff -bor ($m[$i] -bxor $want[$i]) }
        return $diff -eq 0
    } catch { return $false }
}

function Get-ConfigText($Body) {
    # The addresses in Rollcall's reply as the exact text it signed (see updatesign.py in the add-on).
    $servers = @(@($Body.servers) | Where-Object { $null -ne $_ } | ForEach-Object { [string]$_ }) -join ','
    $rt = $Body.route
    $route = if ($rt) { ([string]$rt.inside) + '|' + ([string]$rt.outside) + '|' + ((@(@($rt.networks) | Where-Object { $null -ne $_ } | ForEach-Object { [string]$_ })) -join ',') } else { '' }
    return [Text.Encoding]::UTF8.GetBytes("rollcall-agent-config/1`nservers=$servers`nroute=$route`n")
}

$MessageHeading = 'Message from the Rollcall Administrator'  # fixed here: the sender can't change it

function Get-MessageText($M) {
    # A message as the exact text Rollcall signed (see messages.py in the add-on)
    $text = ([string]$M.text) -replace "`r`n", "`n" -replace "`r", "`n"
    return [Text.Encoding]::UTF8.GetBytes("rollcall-message/1`nid=$([string]$M.id)`nexpires=$([long]$M.expires)`n$text")
}

function Send-SessionMessage([string]$Title, [string]$Text) {
    # Show a message box in every signed-in session (console and Remote Desktop), as 'msg *' does, without
    # waiting for anyone to choose OK. Returns how many sessions it went to.
    if (-not ('Rollcall.Wts' -as [type])) {
        Add-Type -Namespace Rollcall -Name Wts -MemberDefinition @'
[DllImport("wtsapi32.dll", SetLastError = true)]
public static extern bool WTSEnumerateSessions(IntPtr hServer, int reserved, int version, out IntPtr sessions, out int count);
[DllImport("wtsapi32.dll")]
public static extern void WTSFreeMemory(IntPtr memory);
[DllImport("wtsapi32.dll", EntryPoint = "WTSSendMessageW", SetLastError = true, CharSet = CharSet.Unicode)]
public static extern bool WTSSendMessage(IntPtr hServer, int sessionId, string title, int titleBytes, string message, int messageBytes, int style, int timeout, out int response, bool wait);
[StructLayout(LayoutKind.Sequential)]
public struct SessionInfo { public int SessionId; public IntPtr WinStationName; public int State; }
'@
    }
    $list = [IntPtr]::Zero; $count = 0
    if (-not [Rollcall.Wts]::WTSEnumerateSessions([IntPtr]::Zero, 0, 1, [ref]$list, [ref]$count)) { throw "couldn't list the signed-in sessions" }
    $sent = 0
    try {
        $size = [Runtime.InteropServices.Marshal]::SizeOf([type][Rollcall.Wts+SessionInfo])
        for ($i = 0; $i -lt $count; $i++) {
            $info = [Runtime.InteropServices.Marshal]::PtrToStructure([IntPtr]($list.ToInt64() + $i * $size), [type][Rollcall.Wts+SessionInfo])
            if ($info.SessionId -eq 0 -or $info.State -ne 0) { continue }  # session 0 is services; 0 = WTSActive (someone signed in)
            $resp = 0
            # MB_OK | MB_ICONINFORMATION | MB_SETFOREGROUND | MB_TOPMOST; no timeout; don't wait
            if ([Rollcall.Wts]::WTSSendMessage([IntPtr]::Zero, $info.SessionId, $Title, $Title.Length * 2, $Text, $Text.Length * 2, 0x00050040, 0, [ref]$resp, $false)) { $sent++ }
        }
    } finally { [Rollcall.Wts]::WTSFreeMemory($list) }
    return $sent
}

function Show-RollcallMessages($State, $Messages) {
    # Messages from a Rollcall admin (only on devices an admin included, and only with the messages option on).
    # Each must be signed with Rollcall's own key, so a reply changed on the way can't put words on anyone's
    # screen. Shown once; with nobody signed in it's tried again at each report until it expires. What happened
    # goes in the next report (messages_shown).
    $log = [Collections.ArrayList]@(@($State.messages_log) | Where-Object { $_ -and $_.id })
    $done = @($log | Where-Object { $_.sessions -gt 0 } | ForEach-Object { [string]$_.id })
    $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    foreach ($m in @($Messages | Select-Object -First 3)) {
        $id = [string]$m.id
        if (-not $id -or $done -contains $id -or [long]$m.expires -le $now) { continue }
        if (-not (Test-RollcallSignature (Get-MessageText $m) ([string]$m.sig))) { Write-AgentLog "WARN A message from Rollcall didn't have a good signature, so it wasn't shown"; continue }
        $text = ([string]$m.text) -replace "`r`n", "`n" -replace "`n", "`r`n"
        $n = 0; $err = $null
        try { $n = Send-SessionMessage $MessageHeading $text } catch { $err = $_.Exception.Message }
        $entry = [ordered]@{ id = $id; sessions = [int]$n }
        if ($err) { $entry.error = $err }
        foreach ($old in @($log | Where-Object { [string]$_.id -eq $id })) { $log.Remove($old) }
        [void]$log.Add($entry)
        Write-AgentLog $(if ($err) { "WARN Couldn't show a message from Rollcall: $err" } elseif ($n) { "Showed a message from Rollcall in $n session(s)" } else { "A message from Rollcall is waiting: nobody is signed in" })
    }
    $State.messages_log = @($log | Select-Object -Last 20)
}

function Invoke-AgentUpdate($State, $Offer) {
    # The add-on offers a newer agent only when an admin has turned updates on. The download is checked before
    # anything changes: it must be signed with Rollcall's own key (the public half is built into this script, so
    # a reply changed on the way can't sign one), be the newer version offered, and parse as PowerShell. Before
    # 1.0.53 it was signed with this agent's token, which crosses the network with every report.
    # The old copy is kept as RollcallAgent.ps1.old (PingMonitorAgent.ps1.old before the move). The new one runs
    # from the next report.
    if (-not $Offer -or -not $Offer.version -or -not (Test-NewerVersion ([string]$Offer.version) $AgentVersion)) { return }
    if (-not $UpdateKey -or $UpdateKey -like '__PM_*') { throw "This copy has no update key built in (download it again from Rollcall), so it can't check updates" }
    $dest = Join-Path $DataPath $ScriptName
    # An agent installed with -DataPath somewhere else runs under the name it was installed with (the old one, if it
    # was installed before 1.0.60): update that, or it would never update again
    if ($PSCommandPath -and (Split-Path $PSCommandPath -Parent) -eq $DataPath -and (Split-Path $PSCommandPath -Leaf) -in $OldScriptName, $NewScriptName) { $dest = $PSCommandPath }
    if (-not (Test-Path $dest)) { Write-AgentLog "WARN An update is waiting, but $dest isn't here to update (run the agent from its installed copy)"; return }  # only an installed agent updates itself
    $active = if ($script:ActiveServer) { $script:ActiveServer } else { @(Get-ServerList)[0] }
    $uri = $active + '/agent/update?os=windows&sig=rsa&server=' + [uri]::EscapeDataString((@($Server -split '[,;\s]+' | Where-Object { $_ } | ForEach-Object { $_.Trim().TrimEnd('/') }) -join ','))
    if ($IgnoreCertificate) { $uri += '&ignore_cert=1' }
    $params = @{ Uri = $uri; Method = 'Get'; TimeoutSec = 60; UseBasicParsing = $true; Headers = @{ Authorization = "Bearer $($State.token)" } }
    if ($uri -like 'https:*' -and $IgnoreCertificate) {
        if ($PSVersionTable.PSVersion.Major -ge 6) { $params.SkipCertificateCheck = $true }
        else { $prevCb = [Net.ServicePointManager]::ServerCertificateValidationCallback; [Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }; $cbSet = $true }
    }
    # -IgnoreCertificate in Windows PowerShell can only be set for the whole process: put it back straight after
    # this one request to Rollcall, so nothing else the agent fetches skips the check (review F14)
    try {
        $raw = if (Test-PinnedUrl $uri) { $p = Invoke-PinnedRequest $uri 'GET' $null $State.token 60; if ($p.status -ne 200) { throw "HTTP $($p.status)" }; $p.bytes }
               else { (Invoke-WebRequest @params).RawContentStream.ToArray() }
    } finally { if ($cbSet) { [Net.ServicePointManager]::ServerCertificateValidationCallback = $prevCb } }
    $got = $null
    try { $got = [Text.Encoding]::UTF8.GetString($raw) | ConvertFrom-Json } catch { }
    if (-not $got -or -not $got.script -or -not $got.signature) { throw 'The update came without a signature, so it was not installed' }
    $bytes = [Convert]::FromBase64String([string]$got.script)
    if (-not (Test-RollcallSignature $bytes ([string]$got.signature))) { throw 'The update failed its signature check, so it was not installed' }
    $text = [Text.Encoding]::UTF8.GetString($bytes).TrimStart([char]0xFEFF)
    if ($text -notmatch "\`$AgentVersion = '([^']+)'" -or $Matches[1] -ne [string]$Offer.version) { throw 'The update is not the version offered, so it was not installed' }
    $errs = $null
    [void][Management.Automation.Language.Parser]::ParseInput($text, [ref]$null, [ref]$errs)
    if ($errs -and $errs.Count) { throw "The update doesn't parse ($($errs[0].Message)), so it was not installed" }
    $new = "$dest.new"
    [IO.File]::WriteAllText($new, $text, (New-Object Text.UTF8Encoding $true))
    Copy-Item -Path $dest -Destination "$dest.old" -Force
    Move-Item -Path $new -Destination $dest -Force
    Write-AgentLog "Updated the agent from $AgentVersion to $($Offer.version); the new version runs from the next report"
}

function Get-RunLock([string]$Name = 'Global\RollcallAgentRun') {
    # $true once this run holds the one-run-at-a-time lock; $false if another run has it.
    # The scheduled task runs as SYSTEM, and a lock made with Windows' defaults would be SYSTEM's alone, so
    # running the script by hand meanwhile failed with "Access to the path 'Global\RollcallAgentRun' is
    # denied". So it's made for any signed-in user to wait on; one left by an older agent that still can't
    # be opened means a run as SYSTEM is going.
    $m = $null
    try {
        $sec = New-Object Security.AccessControl.MutexSecurity
        foreach ($r in @(@('S-1-5-18', 'FullControl'), @('S-1-5-32-544', 'FullControl'), @('S-1-5-11', 'Synchronize, Modify'))) {
            $sec.AddAccessRule((New-Object Security.AccessControl.MutexAccessRule((New-Object Security.Principal.SecurityIdentifier $r[0]), [Security.AccessControl.MutexRights]$r[1], 'Allow')))
        }
        $created = $false
        $m = [Threading.Mutex]::new($false, $Name, [ref]$created, $sec)  # Windows PowerShell 5.1
    } catch { $m = $null }
    if (-not $m) { try { $m = [Threading.Mutex]::OpenExisting($Name, [Security.AccessControl.MutexRights]'Synchronize, Modify') } catch { $m = $null } }
    if (-not $m) { try { $m = New-Object Threading.Mutex($false, $Name) } catch { return $false } }  # PowerShell 7: none yet
    $got = $true
    try { $got = $m.WaitOne(0) } catch { $got = $true }  # abandoned by an earlier run that ended without letting go: ours now
    if (-not $got) { $m.Dispose(); return $false }
    $script:RunLock = $m
    return $true
}

$StuckMinutes = 20  # a run going longer than this is stuck (they normally take seconds, at most a few minutes)

function Get-AgentProcess {
    # Other PowerShell processes running this agent (the installed copy, or one run by hand from a console)
    try {
        @(Get-CimInstance -ClassName Win32_Process -Filter "Name='powershell.exe' OR Name='pwsh.exe'" -ErrorAction Stop |
            Where-Object { $_.ProcessId -ne $PID -and $_.CommandLine -match '(PingMonitorAgent|RollcallAgent)\.ps1' })
    } catch { @() }
}

function Stop-AgentProcess($Processes) {
    foreach ($p in @($Processes)) { try { Stop-Process -Id $p.ProcessId -Force -ErrorAction Stop } catch { } }
    if (@($Processes).Count) { Start-Sleep -Milliseconds 500 }
}

function Stop-StuckRun([int]$Minutes = $StuckMinutes) {
    # A run that hangs (a check that never answers) would hold the lock, and Windows lets a scheduled
    # task run for 72 hours, so every later run would skip and the device would stop reporting. Stop it,
    # say which step it was stuck on, and carry on. $true if one was stopped.
    $old = @(Get-AgentProcess | Where-Object { $_.CreationDate -and $_.CreationDate -lt (Get-Date).AddMinutes(-$Minutes) })
    if (-not $old.Count) { return $false }
    $since = ($old | Sort-Object CreationDate | Select-Object -First 1).CreationDate
    $at = ''
    try {
        $step = (Get-Content -LiteralPath (Join-Path $DataPath 'run-step.txt') -Raw -ErrorAction Stop).Trim() -split "`t"
        if ($step[0]) { $at = " at step '$($step[0])'" }
    } catch { }
    Stop-AgentProcess $old
    $msg = "agent: stopped a run stuck$at since {0} ({1} min)" -f $since.ToString('yyyy-MM-dd HH:mm'), [int]((Get-Date) - $since).TotalMinutes
    [void]$script:Errors.Add($msg)
    Write-AgentLog "WARN $msg"
    return $true
}

# ---------------------------------------------------------------------------
# The move to Rollcall's own names (1.0.60): C:\ProgramData\PingMonitor\PingMonitorAgent.ps1 and the task
# "Ping Monitor Agent" become C:\ProgramData\Rollcall\RollcallAgent.ps1 and "Rollcall Agent". An agent that
# updated itself in the old place copies itself, its token and its state across and starts the new task; the old
# one stays as the fallback until the new one has reported, and only then does the new one remove it. If the
# move fails, the old one carries on and the next report says why.
# ---------------------------------------------------------------------------
function Get-NewLayoutState {
    # The new place's state, if a move has been made and the new one has reported from it with this token
    $p = Join-Path $NewDataPath 'state.json'
    if (-not (Test-Path $p)) { return $null }
    try { return (Get-Content $p -Raw | ConvertFrom-Json) } catch { return $null }
}

function New-AgentTask([string]$Name, [string]$Script) {
    $cmd = "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$Script`""
    if ($IgnoreCertificate) { $cmd += ' -IgnoreCertificate' }
    $ErrorActionPreference = 'Continue'
    $null = & schtasks.exe /Create /TN $Name /TR $cmd /SC MINUTE /MO $IntervalMinutes /RU SYSTEM /RL HIGHEST /F 2>&1
    if ($LASTEXITCODE -ne 0) { throw "Couldn't create the scheduled task '$Name' (schtasks exit code $LASTEXITCODE)" }
}

function Move-ToNewName($State) {
    if (-not $script:LegacyLayout) { return }
    $now = (Get-Date).ToUniversalTime()
    if ($State.rename_failed_at) {
        try { if (($now - [DateTime]::Parse([string]$State.rename_failed_at, [Globalization.CultureInfo]::InvariantCulture, 'AdjustToUniversal')).TotalHours -lt 24) { return } } catch { }
    }
    if ($State.rename_started_at) {
        try { if (($now - [DateTime]::Parse([string]$State.rename_started_at, [Globalization.CultureInfo]::InvariantCulture, 'AdjustToUniversal')).TotalMinutes -lt 60) { return } } catch { }
    }
    try {
        New-Item -ItemType Directory -Path $NewDataPath -Force | Out-Null
        Protect-DataFolder $NewDataPath
        $open = @(Get-DataFolderWriters $NewDataPath)
        if ($open.Count) { throw "couldn't lock down $NewDataPath ($($open -join ', ') can change it)" }
        $have = Get-NewLayoutState
        if (-not ($have -and $have.token -eq $State.token)) {
            # Its token and state (event cursors, caches), but not "last reported": that's for the new one to set
            foreach ($f in @(Get-ChildItem -Path $DataPath -File -ErrorAction Stop)) {
                if ($f.Name -match '\.(ps1|old|new|tmp|lock)$|^agent\.log$|^run-step\.txt$') { continue }
                Copy-Item -Path $f.FullName -Destination (Join-Path $NewDataPath $f.Name) -Force
            }
            $raw = Get-Content (Join-Path $NewDataPath 'state.json') -Raw | ConvertFrom-Json
            $raw.PSObject.Properties.Remove('last_run'); $raw.PSObject.Properties.Remove('rename_started_at'); $raw.PSObject.Properties.Remove('rename_failed_at')
            $raw | ConvertTo-Json -Depth 4 | Set-Content -Path (Join-Path $NewDataPath 'state.json') -Encoding UTF8
        }
        $dest = Join-Path $NewDataPath $NewScriptName
        Copy-Item -Path $PSCommandPath -Destination $dest -Force
        New-AgentTask $NewTaskName $dest
        Set-TaskTimeLimit @($NewTaskName)
        $State.rename_started_at = ConvertTo-UtcString (Get-Date); $State.rename_failed_at = $null; $State.rename_error = $null
        $null = & schtasks.exe /Run /TN $NewTaskName 2>&1
        Write-AgentLog "Moving to the new name: $dest, task '$NewTaskName'. This one stays as the fallback until that one has reported"
    } catch {
        $State.rename_failed_at = ConvertTo-UtcString (Get-Date); $State.rename_error = [string]$_.Exception.Message
        Write-AgentLog "WARN Couldn't move to the new name (carrying on as before; tried again in a day): $($_.Exception.Message)"
    }
}

function Remove-OldName($State) {
    # Run by the agent in its new place, after a report has gone: the old task and folder are no longer needed
    if ($script:LegacyLayout -or $DataPath -ne $NewDataPath) { return }
    $ErrorActionPreference = 'Continue'
    $tasks = @($OldTaskName, "$OldTaskName (start-up)", "$OldTaskName (system file check)") | Where-Object { $null = & schtasks.exe /Query /TN $_ 2>&1; $LASTEXITCODE -eq 0 }
    $oldScript = Join-Path $OldDataPath $OldScriptName
    $oldState = Join-Path $OldDataPath 'state.json'
    if (-not @($tasks).Count -and -not (Test-Path $oldState)) { return }
    if (Test-Path $oldState) {
        try { $o = Get-Content $oldState -Raw | ConvertFrom-Json } catch { $o = $null }
        if ($o -and $o.token -and $o.token -ne $State.token) { return }  # another install's: not this agent's to remove
    }
    foreach ($t in @($tasks)) { $null = & schtasks.exe /Delete /TN $t /F 2>&1 }
    Stop-AgentProcess @(Get-AgentProcess | Where-Object { $_.CommandLine -match [regex]::Escape($oldScript) })
    try {
        Get-ChildItem -Path $OldDataPath -Force -ErrorAction Stop | Remove-Item -Recurse -Force -ErrorAction Stop
        # A small stand-in at the old name: a startup script that still runs the old version with -Install would
        # otherwise put the old name back. The old installer keeps it (its version is higher), and when its task
        # runs it, it removes that task again and does nothing else.
        Set-Content -Path $oldScript -Encoding ASCII -Value @"
# The Rollcall agent moved to $NewDataPath\$NewScriptName (task '$NewTaskName').
# This stand-in only removes the old scheduled tasks if an old startup script puts them back.
# Point any startup script or Group Policy at $NewScriptName, then this folder can be deleted.
`$AgentVersion = '99.0.0'
& schtasks.exe /Delete /TN '$OldTaskName' /F 2>`$null | Out-Null
& schtasks.exe /Delete /TN '$OldTaskName (start-up)' /F 2>`$null | Out-Null
"@
        Write-AgentLog "Moved from '$OldTaskName' ($OldDataPath) to '$NewTaskName' ($NewDataPath); removed the old task(s) and files"
    } catch { Write-AgentLog "WARN Removed the old task(s), but not all of $OldDataPath`: $($_.Exception.Message)" }
}

function Invoke-AgentRun([switch]$ReportOnly) {
    if ($Server -like '__PM_*' -or $EnrolKey -like '__PM_*') {
        throw 'This copy of the script has no add-on address or enrolment key. Download it from the Rollcall dashboard (Agents), or pass -Server and -EnrolKey.'
    }
    if (-not (Test-Path $DataPath)) { New-Item -ItemType Directory -Path $DataPath -Force | Out-Null; Protect-DataFolder }
    $opened = @(Get-DataFolderWriters)
    if ($opened.Count) {
        Protect-DataFolder  # opened up since: put it back, and only carry on if that worked (review F9)
        $open = @(Get-DataFolderWriters)
        if ($open.Count) { throw "Not running: $DataPath could be changed by $($open -join ', '), and its permissions couldn't be put back" }
        Write-AgentLog "WARN the agent's folder had been opened up; its permissions were put back before running"
    }
    if ($script:FolderCheckNote) { Write-AgentLog "WARN $script:FolderCheckNote"; $script:FolderCheckNote = $null }
    $state = Read-State
    if ($opened.Count) {
        # Put back before this run, so the check after the report finds nothing: Rollcall is still told, as before
        $state.integrity = @{ at = ConvertTo-UtcString (Get-Date); first = $false
                              what = @($opened | Select-Object -First 9 | ForEach-Object { Limit-Text "$_ had access to the agent folder" 200 }) }
        try { Save-State $state } catch { }
    }
    if (-not $state.token) { $state.token = New-Token; Save-State $state }
    if ($script:LegacyLayout -and -not ($ReportOnly -or $ShowReport)) {
        $ns = Get-NewLayoutState
        if ($ns -and $ns.last_run -and $ns.token -eq $state.token) {
            Write-AgentLog "This agent has moved to '$NewTaskName' ($NewDataPath), which is reporting: this old copy does nothing (the new one removes it)"
            return
        }
    }
    $script:PreferredServer = [string]$state.last_server
    $script:PushedServers = @($state.servers | Where-Object { $_ -match '^https?://[^\s,;]+$' })
    $script:TlsPinNow = $null; $script:TlsPortNow = 0
    if ($state.tls -and -not $state.tls.off -and $state.tls.pin -and $state.tls.port -gt 0) { $script:TlsPinNow = [string]$state.tls.pin; $script:TlsPortNow = [int]$state.tls.port }
    elseif (-not ($state.tls -and $state.tls.off) -and $TlsPin -notlike '__PM_*' -and $TlsPort -gt 0) { $script:TlsPinNow = $TlsPin; $script:TlsPortNow = $TlsPort }
    $script:Route = $null
    if ($state.route -and $state.route.inside -match '^https?://[^\s,;]+$' -and $state.route.outside -match '^https?://[^\s,;]+$' -and @($state.route.networks).Count) {
        $script:Route = $state.route
        $script:RouteSide = Get-RouteSide $state.route
        if ($script:RouteSide -ne $state.route_side) {
            Write-AgentLog ("{0}: trying the {1} address first" -f $(if ($script:RouteSide -eq 'inside') { 'On an internal network' } else { 'Not on an internal network' }), $script:RouteSide)
            $state.route_side = $script:RouteSide
        }
    }

    $extra = @($ExtraServices) + @($state.watch) | Where-Object { $_ } | Select-Object -Unique
    if (-not ($ReportOnly -or $ShowReport)) {
        # One run at a time (the start-up run and the regular one can meet just after a restart)
        if (-not (Get-RunLock) -and -not ((Stop-StuckRun) -and (Get-RunLock))) { Write-AgentLog 'Another run is still going; skipped this one'; return }
        $script:StepFile = Join-Path $DataPath 'run-step.txt'
        Wait-Network
        if ($script:Route) { $script:RouteSide = Get-RouteSide $script:Route }  # the network may have changed while waiting
    }
    $report = Get-Report $state $extra
    if ($ReportOnly -or $ShowReport) { $report | ConvertTo-Json -Depth 10; return }

    $res = Send-Json '/agent/report' $report $state.token
    if ($res.status -eq 401) {
        Write-AgentLog 'Not enrolled yet: asking to join'
        $res = Send-Json '/agent/enrol' ([ordered]@{
                enrol_key = $EnrolKey; hostname = $report.hostname; fqdn = $report.fqdn
                ips = $report.ips; os = $report.os; agent_version = $AgentVersion; token = $state.token
            }) $null
        if ($res.status -eq 403) { throw 'The add-on rejected the enrolment key. Download a fresh copy of the script from the dashboard.' }
        if ($res.status -eq 410) {
            Write-AgentLog 'This server was rejected or revoked in the Rollcall dashboard. To ask again, run the script with -Uninstall and then -Install.'
            return
        }
        Write-AgentLog 'Waiting for an admin to approve this server in the Rollcall dashboard'
        return  # don't advance cursors: the events will be sent once approved
    }
    if ($res.status -eq 202) { Write-AgentLog 'Waiting for approval in the Rollcall dashboard'; return }
    if ($res.status -ne 200) { throw "Report rejected (HTTP $($res.status))" }

    if ($res.body -and $res.body.watch_services) { $state.watch = @($res.body.watch_services) } else { $state.watch = @() }
    if ($report.Contains('apps')) { $state.apps_sent = $report.apps_hash }
    if ($res.body -and $res.body.send_apps) { $state.apps_sent = $null }  # Rollcall hasn't got this list: send it next time
    if ($report.secrets -and $report.secrets.Contains('findings')) { $state.secrets_sent = $report.secrets.hash }
    if ($res.body -and $res.body.send_secrets) { $state.secrets_sent = $null }
    $sc = if ($res.body) { $res.body.secret_scan } else { $null }
    if ($sc) {
        $state.secret_scan = @{ on = [bool]$sc.on; paths = @(@($sc.paths) | Where-Object { $_ } | ForEach-Object { ([string]$_).Substring(0, [Math]::Min(260, ([string]$_).Length)) } | Select-Object -First 20)
            hours = $(if ($sc.hours) { [int]$sc.hours } else { 24 }) }
    } else { $state.secret_scan = @{ on = $false } }
    $sf = if ($res.body) { $res.body.sfc } else { $null }
    $state.sfc_conf = $(if ($sf) { @{ on = [bool]$sf.on; day = [int]$sf.day; hour = [int]$sf.hour; dism = [bool]$sf.dism; run_now = [int64]$sf.run_now } } else { $null })
    $state.last_run = ConvertTo-UtcString (Get-Date)
    if ($script:ActiveServer) { $state.last_server = $script:ActiveServer }
    # New addresses only with Rollcall's signature: a reply changed on the way can't send this agent elsewhere.
    # Without one, it carries on with the addresses it has.
    # With a serial (Rollcall 1.99 on): signed with a number that never goes down, so an older signed reply replayed
    # later is refused. Once this agent has had one, it needs one every time (review F7).
    $lastSerial = [int64]0; try { $lastSerial = [int64]$state.sig_serial } catch { }
    $serial = $null
    if ($res.body -and $null -ne $res.body.sig_serial -and $res.body.config_sig2 -and ([string]$res.body.sig_serial -match '^\d{1,15}$')) { $serial = [int64]$res.body.sig_serial }
    $tail = if ($null -ne $serial) { "serial=$serial`n" } else { '' }
    if ($null -ne $serial) {
        $signed = Test-RollcallSignature ([Text.Encoding]::UTF8.GetBytes(([Text.Encoding]::UTF8.GetString((Get-ConfigText $res.body))) + $tail)) ([string]$res.body.config_sig2)
        if ($signed -and $serial -lt $lastSerial) {
            Write-AgentLog "WARN Rollcall's reply was signed earlier than one this agent already had (an old reply sent again?); ignored"
            $signed = $false; $serial = $null
        } elseif ($signed) { $state.sig_serial = $serial }
    } elseif ($lastSerial -gt 0) {
        $signed = $false
        if ($res.body -and ($res.body.servers -or $res.body.route -or $res.body.tls -or $res.body.config_sig)) { Write-AgentLog "WARN Rollcall's reply had no serial, though earlier ones did; ignored its addresses and HTTPS details" }
    } else {
        $signed = $res.body -and $res.body.config_sig -and (Test-RollcallSignature (Get-ConfigText $res.body) ([string]$res.body.config_sig))
    }
    if ($res.body -and -not $signed -and ($res.body.servers -or $res.body.route)) { Write-AgentLog "WARN Rollcall's reply had addresses without a good signature; kept the ones this agent has" }
    # Rollcall's own HTTPS: the port and key, signed with the update key (so not changeable on the way)
    if ($res.body -and $res.body.tls -and ($null -ne $serial -or $lastSerial -eq 0)) {
        $tp = [int]$res.body.tls.port; $tk = [string]$res.body.tls.pin
        $ttext = "rollcall-agent-tls/1`nport=$tp`npin=$tk`n"
        $tlsOk = if ($null -ne $serial) { Test-RollcallSignature ([Text.Encoding]::UTF8.GetBytes($ttext + $tail)) ([string]$res.body.tls_sig2) } else { Test-RollcallSignature ([Text.Encoding]::UTF8.GetBytes($ttext)) ([string]$res.body.tls_sig) }
        if ($tp -gt 0 -and $tk -and $tlsOk) {
            if (-not $state.tls -or $state.tls.pin -ne $tk -or [int]$state.tls.port -ne $tp -or $state.tls.off) { Write-AgentLog "Rollcall's HTTPS is on: reports go to port $tp from the next run, to Rollcall's own key only" }
            $state.tls = @{ port = $tp; pin = $tk; off = $false }
        } else { Write-AgentLog "WARN Rollcall's HTTPS details didn't have a good signature; ignored" }
    } elseif ($signed -and $state.tls -and -not $state.tls.off) {
        Write-AgentLog "Rollcall's HTTPS was turned off; reports go over the address this agent has"
        $state.tls = @{ port = 0; pin = ''; off = $true }
    } elseif ($signed -and -not $state.tls -and $TlsPin -notlike '__PM_*') { $state.tls = @{ port = 0; pin = ''; off = $true } }
    if ($signed -and $res.body.servers) {
        $pushed = @($res.body.servers | ForEach-Object { [string]$_ } | Where-Object { $_ -match '^https?://[^\s,;]+$' } | Select-Object -First 4)
        if ($pushed.Count -and (($pushed -join ',') -ne (@($state.servers) -join ','))) {
            Write-AgentLog ("Rollcall's addresses are now: " + ($pushed -join ', '))
        }
        if ($pushed.Count) { $state.servers = $pushed }
    }
    $rt = if ($signed) { $res.body.route } else { $null }
    if ($rt -and [string]$rt.inside -match '^https?://[^\s,;]+$' -and [string]$rt.outside -match '^https?://[^\s,;]+$') {
        $state.route = @{ inside = ([string]$rt.inside).TrimEnd('/'); outside = ([string]$rt.outside).TrimEnd('/')
            networks = @(@($rt.networks) | Where-Object { $_ } | ForEach-Object { [string]$_ } | Select-Object -First 50) }
    } elseif ($signed) {
        $state.route = $null; $state.route_side = $null  # not set under Agents (any more): the last address that worked goes first
    }
    Save-State $state
    $slow = $script:Timings.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 1
    $took = if ($report.run_ms) { '{0:N1} s' -f ($report.run_ms / 1000) } else { '?' }
    Write-AgentLog ("Report sent to {0}: {1} role(s), {2} error(s); run took {3}{4}" -f $script:ActiveServer, @($report.roles).Count, @($report.errors).Count, $took,
        $(if ($slow) { '; slowest: {0} {1:N1} s' -f $slow.Key, ($slow.Value / 1000) } else { '' }))
    if ($res.body -and $res.body.messages) {
        try { Show-RollcallMessages $state @($res.body.messages); Save-State $state } catch { Write-AgentLog "WARN Messages: $($_.Exception.Message)" }
    }
    if ($res.body -and $res.body.agent_update) {
        try { Invoke-AgentUpdate $state $res.body.agent_update } catch { Write-AgentLog "WARN Agent update: $($_.Exception.Message)" }
    }
    Register-StartupTask
    Set-TaskTimeLimit
    if ($script:LegacyLayout) { Move-ToNewName $state; try { Save-State $state } catch { } }
    else { Remove-OldName $state }
    $wasChecked = [bool]$state.perm_checked
    Test-AgentFolderSecurity $state
    if ($state.integrity -or $state.perm_checked -ne $wasChecked) { try { Save-State $state } catch { } }
    # After the report, so it never slows reports down; the findings go with the next one
    try {
        $st = Invoke-SecretScan $state
        if ($st -and $st.finished) {
            Write-AgentLog ("Password scan finished: {0} file(s) checked, {1} finding(s)" -f $st.files.Count, @($st.found).Count)
        }
    } catch { Write-AgentLog "WARN Password scan: $($_.Exception.Message)" }
}

# ---------------------------------------------------------------------------
# Install / uninstall
# ---------------------------------------------------------------------------
function Install-Agent {
    if ($Server -like '__PM_*' -or $EnrolKey -like '__PM_*') {
        throw 'Download the script from the Rollcall dashboard (Agents) so it includes the add-on address and enrolment key.'
    }
    New-Item -ItemType Directory -Path $DataPath -Force | Out-Null
    Protect-DataFolder
    $open = @(Get-DataFolderWriters)
    if ($open.Count) {  # never create a SYSTEM task that runs from a folder others can change (review F9)
        throw "Couldn't lock down $DataPath (these can still change it: $($open -join ', ')). The agent wasn't installed; check the folder's permissions and run the install again."
    }
    # Installing over an agent still under the old name (Ping Monitor): its token and state come across, so it
    # stays approved; the new one removes the old task and folder once it has reported (Remove-OldName)
    if ($DataPath -eq $NewDataPath -and (Test-Path (Join-Path $OldDataPath 'state.json')) -and -not (Test-Path (Join-Path $NewDataPath 'state.json'))) {
        foreach ($f in @(Get-ChildItem -Path $OldDataPath -File)) {
            if ($f.Name -match '\.(ps1|old|new|tmp|lock)$|^agent\.log$|^run-step\.txt$') { continue }
            Copy-Item -Path $f.FullName -Destination (Join-Path $NewDataPath $f.Name) -Force
        }
        Write-AgentLog "Brought the token and state across from $OldDataPath (the old name); its task is removed after the first report"
    }
    $dest = Join-Path $DataPath $ScriptName
    # A startup script on the share can be older than a copy that has updated itself:
    # keep the newer one, so the two don't keep swapping versions.
    $installed = $null
    if (Test-Path $dest) { $m = Select-String -Path $dest -Pattern "\`$AgentVersion = '([^']+)'" | Select-Object -First 1; if ($m) { $installed = $m.Matches[0].Groups[1].Value } }
    if ($installed -and (Test-NewerVersion $installed $AgentVersion)) {
        Write-AgentLog "Kept the installed agent $installed (newer than this copy, $AgentVersion)"
    } elseif ($SelfPath -and (Test-Path $SelfPath)) {
        if ($SelfPath -ne $dest) { Copy-Item -Path $SelfPath -Destination $dest -Force }
    } elseif ($SelfText -and $SelfText -match '(Rollcall|Ping Monitor) agent') {
        # Run as a script block (no file): write the script text out, with a BOM
        # so Windows PowerShell reads it as UTF-8.
        [IO.File]::WriteAllText($dest, $SelfText, (New-Object Text.UTF8Encoding $true))
    }
    if (-not (Test-Path $dest)) { throw "Couldn't save the agent to $dest" }
    $null = Stop-StuckRun  # a stuck earlier run would keep the new one waiting (a healthy one is left to finish)
    $cmd = "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$dest`""
    if ($IgnoreCertificate) { $cmd += ' -IgnoreCertificate' }
    & schtasks.exe /Create /TN $TaskName /TR $cmd /SC MINUTE /MO $IntervalMinutes /RU SYSTEM /RL HIGHEST /F | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Couldn't create the scheduled task (schtasks exit code $LASTEXITCODE)" }
    Set-TaskTimeLimit
    & schtasks.exe /Run /TN $TaskName | Out-Null
    Write-AgentLog "Installed version $AgentVersion; reporting to $Server every $IntervalMinutes min"
    Write-Output "Rollcall agent $AgentVersion installed. It will appear in the dashboard's Agents list for approval within a minute."
}

# Also run once a minute after Windows starts, so Rollcall hears about a restart straight away
# (a paused computer's pause ends when it's back) instead of up to 5 minutes later.
# Called after the report is sent, and can never fail a run: in Windows PowerShell 5.1 with
# $ErrorActionPreference = 'Stop', anything a program writes to stderr would otherwise end the run.
$TaskTimeLimit = 'PT30M'
# Stop each of the agent's scheduled tasks after 30 minutes. schtasks leaves Windows' default of 72 hours,
# and Windows doesn't start a task again while it's still running, so one stuck run (a check that never
# answers) kept a device from reporting for days. Runs take seconds, a few minutes at most. Checked after
# every report, so agents installed before this fix themselves; it can never fail a run.
function Set-TaskTimeLimit([string[]]$Names = @($TaskName, "$TaskName (start-up)"), [string]$Limit = $TaskTimeLimit) {
    $ErrorActionPreference = 'Continue'
    try {
        if (-not (Get-Command Get-ScheduledTask -ErrorAction SilentlyContinue)) { return }  # before Windows 8 / Server 2012
        foreach ($n in $Names) {
            $t = Get-ScheduledTask -TaskName $n -ErrorAction SilentlyContinue
            if (-not $t -or [string]$t.Settings.ExecutionTimeLimit -eq $Limit) { continue }
            $t.Settings.ExecutionTimeLimit = $Limit
            $null = Set-ScheduledTask -InputObject $t -ErrorAction Stop
            Write-AgentLog "The scheduled task '$n' now stops a run after $($Limit -replace '^PT', '' -replace 'M$', ' minutes' -replace 'H$', ' hours')"
        }
    } catch { Write-AgentLog "WARN Couldn't set the scheduled task's time limit: $($_.Exception.Message)" }
}

function Register-StartupTask {
    $ErrorActionPreference = 'Continue'
    try {
        $dest = Join-Path $DataPath $ScriptName
        if (-not $PSCommandPath -or $PSCommandPath -ne $dest -or -not (Get-Command schtasks.exe -ErrorAction SilentlyContinue)) { return }
        $name = "$TaskName (start-up)"
        $null = & schtasks.exe /Query /TN $name 2>&1
        if ($LASTEXITCODE -eq 0) { return }
        $cmd = "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$dest`""
        if ($IgnoreCertificate) { $cmd += ' -IgnoreCertificate' }
        $null = & schtasks.exe /Create /TN $name /TR $cmd /SC ONSTART /DELAY 0001:00 /RU SYSTEM /RL HIGHEST /F 2>&1
        if ($LASTEXITCODE -eq 0) { Write-AgentLog 'Added a start-up run, so restarts are reported straight away' }
        else { Write-AgentLog "WARN Couldn't add the start-up run (schtasks exit code $LASTEXITCODE)" }
    } catch { Write-AgentLog "WARN Couldn't add the start-up run: $($_.Exception.Message)" }
}

function Uninstall-Agent {
    & schtasks.exe /Delete /TN $TaskName /F 2>$null | Out-Null
    Stop-AgentProcess (Get-AgentProcess)  # a run still going (or stuck) would otherwise carry on, holding the lock
    $ErrorActionPreference = 'Continue'
    $null = & schtasks.exe /Delete /TN "$TaskName (start-up)" /F 2>&1  # may not exist
    $null = & schtasks.exe /Delete /TN $SfcTaskName /F 2>&1  # the system file check's task, if it ever ran
    if (-not $script:LegacyLayout) {  # anything left under the old name (Ping Monitor) goes too
        foreach ($t in @($OldTaskName, "$OldTaskName (start-up)", "$OldTaskName (system file check)")) { $null = & schtasks.exe /Delete /TN $t /F 2>&1 }
        if ($DataPath -eq $NewDataPath -and (Test-Path $OldDataPath)) { Remove-Item -Path $OldDataPath -Recurse -Force -ErrorAction SilentlyContinue }
    }
    $ErrorActionPreference = 'Stop'
    if (Test-Path $DataPath) { Remove-Item -Path $DataPath -Recurse -Force }
    Write-Output 'Rollcall agent removed. Revoke it in the dashboard too if it was approved.'
}

function Main {
    try {
        $doInstall, $doUninstall, $doReport = [bool]$Install, [bool]$Uninstall, [bool]$ShowReport
        switch ($Action.Trim().ToLower()) {
            '' { }
            'install' { $doInstall = $true }
            'uninstall' { $doUninstall = $true }
            'report' { $doReport = $true }
            default { throw "Unknown -Action '$Action'. Use Install, Uninstall or Report." }
        }
        if ($SecretTest) {
            $st = Invoke-SecretScan @{} 0 @((Resolve-Path -LiteralPath $SecretTest).Path)
            ConvertTo-Json -InputObject @($st.found | Sort-Object @{ e = { $_.path } }, @{ e = { [int]$_.line } }, @{ e = { $_.rule } }) -Depth 3
            return
        }
        if ($doUninstall) { Uninstall-Agent; return }
        if ($doInstall) { Install-Agent; return }
        Invoke-AgentRun -ReportOnly:$doReport
    } catch {
        Write-AgentLog "ERROR $($_.Exception.Message)"
        Write-Error $_.Exception.Message -ErrorAction Continue
        exit 1
    }
}

if ($MyInvocation.InvocationName -ne '.') { Main }
