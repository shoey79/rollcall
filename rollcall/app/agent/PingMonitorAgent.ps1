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

    It runs every 5 minutes as a SYSTEM scheduled task and sends a small
    JSON report to the add-on. It never accepts commands from the add-on.

    First run: the server asks to join, and an admin approves it in the
    Rollcall dashboard (Agents). Until then reports are refused.

.PARAMETER Install
    Copy the script to C:\ProgramData\PingMonitor, create the scheduled task
    and run it once. Safe to run repeatedly (e.g. as a GPO startup script);
    it also updates the installed copy.

.PARAMETER Uninstall
    Remove the scheduled task and C:\ProgramData\PingMonitor.

.PARAMETER Action
    Install, Uninstall or Report: the same as the switches, as text. Use this
    from tools that can't pass switches, such as MECM Run Scripts.

.PARAMETER ShowReport
    Collect and print the report without sending it (troubleshooting).

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File \\example.local\NETLOGON\PingMonitorAgent.ps1 -Install

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
    [string]$DataPath = ''
)

$AgentVersion = '1.0.11'
$TaskName = 'Ping Monitor Agent'
# Where this script is running from, captured at the top level so Install can
# copy it even when it's run from MECM's script store or as a script block.
$SelfPath = $PSCommandPath
$SelfText = $null
try { if ($MyInvocation.MyCommand.ScriptContents) { $SelfText = $MyInvocation.MyCommand.ScriptContents } } catch { }
if (-not $SelfText) { try { $SelfText = $MyInvocation.MyCommand.ScriptBlock.ToString() } catch { } }
$ErrorActionPreference = 'Stop'
if (-not $DataPath) { $DataPath = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'PingMonitor' }
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
function Measure-Step([string]$Name, [scriptblock]$Block) {
    # Runs one part of the collection and records how long it took (ms).
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
    $state = @{ token = $null; last_run = $null; cursors = @{}; watch = @(); patch = $null; amd_raid = $null; veeam = $null; veeam_cursor = $null; vbo = $null; vbo_checked = $null }
    if (Test-Path $StatePath) {
        try {
            $raw = Get-Content $StatePath -Raw | ConvertFrom-Json
            $state.token = $raw.token
            $state.last_run = $raw.last_run
            if ($raw.cursors) {
                foreach ($p in $raw.cursors.PSObject.Properties) { $state.cursors[$p.Name] = [long]$p.Value }
            }
            if ($raw.watch) { $state.watch = @($raw.watch) }
            if ($raw.amd_raid) { $state.amd_raid = [string]$raw.amd_raid }
            if ($raw.veeam) { $state.veeam = [string]$raw.veeam }
            if ($raw.veeam_cursor) { $state.veeam_cursor = [int64]$raw.veeam_cursor }
            if ($raw.vbo) { $state.vbo = [string]$raw.vbo }
            if ($raw.vbo_checked) { try { $state.vbo_checked = [int64]$raw.vbo_checked } catch { } }
            if ($raw.patch) { $state.patch = @{ checked = $raw.patch.checked; date = $raw.patch.date; kb = $raw.patch.kb; source = $raw.patch.source } }
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

function Protect-DataFolder {
    # The token lives here: SYSTEM and Administrators only.
    try {
        & icacls.exe $DataPath /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
    } catch { Write-AgentLog "WARN couldn't set folder permissions: $($_.Exception.Message)" }
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

function Get-NewEvents([hashtable]$Filter, [int]$Max, [string]$CursorName, $State) {
    # Events newer than the last run, de-duplicated by RecordId.
    try {
        $events = @(Get-WinEvent -FilterHashtable $Filter -MaxEvents $Max -ErrorAction Stop)
    } catch {
        if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*' -or $_.Exception.Message -like 'No events were found*') {
            return @()
        }
        throw
    }
    $last = 0
    if ($State.cursors.ContainsKey($CursorName)) { $last = [long]$State.cursors[$CursorName] }
    $newest = ($events | Measure-Object -Property RecordId -Maximum).Maximum
    if ($null -ne $newest -and $newest -lt $last) { $last = 0 }  # log was cleared
    $fresh = @($events | Where-Object { $_.RecordId -gt $last })
    if ($null -ne $newest -and $newest -gt $last) { $State.cursors[$CursorName] = [long]$newest }
    return $fresh
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
    $pending = $false
    foreach ($key in @(
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending',
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')) {
        try { if (Test-Path $key) { $pending = $true } } catch { }
    }
    $info.pending_reboot = $pending
    return $info
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
    if ($fresh) { return @{ date = $c.date; kb = $c.kb; source = $c.source; cached = $true } }
    $p = Get-LastPatch
    $State.patch = @{ checked = ConvertTo-UtcString (Get-Date); date = (ConvertTo-UtcString $p.date); kb = $p.kb; source = $p.source }
    return @{ date = $State.patch.date; kb = $p.kb; source = $p.source; cached = $false }
}

function Get-LastPatch {
    # The newest of three sources, because each can miss things:
    #  - Windows Update Agent history: includes MECM/WSUS installs (MECM uses the agent)
    #  - Setup event log: Windows Servicing records every package it installs,
    #    however it arrived, even with the Windows Update service disabled
    #  - Win32_QuickFixEngineering: its InstalledOn text is US-format; Get-HotFix
    #    can misread it on non-US servers, so it's parsed here explicitly
    $best = @{ date = $null; kb = $null; source = $null }
    $consider = {
        param($Date, $Kb, $Source)
        if ($Date -and $Date -le (Get-Date).AddDays(1) -and (-not $best.date -or $Date -gt $best.date)) {
            $best.date = $Date; $best.kb = $Kb; $best.source = $Source
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
                & $consider ([DateTime]$h.Date).ToLocalTime() $kb 'Windows Update history'
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
            & $consider $d ([string]$q.HotFixID) 'Installed updates list'
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

function Get-ServiceReport($AllServices, $Discovery) {
    $watched = @()
    foreach ($name in $Discovery.watch.Keys) {
        $s = $AllServices | Where-Object { $_.Name -eq $name } | Select-Object -First 1
        if ($s) {
            $watched += [ordered]@{
                name = [string]$s.Name; display = [string]$s.DisplayName; state = [string]$s.State
                start_mode = [string]$s.StartMode; role = [string]$Discovery.watch[$name]
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
        $stopped += [ordered]@{ name = [string]$s.Name; display = [string]$s.DisplayName; state = [string]$s.State }
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
            $events = Get-NewEvents @{ LogName = $log; Level = 1, 2; StartTime = $Since } 300 $log $State
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
                        message = Limit-Text ($(if ($e.Message) { $e.Message } else { '(no description)' })) 300
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
    try {
        $ids = @($SecurityIds.Keys | ForEach-Object { [int]$_ })
        $events = Get-NewEvents @{ LogName = 'Security'; Id = $ids; StartTime = $Since } 300 'Security-notable' $State
        $items = @()
        foreach ($e in ($events | Sort-Object TimeCreated -Descending | Select-Object -First 50)) {
            $f = Get-EventFields $e
            $who = @($f['TargetDomainName'], $f['TargetUserName']) | Where-Object { $_ -and $_ -ne '-' }
            $items += [ordered]@{
                time    = ConvertTo-UtcString $e.TimeCreated
                id      = [int]$e.Id
                what    = $SecurityIds[[int]$e.Id]
                account = if ($e.Id -in 4728, 4732, 4756, 4729, 4733, 4757) { [string]$f['MemberName'] } else { ($who -join '\') }
                group   = if ($e.Id -in 4728, 4732, 4756, 4729, 4733, 4757) { (@($f['TargetDomainName'], $f['TargetUserName']) | Where-Object { $_ }) -join '\' } else { $null }
                by      = (@($f['SubjectDomainName'], $f['SubjectUserName']) | Where-Object { $_ -and $_ -ne '-' }) -join '\'
                source  = if ($e.Id -eq 4740) { [string]$f['TargetDomainName'] } else { $null }
            }
        }
        # 4740's TargetDomainName is the caller computer, not a domain
        foreach ($i in $items) { if ($i.id -eq 4740) { $i.account = ($i.account -split '\\')[-1] } }
        $report.items = $items
    } catch { Add-CollectorError 'security' $_ }
    try {
        $failed = Get-NewEvents @{ LogName = 'Security'; Id = 4625; StartTime = $Since } 2000 'Security-4625' $State
        $report.failed_logons.count = @($failed).Count
        if (@($failed).Count -gt 0) {
            $rows = foreach ($e in $failed) {
                $f = Get-EventFields $e
                [pscustomobject]@{
                    account = ((@($f['TargetDomainName'], $f['TargetUserName']) | Where-Object { $_ -and $_ -ne '-' }) -join '\')
                    source  = if ($f['IpAddress'] -and $f['IpAddress'] -ne '-') { $f['IpAddress'] } else { [string]$f['WorkstationName'] }
                }
            }
            $report.failed_logons.top = @($rows | Group-Object account, source | Sort-Object Count -Descending |
                Select-Object -First 5 | ForEach-Object {
                    [ordered]@{ account = $_.Group[0].account; source = $_.Group[0].source; count = $_.Count }
                })
        }
    } catch { Add-CollectorError 'failed-logons' $_ }
    return $report
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
            $checks.hyperv = @(Get-VM | ForEach-Object {
                    [ordered]@{ name = [string]$_.Name; state = [string]$_.State; status = [string]$_.Status }
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
                signature_age_days = [int]$mp.AntivirusSignatureAge
                detections = @()
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
                    runs = @($v.runs | Where-Object { $_ } | ForEach-Object { ConvertTo-IsoText $_ }) }
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
            if ($desc -notmatch "^(?<type>.+?) job '(?<name>.+)' finished with (?<res>\w+)\.?\s*(?<detail>.*)$") { continue }
            $jname = $Matches['name']; $jtype = $Matches['type']; $jdetail = $Matches['detail']; $jres = $Matches['res']
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
    $State.veeam = ($jobs | ConvertTo-Json -Depth 4 -Compress)
    return @(foreach ($k in $jobs.Keys) { $j = $jobs[$k]
        [ordered]@{ source = 'Backup & Replication'; id = $k; name = $j.name; type = $j.type; result = $j.result; finished = $j.finished
            retry = [bool]$j.retry; detail = $j.detail; last_success = $j.last_success; session = $j.session; runs = @($j.runs) } })
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
            $report.last_patch_source = $patch.source
        }
        $report.last_patch_cached = [bool]$patch.cached
    } catch { Add-CollectorError 'updates' $_ }

    $allServices = @()
    try { $allServices = @(Measure-Step 'service list' { Get-CimInstance -ClassName Win32_Service }) } catch { Add-CollectorError 'services' $_ }
    $discovery = Measure-Step 'roles' { Get-Discovery $allServices $ExtraWatch $(if ($sys) { [bool]$sys.workstation } else { $false }) }
    $report.roles = $discovery.roles

    # @() keeps a single disk as a list: PowerShell unwraps one-item arrays returned from functions
    try { $report.disks = @(Measure-Step 'disks' { Get-Disks }) } catch { Add-CollectorError 'disks' $_ }
    try { $report.services = Measure-Step 'services' { Get-ServiceReport $allServices $discovery } } catch { Add-CollectorError 'services' $_ }
    $report.events = Measure-Step 'event logs' { Get-EventReport $State $since }
    $report.security = Measure-Step 'security log' { Get-SecurityReport $State $since }
    $report.checks = Get-RoleChecks $discovery.roles $since $State
    try {
        $bjobs = @()
        $vbr = Measure-Step 'veeam b&r' { Get-VeeamJobs $State }
        if ($null -ne $vbr) { $bjobs += @($vbr) }
        $vbo = $null
        try { $vbo = Measure-Step 'veeam m365' { Get-VboJobs $State } } catch { Add-CollectorError 'veeam m365' $_ }
        if ($null -ne $vbo) { $bjobs += @($vbo) }
        if ($null -ne $vbr -or $null -ne $vbo) { $report.checks.backups = [ordered]@{ jobs = @($bjobs) } }
    } catch { Add-CollectorError 'veeam' $_ }
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
function Send-Json([string]$Path, $Body, [string]$Token) {
    $uri = $Server.TrimEnd('/') + $Path
    $json = $Body | ConvertTo-Json -Depth 10 -Compress
    $params = @{
        Uri = $uri; Method = 'Post'; Body = [Text.Encoding]::UTF8.GetBytes($json)
        ContentType = 'application/json; charset=utf-8'; TimeoutSec = 30; UseBasicParsing = $true
    }
    if ($Token) { $params.Headers = @{ Authorization = "Bearer $Token" } }
    if ($uri -like 'https:*') {
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        if ($IgnoreCertificate) {
            if ($PSVersionTable.PSVersion.Major -ge 6) { $params.SkipCertificateCheck = $true }
            else { [Net.ServicePointManager]::ServerCertificateValidationCallback = { $true } }
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
    }
}

function Test-NewerVersion([string]$A, [string]$B) {
    # True when version A is newer than version B (e.g. 1.0.10 > 1.0.9).
    try { return ([version]($A -replace '[^\d.]', '')) -gt ([version]($B -replace '[^\d.]', '')) } catch { return $false }
}

function Invoke-AgentUpdate($State, $Offer) {
    # The add-on offers a newer agent only when an admin has turned updates on. The
    # download is checked before anything changes: it must be signed with this server's
    # own token (HMAC-SHA256), be a newer version than this one, and parse as PowerShell.
    # The old copy is kept as PingMonitorAgent.ps1.old. The new one runs from the next report.
    if (-not $Offer -or -not $Offer.version -or -not (Test-NewerVersion ([string]$Offer.version) $AgentVersion)) { return }
    $dest = Join-Path $DataPath 'PingMonitorAgent.ps1'
    if (-not (Test-Path $dest)) { return }  # only an installed agent updates itself
    $uri = $Server.TrimEnd('/') + '/agent/update?os=windows&server=' + [uri]::EscapeDataString($Server.TrimEnd('/'))
    if ($IgnoreCertificate) { $uri += '&ignore_cert=1' }
    $params = @{ Uri = $uri; Method = 'Get'; TimeoutSec = 60; UseBasicParsing = $true; Headers = @{ Authorization = "Bearer $($State.token)" } }
    if ($uri -like 'https:*' -and $IgnoreCertificate) {
        if ($PSVersionTable.PSVersion.Major -ge 6) { $params.SkipCertificateCheck = $true }
        else { [Net.ServicePointManager]::ServerCertificateValidationCallback = { $true } }
    }
    $r = Invoke-WebRequest @params
    $bytes = $r.RawContentStream.ToArray()
    $sig = [string]($r.Headers['X-Rollcall-Signature'] | Select-Object -First 1)
    $key = (New-Object Security.Cryptography.SHA256Managed).ComputeHash([Text.Encoding]::UTF8.GetBytes([string]$State.token))
    $mac = -join ((New-Object Security.Cryptography.HMACSHA256 (, $key)).ComputeHash($bytes) | ForEach-Object { $_.ToString('x2') })
    if (-not $sig -or $sig.ToLower() -ne $mac) { throw 'The update failed its signature check, so it was not installed' }
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

function Invoke-AgentRun([switch]$ReportOnly) {
    if ($Server -like '__PM_*' -or $EnrolKey -like '__PM_*') {
        throw 'This copy of the script has no add-on address or enrolment key. Download it from the Rollcall dashboard (Agents), or pass -Server and -EnrolKey.'
    }
    if (-not (Test-Path $DataPath)) { New-Item -ItemType Directory -Path $DataPath -Force | Out-Null; Protect-DataFolder }
    $state = Read-State
    if (-not $state.token) { $state.token = New-Token; Save-State $state }

    $extra = @($ExtraServices) + @($state.watch) | Where-Object { $_ } | Select-Object -Unique
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
    $state.last_run = ConvertTo-UtcString (Get-Date)
    Save-State $state
    $slow = $script:Timings.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 1
    $took = if ($report.run_ms) { '{0:N1} s' -f ($report.run_ms / 1000) } else { '?' }
    Write-AgentLog ("Report sent: {0} role(s), {1} error(s); run took {2}{3}" -f @($report.roles).Count, @($report.errors).Count, $took,
        $(if ($slow) { '; slowest: {0} {1:N1} s' -f $slow.Key, ($slow.Value / 1000) } else { '' }))
    if ($res.body -and $res.body.agent_update) {
        try { Invoke-AgentUpdate $state $res.body.agent_update } catch { Write-AgentLog "WARN Agent update: $($_.Exception.Message)" }
    }
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
    $dest = Join-Path $DataPath 'PingMonitorAgent.ps1'
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
    $cmd = "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$dest`""
    if ($IgnoreCertificate) { $cmd += ' -IgnoreCertificate' }
    & schtasks.exe /Create /TN $TaskName /TR $cmd /SC MINUTE /MO $IntervalMinutes /RU SYSTEM /RL HIGHEST /F | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Couldn't create the scheduled task (schtasks exit code $LASTEXITCODE)" }
    & schtasks.exe /Run /TN $TaskName | Out-Null
    Write-AgentLog "Installed version $AgentVersion; reporting to $Server every $IntervalMinutes min"
    Write-Output "Rollcall agent $AgentVersion installed. It will appear in the dashboard's Agents list for approval within a minute."
}

function Uninstall-Agent {
    & schtasks.exe /Delete /TN $TaskName /F 2>$null | Out-Null
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
