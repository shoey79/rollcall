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

$AgentVersion = '1.0.6'
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
    $state = @{ token = $null; last_run = $null; cursors = @{}; watch = @(); patch = $null }
    if (Test-Path $StatePath) {
        try {
            $raw = Get-Content $StatePath -Raw | ConvertFrom-Json
            $state.token = $raw.token
            $state.last_run = $raw.last_run
            if ($raw.cursors) {
                foreach ($p in $raw.cursors.PSObject.Properties) { $state.cursors[$p.Name] = [long]$p.Value }
            }
            if ($raw.watch) { $state.watch = @($raw.watch) }
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
    @{ Role = 'Veeam Backup'; Pattern = '^Veeam(BackupSvc|BrokerSvc|CatalogSvc|DeploySvc|MountSvc|TransportSvc|BackupRESTSvc)$' }
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
    if ($SelfPath -and (Test-Path $SelfPath)) {
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
