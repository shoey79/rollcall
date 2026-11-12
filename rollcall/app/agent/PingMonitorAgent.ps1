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

$AgentVersion = '1.0.35'
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
    $state = @{ token = $null; last_run = $null; cursors = @{}; watch = @(); patch = $null; amd_raid = $null; veeam = $null; veeam_cursor = $null; vbo = $null; vbo_checked = $null; apps_sent = $null }
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
            if ($raw.amd_raid) { $state.amd_raid = [string]$raw.amd_raid }
            if ($raw.veeam) { $state.veeam = [string]$raw.veeam }
            if ($raw.veeam_cursor) { $state.veeam_cursor = [int64]$raw.veeam_cursor }
            if ($raw.vbo) { $state.vbo = [string]$raw.vbo }
            if ($raw.apps_sent) { $state.apps_sent = [string]$raw.apps_sent }
            if ($raw.vbo_checked) { try { $state.vbo_checked = [int64]$raw.vbo_checked } catch { } }
            if ($raw.exch_dbs) { $state.exch_dbs = [string]$raw.exch_dbs }
            if ($raw.exch_checked) { try { $state.exch_checked = [int64]$raw.exch_checked } catch { } }
            if ($raw.ad_report) { $state.ad_report = [string]$raw.ad_report }
            if ($raw.ad_checked) { try { $state.ad_checked = [int64]$raw.ad_checked } catch { } }
            if ($raw.laps_ad_at) { try { $state.laps_ad_at = [int64]$raw.laps_ad_at; $state.laps_ad_exp = [string]$raw.laps_ad_exp; $state.laps_ad_attr = [string]$raw.laps_ad_attr } catch { } }
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
    try { $report.sessions = @(Measure-Step 'signed-in users' { Get-SignedInUsers }) } catch { Add-CollectorError 'signed-in users' $_ }
    try {
        $apps = @(Measure-Step 'installed software' { Get-InstalledApps })
        $report.apps_hash = Get-AppsHash $apps
        if ($State.apps_sent -ne $report.apps_hash) { $report.apps = $apps }  # only when it changed, or Rollcall asked
    } catch { Add-CollectorError 'installed software' $_ }
    try { $report.services = Measure-Step 'services' { Get-ServiceReport $allServices $discovery } } catch { Add-CollectorError 'services' $_ }
    $report.events = Measure-Step 'event logs' { Get-EventReport $State $since }
    $report.security = Measure-Step 'security log' { Get-SecurityReport $State $since }
    try { $report.security.admins = @(Measure-Step 'administrators' { Get-LocalAdmins }) } catch { Add-CollectorError 'administrators' $_ }
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
        $laps = Measure-Step 'laps' { Get-LapsStatus $State ($discovery.roles -contains 'Domain controller') $(if ($sys) { [bool]$sys.part_of_domain } else { $false }) }
        if ($laps) { $report.checks.laps = $laps }
    } catch { Add-CollectorError 'laps' $_ }
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
function Get-ServerList {
    # -Server can list several addresses, e.g. internal then external:
    # 'http://10.0.0.5:8100,https://rollcall.example.com:8100'. The one that worked last is tried first.
    # Addresses the add-on sent (set under Agents) come first; the ones this copy was installed with
    # stay on the end, so a mistake in the dashboard can't cut the agent off.
    $all = @(@($script:PushedServers) + @($Server -split '[,;\s]+') | Where-Object { $_ } | ForEach-Object { $_.Trim().TrimEnd('/') } | Select-Object -Unique)
    if ($script:PreferredServer -and $all -contains $script:PreferredServer) {
        $all = @($script:PreferredServer) + @($all | Where-Object { $_ -ne $script:PreferredServer })
    }
    return $all
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
    $active = if ($script:ActiveServer) { $script:ActiveServer } else { @(Get-ServerList)[0] }
    $uri = $active + '/agent/update?os=windows&server=' + [uri]::EscapeDataString((@($Server -split '[,;\s]+' | Where-Object { $_ } | ForEach-Object { $_.Trim().TrimEnd('/') }) -join ','))
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
    $script:PreferredServer = [string]$state.last_server
    $script:PushedServers = @($state.servers | Where-Object { $_ -match '^https?://[^\s,;]+$' })

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
    if ($report.Contains('apps')) { $state.apps_sent = $report.apps_hash }
    if ($res.body -and $res.body.send_apps) { $state.apps_sent = $null }  # Rollcall hasn't got this list: send it next time
    $state.last_run = ConvertTo-UtcString (Get-Date)
    if ($script:ActiveServer) { $state.last_server = $script:ActiveServer }
    if ($res.body -and $res.body.servers) {
        $pushed = @($res.body.servers | ForEach-Object { [string]$_ } | Where-Object { $_ -match '^https?://[^\s,;]+$' } | Select-Object -First 4)
        if ($pushed.Count -and (($pushed -join ',') -ne (@($state.servers) -join ','))) {
            Write-AgentLog ("Rollcall's addresses are now: " + ($pushed -join ', '))
        }
        if ($pushed.Count) { $state.servers = $pushed }
    }
    Save-State $state
    $slow = $script:Timings.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 1
    $took = if ($report.run_ms) { '{0:N1} s' -f ($report.run_ms / 1000) } else { '?' }
    Write-AgentLog ("Report sent to {0}: {1} role(s), {2} error(s); run took {3}{4}" -f $script:ActiveServer, @($report.roles).Count, @($report.errors).Count, $took,
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
