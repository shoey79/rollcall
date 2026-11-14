# Installs the test MSI on a GitHub Windows machine: silently (as MECM does: no screens), then
# interactively (the "installed" screen must appear; a screenshot is kept). Run from the repo root.
param([string]$Msi = 'out\agent.msi', [string]$Out = 'out')
$ErrorActionPreference = 'Stop'
$Msi = (Resolve-Path $Msi).Path
New-Item -ItemType Directory -Force -Path $Out | Out-Null
$Out = (Resolve-Path $Out).Path
function Install([string]$Mode, [string]$Log) {
    $argList = @('/i', "`"$Msi`"", '/l*v', "`"$Log`"") + $(if ($Mode -eq 'silent') { @('/qn') } else { @() })
    return Start-Process msiexec.exe -ArgumentList $argList -PassThru
}
function Remove-Agent {
    $p = Get-CimInstance Win32_Product -Filter "Name = 'Rollcall agent'" -ErrorAction SilentlyContinue
    foreach ($x in @($p)) { Start-Process msiexec.exe -ArgumentList @('/x', $x.IdentifyingNumber, '/qn') -Wait }
}
function Fail([string]$Why) { Write-Host "FAILED: $Why"; exit 1 }

# 1. Silent install: must succeed, set up the scheduled task, and show no screen
$p = Install 'silent' "$Out\silent.log"; $p.WaitForExit()
if ($p.ExitCode -ne 0) { Fail "silent install exit code $($p.ExitCode)" }
if (-not (Get-ScheduledTask -TaskName 'Ping Monitor Agent' -ErrorAction SilentlyContinue)) { Fail 'no scheduled task after the silent install' }
if ((Get-Content "$Out\silent.log" -Raw) -match 'Dialog created|Action start .*: RcDone') { Fail 'a screen was shown in a silent install' }
Write-Host 'Silent install: OK, no screens'
Remove-Agent

# 2. Interactive install: the "installed" screen must appear
$p = Install 'full' "$Out\interactive.log"
$shown = $false
for ($i = 0; $i -lt 120 -and -not $shown; $i++) {
    Start-Sleep -Seconds 1
    if ((Test-Path "$Out\interactive.log") -and ((Get-Content "$Out\interactive.log" -Raw -ErrorAction SilentlyContinue) -match 'Dialog created.*RcDone|Action start .*: RcDone')) { $shown = $true }
}
Start-Sleep -Seconds 3
try {
    Add-Type -AssemblyName System.Windows.Forms, System.Drawing
    $b = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
    $bmp = New-Object System.Drawing.Bitmap $b.Width, $b.Height
    [System.Drawing.Graphics]::FromImage($bmp).CopyFromScreen($b.Location, [System.Drawing.Point]::Empty, $b.Size)
    $bmp.Save("$Out\installed-screen.png", [System.Drawing.Imaging.ImageFormat]::Png)
} catch { Write-Host "Couldn't take a screenshot: $($_.Exception.Message)" }
Get-Process msiexec -ErrorAction SilentlyContinue | Where-Object { $_.MainWindowTitle } | Stop-Process -Force
if (-not $shown) { Fail 'the "installed" screen was not shown in an interactive install' }
if (-not (Get-ScheduledTask -TaskName 'Ping Monitor Agent' -ErrorAction SilentlyContinue)) { Fail 'no scheduled task after the interactive install' }
Write-Host 'Interactive install: OK, "installed" screen shown'
Remove-Agent
