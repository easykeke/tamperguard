#Requires -Version 5.1
<#
.SYNOPSIS
  Installs the TamperGuard control plane as a Windows service.

.DESCRIPTION
  Copies tg-server.exe, initialises the data directory (CA, keys, admin
  password, one-time bootstrap tokens), registers TamperGuardServer as an
  automatic LocalSystem service, starts it and opens the firewall port.

  Must run from an elevated PowerShell. The admin password and bootstrap
  tokens are printed exactly once and also saved to <DataDir>\init-output.txt.
#>
param(
    [string]$DataDir = 'C:\ProgramData\TamperGuardServer',
    [string]$Listen = ':8443',
    [string]$InstallDir = 'C:\Program Files\TamperGuardServer',
    [switch]$NoFirewall
)

$ErrorActionPreference = 'Stop'
$ServiceName = 'TamperGuardServer'

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "ERROR: run this script from an elevated PowerShell." -ForegroundColor Red
    exit 2
}

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
New-Item -ItemType Directory -Force -Path $DataDir | Out-Null

$source = Join-Path $PSScriptRoot 'tg-server.exe'
$exe = Join-Path $InstallDir 'tg-server.exe'
if (Test-Path $source) {
    Copy-Item $source $exe -Force
}
if (-not (Test-Path $exe)) {
    Write-Host "ERROR: tg-server.exe not found next to this script." -ForegroundColor Red
    exit 2
}

$configFile = Join-Path $DataDir 'server.json'
$initOutput = Join-Path $DataDir 'init-output.txt'
if (-not (Test-Path $configFile)) {
    Write-Host "initialising control plane data in $DataDir ..." -ForegroundColor Cyan
    & $exe init --data-dir $DataDir --listen $Listen 2>&1 | Tee-Object -FilePath $initOutput
    Write-Host ""
    Write-Host "The admin password and bootstrap tokens above are shown once;" -ForegroundColor Yellow
    Write-Host "they were also saved to $initOutput" -ForegroundColor Yellow
} else {
    Write-Host "data directory already initialised: $DataDir"
}

# Restrict the data directory: only SYSTEM and Administrators. Take ownership
# first: files created by init may not be owned by the current administrator,
# and icacls /T can leave individual files with an empty DACL.
takeown /f $DataDir /r /d y 2>$null | Out-Null
icacls $DataDir /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" /T /C | Out-Null
Get-ChildItem -LiteralPath $DataDir -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
    icacls $_.FullName /grant:r "*S-1-5-18:F" "*S-1-5-32-544:F" | Out-Null
}

if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
    $svcKey = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
    Set-ItemProperty -Path $svcKey -Name ImagePath -Value "`"$exe`" serve --data-dir `"$DataDir`"" -ErrorAction Stop
    Set-ItemProperty -Path $svcKey -Name ObjectName -Value 'LocalSystem' -ErrorAction Stop
    Set-ItemProperty -Path $svcKey -Name Start -Value 2 -Type DWord -ErrorAction Stop
    Write-Host "service $ServiceName already exists; configuration updated"
} else {
    New-Service -Name $ServiceName -BinaryPathName "`"$exe`" serve --data-dir `"$DataDir`"" `
        -DisplayName 'TamperGuard Control Plane' -StartupType Automatic | Out-Null
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName" -Name ObjectName -Value 'LocalSystem' -ErrorAction SilentlyContinue
}

sc.exe description $ServiceName "TamperGuard web tamper-proof control plane" | Out-Null
sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/10000/restart/30000 | Out-Null

try {
    Start-Service -Name $ServiceName
} catch {
    Write-Host "ERROR: service $ServiceName did not start: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "  check: sc.exe qc $ServiceName" -ForegroundColor Yellow
    exit 3
}

if (-not $NoFirewall) {
    $port = ($Listen -split ':')[-1]
    if ($port -match '^\d+$') {
        $ruleName = "TamperGuard Control Plane ($port)"
        Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
        New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Protocol TCP -LocalPort ([int]$port) -Action Allow | Out-Null
        Write-Host "firewall rule added for TCP $port"
    }
}

Write-Host ""
Write-Host "TamperGuard control plane is running." -ForegroundColor Green
Write-Host "  service : $ServiceName"
Write-Host "  binary  : $exe"
Write-Host "  data    : $DataDir"
Write-Host "  CA      : $(Join-Path $DataDir 'keys\ca.crt')"
Write-Host "  console : https://$($env:COMPUTERNAME):$((($Listen -split ':')[-1]))"
Write-Host ""
Write-Host "Enrol agents against https://<this-host>:$((($Listen -split ':')[-1])) with the bootstrap tokens printed above."
