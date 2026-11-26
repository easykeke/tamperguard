#Requires -Version 5.1
<#
.SYNOPSIS
  Installs TamperGuard agents as hardened Windows services (no kernel driver).

.DESCRIPTION
  The agent and publisher run as LocalSystem, start automatically, restart on
  failure, and their service security descriptors are rewritten so that only
  SYSTEM can stop/reconfigure/delete them. A watchdog service (also SYSTEM,
  also ACL-locked) restarts them if they are stopped and re-applies the service
  and directory ACLs if they are tampered with.

  There is no driver: an administrator who takes ownership of the services can
  still disable them. This raises "just stop the agent" from one command to a
  deliberate ownership change, and the watchdog makes casual stops temporary.

  Must be run from an elevated PowerShell, with tg-agent.exe (and optionally
  tg-publish.exe) in C:\Program Files\TamperGuard.
#>
$ErrorActionPreference = 'Stop'

$AgentDir   = 'C:\Program Files\TamperGuard'
$StateDir   = 'C:\ProgramData\TamperGuard'
$PublishDir = 'C:\ProgramData\TamperGuard-publish'
$AgentSvc   = 'TamperGuardAgent'
$PublishSvc = 'TamperGuardPublish'
$Watchdog   = 'TamperGuardWatchdog'

$identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "ERROR: run this script from an elevated PowerShell." -ForegroundColor Red
    exit 2
}

$agentExe = Join-Path $AgentDir 'tg-agent.exe'
if (-not (Test-Path $agentExe)) {
    Write-Host "ERROR: $agentExe not found. Copy tg-agent.exe into $AgentDir first." -ForegroundColor Red
    exit 2
}
$publishExe = Join-Path $AgentDir 'tg-publish.exe'
New-Item -ItemType Directory -Force -Path $StateDir | Out-Null
New-Item -ItemType Directory -Force -Path $PublishDir | Out-Null

# SDDL: SYSTEM full; Administrators may query/start but NOT stop (no WP),
# pause (no DT), reconfigure (no DC) or delete (no SD/WD/WO).
$sddl = 'D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCLCSWRPLOCRRC;;;BA)(A;;CCLCSWLOCRRC;;;IU)'

function Install-Service([string]$name, [string]$display, [string]$binPath) {
    if (Get-Service -Name $name -ErrorAction SilentlyContinue) {
        sc.exe config $name binPath= $binPath start= auto obj= LocalSystem | Out-Null
    } else {
        sc.exe create $name binPath= $binPath start= auto obj= LocalSystem DisplayName= $display | Out-Null
    }
    sc.exe description $name $display | Out-Null
    sc.exe failure $name reset= 86400 actions= restart/5000/restart/10000/restart/30000 | Out-Null
    sc.exe sdset $name $sddl | Out-Null
}

# 1. Protection agent service.
Install-Service $AgentSvc 'TamperGuard Protection Agent' "`"$agentExe`" run --state-dir `"$StateDir`""

# 2. Publisher service when the binary is present.
$services = @($AgentSvc)
if (Test-Path $publishExe) {
    Install-Service $PublishSvc 'TamperGuard Publisher' "`"$publishExe`" run --state-dir `"$PublishDir`""
    $services += $PublishSvc
}

# 3. Watchdog service: restarts stopped agents and re-applies ACLs every 3s.
$watchBin = "`"$agentExe`" watchdog --service $($services -join ',') --agent-dir `"$AgentDir`" --state-dir `"$StateDir`" --publish-dir `"$PublishDir`" --sddl `"$sddl`""
Install-Service $Watchdog 'TamperGuard Watchdog' $watchBin

# 4. Protect program and state directories: SYSTEM full, admins read-only.
foreach ($dir in @($AgentDir, $StateDir, $PublishDir)) {
    icacls $dir /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)RX" /T /C | Out-Null
}

foreach ($svc in $services) {
    Start-Service $svc
}
Start-Service $Watchdog

Write-Host "installed services: $($services -join ', ') + $Watchdog" -ForegroundColor Green
Write-Host "  binary : $agentExe"
Write-Host "  state  : $StateDir"
Write-Host "  stop   : denied for Administrators; watchdog restarts within ~3s"
Write-Host ""
Write-Host "Next: enrol each agent once (from an elevated shell):" -ForegroundColor Cyan
Write-Host "  & `"$agentExe`" enroll --server https://<control-plane>:8443 --bootstrap <token> --ca <ca.crt> --state-dir `"$StateDir`" --role protect --publisher-sids <publisher-account>"
if (Test-Path $publishExe) {
    Write-Host "  & `"$agentExe`" enroll --server https://<control-plane>:8443 --bootstrap <publish-token> --ca <ca.crt> --state-dir `"$PublishDir`" --role publish"
}
