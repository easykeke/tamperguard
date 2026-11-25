#Requires -Version 5.1
<#
.SYNOPSIS
  Installs TamperGuard as a hardened Windows service (no kernel driver).

.DESCRIPTION
  The agent runs as LocalSystem (needed for ACL/MIC), starts automatically,
  restarts on failure, and the service's security descriptor is rewritten so
  that only SYSTEM can stop/configure it: an administrator can query and start
  it, but a plain `net stop` or `sc delete` is denied. This is the practical
  substitute for driver-based self-protection: it makes "just stop the agent"
  a deliberate, extra step rather than the path of least resistance.

  Must be run from an elevated PowerShell.
#>
$ErrorActionPreference = 'Stop'

$AgentDir  = 'C:\Program Files\TamperGuard'
$StateDir  = 'C:\ProgramData\TamperGuard'
$Service   = 'TamperGuardAgent'

$identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "ERROR: run this script from an elevated PowerShell." -ForegroundColor Red
    exit 2
}

$exe = Join-Path $AgentDir 'tg-agent.exe'
if (-not (Test-Path $exe)) {
    Write-Host "ERROR: $exe not found. Copy tg-agent.exe into $AgentDir first." -ForegroundColor Red
    exit 2
}
New-Item -ItemType Directory -Force -Path $StateDir | Out-Null

# 1. Service: LocalSystem, auto start, restart on failure.
if (Get-Service -Name $Service -ErrorAction SilentlyContinue) {
    Write-Host "service $Service already exists; updating configuration"
    sc.exe config $Service binPath= "\"$exe\" run --state-dir \"$StateDir\"" start= auto obj= LocalSystem | Out-Null
} else {
    sc.exe create $Service binPath= "\"$exe\" run --state-dir \"$StateDir\"" start= auto obj= LocalSystem DisplayName= "TamperGuard Agent" | Out-Null
}
sc.exe description $Service "TamperGuard protection agent (web tamper protection)" | Out-Null
sc.exe failure $Service reset= 86400 actions= restart/5000/restart/10000/restart/30000 | Out-Null

# 2. Service ACL: SYSTEM full control; Administrators may query/start but not
#    stop, reconfigure or delete (no WP/DT/DC/SD rights).
#    SDDL rights: CC=query config, LC=query status, SW=enum dependents,
#    RP=start, WP=stop, DT=pause, LO=interrogate, CR=control.
$sddl = 'D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCLCSWRPLOCRRC;;;BA)(A;;CCLCSWLOCRRC;;;IU)'
sc.exe sdset $Service $sddl | Out-Null

# 3. Protect the program directory and the state directory: SYSTEM owns them,
#    administrators can read but not replace the binary or the config.
icacls $AgentDir /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)RX" /T /C | Out-Null
icacls $StateDir /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)RX" /T /C | Out-Null

Start-Service $Service
Write-Host "service $Service installed and started" -ForegroundColor Green
Write-Host "  binary : $exe"
Write-Host "  state  : $StateDir"
Write-Host "  stop   : run as SYSTEM (e.g. psexec -s) or take ownership of the service first"
Write-Host ""
Write-Host "Next: enrol the agent (one-off, from an elevated shell):" -ForegroundColor Cyan
Write-Host "  & `"$exe`" enroll --server https://<control-plane>:8443 --bootstrap <token> --ca <ca.crt> --state-dir `"$StateDir`" --role protect --publisher-sids <publisher-account>"
