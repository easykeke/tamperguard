#Requires -Version 5.1
<#
.SYNOPSIS
  Verifies the no-driver stop/uninstall hardening on Windows.

.DESCRIPTION
  Run from an elevated PowerShell after install-service.ps1. Checks:
    1. `sc stop TamperGuardAgent` is denied for Administrators
    2. killing the agent process is repaired by the watchdog within seconds
    3. `sc delete TamperGuardAgent` is denied
  Expected results are printed as PASS/FAIL. This is a demonstration of the
  boundary: an administrator who takes ownership of both services can still
  disable them, which no user-mode product can prevent.
#>
$ErrorActionPreference = 'Continue'

function Show-Result([string]$name, [bool]$ok, [string]$detail) {
    $tag = if ($ok) { 'PASS' } else { 'FAIL' }
    Write-Host ("[{0}] {1} :: {2}" -f $tag, $name, $detail)
}

Write-Host "1) sc stop TamperGuardAgent (expect Access Denied)"
$out = sc.exe stop TamperGuardAgent 2>&1 | Out-String
$denied = $out -match 'Access is denied|拒绝访问|5'
Show-Result 'service stop denied' $denied ($out.Trim() -split "`n" | Select-Object -First 1)

Write-Host "2) kill agent process, expect watchdog to restart it"
$before = (Get-Service TamperGuardAgent -ErrorAction SilentlyContinue).Status
taskkill.exe /F /IM tg-agent.exe 2>$null | Out-Null
Start-Sleep -Seconds 6
$after = (Get-Service TamperGuardAgent -ErrorAction SilentlyContinue).Status
Show-Result 'watchdog restarted agent' ($after -eq 'Running') "before=$before after=$after"

Write-Host "3) sc delete TamperGuardAgent (expect Access Denied)"
$out = sc.exe delete TamperGuardAgent 2>&1 | Out-String
$denied = $out -match 'Access is denied|拒绝访问|5'
Show-Result 'service delete denied' $denied ($out.Trim() -split "`n" | Select-Object -First 1)

Write-Host ""
Write-Host "Boundary: taking ownership of both services is still possible for an administrator;" -ForegroundColor Yellow
Write-Host "the product makes casual stop/delete fail and leaves an audit trail." -ForegroundColor Yellow
