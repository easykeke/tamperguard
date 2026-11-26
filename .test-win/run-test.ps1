#Requires -Version 5.1
<#
.SYNOPSIS
  Runs the Windows strict-mode test. Default: as a one-shot SYSTEM task (the
  production deployment form), because only a SYSTEM agent can apply the System
  integrity label and write to files locked to SYSTEM.

.PARAMETER Admin
  Run directly in this elevated administrator session instead. The DACL, release
  window and revocation are verified, but the System label and self-heal restore
  cannot be (a High process may not label objects System and has no data-write
  right in the strict DACL).

.EXAMPLE
  cd E:\AI-learn\Tamper-proof\.test-win
  Set-ExecutionPolicy -Scope Process Bypass -Force
  .\run-test.ps1
#>
param([switch]$Admin)

$ErrorActionPreference = 'Stop'

$dir  = $PSScriptRoot
$exe  = Join-Path $dir 'tg-winacl-test.exe'
$log  = Join-Path $dir 'results.log'
$task = 'TGTamperGuardHarness'

$identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "ERROR: run this script from an elevated PowerShell." -ForegroundColor Red
    exit 2
}
if (-not (Test-Path $exe)) {
    Write-Host "ERROR: $exe missing; rebuild with: go build -o .test-win/tg-winacl-test.exe ./cmd/tg-winacl-test" -ForegroundColor Red
    exit 2
}

"=== run-test $(Get-Date -Format s) user=$($identity.Name) mode=$(if($Admin){'admin'}else{'system'}) ===" |
    Set-Content -Encoding UTF8 $log

if ($Admin) {
    Write-Host "running in admin mode (System label and self-heal are skipped)" -ForegroundColor Yellow
    & $exe --dir (Join-Path $dir 'sandbox') --log $log --mode admin
    $code = $LASTEXITCODE
    "exit=$code" | Add-Content -Encoding UTF8 $log
    Write-Host "exit=$code log=$log"
    exit $code
}

Write-Host "registering one-shot SYSTEM task to run the harness..." -ForegroundColor Cyan
$arguments = '--dir "{0}" --log "{1}" --mode system' -f (Join-Path $dir 'sandbox'), $log
$action    = New-ScheduledTaskAction -Execute $exe -Argument $arguments
$sysPrincipal = New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\SYSTEM' `
    -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName $task -Action $action -Principal $sysPrincipal -Force | Out-Null
Start-ScheduledTask -TaskName $task

$deadline = (Get-Date).AddSeconds(180)
do {
    Start-Sleep -Seconds 1
    $state = (Get-ScheduledTask -TaskName $task).State
} while ($state -eq 'Running' -and (Get-Date) -lt $deadline)

$info = Get-ScheduledTaskInfo -TaskName $task
Unregister-ScheduledTask -TaskName $task -Confirm:$false
"SYSTEM task result=$($info.LastTaskResult)" | Add-Content -Encoding UTF8 $log
Write-Host "SYSTEM task result=$($info.LastTaskResult)"
Write-Host ""
Write-Host "--- results.log ---"
Get-Content $log -Raw
Write-Host "log: $log"
exit ([int]$info.LastTaskResult)
