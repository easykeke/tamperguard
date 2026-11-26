#Requires -Version 5.1
<#
.SYNOPSIS
  Windows strict-mode on-host test.

.DESCRIPTION
  Default: runs the harness as a one-shot SYSTEM scheduled task, because only a
  SYSTEM agent can apply the System integrity label and write to files locked to
  SYSTEM. Everything is staged under C:\ProgramData\TamperGuard-test first: files
  in the development workspace may carry a Low mandatory label (created by a
  sandboxed process) and a SYSTEM task cannot start such an image (0xC0000142).

.PARAMETER Admin
  Run directly in this elevated administrator session. Verified: strict DACL,
  release window, revocation. Not verified: System label (a High process may not
  label objects System) and self-heal restore (the strict DACL denies data writes
  to an administrator).

.EXAMPLE
  cd E:\AI-learn\Tamper-proof\.test-win
  Set-ExecutionPolicy -Scope Process Bypass -Force
  .\run-test.ps1
#>
param([switch]$Admin)

$ErrorActionPreference = 'Stop'

$staging  = 'C:\ProgramData\TamperGuard-test'
$sandbox  = Join-Path $staging 'sandbox'
$logStage = Join-Path $staging 'results.log'
$logLocal = Join-Path $PSScriptRoot 'results.log'
$diagTask = 'TGTamperGuardDiag'
$taskName = 'TGTamperGuardHarness'

$identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "ERROR: run this script from an elevated PowerShell." -ForegroundColor Red
    exit 2
}

New-Item -ItemType Directory -Force $staging | Out-Null
& icacls.exe $staging /grant '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' *> $null
$srcExe = Join-Path $PSScriptRoot 'tg-winacl-test.exe'
if (-not (Test-Path $srcExe)) {
    Write-Host "ERROR: $srcExe missing; rebuild with: go build -o .test-win/tg-winacl-test.exe ./cmd/tg-winacl-test" -ForegroundColor Red
    exit 2
}
$exe = Join-Path $staging 'tg-winacl-test.exe'
Copy-Item -Force $srcExe $exe
Remove-Item -Force $logStage -ErrorAction SilentlyContinue

$mode = if ($Admin) { 'admin' } else { 'system' }
"=== run-test $(Get-Date -Format s) user=$($identity.Name) mode=$mode ===" | Set-Content -Encoding UTF8 $logLocal

if ($Admin) {
    Write-Host "admin mode: System label and self-heal are not verified" -ForegroundColor Yellow
    & $exe --dir $sandbox --log $logStage --mode admin
    $code = $LASTEXITCODE
    Copy-Item -Force $logStage $logLocal -ErrorAction SilentlyContinue
    "exit=$code" | Add-Content -Encoding UTF8 $logLocal
    Write-Host "--- results.log ---"; Get-Content $logLocal -Raw
    exit $code
}

# --- 1. self-check: can a SYSTEM task run anything at all? ---
Write-Host "SELF-CHECK: SYSTEM task mechanism" -ForegroundColor Cyan
$diagFile = Join-Path $staging 'diag.txt'
Remove-Item -Force $diagFile -ErrorAction SilentlyContinue
$diagAction = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument ('/c echo ok > "{0}"' -f $diagFile)
$sysPrincipal = New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\SYSTEM' -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName $diagTask -Action $diagAction -Principal $sysPrincipal -Force | Out-Null
Start-ScheduledTask -TaskName $diagTask
Start-Sleep -Seconds 3
$diagInfo = Get-ScheduledTaskInfo -TaskName $diagTask
Unregister-ScheduledTask -TaskName $diagTask -Confirm:$false
$diagOK = Test-Path $diagFile
Add-Content -Path $logLocal -Encoding UTF8 ("self-check SYSTEM cmd task result={0} file={1}" -f $diagInfo.LastTaskResult, $diagOK)
if (-not $diagOK) {
    Add-Content -Path $logLocal -Encoding UTF8 "SYSTEM task mechanism failed; aborting"
    Write-Host "SYSTEM task self-check FAILED (result=$($diagInfo.LastTaskResult))" -ForegroundColor Red
    Get-Content $logLocal -Raw
    exit 1
}

# --- 2. run the harness as SYSTEM ---
Write-Host "running harness as SYSTEM (staged under $staging)..." -ForegroundColor Cyan
$arguments = '--dir "{0}" --log "{1}" --mode system' -f $sandbox, $logStage
$action = New-ScheduledTaskAction -Execute $exe -Argument $arguments
Register-ScheduledTask -TaskName $taskName -Action $action -Principal $sysPrincipal -Force | Out-Null
Start-ScheduledTask -TaskName $taskName

$deadline = (Get-Date).AddSeconds(240)
do {
    Start-Sleep -Seconds 1
    $state = (Get-ScheduledTask -TaskName $taskName).State
} while ($state -eq 'Running' -and (Get-Date) -lt $deadline)

$info = Get-ScheduledTaskInfo -TaskName $taskName
Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
Add-Content -Path $logLocal -Encoding UTF8 ("SYSTEM harness task result={0}" -f $info.LastTaskResult)
Copy-Item -Force $logStage $logLocal -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "--- results.log ---"
Get-Content $logLocal -Raw
Write-Host "log: $logLocal"
# 0 = success, 1 = assertions failed, other = task/process failure
exit ([int]$info.LastTaskResult)
