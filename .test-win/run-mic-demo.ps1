#Requires -Version 5.1
<#
.SYNOPSIS
  Proves (where the host supports integrity labels) that a System label denies
  writes from an elevated administrator session.

.DESCRIPTION
  A process cannot label an object above its own integrity level, so the label
  must be applied by a SYSTEM task - exactly what the agent service does. The
  helper tg-label.exe applies the real strict DACL + label through the product
  code path.

  Some Windows builds/environments accept the SACL write but do not keep the
  label; in that case the helper fails and this demo reports SKIP (the strict
  DACL still blocks administrator writes, which run-test.ps1 verifies).

.EXAMPLE
  cd E:\AI-learn\Tamper-proof\.test-win
  Set-ExecutionPolicy -Scope Process Bypass -Force
  .\run-mic-demo.ps1
#>
$ErrorActionPreference = 'Stop'

$staging = 'C:\ProgramData\TamperGuard-test'
$demo    = Join-Path $staging 'mic-demo'
$site    = Join-Path $demo 'site'
$state   = Join-Path $staging 'label-state'
$log     = Join-Path $PSScriptRoot 'mic-demo.log'
$applyLog = Join-Path $staging 'label-apply.log'

function Log([string]$msg) {
    $line = "{0} {1}" -f (Get-Date -Format s), $msg
    Add-Content -Path $log -Value $line -Encoding UTF8
    Write-Host $msg
}
trap {
    Log ("ERROR: " + $_.Exception.Message)
    Log ("  at: " + $_.ScriptStackTrace)
    exit 1
}

$identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "ERROR: run this script from an elevated PowerShell." -ForegroundColor Red
    exit 2
}

New-Item -ItemType Directory -Force $staging | Out-Null
& icacls.exe $staging /grant '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' *> $null
$labelSrc = Join-Path $PSScriptRoot 'tg-label.exe'
if (-not (Test-Path $labelSrc)) {
    Write-Host "ERROR: $labelSrc missing; rebuild with: go build -o .test-win/tg-label.exe ./cmd/tg-label" -ForegroundColor Red
    exit 2
}
$labelExe = Join-Path $staging 'tg-label.exe'
Copy-Item -Force $labelSrc $labelExe

"=== run-mic-demo $(Get-Date -Format s) user=$($identity.Name) ===" | Set-Content -Encoding UTF8 $log

# Clean a previous demo (only if it exists; takeown on a missing path is an error).
if (Test-Path $demo) {
    & icacls.exe $demo /reset /T /C *> $null
    Remove-Item -Recurse -Force $demo -ErrorAction SilentlyContinue
}
New-Item -ItemType Directory -Force $site | Out-Null
$index = Join-Path $site 'index.html'
Set-Content -Path $index -Value 'original' -NoNewline

function Invoke-SystemCmd([string]$taskSuffix, [string]$commandLine) {
    $task = "TGMicDemo_{0}" -f $taskSuffix
    $action = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument ('/c ' + $commandLine)
    $taskPrincipal = New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\SYSTEM' `
        -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName $task -Action $action -Principal $taskPrincipal -Force | Out-Null
    Start-ScheduledTask -TaskName $task
    Start-Sleep -Seconds 4
    $info = Get-ScheduledTaskInfo -TaskName $task
    Unregister-ScheduledTask -TaskName $task -Confirm:$false
    return [int]$info.LastTaskResult
}

Log "step: apply strict DACL + System label from a SYSTEM task"
$apply = '"{0}" --mode apply --path "{1}" --level system --state "{2}" > "{3}" 2>&1' -f `
    $labelExe, $site, $state, $applyLog
$code = Invoke-SystemCmd 'apply' $apply
Log "apply exit=$code"
if (Test-Path $applyLog) { foreach ($l in Get-Content $applyLog) { Log ("    " + $l) } }

if ($code -ne 0) {
    Log "SKIP: this host does not keep integrity labels (apply failed); the strict DACL still blocks administrator writes"
    $reset = '"{0}" --mode reset --path "{1}" --state "{2}"' -f $labelExe, $site, $state
    Invoke-SystemCmd 'reset-skip' $reset | Out-Null
    Remove-Item -Recurse -Force $demo -ErrorAction SilentlyContinue
    Log "RESULT: SKIP"
    exit 0
}

Log "--- icacls after SYSTEM label ---"
foreach ($line in (& icacls.exe $site | Out-String) -split "`n") {
    if ($line.Trim().Length -gt 0) { Log ("    " + $line.TrimEnd()) }
}

$blockedOverwrite = $false
try {
    Set-Content -Path $index -Value 'evil' -NoNewline -ErrorAction Stop
    Log "[FAIL] administrator overwrite SUCCEEDED"
} catch {
    $blockedOverwrite = $true
    Log ("[ok] administrator overwrite denied: " + $_.Exception.Message)
}
$blockedCreate = $false
try {
    Set-Content -Path (Join-Path $site 'new.html') -Value 'evil' -NoNewline -ErrorAction Stop
    Log "[FAIL] administrator create SUCCEEDED"
} catch {
    $blockedCreate = $true
    Log "[ok] administrator create denied"
}
$content = Get-Content $index -Raw
Log ("content after attempts: '" + $content + "'")
if ($content -ne 'original') { Log "[FAIL] content changed" }

Log "step: reset label and permissions from a SYSTEM task"
$reset = '"{0}" --mode reset --path "{1}" --state "{2}"' -f $labelExe, $site, $state
$resetCode = Invoke-SystemCmd 'reset' $reset
Log "reset exit=$resetCode"
& icacls.exe $site /reset /T /C *> $null
Remove-Item -Recurse -Force $demo -ErrorAction SilentlyContinue

if ($blockedOverwrite -and $blockedCreate -and $content -eq 'original') {
    Log "RESULT: PASS"
    exit 0
}
Log "RESULT: FAIL"
exit 1
