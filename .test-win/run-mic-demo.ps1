#Requires -Version 5.1
<#
.SYNOPSIS
  Proves that a System integrity label denies writes from an elevated
  administrator session.

.DESCRIPTION
  A process cannot label an object above its own integrity level, so the System
  label must be applied by a SYSTEM task (this is exactly what the agent service
  does). The demo folder is staged under C:\ProgramData\TamperGuard-test so it
  does not inherit a Low label from the development workspace.

  Steps:
    1. create a demo folder with a file ('original');
    2. a one-shot SYSTEM task applies the strict DACL and the System label;
    3. from this elevated administrator session, overwrite and create must both
       be denied and the content must stay 'original';
    4. a one-shot SYSTEM task resets the label and permissions, then the folder
       is removed.

.EXAMPLE
  cd E:\AI-learn\Tamper-proof\.test-win
  Set-ExecutionPolicy -Scope Process Bypass -Force
  .\run-mic-demo.ps1
#>
$ErrorActionPreference = 'Stop'

$staging = 'C:\ProgramData\TamperGuard-test'
$demo    = Join-Path $staging 'mic-demo'
$site    = Join-Path $demo 'site'
$log     = Join-Path $PSScriptRoot 'mic-demo.log'

function Log([string]$msg) {
    $line = "{0} {1}" -f (Get-Date -Format s), $msg
    Add-Content -Path $log -Value $line -Encoding UTF8
    Write-Host $msg
}

$identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "ERROR: run this script from an elevated PowerShell." -ForegroundColor Red
    exit 2
}

New-Item -ItemType Directory -Force $staging | Out-Null
& icacls.exe $staging /grant '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' *> $null
"=== run-mic-demo $(Get-Date -Format s) user=$($identity.Name) ===" | Set-Content -Encoding UTF8 $log

# Clean a previous demo (it may still carry the strict DACL / System label).
& takeown.exe /F $demo /R /D Y *> $null
& icacls.exe $demo /reset /T /C *> $null
Remove-Item -Recurse -Force $demo -ErrorAction SilentlyContinue

New-Item -ItemType Directory -Force $site | Out-Null
$index = Join-Path $site 'index.html'
Set-Content -Path $index -Value 'original' -NoNewline

function Invoke-SystemScript([string]$name, [string]$body) {
    $scriptPath = Join-Path $staging ("{0}.ps1" -f $name)
    Set-Content -Path $scriptPath -Value $body -Encoding UTF8
    $task = "TGMicDemo_{0}" -f $name
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' `
        -Argument ("-NoProfile -ExecutionPolicy Bypass -File `"{0}`"" -f $scriptPath)
    $taskPrincipal = New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\SYSTEM' `
        -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName $task -Action $action -Principal $taskPrincipal -Force | Out-Null
    Start-ScheduledTask -TaskName $task
    Start-Sleep -Seconds 3
    $info = Get-ScheduledTaskInfo -TaskName $task
    Unregister-ScheduledTask -TaskName $task -Confirm:$false
    Log "SYSTEM task $name exit=$($info.LastTaskResult)"
    Remove-Item $scriptPath -ErrorAction SilentlyContinue
}

$setup = @'
$ErrorActionPreference = 'Stop'
icacls "{0}" /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(Rc,WDAC,WO)" "Everyone:(RX)" /T /C | Out-Null
icacls "{0}" /setintegritylevel (OI)(CI)System | Out-Null
'@ -f $site
Invoke-SystemScript 'setup' $setup

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

$cleanup = @'
$ErrorActionPreference = 'Stop'
icacls "{0}" /setintegritylevel (OI)(CI)Medium | Out-Null
icacls "{0}" /reset /T /C | Out-Null
'@ -f $site
Invoke-SystemScript 'cleanup' $cleanup
& icacls.exe $site /reset /T /C *> $null
Remove-Item -Recurse -Force $demo -ErrorAction SilentlyContinue

if ($blockedOverwrite -and $blockedCreate -and $content -eq 'original') {
    Log "RESULT: PASS"
    exit 0
}
Log "RESULT: FAIL"
exit 1
