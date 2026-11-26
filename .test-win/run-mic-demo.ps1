#Requires -Version 5.1
<#
.SYNOPSIS
  Proves the "administrator write is denied by the System integrity label" case.

.DESCRIPTION
  A process cannot label an object above its own integrity level, so an elevated
  administrator (High) cannot apply a System label - that needs a SYSTEM agent.
  This script therefore:
    1. creates a demo folder and a file;
    2. runs a one-shot SYSTEM scheduled task that applies the strict DACL and the
       System label (exactly what the agent service does);
    3. from this (elevated administrator) session tries to overwrite and create
       files - both must be denied;
    4. runs another SYSTEM task to reset the label and permissions, then removes
       the demo folder.

  Run from an elevated PowerShell:
    cd E:\AI-learn\Tamper-proof\.test-win
    Set-ExecutionPolicy -Scope Process Bypass -Force
    .\run-mic-demo.ps1
#>
$ErrorActionPreference = 'Stop'

$dir  = $PSScriptRoot
$demo = Join-Path $dir 'mic-demo'
$site = Join-Path $demo 'site'
$log  = Join-Path $dir 'mic-demo.log'

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

"=== run-mic-demo $(Get-Date -Format s) user=$($identity.Name) ===" | Set-Content -Encoding UTF8 $log
Log "elevated=True"

# Clean any previous demo folder (it may still carry the strict DACL).
& takeown.exe /F $demo /R /D Y *> $null
& icacls.exe $demo /reset /T /C *> $null
Remove-Item -Recurse -Force $demo -ErrorAction SilentlyContinue

New-Item -ItemType Directory -Force $site | Out-Null
$index = Join-Path $site 'index.html'
Set-Content -Path $index -Value 'original' -NoNewline

function Invoke-SystemScript([string]$name, [string]$body) {
    $scriptPath = Join-Path $dir ("{0}.ps1" -f $name)
    Set-Content -Path $scriptPath -Value $body -Encoding UTF8
    $task = "TGMicDemo_{0}" -f $name
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' `
        -Argument ("-NoProfile -ExecutionPolicy Bypass -File `"{0}`"" -f $scriptPath)
    $principalTask = New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\SYSTEM' `
        -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName $task -Action $action -Principal $principalTask -Force | Out-Null
    Start-ScheduledTask -TaskName $task
    Start-Sleep -Seconds 3
    $info = Get-ScheduledTaskInfo -TaskName $task
    Unregister-ScheduledTask -TaskName $task -Confirm:$false
    Log "SYSTEM task $name exit=$($info.LastTaskResult)"
    Remove-Item $scriptPath -ErrorAction SilentlyContinue
}

# 1. SYSTEM applies the strict DACL and the System label.
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

# 2. Elevated administrator tries to write.
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

# 3. SYSTEM resets label and permissions; then this session cleans up.
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
