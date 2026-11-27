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
$SetupDir   = 'C:\ProgramData\TamperGuardSetup'
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

# Reclaim the program directory if a previous install hardened it.
if (Test-Path $AgentDir) {
    takeown /f "$AgentDir" /r /d y 2>$null | Out-Null
    icacls "$AgentDir" /grant "*S-1-5-32-544:(OI)(CI)F" /T /C | Out-Null
}

function Copy-IfNeeded([string]$src, [string]$dst) {
    if (-not (Test-Path $src)) { return }
    # The one-click wrapper already placed the latest files; never fight a
    # hardened/ACL-protected destination just to re-copy identical content.
    if (Test-Path $dst) { return }
    $s = (Resolve-Path -LiteralPath $src).Path
    $d = $dst
    if ($s -ne $d) {
        Copy-Item -LiteralPath $s -Destination $dst -Force
    }
}

# CA certificate, if it was downloaded next to the bundle.
Copy-IfNeeded (Join-Path $PSScriptRoot 'ca.crt') (Join-Path $AgentDir 'ca.crt')

# Copy binaries from the extracted bundle next to this script.
New-Item -ItemType Directory -Force -Path $SetupDir | Out-Null
icacls $SetupDir /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-32-545:(OI)(CI)RX" /T /C | Out-Null

New-Item -ItemType Directory -Force -Path $AgentDir | Out-Null
foreach ($bin in @('tg-agent.exe', 'tg-publish.exe')) {
    Copy-IfNeeded (Join-Path $PSScriptRoot $bin) (Join-Path $AgentDir $bin)
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
$sddl = 'D:(A;;GA;;;SY)(A;;CCLCSWRPLOCRRC;;;BA)(A;;CCLCSWLOCRRC;;;IU)'
$permissive = 'D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GR;;;IU)'

$script:servicesReset = $false
function Reset-Services {
    if ($script:servicesReset) { return }
    $script:servicesReset = $true
    Write-Host "existing services are locked; deleting and recreating them as SYSTEM..." -ForegroundColor Yellow
    $cmdPath = Join-Path $SetupDir 'svc-reset.cmd'
    $done    = Join-Path $SetupDir 'svc-reset.done'
    Remove-Item $done -Force -ErrorAction SilentlyContinue
    $body = @'
@echo off
sc stop TamperGuardWatchdog >nul 2>&1
sc stop TamperGuardAgent >nul 2>&1
sc stop TamperGuardPublish >nul 2>&1
timeout /t 3 /nobreak >nul
sc delete TamperGuardWatchdog >nul 2>&1
sc delete TamperGuardAgent >nul 2>&1
sc delete TamperGuardPublish >nul 2>&1
echo done > "__DONE__"
'@
    $body = $body.Replace('__DONE__', $done)
    Set-Content -LiteralPath $cmdPath -Value $body -Encoding ASCII
    $taskArgs = '/Create /TN TamperGuardSvcReset /TR "' + $cmdPath + '" /SC ONCE /ST 23:59 /RU SYSTEM /RL HIGHEST /F'
    $create = Start-Process -FilePath schtasks.exe -ArgumentList $taskArgs -Wait -PassThru -WindowStyle Hidden
    if ($create.ExitCode -ne 0) { throw "could not create the service reset task (exit $($create.ExitCode))" }
    Start-Process -FilePath schtasks.exe -ArgumentList '/Run /TN TamperGuardSvcReset' -Wait -WindowStyle Hidden | Out-Null
    for ($i = 0; $i -lt 60; $i++) {
        if (Test-Path $done) { break }
        Start-Sleep -Seconds 1
    }
    Start-Process -FilePath schtasks.exe -ArgumentList '/Delete /TN TamperGuardSvcReset /F' -Wait -WindowStyle Hidden | Out-Null
    for ($i = 0; $i -lt 60; $i++) {
        $left = @(Get-Service TamperGuardAgent,TamperGuardPublish,TamperGuardWatchdog -ErrorAction SilentlyContinue)
        if ($left.Count -eq 0) { break }
        Start-Sleep -Seconds 1
    }
}

function Start-ServiceAsSystem([string]$name) {
    $cmd = Join-Path $SetupDir ("start-" + $name + ".cmd")
    $done = Join-Path $SetupDir ("start-" + $name + ".done")
    Remove-Item $done -Force -ErrorAction SilentlyContinue
    $body = "@echo off`r`nsc start $name >nul 2>&1`r`necho done > `"$done`""
    Set-Content -LiteralPath $cmd -Value $body -Encoding ASCII
    $taskArgs = '/Create /TN TamperGuardStart /TR "' + $cmd + '" /SC ONCE /ST 23:59 /RU SYSTEM /RL HIGHEST /F'
    $create = Start-Process -FilePath schtasks.exe -ArgumentList $taskArgs -Wait -PassThru -WindowStyle Hidden
    if ($create.ExitCode -ne 0) { throw "could not create start task for $name" }
    Start-Process -FilePath schtasks.exe -ArgumentList '/Run /TN TamperGuardStart' -Wait -WindowStyle Hidden | Out-Null
    for ($i = 0; $i -lt 20; $i++) {
        if (Test-Path $done) { break }
        Start-Sleep -Seconds 1
    }
    Start-Process -FilePath schtasks.exe -ArgumentList '/Delete /TN TamperGuardStart /F' -Wait -WindowStyle Hidden | Out-Null
}

function Install-Service([string]$name, [string]$display, [string]$binPath) {
    # New-Service takes the command line verbatim (no sc.exe quoting pitfalls
    # with "C:\Program Files\..." paths).
    $existing = Get-Service -Name $name -ErrorAction SilentlyContinue
    if ($existing) {
        # Configure through the registry: Administrators can write it even when
        # the service ACL denies SERVICE_CHANGE_CONFIG.
        $svcKey = "HKLM:\SYSTEM\CurrentControlSet\Services\$name"
        Set-ItemProperty -Path $svcKey -Name ImagePath -Value $binPath -ErrorAction Stop
        Set-ItemProperty -Path $svcKey -Name ObjectName -Value 'LocalSystem' -ErrorAction Stop
        Set-ItemProperty -Path $svcKey -Name Start -Value 2 -Type DWord -ErrorAction Stop
        Write-Host "service $name already exists; configuration updated via registry"
    } else {
        New-Service -Name $name -BinaryPathName $binPath -DisplayName $display -StartupType Automatic | Out-Null
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$name" -Name ObjectName -Value 'LocalSystem' -ErrorAction Stop
    }
    sc.exe description $name $display | Out-Null
    sc.exe failure $name reset= 86400 actions= restart/5000/restart/10000/restart/30000 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "sc failure failed for $name (run as Administrator)" }
}

# 1. Protection agent service.
$StatusDir = 'C:\ProgramData\TamperGuardStatus'
New-Item -ItemType Directory -Force -Path $StatusDir | Out-Null
Install-Service $AgentSvc 'TamperGuard Protection Agent' "`"$agentExe`" run --state-dir `"$StateDir`" --status-dir `"$StatusDir`""

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
$agentEnrolled = Test-Path (Join-Path $StateDir 'agent.json')
$publishEnrolled = Test-Path (Join-Path $PublishDir 'agent.json')
icacls $AgentDir /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)RX" "*S-1-5-32-545:(OI)(CI)RX" /T /C | Out-Null
icacls $agentExe /grant:r "*S-1-5-18:RX" "*S-1-5-32-544:RX" "*S-1-5-32-545:RX" | Out-Null
if (Test-Path (Join-Path $AgentDir 'tg-agent-gui.exe')) {
    icacls (Join-Path $AgentDir 'tg-agent-gui.exe') /grant:r "*S-1-5-18:RX" "*S-1-5-32-544:RX" "*S-1-5-32-545:RX" | Out-Null
}
if ((Get-Acl $agentExe).Access.Count -eq 0) {
    throw "ACL on $agentExe is empty after hardening; refusing to leave a non-executable agent"
}
# Do not lock a state directory before it has been enrolled: enrolling runs as
# the administrator and needs to create agent.json there.
if ($agentEnrolled) {
    icacls $StateDir /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)RX" /T /C | Out-Null
}
if ($publishEnrolled) {
    icacls $PublishDir /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)RX" /T /C | Out-Null
}
icacls $StatusDir /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)RX" "*S-1-5-32-545:(OI)(CI)RX" /T /C | Out-Null

$started = @()
if ($agentEnrolled) {
    try {
        Start-ServiceAsSystem $AgentSvc
        $started += $AgentSvc
    } catch {
        Write-Host "WARN: $AgentSvc did not start: $($_.Exception.Message)" -ForegroundColor Yellow
    }
} else {
    Write-Host "Agent not enrolled yet; service left stopped until you enrol." -ForegroundColor Yellow
}
if ($publishEnrolled) {
    try {
        Start-ServiceAsSystem $PublishSvc
        $started += $PublishSvc
    } catch {
        Write-Host "WARN: $PublishSvc did not start: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}
if ($started.Count -gt 0) {
    try {
        Start-ServiceAsSystem $Watchdog
        $started += $Watchdog
    } catch {
        Write-Host "WARN: $Watchdog did not start: $($_.Exception.Message)" -ForegroundColor Yellow
    }
} else {
    Write-Host "Watchdog left stopped until an agent is enrolled." -ForegroundColor Yellow
}

# 5. Native GUI client (C/S): talks to the service over the local named pipe.
$guiSrc = Join-Path $PSScriptRoot 'tg-agent-gui.exe'
$guiDir = 'C:\ProgramData\TamperGuardUi'
$guiDst = Join-Path $guiDir 'tg-agent-gui.exe'
New-Item -ItemType Directory -Force -Path $guiDir | Out-Null
if (Test-Path $guiSrc) {
    Copy-IfNeeded $guiSrc $guiDst
}
if (Test-Path $guiDst) {
    icacls $guiDir /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)RX" "*S-1-5-32-545:(OI)(CI)RX" /T /C | Out-Null
    $startup = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\StartUp\TamperGuardGui.lnk'
    $ws = New-Object -ComObject WScript.Shell
    $shortcut = $ws.CreateShortcut($startup)
    $shortcut.TargetPath = $guiDst
    $shortcut.WorkingDirectory = $guiDir
    $shortcut.Description = 'TamperGuard GUI client'
    $shortcut.Save()
    # Do not start a GUI from the elevated installer: UIPI can deny it, and the
    # console user should own the tray process. The Startup shortcut starts it at
    # the next sign-in; it can also be launched manually.
    Write-Host "GUI shortcut created (starts at next sign-in)." -ForegroundColor Green
}

if ($agentEnrolled -and $started.Count -gt 0) {
    foreach ($svcName in ($services + $Watchdog)) {
        sc.exe sdset $svcName $sddl 2>$null | Out-Null
        if ($LASTEXITCODE -ne 0) {
            Write-Host "WARN: could not harden $svcName ACL (existing ACL kept)" -ForegroundColor Yellow
        }
    }
}

Write-Host "installed services: $($services -join ', ') + $Watchdog" -ForegroundColor Green
Write-Host "  binary : $agentExe"
Write-Host "  state  : $StateDir"
Write-Host "  stop   : denied for Administrators; watchdog restarts within ~3s"
Write-Host ""
Write-Host ""
Write-Host "Next: download ca.crt from the console, place it next to the binaries, then enrol:" -ForegroundColor Cyan
Write-Host "  (ca.crt download: <console>/api/v1/downloads/agent?file=ca.crt)" -ForegroundColor Cyan
Write-Host "  & `"$agentExe`" enroll --server https://<control-plane>:8443 --bootstrap <token> --ca <ca.crt> --state-dir `"$StateDir`" --role protect --publisher-sids <publisher-account>"
if (Test-Path $publishExe) {
    Write-Host "  & `"$agentExe`" enroll --server https://<control-plane>:8443 --bootstrap <publish-token> --ca <ca.crt> --state-dir `"$PublishDir`" --role publish"
}
