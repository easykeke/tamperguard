#Requires -Version 5.1
<#
.SYNOPSIS
  TamperGuard tray UI for Windows.

.DESCRIPTION
  Runs in the logged-in user's session and only displays status: the protection
  service (LocalSystem) owns enforcement. The tray reads the status snapshot the
  service writes to C:\ProgramData\TamperGuardStatus, so it never needs
  administrator rights and cannot weaken protection.

  Menu: open the console, show the current status, exit the tray (the service
  keeps running).
#>
$ErrorActionPreference = 'SilentlyContinue'

$StatusPath = 'C:\ProgramData\TamperGuardStatus\status.json'

# Single instance per session.
$mutex = New-Object System.Threading.Mutex($false, 'Global\TamperGuardTray')
if (-not $mutex.WaitOne(0)) { exit 0 }

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

function Read-Status {
    if (-not (Test-Path $StatusPath)) { return $null }
    try {
        return Get-Content -LiteralPath $StatusPath -Raw -Encoding UTF8 | ConvertFrom-Json
    } catch {
        return $null
    }
}

function Status-Text([object]$s) {
    if (-not $s) { return 'TamperGuard：未安装或未运行' }
    $age = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() - [int64]$s.last_heartbeat
    if ($age -gt 90) { return 'TamperGuard：服务离线（超过 90 秒无心跳）' }
    $mode = if ($s.degraded) { '降级' } else { '正常' }
    return ('TamperGuard：在线 / {0} / {1}' -f $s.enforcer, $mode)
}

$notify = New-Object System.Windows.Forms.NotifyIcon
$notify.Icon = [System.Drawing.SystemIcons]::Shield
$notify.Text = 'TamperGuard'
$notify.Visible = $true

$menu = New-Object System.Windows.Forms.ContextMenuStrip
$itemOpen = $menu.Items.Add('打开管理端')
$itemStatus = $menu.Items.Add('查看防护状态')
$menu.Items.Add('-') | Out-Null
$itemExit = $menu.Items.Add('退出托盘（服务继续运行）')
$notify.ContextMenuStrip = $menu

$itemOpen.add_Click({
    $s = Read-Status
    if ($s -and $s.server_url) {
        Start-Process $s.server_url
    } else {
        [System.Windows.Forms.MessageBox]::Show('没有可用的管理端地址：Agent 尚未注册。', 'TamperGuard') | Out-Null
    }
})

$itemStatus.add_Click({
    $s = Read-Status
    if (-not $s) {
        [System.Windows.Forms.MessageBox]::Show('TamperGuard Agent 尚未安装或尚未注册。', 'TamperGuard') | Out-Null
        return
    }
    $age = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() - [int64]$s.last_heartbeat
    $lines = @(
        ('状态：' + (Status-Text $s)),
        ('Agent ID：' + $s.agent_id),
        ('角色：' + $s.role),
        ('版本：' + $s.version),
        ('执行层：' + $s.enforcer),
        ('降级：' + $s.degraded),
        ('策略摘要：' + $s.policy_digest),
        ('管理端：' + $s.server_url),
        ('最后心跳：' + ([DateTimeOffset]::FromUnixTimeSeconds([int64]$s.last_heartbeat).ToLocalTime().ToString('yyyy-MM-dd HH:mm:ss'))),
        ('心跳距今：' + $age + ' 秒')
    )
    [System.Windows.Forms.MessageBox]::Show(($lines -join "`r`n"), 'TamperGuard 防护状态') | Out-Null
})

$itemExit.add_Click({
    $notify.Visible = $false
    $notify.Dispose()
    [System.Windows.Forms.Application]::Exit()
})

function Update-Tray {
    $s = Read-Status
    $text = Status-Text $s
    if ($text.Length -gt 63) { $text = $text.Substring(0, 63) }
    $notify.Text = $text
}

$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = 5000
$timer.add_Tick({ Update-Tray })
$timer.Start()

Update-Tray
[System.Windows.Forms.Application]::Run()
