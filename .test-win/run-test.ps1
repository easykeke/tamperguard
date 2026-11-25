#Requires -Version 5.1
# One-shot Windows strict-mode test. Run from an elevated PowerShell:
#   cd E:\AI-learn\Tamper-proof\.test-win
#   Set-ExecutionPolicy -Scope Process Bypass -Force
#   .\run-test.ps1
$ErrorActionPreference = 'Stop'

$dir = Split-Path -Parent $MyInvocation.MyCommand.Path
$exe = Join-Path $dir 'tg-winacl-test.exe'
$log = Join-Path $dir 'results.log'

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "ERROR: run this script from an elevated PowerShell (Run as administrator)." -ForegroundColor Red
    exit 2
}
if (-not (Test-Path $exe)) {
    Write-Host "ERROR: $exe is missing; rebuild with: go build -o .test-win\tg-winacl-test.exe ./cmd/tg-winacl-test" -ForegroundColor Red
    exit 2
}

"=== tg-winacl-test $(Get-Date -Format s) ===" | Set-Content -Encoding UTF8 $log
"user=$($identity.Name) elevated=True" | Add-Content -Encoding UTF8 $log
Write-Host "running $exe" -ForegroundColor Cyan
& $exe --dir (Join-Path $dir 'sandbox') 2>&1 | Tee-Object -FilePath $log -Append
$code = $LASTEXITCODE
"exit=$code" | Add-Content -Encoding UTF8 $log
Write-Host ""
Write-Host "log: $log"
exit $code
