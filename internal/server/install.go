package server

import (
	"archive/zip"
	"bytes"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/easykeke/tamperguard/internal/idgen"
	"github.com/easykeke/tamperguard/internal/token"
)

var hostSafe = regexp.MustCompile(`^[A-Za-z0-9.\-:\[\]]+$`)

func (s *Server) controlURL(r *http.Request) (string, error) {
	host := r.Host
	if !hostSafe.MatchString(host) {
		return "", fmt.Errorf("invalid host header")
	}
	return "https://" + host, nil
}

// handleLinuxInstallScript serves a one-command installer with the bootstrap
// token embedded. The token is single-use; the script installs the binary, CA,
// systemd unit and enrols in one pass.
func (s *Server) handleLinuxInstallScript(w http.ResponseWriter, r *http.Request) {
	role := r.URL.Query().Get("role")
	if role == "" {
		role = "protect"
	}
	if role != "protect" && role != "publish" {
		writeErr(w, http.StatusBadRequest, "invalid", "role must be protect or publish")
		return
	}
	tok := r.URL.Query().Get("token")
	if tok == "" || len(tok) > 256 {
		writeErr(w, http.StatusBadRequest, "invalid", "missing token")
		return
	}
	base, err := s.controlURL(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid", err.Error())
		return
	}
	bin, svc, state, unit := "tg-agent", "tamperguard-agent", "/var/lib/tamperguard-agent", agentUnit
	if role == "publish" {
		bin, svc, state, unit = "tg-publish", "tamperguard-publish", "/var/lib/tamperguard-publish", publishUnit
	}
	script := fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail
if [ "$(id -u)" -ne 0 ]; then echo "run as root: curl ... | sudo bash"; exit 1; fi
BASE=%q
TOKEN=%q
ROLE=%q
BIN=%q
SVC=%q
STATE=%q
case "$(uname -m)" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) echo "unsupported arch: $(uname -m)"; exit 1 ;;
esac
mkdir -p /etc/tamperguard
curl -fsSk "$BASE/api/v1/downloads/agent?file=ca.crt" -o /etc/tamperguard/ca.crt
curl -fsSk "$BASE/api/v1/downloads/agent?role=$ROLE&os=linux&arch=$ARCH" -o "/usr/local/bin/$BIN"
chmod 0755 "/usr/local/bin/$BIN"
"/usr/local/bin/$BIN" enroll --server "$BASE" --bootstrap "$TOKEN" --ca /etc/tamperguard/ca.crt --role "$ROLE" --state-dir "$STATE"
cat > "/etc/systemd/system/$SVC.service" <<UNIT
%s
UNIT
systemctl daemon-reload
systemctl enable --now "$SVC"
echo "installed and enrolled: $SVC"
`, base, tok, role, bin, svc, state, strings.ReplaceAll(unit, statePlaceholder, state))

	w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
	w.Header().Set("Content-Disposition", `inline; filename="tamperguard-install.sh"`)
	_, _ = w.Write([]byte(script))
}

const statePlaceholder = "__STATE_DIR__"

const agentUnit = `[Unit]
Description=TamperGuard protection agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/tg-agent run --state-dir ` + statePlaceholder + `
Restart=always
RestartSec=3
RefuseManualStop=yes

[Install]
WantedBy=multi-user.target
`

const publishUnit = `[Unit]
Description=TamperGuard publisher agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/tg-publish run --state-dir ` + statePlaceholder + `
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
`

// handleWindowsInstallPackage builds a personalised zip: binaries, CA and a
// one-click script that enrols the host and installs the hardened services.
func (s *Server) handleWindowsInstallPackage(w http.ResponseWriter, r *http.Request) {
	role := r.URL.Query().Get("role")
	if role == "" {
		role = "protect"
	}
	if role != "protect" && role != "publish" {
		writeErr(w, http.StatusBadRequest, "invalid", "role must be protect or publish")
		return
	}
	base, err := s.controlURL(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid", err.Error())
		return
	}
	raw := idgen.Token(24)
	if err := s.st.AddBootstrapToken(token.DigestString(raw), role); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	dir := filepath.Join(s.cfg.DataDir, "downloads")
	files := map[string]string{
		"tg-agent.exe":         filepath.Join(dir, "tg-agent-windows-amd64.exe"),
		"tg-publish.exe":       filepath.Join(dir, "tg-publish-windows-amd64.exe"),
		"tg-agent-gui.exe":     filepath.Join(dir, "tg-agent-gui.exe"),
		"install-service.ps1":  filepath.Join(dir, "install-service.ps1"),
		"verify-hardening.ps1": filepath.Join(dir, "verify-hardening.ps1"),
		"ca.crt":               filepath.Join(s.cfg.DataDir, "keys", "ca.crt"),
	}
	// Accept locally built names as a fallback.
	fallbacks := map[string]string{
		"tg-agent-gui.exe": filepath.Join(dir, "tg-agent-gui.exe"),
	}

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	add := func(name string, data []byte) error {
		fw, err := zw.Create(name)
		if err != nil {
			return err
		}
		_, err = fw.Write(data)
		return err
	}
	for name, path := range files {
		data, err := os.ReadFile(path)
		if err != nil {
			if alt, ok := fallbacks[name]; ok {
				data, err = os.ReadFile(alt)
			}
			if err != nil {
				writeErr(w, http.StatusInternalServerError, "internal", "missing "+name+" on control plane")
				return
			}
		}
		if err := add(name, data); err != nil {
			writeErr(w, http.StatusInternalServerError, "internal", err.Error())
			return
		}
	}
	state := `C:\ProgramData\TamperGuard`
	if role == "publish" {
		state = `C:\ProgramData\TamperGuard-publish`
	}
	psQuote := func(v string) string { return strings.ReplaceAll(v, "'", "''") }
	wrapper := fmt.Sprintf(`$ErrorActionPreference = 'Stop'
$Server = '%s'
$Token  = '%s'
$Role   = '%s'
$State  = '%s'
$root   = Split-Path -Parent $MyInvocation.MyCommand.Path
$agentDir = 'C:\Program Files\TamperGuard'

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$pr = New-Object Security.Principal.WindowsPrincipal($id)
if (-not $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "elevating..." -ForegroundColor Yellow
    Start-Process powershell -Verb RunAs -ArgumentList ('-NoProfile -ExecutionPolicy Bypass -File "{0}"' -f $PSCommandPath)
    exit 0
}

New-Item -ItemType Directory -Force -Path $agentDir | Out-Null
$files = @('tg-agent.exe','tg-publish.exe','tg-agent-gui.exe','install-service.ps1','verify-hardening.ps1','ca.crt')
function Copy-Binaries {
    foreach ($f in $files) {
        if (Test-Path (Join-Path $root $f)) {
            try {
                Copy-Item (Join-Path $root $f) (Join-Path $agentDir $f) -Force -ErrorAction Stop
            } catch {
                Write-Host "copy failed: $f :: $($_.Exception.Message)" -ForegroundColor Yellow
                return $false
            }
        }
    }
    return $true
}

if (-not (Copy-Binaries)) {
    Write-Host "program directory is hardened; reclaiming it as SYSTEM..." -ForegroundColor Yellow
    $prep = 'C:\Windows\Temp\tg-prep.cmd'
    $prepBody = @'
@echo off
sc stop TamperGuardWatchdog >nul 2>&1
sc stop TamperGuardAgent >nul 2>&1
sc stop TamperGuardPublish >nul 2>&1
timeout /t 2 /nobreak >nul
takeown /f "__AGENTDIR__" /r /d y >nul 2>&1
icacls "__AGENTDIR__" /grant "*S-1-5-32-544:(OI)(CI)F" /T >nul 2>&1
if exist "__STATE__" (
  takeown /f "__STATE__" /r /d y >nul 2>&1
  icacls "__STATE__" /grant "*S-1-5-32-544:(OI)(CI)F" /T >nul 2>&1
)
'@
    $prepBody = $prepBody.Replace('__AGENTDIR__', $agentDir).Replace('__STATE__', $State)
    Set-Content -LiteralPath $prep -Value $prepBody -Encoding ASCII
    $taskArgs = '/Create /TN TamperGuardPrep /TR C:\Windows\Temp\tg-prep.cmd /SC ONCE /ST 00:00 /RU SYSTEM /RL HIGHEST /F'
    $create = Start-Process -FilePath schtasks.exe -ArgumentList $taskArgs -Wait -PassThru -WindowStyle Hidden
    if ($create.ExitCode -eq 0) {
        Start-Process -FilePath schtasks.exe -ArgumentList '/Run /TN TamperGuardPrep' -Wait -WindowStyle Hidden | Out-Null
        Start-Sleep -Seconds 7
        Start-Process -FilePath schtasks.exe -ArgumentList '/Delete /TN TamperGuardPrep /F' -Wait -WindowStyle Hidden | Out-Null
    }
    if (-not (Copy-Binaries)) {
        throw "cannot write to $agentDir even after reclaim; close any running agent and retry"
    }
}

# First pass registers services without starting or locking state.
& (Join-Path $agentDir 'install-service.ps1')

if (-not (Test-Path (Join-Path $State 'agent.json'))) {
    & (Join-Path $agentDir 'tg-agent.exe') enroll --server $Server --bootstrap $Token --ca (Join-Path $agentDir 'ca.crt') --role $Role --state-dir $State
}

# Second pass locks ACLs and starts the enrolled services.
& (Join-Path $agentDir 'install-service.ps1')

if ($Role -eq 'protect' -and (Test-Path (Join-Path $agentDir 'tg-agent-gui.exe'))) {
    Start-Process (Join-Path $agentDir 'tg-agent-gui.exe')
}
Write-Host "TamperGuard installed and enrolled ($Role)." -ForegroundColor Green
Start-Sleep -Seconds 5
`, psQuote(base), psQuote(raw), psQuote(role), psQuote(state))
	cmd := `@echo off
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0install-and-enroll.ps1"
pause
`
	if err := add("install-and-enroll.ps1", []byte(wrapper)); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	if err := add("install.cmd", []byte(cmd)); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	if err := zw.Close(); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="tamperguard-install.zip"`)
	w.Header().Set("Content-Length", fmt.Sprintf("%d", buf.Len()))
	_, _ = w.Write(buf.Bytes())
}
