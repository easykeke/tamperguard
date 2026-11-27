//go:build windows

// Package watchdog keeps the TamperGuard services present and running, and
// re-applies their hardened security descriptors and directory ACLs. It is a
// second LocalSystem service: stopping the agent alone does not help, because
// the watchdog restarts it. A determined administrator can still take ownership
// of both services; that boundary is documented and unchanged without a driver.
package watchdog

import (
	"fmt"
	"log"
	"os/exec"
	"strings"
	"time"

	"golang.org/x/sys/windows/svc"
)

// Options describes what the watchdog protects.
type Options struct {
	Services    []string // services that must exist and run
	AgentDir    string
	StateDir    string
	PublishDir  string
	ServiceSDDL string
}

type handler struct {
	opts Options
}

// Run starts the Windows service dispatcher.
func regLog(name, value string) {
	_ = exec.Command("reg", "add", `HKLM\SOFTWARE\TamperGuard`, "/v", name,
		"/t", "REG_SZ", "/d", value, "/f").Run()
}

func Run(opts Options) error {
	regLog("WatchdogRun", fmt.Sprintf("services=%v", opts.Services))
	if len(opts.Services) == 0 {
		return fmt.Errorf("watchdog: no services configured")
	}
	log.Printf("watchdog: starting service, protected=%v", opts.Services)
	err := svc.Run("TamperGuardWatchdog", &handler{opts: opts})
	regLog("WatchdogExit", fmt.Sprintf("err=%v", err))
	return err
}

func (h *handler) Execute(args []string, requests <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	go h.loop()
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for req := range requests {
		switch req.Cmd {
		case svc.Stop, svc.Shutdown:
			status <- svc.Status{State: svc.StopPending}
			return false, 0
		}
	}
	return false, 0
}

func (h *handler) loop() {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		h.enforce()
	}
}

func (h *handler) enforce() {
	for _, name := range h.opts.Services {
		out, err := exec.Command("sc.exe", "query", name).CombinedOutput()
		text := string(out)
		if err != nil || strings.Contains(text, "1060") {
			log.Printf("watchdog: service %s missing: %s", name, strings.TrimSpace(text))
			continue
		}
		if strings.Contains(text, "STOPPED") {
			log.Printf("watchdog: service %s stopped, restarting", name)
			_ = exec.Command("sc.exe", "start", name).Run()
		}
		if h.opts.ServiceSDDL != "" {
			_ = exec.Command("sc.exe", "sdset", name, h.opts.ServiceSDDL).Run()
		}
	}
	// Re-apply directory ACLs: SYSTEM full, administrators read-only.
	for _, dir := range []string{h.opts.AgentDir, h.opts.StateDir, h.opts.PublishDir} {
		if dir == "" {
			continue
		}
		_ = exec.Command("icacls", dir,
			"/inheritance:r",
			"/grant:r", "SYSTEM:(OI)(CI)F",
			"Administrators:(OI)(CI)RX",
			"/T", "/C").Run()
	}
}
