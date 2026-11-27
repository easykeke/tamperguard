//go:build windows

package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"time"

	"golang.org/x/sys/windows/svc"
)

// runUnderServiceManager hands control to the Windows SCM when the process was
// started as a service. A console run returns handled=false and keeps the normal
// signal-based path.
func bootLog(format string, args ...any) {
	f, err := os.OpenFile(`C:\ProgramData\TamperGuardStatus\service-boot.log`, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, time.Now().Format("2006-01-02 15:04:05 ")+format+"\n", args...)
	_ = exec.Command("icacls", `C:\ProgramData\TamperGuardStatus\service-boot.log`, "/grant", "*S-1-5-32-545:R").Run()
}

func tryServiceMode(name string, args []string) (bool, error) {
	bootLog("tryServiceMode name=%s args=%v", name, args)
	isService, err := svc.IsWindowsService()
	bootLog("IsWindowsService=%v err=%v", isService, err)
	if err != nil || !isService {
		return false, nil
	}
	err = svc.Run(name, &serviceHandler{run: func(ctx context.Context) error { return cmdRunContext(args, ctx) }})
	bootLog("svc.Run returned err=%v", err)
	return true, err
}

func serviceLog(format string, args ...any) {
	f, err := os.OpenFile(`C:\Windows\Temp\tg-agent-service.log`, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, time.Now().Format("2006-01-02 15:04:05 ")+format+"\n", args...)
	_ = exec.Command("icacls", `C:\ProgramData\TamperGuardStatus\service-boot.log`, "/grant", "*S-1-5-32-545:R").Run()
}

type serviceHandler struct {
	run func(context.Context) error
}

func (h *serviceHandler) Execute(_ []string, requests <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	serviceLog("service starting")
	status <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- h.run(ctx) }()
	serviceLog("service reported running")

	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case err := <-done:
			if err != nil {
				serviceLog("service run failed: %v", err)
				return true, 1
			}
			serviceLog("service exited cleanly")
			return false, 0
		case req := <-requests:
			switch req.Cmd {
			case svc.Stop, svc.Shutdown:
				serviceLog("stop requested")
				status <- svc.Status{State: svc.StopPending}
				cancel()
				select {
				case <-done:
				case <-time.After(15 * time.Second):
				}
				return false, 0
			}
		}
	}
}
