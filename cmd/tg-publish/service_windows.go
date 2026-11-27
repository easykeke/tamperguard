//go:build windows

package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"golang.org/x/sys/windows/svc"
)

func tryServiceMode(name string, args []string) (bool, error) {
	isService, err := svc.IsWindowsService()
	if err != nil || !isService {
		return false, nil
	}
	return true, svc.Run(name, &serviceHandler{run: func(ctx context.Context) error { return cmdRunContext(args, ctx) }})
}

func serviceLog(format string, args ...any) {
	f, err := os.OpenFile(`C:\Windows\Temp\tg-publish-service.log`, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, time.Now().Format("2006-01-02 15:04:05 ")+format+"\n", args...)
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
