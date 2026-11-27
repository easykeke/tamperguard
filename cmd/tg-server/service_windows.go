//go:build windows

package main

import (
	"context"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows/svc"
)

func tryServerService(name string, args []string) (bool, error) {
	isService, err := svc.IsWindowsService()
	if err != nil || !isService {
		return false, nil
	}
	dataDir := ""
	for i := 0; i+1 < len(args); i++ {
		if args[i] == "--data-dir" {
			dataDir = args[i+1]
		}
	}
	return true, svc.Run(name, &serverServiceHandler{dataDir: dataDir, run: func(ctx context.Context) error {
		return cmdServeContext(args, ctx)
	}})
}

type serverServiceHandler struct {
	dataDir string
	run     func(context.Context) error
}

func (h *serverServiceHandler) Execute(_ []string, requests <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- h.run(ctx) }()

	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case err := <-done:
			if err != nil {
				if h.dataDir != "" {
					_ = os.WriteFile(filepath.Join(h.dataDir, "service-error.txt"), []byte(err.Error()+"\n"), 0o644)
				}
				return true, 1
			}
			return false, 0
		case req := <-requests:
			switch req.Cmd {
			case svc.Stop, svc.Shutdown:
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
