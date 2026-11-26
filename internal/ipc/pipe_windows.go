//go:build windows

package ipc

import (
	"bufio"
	"encoding/json"
	"os"
	"runtime"
	"time"

	"golang.org/x/sys/windows"
)

// PipeName is the local named pipe used by the GUI client.
const PipeName = `\\.\pipe\TamperGuardAgent`

// Serve starts the named-pipe server in the background. The pipe is readable by
// authenticated users (the GUI runs as the logged-in user), while the agent
// remains a SYSTEM service.
func Serve(status func() Status) {
	go serveLoop(status)
}

func serveLoop(status func() Status) {
	name, err := windows.UTF16PtrFromString(PipeName)
	if err != nil {
		return
	}
	sd, err := windows.SecurityDescriptorFromString(`D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;AU)`)
	if err != nil {
		return
	}
	sa := &windows.SecurityAttributes{SecurityDescriptor: sd}

	for {
		h, err := windows.CreateNamedPipe(name,
			windows.PIPE_ACCESS_DUPLEX,
			windows.PIPE_TYPE_BYTE|windows.PIPE_READMODE_BYTE|windows.PIPE_WAIT,
			windows.PIPE_UNLIMITED_INSTANCES, 65536, 65536, 0, sa)
		if err != nil {
			time.Sleep(time.Second)
			continue
		}
		if err := windows.ConnectNamedPipe(h, nil); err != nil && err != windows.ERROR_PIPE_CONNECTED {
			windows.CloseHandle(h)
			continue
		}
		handleConn(h, status)
		windows.CloseHandle(h)
		runtime.Gosched()
	}
}

func handleConn(h windows.Handle, status func() Status) {
	f := os.NewFile(uintptr(h), "pipe")
	if f == nil {
		return
	}
	defer f.Close()
	_ = f.SetDeadline(time.Now().Add(5 * time.Second))
	line, err := bufio.NewReader(f).ReadString('\n')
	if err != nil {
		return
	}
	var req Request
	_ = json.Unmarshal([]byte(line), &req)
	var resp any = status()
	if req.Cmd == "ping" {
		resp = map[string]string{"ok": "pong"}
	}
	raw, err := json.Marshal(resp)
	if err != nil {
		return
	}
	_, _ = f.Write(append(raw, '\n'))
}
