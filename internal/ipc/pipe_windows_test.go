//go:build windows

package ipc

import (
	"bufio"
	"encoding/json"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestPipeRoundTrip(t *testing.T) {
	Serve(func() Status {
		return Status{AgentID: "n_test", Role: "protect", Enforcer: "windows-acl", LastHeartbeat: time.Now().Unix()}
	})
	time.Sleep(200 * time.Millisecond)

	name, _ := windows.UTF16PtrFromString(PipeName)
	var h windows.Handle
	var err error
	for i := 0; i < 20; i++ {
		h, err = windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE,
			0, nil, windows.OPEN_EXISTING, 0, 0)
		if err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("open pipe: %v", err)
	}
	f := os.NewFile(uintptr(h), "pipe")
	defer f.Close()
	if _, err := f.Write([]byte("{\"cmd\":\"status\"}\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	line, err := bufio.NewReader(f).ReadString('\n')
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var got Status
	if err := json.Unmarshal([]byte(line), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.AgentID != "n_test" || got.Enforcer != "windows-acl" {
		t.Fatalf("unexpected status: %+v", got)
	}
}
