package rasp

import (
	"bufio"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"path/filepath"
	"testing"
	"time"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestServerConfigAndEvents(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "rasp.sock")
	events := make(chan Event, 4)
	srv, err := New(socket, func(e Event) { events <- e }, discardLogger())
	if err != nil {
		t.Fatalf("start server: %v", err)
	}
	defer srv.Close()

	conn, err := net.Dial("unix", srv.Socket())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	enc := json.NewEncoder(conn)
	dec := json.NewDecoder(bufio.NewReader(conn))

	if err := enc.Encode(Message{Type: "hello", PID: 4242, App: "node"}); err != nil {
		t.Fatal(err)
	}
	var msg Message
	if err := dec.Decode(&msg); err != nil {
		t.Fatalf("decode config: %v", err)
	}
	if msg.Type != "config" {
		t.Fatalf("expected config, got %+v", msg)
	}
	if len(msg.Rules) != 0 {
		t.Fatalf("expected no rules yet, got %v", msg.Rules)
	}

	// A policy update must be pushed to the connected probe.
	srv.UpdateRules([]Rule{{Path: "/var/www", Recursive: true, Mode: "observe"}})
	if err := dec.Decode(&msg); err != nil {
		t.Fatalf("decode pushed config: %v", err)
	}
	if msg.Type != "config" || len(msg.Rules) != 1 || msg.Rules[0].Mode != "observe" {
		t.Fatalf("unexpected pushed config: %+v", msg)
	}

	// Events reported by the probe reach the callback.
	if err := enc.Encode(Message{
		Type: "event", Path: "/var/www/x.php", Op: "write",
		Decision: "blocked", PID: 4242, App: "node", Stack: "at foo",
	}); err != nil {
		t.Fatal(err)
	}
	select {
	case ev := <-events:
		if ev.Path != "/var/www/x.php" || ev.Decision != "blocked" || ev.PID != 4242 {
			t.Fatalf("unexpected event: %+v", ev)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("event not delivered")
	}
}

func TestServerDisconnectAndClose(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "rasp.sock")
	srv, err := New(socket, nil, discardLogger())
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("unix", srv.Socket())
	if err != nil {
		t.Fatal(err)
	}
	_ = json.NewEncoder(conn).Encode(Message{Type: "hello", PID: 1})
	deadline := time.Now().Add(2 * time.Second)
	for srv.Clients() != 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if srv.Clients() != 1 {
		t.Fatalf("expected 1 client, got %d", srv.Clients())
	}
	conn.Close()
	for srv.Clients() != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if srv.Clients() != 0 {
		t.Fatalf("client not removed, got %d", srv.Clients())
	}
	if err := srv.Close(); err != nil {
		t.Fatal(err)
	}
}
