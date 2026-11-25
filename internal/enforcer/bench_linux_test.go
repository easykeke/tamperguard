//go:build linux

package enforcer

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/easykeke/tamperguard/internal/policy"
)

// silenceLogs keeps enforcer log lines from being interleaved into the
// benchmark result lines.
func silenceLogs(b *testing.B) {
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
	b.Cleanup(func() { slog.SetDefault(prev) })
}

// Benchmarks for the enforcement overhead. Run as root on a host with bpf LSM:
//
//	sudo go test ./internal/enforcer -run '^$' -bench . -benchtime=20000x
//
// The numbers are the cost the kernel pays for the hook + map lookups; compare
// each "Protected" case against its "Unprotected" twin on the same machine.

var benchData = []byte("0123456789abcdef0123456789abcdef")

func BenchmarkWriteUnprotected(b *testing.B) {
	dir := b.TempDir()
	path := filepath.Join(dir, "f.txt")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := os.WriteFile(path, benchData, 0o644); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkWriteProtectedGranted(b *testing.B) {
	if os.Getuid() != 0 {
		b.Skip("requires root")
	}
	silenceLogs(b)
	dir := b.TempDir()
	enf, err := NewEBPF([]int{os.Getuid()})
	if err != nil {
		b.Skipf("eBPF unavailable: %v", err)
	}
	defer enf.Close()
	snap := &policy.Snapshot{Policy: policy.Policy{
		ID: "bench", Name: "bench", Version: 1,
		Paths: []policy.PathRule{{Path: dir, Recursive: true, Mode: policy.ModeEnforce}},
	}}
	_ = enf.Update(Runtime{Policy: snap, Grants: []policy.Grant{{
		TokenID: "tok-bench", Subject: "pub", NodeID: "node",
		Paths: []string{dir}, ExpiresAt: time.Now().Unix() + 3600,
	}}})
	defer func() { _ = enf.Update(Runtime{}) }()
	path := filepath.Join(dir, "f.txt")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := os.WriteFile(path, benchData, 0o644); err != nil {
			b.Fatal(err)
		}
	}
	// Stop before the defers run: unloading the eBPF programs costs seconds and
	// would otherwise be divided into the per-operation number.
	b.StopTimer()
}

func BenchmarkCreateProtectedGranted(b *testing.B) {
	if os.Getuid() != 0 {
		b.Skip("requires root")
	}
	silenceLogs(b)
	dir := b.TempDir()
	enf, err := NewEBPF([]int{os.Getuid()})
	if err != nil {
		b.Skipf("eBPF unavailable: %v", err)
	}
	defer enf.Close()
	snap := &policy.Snapshot{Policy: policy.Policy{
		ID: "bench", Name: "bench", Version: 1,
		Paths: []policy.PathRule{{Path: dir, Recursive: true, Mode: policy.ModeEnforce}},
	}}
	_ = enf.Update(Runtime{Policy: snap, Grants: []policy.Grant{{
		TokenID: "tok-bench", Subject: "pub", NodeID: "node",
		Paths: []string{dir}, ExpiresAt: time.Now().Unix() + 3600,
	}}})
	defer func() { _ = enf.Update(Runtime{}) }()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p := filepath.Join(dir, fmt.Sprintf("f-%d.txt", i))
		if err := os.WriteFile(p, benchData, 0o644); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
}

func BenchmarkCreateUnprotected(b *testing.B) {
	dir := b.TempDir()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p := filepath.Join(dir, fmt.Sprintf("f-%d.txt", i))
		if err := os.WriteFile(p, benchData, 0o644); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkStatUnprotected(b *testing.B) {
	dir := b.TempDir()
	path := filepath.Join(dir, "f.txt")
	if err := os.WriteFile(path, benchData, 0o644); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := os.Stat(path); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkReadUnprotected(b *testing.B) {
	dir := b.TempDir()
	path := filepath.Join(dir, "f.txt")
	if err := os.WriteFile(path, benchData, 0o644); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := os.ReadFile(path); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkReadProtected(b *testing.B) {
	if os.Getuid() != 0 {
		b.Skip("requires root")
	}
	silenceLogs(b)
	dir := b.TempDir()
	path := filepath.Join(dir, "f.txt")
	if err := os.WriteFile(path, benchData, 0o644); err != nil {
		b.Fatal(err)
	}
	enf, err := NewEBPF([]int{os.Getuid()})
	if err != nil {
		b.Skipf("eBPF unavailable: %v", err)
	}
	defer enf.Close()
	snap := &policy.Snapshot{Policy: policy.Policy{
		ID: "bench", Name: "bench", Version: 1,
		Paths: []policy.PathRule{{Path: dir, Recursive: true, Mode: policy.ModeEnforce}},
	}}
	_ = enf.Update(Runtime{Policy: snap})
	defer func() { _ = enf.Update(Runtime{}) }()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := os.ReadFile(path); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
}

func BenchmarkStatProtected(b *testing.B) {
	if os.Getuid() != 0 {
		b.Skip("requires root")
	}
	silenceLogs(b)
	dir := b.TempDir()
	path := filepath.Join(dir, "f.txt")
	if err := os.WriteFile(path, benchData, 0o644); err != nil {
		b.Fatal(err)
	}
	enf, err := NewEBPF([]int{os.Getuid()})
	if err != nil {
		b.Skipf("eBPF unavailable: %v", err)
	}
	defer enf.Close()
	snap := &policy.Snapshot{Policy: policy.Policy{
		ID: "bench", Name: "bench", Version: 1,
		Paths: []policy.PathRule{{Path: dir, Recursive: true, Mode: policy.ModeEnforce}},
	}}
	_ = enf.Update(Runtime{Policy: snap})
	defer func() { _ = enf.Update(Runtime{}) }()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := os.Stat(path); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
}
