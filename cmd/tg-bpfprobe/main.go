// Command tg-bpfprobe is a diagnostic helper: it attaches the eBPF LSM
// programs, protects one directory and holds the protection for a while so the
// behaviour can be inspected from another shell (bpftool, manual writes).
//
// It is a development tool, not part of the shipped agent.
package main

import (
	"fmt"
	"os"
	"time"

	"github.com/easykeke/tamperguard/internal/enforcer"
	"github.com/easykeke/tamperguard/internal/policy"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: tg-bpfprobe <dir> [seconds]")
		os.Exit(2)
	}
	dir := os.Args[1]
	secs := 30
	if len(os.Args) > 2 {
		fmt.Sscanf(os.Args[2], "%d", &secs)
	}
	enf, err := enforcer.NewEBPF([]int{os.Getuid()})
	if err != nil {
		fmt.Println("ATTACH_FAILED:", err)
		os.Exit(1)
	}
	snap := &policy.Snapshot{Policy: policy.Policy{
		ID: "probe", Name: "probe", Version: 1,
		Paths: []policy.PathRule{
			{Path: dir, Recursive: true, Mode: policy.ModeEnforce},
			// Also protect one file directly, so the diagnostic can tell an
			// inode-lookup failure apart from a parent-dentry failure.
			{Path: dir + "/index.html", Recursive: false, Mode: policy.ModeEnforce},
		},
	}}
	if err := enf.Update(enforcer.Runtime{Policy: snap}); err != nil {
		fmt.Println("UPDATE_FAILED:", err)
	}
	d, f, g := enf.Stats()
	fmt.Printf("READY dirs=%d files=%d grants=%d cap=%+v\n", d, f, g, enf.Capability())
	go func() {
		for ev := range enf.Events() {
			fmt.Printf("EVENT kind=%s path=%s op=%s reason=%s\n", ev.Kind, ev.Path, ev.Op, ev.Reason)
		}
	}()
	go func() {
		for i := 0; i < secs; i++ {
			time.Sleep(time.Second)
			c := enf.Counters()
			fmt.Printf("COUNTERS perm_calls=%d protected_hits=%d denies=%d file_open=%d inode_perm=%d\n",
				c[0], c[1], c[2], c[3], c[4])
		}
	}()
	time.Sleep(time.Duration(secs) * time.Second)
	_ = enf.Close()
}
