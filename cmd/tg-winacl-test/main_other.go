//go:build !windows

// The Windows ACL/MIC test harness only builds for Windows.
package main

import "fmt"

func main() {
	fmt.Println("tg-winacl-test is Windows-only")
}
