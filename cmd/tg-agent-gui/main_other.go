//go:build !windows

package main

import "fmt"

func main() {
	fmt.Println("tg-agent-gui: only supported on Windows")
}
