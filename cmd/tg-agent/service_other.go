//go:build !windows

package main

func tryServiceMode(string, []string) (bool, error) {
	return false, nil
}
