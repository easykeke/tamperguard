//go:build !windows

package main

func tryServerService(string, []string) (bool, error) { return false, nil }
