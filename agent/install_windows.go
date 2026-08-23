//go:build windows

package main

import "fmt"

func installService() error {
	exe, _ := osExecutable()
	return fmt.Errorf(
		"windows installer not yet implemented; register a scheduled task running: %s",
		exe)
}

func uninstallService() error {
	return fmt.Errorf("windows uninstaller not yet implemented")
}
