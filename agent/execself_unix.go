//go:build !windows

package main

import (
	"log"
	"os"
	"syscall"
)

// execSelf replaces this process image with the freshly installed binary,
// preserving pid, fds and the service manager's supervision.
func execSelf() {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	if err := syscall.Exec(exe, os.Args, os.Environ()); err != nil {
		log.Printf("self-update: exec failed: %v", err)
	}
}
